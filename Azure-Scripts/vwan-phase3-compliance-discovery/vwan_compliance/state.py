"""Persistent cross-run state for incremental re-scanning
(--state-file, default ./phase3_state.json).

Tracks, per subscription ID: last scan timestamp, outcome, verdict counts,
a content hash of the inputs that determined its scope, and -- so a run
that skips most subscriptions can still emit a COMPLETE current-state
report without re-scanning them -- the full set of findings/offending
routes/errors from the last time it succeeded or partially succeeded.

Written incrementally: main.py calls record() once a subscription's Phase 4
evaluation is fully complete, so an interrupted run resumes cleanly (already
somewhere in NOT_EVALUATED / PARTIAL / ERROR) instead of restarting from
scratch.

Corrupt/missing state files are treated as empty rather than fatal, same
philosophy as cache.RunCache.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .logging_config import get_logger
from .models import ScanOutcome

log = get_logger("state")

# Subscriptions in one of these outcomes are always retried, regardless of
# --retry-failed-only / input hash / --max-age-days.
ALWAYS_RETRY_OUTCOMES = {ScanOutcome.PARTIAL.value, ScanOutcome.ERROR.value}


@dataclass
class SubscriptionState:
    subscription_id: str
    last_scan_utc: Optional[str] = None
    outcome: str = ScanOutcome.ERROR.value
    input_hash: str = ""
    verdict_counts: dict = field(default_factory=dict)
    subnets_total: int = 0
    subnets_errored: int = 0
    last_error_summary: str = ""
    # Full replay data, so an ALREADY_EVALUATED subscription can still
    # contribute to this run's merged report without a fresh Azure call.
    findings: list = field(default_factory=list)          # list[dict], see output._finding_to_dict
    offending_routes: list = field(default_factory=list)  # list[dict]
    errors: list = field(default_factory=list)             # list[dict]
    # MERGE-FORWARD: attempts that produced strictly worse data than what's
    # already recorded (e.g. a second run under an account with insufficient
    # RBAC turning prior MEASURED verdicts into all-ERROR) are logged here
    # instead of overwriting findings/offending_routes/errors above. See
    # main.py's on_subscription_complete for the decision logic.
    failed_attempts: list = field(default_factory=list)    # list[dict]: timestamp_utc, outcome, subnets_total, subnets_errored, reason


class ScanState:
    def __init__(self, path: Path):
        self.path = path
        self._data: dict[str, dict] = {}
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
                log.info("Loaded scan state from %s (%d subscription(s) recorded).", path, len(self._data))
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Could not read state file %s (%s) - starting fresh.", path, exc)
                self._data = {}

    def get(self, subscription_id: str) -> Optional[SubscriptionState]:
        raw = self._data.get(subscription_id)
        if raw is None:
            return None
        known = {f.name for f in SubscriptionState.__dataclass_fields__.values()}
        return SubscriptionState(**{k: v for k, v in raw.items() if k in known})

    def record(self, state: SubscriptionState) -> None:
        self._data[state.subscription_id] = asdict(state)
        self._flush()

    def _flush(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2, default=str), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("Could not write state file %s (%s).", self.path, exc)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_input_hash(cmdb_row, azure_row, flags: dict) -> str:
    """Hash of everything that determines a subscription's scan scope, so a
    meaningful input change (CMDB Organization/Environment edit, Azure
    export status flip, a changed --config/--expected-next-hop/sampling
    flag) invalidates a previously-successful result even before
    --max-age-days would.

    Deliberately hashes an explicit, stable field list rather than the raw
    CmdbRow -- that dataclass also carries fields computed fresh every run
    (bucket, azure_display_name, etc.) that would cause spurious hash
    mismatches unrelated to actual input drift.
    """
    cmdb_fingerprint = None
    if cmdb_row is not None:
        cmdb_fingerprint = {
            "name": cmdb_row.name,
            "organization": cmdb_row.organization,
            "environment": cmdb_row.environment,
            "install_status": cmdb_row.install_status,
            "supported_by": cmdb_row.supported_by,
            "owned_by": cmdb_row.owned_by,
        }
    azure_fingerprint = None
    if azure_row is not None:
        azure_fingerprint = {
            "name": azure_row.name,
            "my_role": azure_row.my_role,
            "status": azure_row.status,
            "parent_management_group": azure_row.parent_management_group,
        }
    payload = {"cmdb": cmdb_fingerprint, "azure": azure_fingerprint, "flags": flags}
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def classify_subscription(
    subscription_id: str,
    state: ScanState,
    current_hash: str,
    *,
    rescan_all: bool,
    rescan_ids: set[str],
    max_age_days: Optional[int],
) -> tuple[str, Optional[SubscriptionState]]:
    """Return (classification, prior_state). classification is one of
    ALREADY_EVALUATED / NOT_EVALUATED / PARTIAL / ERROR -- whether *this*
    run should (re-)attempt the subscription. --retry-failed-only is
    applied as a further filter by the caller, not here, since it changes
    which classifications are actually scanned rather than what the
    classification itself is.
    """
    if rescan_all or subscription_id in rescan_ids:
        return "NOT_EVALUATED", state.get(subscription_id)

    prior = state.get(subscription_id)
    if prior is None:
        return "NOT_EVALUATED", None

    if prior.outcome in ALWAYS_RETRY_OUTCOMES:
        return prior.outcome, prior

    if prior.input_hash != current_hash:
        return "NOT_EVALUATED", prior

    if max_age_days is not None and prior.last_scan_utc:
        try:
            last = datetime.fromisoformat(prior.last_scan_utc)
            age_days = (datetime.now(timezone.utc) - last).total_seconds() / 86400
            if age_days > max_age_days:
                return "NOT_EVALUATED", prior
        except ValueError:
            pass

    return "ALREADY_EVALUATED", prior


def parse_rescan_ids(values: Optional[list[str]]) -> set[str]:
    """--rescan accepts either multiple args or a single comma-separated
    value (or both); normalize to a lower-cased set of subscription IDs."""
    if not values:
        return set()
    out: set[str] = set()
    for v in values:
        for part in v.split(","):
            part = part.strip().lower()
            if part:
                out.add(part)
    return out

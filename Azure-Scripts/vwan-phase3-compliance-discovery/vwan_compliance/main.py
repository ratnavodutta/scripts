"""CLI entry point wiring Phase 0 (CMDB scope) -> Phase 0b (optional Azure
export) -> Phase 0.5 (file-level reconciliation) -> Phase 1 (auth + live
RBAC reconciliation) -> Phase 2 (vWAN baseline) -> Phase 3 (inventory sweep)
-> Phase 4 (compliance verdict, incremental) -> output. READ-ONLY end to end.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

# NOTE: only the CMDB/Azure-export/reconcile modules (openpyxl + stdlib csv)
# are imported at module load time. Everything Azure-facing (auth, baseline,
# inventory, compliance, output) is imported lazily inside main(), AFTER the
# --dry-run early-return. This lets `--dry-run` work on a machine that only
# has openpyxl installed -- it never needs azure-identity/azure-mgmt-* to
# just read and print the CMDB + Azure-export-reconciled scope.
from .azure_export import AzureExportFileError, load_azure_export, resolve_azure_export_path
from .cmdb import (
    CmdbFileError,
    apply_filters,
    confirm_or_exit,
    load_cmdb,
    print_scope_summary,
    resolve_cmdb_path,
)
from .logging_config import configure_logging, get_logger
from .models import ScanOutcome
from .reconcile import DEFAULT_EXCLUDE_NAME_PATTERNS, in_scan_scope, reconcile_with_azure_export

log = get_logger("main")

try:
    from . import __version__ as SCRIPT_VERSION
except ImportError:  # pragma: no cover - defensive only
    SCRIPT_VERSION = "unknown"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vwan-phase3-discovery",
        description=(
            "Read-only discovery of Azure subscriptions/VNets/subnets whose "
            "traffic does NOT yet route through the Azure vWAN transit hub. "
            "Scope is driven by a ServiceNow CMDB export (optionally cross-checked "
            "against an Azure portal subscription export), reconciled against "
            "what the credential can actually see in Azure. Never creates, "
            "modifies, or deletes any Azure resource."
        ),
    )
    # --- Phase 0: CMDB scope ---
    p.add_argument("--cmdb-file", default=None, help="Path to the ServiceNow CMDB export (.xlsx/.xls). Prompted interactively if omitted.")
    p.add_argument("--cmdb-sheet", default=None, help="Worksheet name to read. Default: first sheet.")
    p.add_argument("--filter-org", nargs="*", default=None, help="Only scan CMDB rows whose Organization matches one of these values (case-insensitive).")
    p.add_argument("--filter-environment", nargs="*", default=None, help="Only scan CMDB rows whose Environment matches one of these values (case-insensitive).")
    p.add_argument("--filter-install-status", default="Installed", help="Only scan CMDB rows with this Install Status. Default: 'Installed'. Pass '' to disable.")
    p.add_argument("--yes", action="store_true", help="Skip the interactive scope confirmation prompt (required for non-interactive/CI runs). Also skips the optional --azure-file prompt.")

    # --- Phase 0b: Azure portal export (optional) ---
    p.add_argument("--azure-file", default=None, help="Path to the Azure portal's subscription-list export (.csv). Optional -- cross-checks the CMDB scope. Prompted interactively (skippable) if omitted and not --yes.")
    p.add_argument("--exclude-name-pattern", nargs="*", default=None, help=f"Regex pattern(s) matched against the subscription name; matches are excluded from scanning (e.g. licensing-only subs). Default: {DEFAULT_EXCLUDE_NAME_PATTERNS}")
    p.add_argument("--include-disabled", action="store_true", help="Include subscriptions whose Azure export Status != Active (excluded by default).")

    # --- Phase 1: auth ---
    p.add_argument("--tenant-id", default=None, help="Azure AD tenant ID to authenticate against (optional).")
    p.add_argument(
        "--credential-map", default=None, type=Path,
        help="Path to a JSON file routing specific subscription IDs to specific Azure CLI accounts "
             "(see config/credential_map.example.json), e.g. when different subscriptions require "
             "different identities' RBAC. Both accounts must already be signed in via separate "
             "`az login` calls. Without this flag, a single credential (DefaultAzureCredential) is "
             "used for every subscription, as before.",
    )

    # --- Phase 2: baseline overrides ---
    p.add_argument(
        "--config", default=None, type=Path,
        help="Path to a JSON config file (see config/expected_next_hops.example.json) overriding/extending the auto-discovered compliant next-hop baseline and manual bypass subnets.",
    )
    p.add_argument(
        "--expected-next-hop", nargs="*", default=[],
        help="Additional private IP(s) to treat as compliant next hops, on top of what --config and Phase 2 auto-discover.",
    )

    # --- Incremental scanning ---
    p.add_argument("--state-file", default=Path("./phase3_state.json"), type=Path, help="Path to the incremental scan-state file. Default: ./phase3_state.json")
    p.add_argument("--rescan-all", action="store_true", help="Ignore scan state; re-scan every in-scope subscription from scratch.")
    p.add_argument("--rescan", nargs="*", default=[], help="Force re-scan of specific subscription ID(s) (space- and/or comma-separated), regardless of prior state.")
    p.add_argument("--max-age-days", type=int, default=None, help="Treat a prior successful scan older than N days as stale and re-scan it.")
    p.add_argument("--retry-failed-only", action="store_true", help="Only (re-)attempt subscriptions with a prior PARTIAL/ERROR outcome; skip subscriptions never attempted before.")

    # --- Performance ---
    p.add_argument("--max-workers", type=int, default=8, help="Bounded thread pool size for parallel subscription/NIC calls. Default: 8.")
    p.add_argument(
        "--sample-nics-per-subnet", type=int, default=1,
        help="Number of NICs to sample per subnet for effective-route evaluation. Default: 1 (fast). Ignored if --evaluate-all-nics is set.",
    )
    p.add_argument(
        "--evaluate-all-nics", action="store_true",
        help="Evaluate effective routes for every NIC in every subnet instead of sampling. Much slower on large estates.",
    )

    # --- Output ---
    p.add_argument("--output-dir", default=Path("./output"), type=Path, help="Directory to write the Excel/CSV/JSON output into. Default: ./output")
    p.add_argument("--output-basename", default="phase3_compliance", help="Base filename (without extension) for the Excel/JSON outputs. Default: phase3_compliance")
    p.add_argument(
        "--no-timestamp-outputs", action="store_true",
        help="Write outputs with fixed filenames (phase3_compliance.xlsx, csv/, phase3_report.json, "
             "etc.), overwriting the previous run's files. Default: every output filename/folder is "
             "suffixed with the run's start date/time (YYYYMMDD_HHMMSS) so successive runs never "
             "overwrite each other's Excel/CSV/JSON/report files.",
    )
    p.add_argument("--cache-file", default=Path("./output/.run_cache.json"), type=Path, help="Path to the resume/effective-route cache file.")
    p.add_argument("--resume", action="store_true", help="Reuse cached effective-route results from a previous partial run (see --cache-file).")
    p.add_argument(
        "--dry-run", action="store_true",
        help="Read and print the CMDB/Azure-export-resolved scope (with filters applied) and exit, without authenticating or making any Azure calls.",
    )
    p.add_argument("--verbose", action="store_true", help="Enable debug-level structured logging.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    configure_logging(args.verbose)
    start = time.monotonic()
    # Captured once, up front, so every output file/folder from this run
    # (Excel, CSV, JSON, phase3_report.*) shares the same timestamp, and a
    # long-running scan doesn't end up straddling two different stamps.
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # --- Phase 0: CMDB scope ---
    try:
        cmdb_path = resolve_cmdb_path(args.cmdb_file)
        log.info("Reading CMDB export: %s", cmdb_path)
        load_result = load_cmdb(cmdb_path, args.cmdb_sheet)
    except CmdbFileError as exc:
        print(f"CMDB FILE ERROR: {exc}", file=sys.stderr)
        return 2

    install_status_filter = args.filter_install_status or None
    scoped_rows = apply_filters(
        load_result.rows, args.filter_org, args.filter_environment, install_status_filter,
    )

    # --- Phase 0b: Azure portal export (optional) ---
    azure_path: Optional[Path] = None
    azure_load = None
    try:
        if args.azure_file is not None:
            azure_path = resolve_azure_export_path(args.azure_file)
        elif not args.yes and sys.stdin.isatty():
            azure_path = resolve_azure_export_path(None)
        if azure_path is not None:
            log.info("Reading Azure portal subscription export: %s", azure_path)
            azure_load = load_azure_export(azure_path)
    except AzureExportFileError as exc:
        print(f"AZURE EXPORT FILE ERROR: {exc}", file=sys.stderr)
        return 2

    # --- Phase 0.5: file-level reconciliation (CMDB vs. Azure export) ---
    exclude_patterns = args.exclude_name_pattern if args.exclude_name_pattern is not None else DEFAULT_EXCLUDE_NAME_PATTERNS
    file_reconciliation = reconcile_with_azure_export(
        scoped_rows, azure_load.rows if azure_load else None, exclude_patterns,
    )

    print_scope_summary(load_result.total_data_rows, scoped_rows, load_result.duplicate_rows, load_result.invalid_rows)
    _print_azure_export_summary(azure_load, file_reconciliation.only_in_azure, scoped_rows)

    if args.dry_run:
        attemptable = [r for r in scoped_rows if in_scan_scope(r, include_disabled=args.include_disabled)[0]]
        print(
            f"\n[dry-run] {len(scoped_rows)} subscription(s) resolved from CMDB after filters; "
            f"{len(attemptable)} would be attempted after file-level exclusions "
            f"(DISABLED/ACCESS_OR_TENANT_GAP/--exclude-name-pattern). "
            "No Azure authentication or API calls were made."
        )
        return 0

    confirm_or_exit(args.yes)

    # Deferred until here: everything below needs the azure-* SDKs, which
    # --dry-run above never touches.
    from .auth import AuthenticationFailure, describe_identity, get_credential
    from .baseline import BaselineConfig, discover_baseline, print_baseline_summary
    from .cache import RunCache
    from .capability_probe import print_capability_summary, probe_subscriptions
    from .compliance import evaluate_subnets
    from .credential_router import CredentialMap, CredentialRouter, CredentialRoutingError, print_credential_routing_table
    from .inventory import reconcile_subscriptions, sweep_vnets_and_subnets
    from .models import CapabilityStatus, Evidence, Verdict
    from .output import print_console_summary, write_csv, write_excel, write_json
    from .report import build_report, write_report_json, write_report_markdown
    from .serialize import error_from_dict, error_to_dict, finding_from_dict, finding_to_dict
    from .state import ScanState, SubscriptionState, classify_subscription, compute_input_hash, now_utc_iso, parse_rescan_ids

    # --- Phase 1: auth + credential routing ---
    credential_routing_meta: dict
    if args.credential_map is not None:
        try:
            cred_map = CredentialMap.load(args.credential_map)
            router = CredentialRouter(credential_map=cred_map)
            router.preflight()
        except CredentialRoutingError as exc:
            print(f"CREDENTIAL ROUTING ERROR: {exc}", file=sys.stderr)
            return 2

        # Validate + print the routing decision for EVERY scoped subscription
        # up front, before any other Azure call -- per the no-silent-fallback
        # requirement, a single bad assignment aborts the whole run rather
        # than falling back to a different identity for that subscription.
        routing_rows = []
        routing_errors = []
        for row in scoped_rows:
            try:
                _, account = router.resolve(row.subscription_id)
                routing_rows.append((row.subscription_id, row.name, account))
            except CredentialRoutingError as exc:
                routing_errors.append(str(exc))
        print_credential_routing_table(router, routing_rows)
        if routing_errors:
            print("\nCREDENTIAL ROUTING ERRORS -- aborting, no silent fallback:", file=sys.stderr)
            for e in routing_errors:
                print(f"  - {e}", file=sys.stderr)
            return 2

        identity = {"upn": None, "app_id": None, "tenant_id": None}
        credential_routing_meta = {
            "mode": "routed",
            "credential_map_file": str(args.credential_map),
            "default_account": cred_map.default_account,
            "overrides": dict(cred_map.overrides),
            "per_subscription_account": {sub_id: account for sub_id, _name, account in routing_rows},
        }
    else:
        try:
            credential = get_credential(args.tenant_id)
        except AuthenticationFailure as exc:
            print(f"AUTHENTICATION ERROR: {exc}", file=sys.stderr)
            return 2
        identity = describe_identity(credential)
        single_label = identity.get("upn") or identity.get("app_id") or "default"
        router = CredentialRouter(single_credential=credential, single_account_label=single_label)
        print_credential_routing_table(router, [(r.subscription_id, r.name, single_label) for r in scoped_rows])
        credential_routing_meta = {"mode": "single", "account": single_label}

    try:
        config = BaselineConfig.load(args.config, args.expected_next_hop)
    except FileNotFoundError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 2

    errors: list = []

    log.info("Reconciling CMDB scope against subscriptions visible in Azure...")
    reconciliation = reconcile_subscriptions(router, scoped_rows, errors)
    if not reconciliation.scan_targets:
        print(
            "No CMDB subscriptions are both in-scope (after filters) and visible to this "
            "credential (IN_BOTH). Nothing to scan. Check RBAC and --filter-* flags.",
            file=sys.stderr,
        )
        return 1

    attemptable_ids = {
        r.subscription_id for r in scoped_rows if in_scan_scope(r, include_disabled=args.include_disabled)[0]
    }
    scan_targets = [s for s in reconciliation.scan_targets if s.subscription_id in attemptable_ids]
    if not scan_targets:
        print(
            "Every IN_BOTH subscription was excluded by file-level reconciliation "
            "(DISABLED / ACCESS_OR_TENANT_GAP / --exclude-name-pattern). Nothing to scan. "
            "Pass --include-disabled or adjust --exclude-name-pattern if that's unexpected.",
            file=sys.stderr,
        )
        return 1
    log.info(
        "Scan targets: %d IN_BOTH (live). %d excluded by file-level reconciliation "
        "(disabled/access-gap/pattern). IN_CMDB_NOT_VISIBLE: %d. VISIBLE_NOT_IN_CMDB (shadow): %d.",
        len(scan_targets),
        len(reconciliation.scan_targets) - len(scan_targets),
        sum(1 for r in reconciliation.cmdb_rows if r.bucket and r.bucket.value == "IN_CMDB_NOT_VISIBLE"),
        len(reconciliation.shadow_subscriptions),
    )

    sub_ids = [s.subscription_id for s in scan_targets]
    sub_names = {s.subscription_id: s.display_name for s in scan_targets}

    # --- Phase 2: vWAN baseline (always full -- not incremental; cheap and
    # hub topology can change independently of any one subnet's history) ---
    log.info("Phase 2: discovering vWAN/vHub baseline...")
    baselines = discover_baseline(router, sub_ids, sub_names, config, errors)
    print_baseline_summary(baselines)

    compliant_ips = set(config.additional_next_hop_ips)
    for b in baselines:
        compliant_ips |= b.compliant_next_hop_ips
    if not compliant_ips:
        log.warning(
            "No compliant next-hop IPs were resolved from Phase 2 or config. "
            "Every subnet with a measurable route will show as NON_COMPLIANT "
            "until you supply --expected-next-hop or a --config file."
        )

    hub_connection_vnet_ids = {
        conn["remote_vnet_id"]: conn["connection_name"]
        for b in baselines for conn in b.connections
        if conn.get("remote_vnet_id")
    }

    # --- Incremental classification (Phase 3/4 unit = subscription) ---
    scan_state = ScanState(args.state_file)
    rescan_ids = parse_rescan_ids(args.rescan)
    azure_rows_by_id = {r.subscription_id: r for r in (azure_load.rows if azure_load else [])}
    cmdb_rows_by_id = {r.subscription_id: r for r in scoped_rows}
    flags_fingerprint = {
        "config_file_hash": _hash_file(args.config),
        "expected_next_hop": sorted(args.expected_next_hop),
        "sample_nics_per_subnet": args.sample_nics_per_subnet,
        "evaluate_all_nics": args.evaluate_all_nics,
        "exclude_name_pattern": sorted(exclude_patterns),
        "include_disabled": args.include_disabled,
    }

    per_sub_classification: dict[str, dict] = {}
    to_scan_ids: list[str] = []
    already_evaluated_ids: list[str] = []
    for sub_id in sub_ids:
        current_hash = compute_input_hash(cmdb_rows_by_id.get(sub_id), azure_rows_by_id.get(sub_id), flags_fingerprint)
        classification, prior = classify_subscription(
            sub_id, scan_state, current_hash,
            rescan_all=args.rescan_all, rescan_ids=rescan_ids, max_age_days=args.max_age_days,
        )
        if args.retry_failed_only and classification == "NOT_EVALUATED":
            classification = "SKIPPED_RETRY_FILTER"
        per_sub_classification[sub_id] = {
            "classification": classification,
            "last_scan_utc": prior.last_scan_utc if prior else None,
            "current_hash": current_hash,
        }
        if classification == "ALREADY_EVALUATED":
            already_evaluated_ids.append(sub_id)
        elif classification != "SKIPPED_RETRY_FILTER":
            to_scan_ids.append(sub_id)

    log.info(
        "Incremental scan plan: %d to (re-)scan, %d already evaluated (reused from state), "
        "%d skipped (--retry-failed-only).",
        len(to_scan_ids), len(already_evaluated_ids),
        sum(1 for c in per_sub_classification.values() if c["classification"] == "SKIPPED_RETRY_FILTER"),
    )

    to_scan_infos = [s for s in scan_targets if s.subscription_id in set(to_scan_ids)]

    # --- Phase 3: inventory sweep (to-scan subscriptions only) ---
    log.info("Phase 3: sweeping VNets/subnets via Azure Resource Graph...")
    subnets = sweep_vnets_and_subnets(router, to_scan_infos, hub_connection_vnet_ids, errors)
    log.info("Discovered %d subnets across %d subscription(s) to (re-)scan.", len(subnets), len(to_scan_infos))

    # --- Pre-flight capability probe (before the main scan) ---
    log.info("Pre-flight: probing effectiveRouteTable/action capability per subscription...")
    capability_results = probe_subscriptions(router, to_scan_infos, subnets, errors)
    print_capability_summary(capability_results)
    insufficient_role_ids = {c.subscription_id for c in capability_results if c.status == CapabilityStatus.CANNOT_READ_ROUTES}

    resourcegraph_failed = any(e.scope == "resourcegraph" for e in errors)
    subs_with_subnets = {s.subscription_id for s in subnets}
    for sub_id in to_scan_ids:
        if sub_id in subs_with_subnets:
            continue
        outcome = ScanOutcome.ERROR.value if resourcegraph_failed else ScanOutcome.SUCCESS.value
        reason = "Resource Graph sweep failed entirely; see Errors sheet." if resourcegraph_failed else ""
        scan_state.record(SubscriptionState(
            subscription_id=sub_id, last_scan_utc=now_utc_iso(), outcome=outcome,
            input_hash=per_sub_classification[sub_id]["current_hash"],
            verdict_counts={}, subnets_total=0, subnets_errored=0, last_error_summary=reason,
        ))

    cache = RunCache(args.cache_file, enabled=args.resume)

    # MERGE-FORWARD STATE: if a subscription previously produced MEASURED
    # (COMPLIANT/NON_COMPLIANT) verdicts and THIS attempt produces zero
    # MEASURED results while erroring out, that's a worse-identity/worse-RBAC
    # re-run (exactly the failure mode that overwrote real N01 data with an
    # all-403 result in a prior incident) -- keep the prior result and log
    # this attempt separately instead of silently replacing good data.
    override_findings: dict[str, list] = {}

    def _measured_conclusive_count(findings_list) -> int:
        return sum(
            1 for f in findings_list
            if getattr(f, "evidence", None) == Evidence.MEASURED
            and getattr(f, "verdict", None) in (Verdict.COMPLIANT, Verdict.NON_COMPLIANT)
        )

    def _measured_conclusive_count_dicts(finding_dicts) -> int:
        return sum(
            1 for fd in finding_dicts
            if fd.get("evidence") == "MEASURED" and fd.get("verdict") in ("COMPLIANT", "NON_COMPLIANT")
        )

    def on_subscription_complete(sub_id, sub_findings, sub_offending, sub_errors) -> None:
        verdict_counts = Counter(f.verdict.value for f in sub_findings)
        subnets_total = len(sub_findings)
        subnets_errored = verdict_counts.get("ERROR", 0)
        if subnets_errored == 0:
            outcome = ScanOutcome.SUCCESS.value
        elif subnets_errored < subnets_total:
            outcome = ScanOutcome.PARTIAL.value
        else:
            outcome = ScanOutcome.ERROR.value
        last_error_summary = "; ".join(sorted({e.reason[:120] for e in sub_errors}))[:500]

        prior = scan_state.get(sub_id)
        this_attempt_measured = _measured_conclusive_count(sub_findings)
        prior_measured = _measured_conclusive_count_dicts(prior.findings) if prior else 0

        if prior is not None and prior_measured > 0 and this_attempt_measured == 0 and subnets_errored > 0:
            log.warning(
                "MERGE-FORWARD: %s previously had %d MEASURED verdict(s); this attempt produced 0 "
                "MEASURED results (%d/%d subnet(s) errored, account=%s). Keeping prior result -- "
                "logging this attempt as a failed retry instead of overwriting good data.",
                sub_id, prior_measured, subnets_errored, subnets_total,
                sub_findings[0].evaluated_by_account if sub_findings else "unknown",
            )
            failed_attempts = list(prior.failed_attempts) + [{
                "timestamp_utc": now_utc_iso(),
                "outcome": outcome,
                "subnets_total": subnets_total,
                "subnets_errored": subnets_errored,
                "reason": last_error_summary,
                "account": sub_findings[0].evaluated_by_account if sub_findings else "unknown",
            }]
            scan_state.record(SubscriptionState(
                subscription_id=sub_id, last_scan_utc=prior.last_scan_utc, outcome=prior.outcome,
                input_hash=prior.input_hash, verdict_counts=prior.verdict_counts,
                subnets_total=prior.subnets_total, subnets_errored=prior.subnets_errored,
                last_error_summary=prior.last_error_summary, findings=prior.findings,
                offending_routes=prior.offending_routes, errors=prior.errors,
                failed_attempts=failed_attempts,
            ))
            override_findings[sub_id] = [finding_from_dict(fd) for fd in prior.findings]
            return

        scan_state.record(SubscriptionState(
            subscription_id=sub_id,
            last_scan_utc=now_utc_iso(),
            outcome=outcome,
            input_hash=per_sub_classification[sub_id]["current_hash"],
            verdict_counts=dict(verdict_counts),
            subnets_total=subnets_total,
            subnets_errored=subnets_errored,
            last_error_summary=last_error_summary,
            findings=[finding_to_dict(f) for f in sub_findings],
            offending_routes=[],  # already embedded per-finding; avoid storing twice
            errors=[error_to_dict(e) for e in sub_errors],
            failed_attempts=list(prior.failed_attempts) if prior else [],
        ))
        log.info("State recorded for %s: %s (%d/%d subnet(s) errored).", sub_id, outcome, subnets_errored, subnets_total)

    # --- Phase 4: compliance verdict (to-scan subnets only) ---
    log.info("Phase 4: evaluating compliance (effective routes)...")
    findings, offending, compliance_errors = evaluate_subnets(
        router, subnets, compliant_ips, config.additional_next_hop_types, config, cache,
        sample_nics_per_subnet=args.sample_nics_per_subnet,
        evaluate_all_nics=args.evaluate_all_nics,
        max_workers=args.max_workers,
        insufficient_role_subscriptions=insufficient_role_ids,
        on_subscription_complete=on_subscription_complete,
    )
    errors.extend(compliance_errors)

    if override_findings:
        log.info("Applying merge-forward overrides for %d subscription(s): %s", len(override_findings), sorted(override_findings))
        findings = [f for f in findings if f.subscription_id not in override_findings]
        for replaced in override_findings.values():
            findings.extend(replaced)

    # --- Merge in replayed (ALREADY_EVALUATED) subscriptions from state ---
    replayed_findings = []
    replayed_errors = []
    for sub_id in already_evaluated_ids:
        prior = scan_state.get(sub_id)
        if prior is None:
            continue
        for fd in prior.findings:
            replayed_findings.append(finding_from_dict(fd))
        for ed in prior.errors:
            replayed_errors.append(error_from_dict(ed))
    if replayed_findings:
        log.info(
            "Replayed %d finding(s) from %d ALREADY_EVALUATED subscription(s) (skipped this run).",
            len(replayed_findings), len(already_evaluated_ids),
        )

    all_findings = findings + replayed_findings
    all_errors = errors + replayed_errors

    out_dir = args.output_dir
    # Every output file/folder is timestamped (YYYYMMDD_HHMMSS, this run's
    # start time) by default so re-running the script never overwrites a
    # previous run's Excel/CSV/JSON/report -- pass --no-timestamp-outputs to
    # go back to fixed filenames (e.g. for a dashboard that always reads
    # phase3_compliance.xlsx from a known path).
    stamp = "" if args.no_timestamp_outputs else f"_{run_timestamp}"
    excel_path = out_dir / f"{args.output_basename}{stamp}.xlsx"
    json_path = out_dir / f"{args.output_basename}{stamp}.json"
    csv_dir = out_dir / f"csv{stamp}"
    report_json_path = out_dir / f"phase3_report{stamp}.json"
    report_md_path = out_dir / f"phase3_report{stamp}.md"
    only_in_azure = file_reconciliation.only_in_azure
    invalid_azure_rows = azure_load.invalid_rows if azure_load else []

    write_excel(excel_path, all_findings, baselines, all_errors, reconciliation.cmdb_rows, reconciliation.shadow_subscriptions, load_result.invalid_rows, only_in_azure, invalid_azure_rows, load_result.raw_rows, capability_results)
    write_csv(csv_dir, all_findings, baselines, all_errors, reconciliation.cmdb_rows, reconciliation.shadow_subscriptions, load_result.invalid_rows, only_in_azure, invalid_azure_rows, load_result.raw_rows, capability_results)
    write_json(json_path, all_findings, baselines, all_errors, reconciliation.cmdb_rows, reconciliation.shadow_subscriptions, load_result.invalid_rows, only_in_azure, invalid_azure_rows, load_result.raw_rows, capability_results)

    elapsed = time.monotonic() - start

    run_metadata = _build_run_metadata_kwargs(
        cmdb_path=cmdb_path, cmdb_row_count=len(load_result.rows),
        azure_path=azure_path, azure_row_count=len(azure_load.rows) if azure_load else 0,
        identity=identity, args=args, elapsed=elapsed, credential_routing=credential_routing_meta,
    )
    report = build_report(
        run_metadata=run_metadata,
        cmdb_rows=reconciliation.cmdb_rows,
        only_in_azure=only_in_azure,
        per_sub_classification=per_sub_classification,
        findings=all_findings,
        errors=all_errors,
        baselines=baselines,
        capability_results=capability_results,
    )
    write_report_json(report_json_path, report)
    write_report_markdown(report_md_path, report)

    print_console_summary(all_findings, reconciliation.cmdb_rows, reconciliation.shadow_subscriptions, only_in_azure)
    print(f"Outputs written to: {out_dir.resolve()}")
    print(f"  Excel:  {excel_path.name}")
    print(f"  JSON:   {json_path.name}")
    print(f"  CSV:    {csv_dir.name}/")
    print(f"  Report: {report_json_path.name}, {report_md_path.name}")
    print(f"Elapsed: {elapsed:.1f}s")
    return 0


def _hash_file(path: Optional[Path]) -> Optional[str]:
    if path is None:
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _build_run_metadata_kwargs(*, cmdb_path, cmdb_row_count, azure_path, azure_row_count, identity, args, elapsed, credential_routing=None) -> dict:
    from .report import build_run_metadata
    flags = {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()}
    return build_run_metadata(
        script_version=SCRIPT_VERSION,
        cmdb_file=str(cmdb_path),
        cmdb_row_count=cmdb_row_count,
        azure_file=str(azure_path) if azure_path else None,
        credential_routing=credential_routing,
        azure_row_count=azure_row_count,
        identity=identity,
        flags=flags,
        runtime_seconds=elapsed,
    )


def _print_azure_export_summary(azure_load, only_in_azure, scoped_rows) -> None:
    if azure_load is None:
        return
    print("\n=== Phase 0b: Azure Portal Export Summary ===")
    print(f"  Total data rows read:      {azure_load.total_data_rows}")
    print(f"  Valid subscription IDs:    {len(azure_load.rows)}")
    print(f"  Duplicate rows:            {len(azure_load.duplicate_rows)}")
    print(f"  Invalid rows:              {len(azure_load.invalid_rows)}")

    only_in_cmdb = sum(1 for r in scoped_rows if r.file_scope_bucket and r.file_scope_bucket.value == "ONLY_IN_CMDB")
    in_both = sum(1 for r in scoped_rows if r.file_scope_bucket and r.file_scope_bucket.value == "IN_BOTH")
    disabled = sum(1 for r in scoped_rows if r.disabled)
    excluded = sum(1 for r in scoped_rows if r.excluded_by_name_pattern)
    org_inferred = sum(1 for r in scoped_rows if r.organization_inferred)
    print(
        f"\n  File reconciliation: IN_BOTH={in_both}  ONLY_IN_CMDB(ACCESS_OR_TENANT_GAP)={only_in_cmdb}  "
        f"ONLY_IN_AZURE={len(only_in_azure)}  DISABLED={disabled}  EXCLUDED={excluded}  ORG_INFERRED={org_inferred}"
    )


if __name__ == "__main__":
    raise SystemExit(main())

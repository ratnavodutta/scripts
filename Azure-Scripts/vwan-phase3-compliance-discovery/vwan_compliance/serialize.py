"""dict <-> dataclass round-trip for SubnetFinding/OffendingRoute/ErrorRecord.

Needed in both directions, unlike output.py's other to-dict helpers:
state.py persists a subscription's findings as plain JSON-safe dicts (for
--resume-style incremental replay across runs), and main.py needs to turn
those same dicts back into real SubnetFinding/OffendingRoute/ErrorRecord
instances to merge them into a run's in-memory results alongside freshly
scanned subnets -- the rest of the pipeline (output.py, report.py) only
knows how to render the dataclasses, not raw dicts.
"""
from __future__ import annotations

from dataclasses import asdict

from .models import ErrorRecord, Evidence, OffendingRoute, SubnetFinding, Verdict


def finding_to_dict(f: SubnetFinding) -> dict:
    d = asdict(f)  # recursively turns offending_routes (list[OffendingRoute]) into list[dict] too
    d["verdict"] = f.verdict.value
    d["evidence"] = f.evidence.value
    return d


def finding_from_dict(d: dict) -> SubnetFinding:
    d = dict(d)
    d["verdict"] = Verdict(d["verdict"])
    d["evidence"] = Evidence(d["evidence"])
    d["offending_routes"] = [OffendingRoute(**r) for r in d.get("offending_routes") or []]
    return SubnetFinding(**d)


def offending_route_to_dict(r: OffendingRoute) -> dict:
    return asdict(r)


def offending_route_from_dict(d: dict) -> OffendingRoute:
    return OffendingRoute(**d)


def error_to_dict(e: ErrorRecord) -> dict:
    return asdict(e)


def error_from_dict(d: dict) -> ErrorRecord:
    return ErrorRecord(**d)

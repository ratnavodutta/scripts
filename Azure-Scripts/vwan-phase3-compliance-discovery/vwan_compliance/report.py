"""Builds phase3_report.json + phase3_report.md: a single, self-contained
report meant to be pasted into / uploaded to an AI assistant (e.g. Copilot)
for follow-up analysis, with no external lookups needed to interpret it.

Kept deliberately separate from output.py (which owns the Excel/CSV/JSON
deliverables mirroring the raw data 1:1): this module's job is to shape and
annotate that same data for a *reader*, human or model, encountering it with
zero other context -- explicit verdict/evidence definitions, explicit
percentage denominators, and an open_questions section for whatever the
script itself couldn't resolve.

Hard rule (explicit in the design brief): NOT_EVALUATED is never counted as
compliant anywhere in this report, and every percentage states which
denominator (total subnets vs. evaluated subnets) it uses.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .inventory import SubscriptionInfo
from .logging_config import get_logger
from .models import (
    AzureExportRow,
    CmdbRow,
    ErrorRecord,
    FileScopeBucket,
    SubnetFinding,
    VHubBaseline,
    Verdict,
)
from .state import now_utc_iso

log = get_logger("report")

# Verdicts that represent a conclusive determination (measured or
# by-design), as opposed to NOT_EVALUATED (no evidence) or ERROR (attempt
# failed). This is the denominator for "compliance rate" percentages.
CONCLUSIVE_VERDICTS = {Verdict.COMPLIANT, Verdict.NON_COMPLIANT, Verdict.EXPECTED_BYPASS}

TOP_N_NON_COMPLIANT = 25


# --------------------------------------------------------------------------
# run_metadata
# --------------------------------------------------------------------------

def build_run_metadata(
    *,
    script_version: str,
    cmdb_file: str,
    cmdb_row_count: int,
    azure_file: Optional[str],
    azure_row_count: int,
    identity: dict,
    flags: dict,
    runtime_seconds: float,
    credential_routing: Optional[dict] = None,
) -> dict:
    return {
        "generated_at_utc": now_utc_iso(),
        "script_version": script_version,
        "inputs": {
            "cmdb_file": cmdb_file,
            "cmdb_row_count": cmdb_row_count,
            "azure_export_file": azure_file,
            "azure_export_row_count": azure_row_count if azure_file else None,
        },
        "identity": identity,
        # "single": one credential for every subscription (identity above).
        # "routed": per-subscription --credential-map -- see per_subscription_account
        # for which account actually produced each subscription's verdicts (also
        # on every subnet finding as evaluated_by_account).
        "credential_routing": credential_routing or {"mode": "single"},
        "flags_in_effect": flags,
        "total_runtime_seconds": round(runtime_seconds, 1),
    }


# --------------------------------------------------------------------------
# scope_reconciliation (file-level: CMDB vs. Azure portal export)
# --------------------------------------------------------------------------

def build_scope_reconciliation(cmdb_rows: list[CmdbRow], only_in_azure: list[AzureExportRow]) -> dict:
    in_both = [r.subscription_id for r in cmdb_rows if r.file_scope_bucket == FileScopeBucket.IN_BOTH]
    only_cmdb = [r.subscription_id for r in cmdb_rows if r.file_scope_bucket == FileScopeBucket.ONLY_IN_CMDB]
    only_azure = [az.subscription_id for az in only_in_azure]
    disabled = [r.subscription_id for r in cmdb_rows if r.disabled]
    excluded = [r.subscription_id for r in cmdb_rows if r.excluded_by_name_pattern]

    return {
        "counts": {
            "in_both": len(in_both),
            "only_in_cmdb_access_or_tenant_gap": len(only_cmdb),
            "only_in_azure_shadow": len(only_azure),
            "disabled": len(disabled),
            "excluded_by_pattern": len(excluded),
        },
        "in_both_subscription_ids": in_both,
        "only_in_cmdb_subscription_ids": only_cmdb,
        "only_in_azure_subscription_ids": only_azure,
        "disabled_subscription_ids": disabled,
        "excluded_by_pattern_subscription_ids": excluded,
        "note": (
            "This reconciles the CMDB export against the Azure portal export file "
            "(both static). It is independent of live RBAC visibility -- see "
            "'coverage' below for that."
        ),
    }


# --------------------------------------------------------------------------
# coverage
# --------------------------------------------------------------------------

def build_coverage(
    cmdb_rows: list[CmdbRow],
    per_sub_classification: dict[str, dict],
    findings: list[SubnetFinding],
    errors: list[ErrorRecord],
) -> dict:
    """per_sub_classification: subscription_id -> {"classification": str,
    "last_scan_utc": Optional[str]} for every subscription that was a live
    scan candidate this run (see main.py)."""
    errors_by_scope_prefix = defaultdict(list)
    for e in errors:
        errors_by_scope_prefix[e.scope.split("/resourceGroups/")[0] if e.scope else ""].append(e)

    findings_by_sub: dict[str, list[SubnetFinding]] = defaultdict(list)
    for f in findings:
        findings_by_sub[f.subscription_id].append(f)

    per_subscription = []
    evaluated_count = 0
    not_evaluated_count = 0
    failed_count = 0

    for row in cmdb_rows:
        sub_id = row.subscription_id
        reasons: list[str] = []
        status = "NOT_ATTEMPTED"

        if row.file_scope_bucket == FileScopeBucket.ONLY_IN_CMDB:
            reasons.append("ACCESS_OR_TENANT_GAP: absent from Azure portal export")
        if row.excluded_by_name_pattern:
            # Use a clean category label here, not the raw exclude_reason --
            # that string embeds the operator's regex pattern verbatim (e.g.
            # "(?i)visual studio"), whose own parentheses would break the
            # naive category-key extraction in write_report_markdown below.
            # The full pattern is still available in the Subscription_Scope
            # sheet's "Exclude Reason" column.
            reasons.append("EXCLUDED_BY_NAME_PATTERN: " + (row.exclude_reason or ""))
        if row.disabled:
            reasons.append(f"DISABLED (status='{row.azure_status}')")
        if row.bucket is not None and row.bucket.value == "IN_CMDB_NOT_VISIBLE":
            reasons.append("missing RBAC: not visible to this credential")

        cls = per_sub_classification.get(sub_id)
        subnets_for_sub = findings_by_sub.get(sub_id, [])
        sub_errors = [
            e for prefix, es in errors_by_scope_prefix.items() if sub_id in prefix for e in es
        ]
        status_codes = Counter(e.status_code for e in sub_errors if e.status_code)

        if cls is not None:
            reasons.append(f"scan classification: {cls['classification']}"
                            + (f" (last scanned {cls['last_scan_utc']})" if cls.get("last_scan_utc") else ""))
            if cls["classification"] == "ALREADY_EVALUATED":
                status = "EVALUATED_FROM_PRIOR_RUN"
            elif subnets_for_sub:
                status = "EVALUATED_THIS_RUN"
            else:
                status = "ATTEMPTED_NO_SUBNETS_FOUND"

        if subnets_for_sub:
            evaluated_count += 1
        elif status == "NOT_ATTEMPTED":
            not_evaluated_count += 1
        if status_codes.get(403) or status_codes.get(429) or any(c not in (403, 429) for c in status_codes):
            failed_count += 1

        by_verdict = Counter(f.verdict.value for f in subnets_for_sub)
        per_subscription.append({
            "subscription_id": sub_id,
            "name": row.name,
            "status": status,
            "reasons": reasons,
            "subnet_verdict_counts": dict(by_verdict),
            "error_status_codes": dict(status_codes),
        })

    return {
        "counts": {
            "subscriptions_with_at_least_one_evaluated_subnet": evaluated_count,
            "subscriptions_not_evaluated": not_evaluated_count,
            "subscriptions_with_errors": failed_count,
        },
        "per_subscription": per_subscription,
    }


# --------------------------------------------------------------------------
# vwan_baseline
# --------------------------------------------------------------------------

def build_vwan_baseline(baselines: list[VHubBaseline]) -> dict:
    hubs = []
    open_questions = []
    for b in baselines:
        fw = None
        if b.firewall:
            fw = {
                "type": b.firewall.resource_type,
                "name": b.firewall.name,
                "private_ip": b.firewall.private_ip,
            }
        else:
            open_questions.append(
                f"Hub '{b.hub_name}' (sub {b.subscription_id}) has NO firewall/NVA detected -- "
                "config gap. Verdicts for subnets peered to this hub cannot be trusted as "
                "COMPLIANT/NON_COMPLIANT until this is resolved."
            )

        has_internet_policy = any(
            "internettraffic" in [d.lower() for d in (route.get("destinations") or [])]
            for rt in b.route_tables for route in (rt.get("routes") or [])
        )
        has_private_policy = any(
            "privatetraffic" in [d.lower() for d in (route.get("destinations") or [])]
            for rt in b.route_tables for route in (rt.get("routes") or [])
        )
        if has_private_policy and not has_internet_policy:
            open_questions.append(
                f"Hub '{b.hub_name}' (sub {b.subscription_id}) has a Routing Intent with only a "
                "PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven "
                "by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet "
                "breakout, not a real Phase 3 violation -- verify manually (see README)."
            )

        hubs.append({
            "vwan_name": b.vwan_name,
            "hub_name": b.hub_name,
            "hub_id": b.hub_id,
            "region": b.region,
            "address_prefix": b.address_prefix,
            "routing_state": b.routing_state,
            "subscription_id": b.subscription_id,
            "subscription_name": b.subscription_name,
            "firewall": fw,
            "connection_count": len(b.connections),
            "gateway_count": len(b.gateways),
            "has_internet_traffic_routing_intent": has_internet_policy,
            "has_private_traffic_routing_intent": has_private_policy,
        })

    all_ips = sorted({ip for b in baselines for ip in b.compliant_next_hop_ips})
    return {
        "hubs": hubs,
        "compliant_next_hop_ips_used_for_verdicts": all_ips,
        "_open_questions": open_questions,
    }


# --------------------------------------------------------------------------
# findings: subscription -> vnet -> subnet
# --------------------------------------------------------------------------

def build_findings_tree(findings: list[SubnetFinding]) -> dict:
    tree: dict[str, dict] = {}
    for f in findings:
        sub = tree.setdefault(f.subscription_id, {
            "subscription_name": f.subscription_name,
            "organization": f.organization,
            "environment": f.environment,
            "vnets": {},
        })
        vnet = sub["vnets"].setdefault(f.vnet_name, {
            "vnet_address_space": f.vnet_address_space,
            "subnets": [],
        })
        vnet["subnets"].append({
            "subnet_name": f.subnet_name,
            "subnet_id": f.subnet_id,
            "address_prefix": f.address_prefix,
            "verdict": f.verdict.value,
            "evidence": f.evidence.value,
            "default_route_next_hop_type": f.default_route_next_hop_type,
            "default_route_next_hop_ip": f.default_route_next_hop_ip,
            "peered_to_hub": f.peered_to_hub,
            "hub_connection_name": f.hub_connection_name,
            "evaluated_by_account": f.evaluated_by_account,
            "offending_routes": [
                {
                    "address_prefix": r.address_prefix,
                    "next_hop_type": r.next_hop_type,
                    "next_hop_ip": r.next_hop_ip,
                    "route_source": r.route_source,
                    "route_table_name": r.route_table_name,
                    "route_name": r.route_name,
                }
                for r in f.offending_routes
            ] if f.verdict == Verdict.NON_COMPLIANT else [],
            "notes": f.notes,
        })
    return tree


# --------------------------------------------------------------------------
# ownership
# --------------------------------------------------------------------------

def build_ownership(cmdb_rows: list[CmdbRow]) -> dict:
    out = {}
    for r in cmdb_rows:
        organization = r.organization or r.inferred_organization or None
        if r.organization:
            org_source = "CMDB"
        elif r.organization_inferred:
            org_source = "INFERRED_FROM_AZURE_MANAGEMENT_GROUP"
        else:
            org_source = "UNKNOWN"
        out[r.subscription_id] = {
            "name": r.name,
            "organization": organization,
            "organization_source": org_source,
            "environment": r.environment or None,
            "supported_by": r.supported_by or None,
            "owned_by": r.owned_by or None,
            "parent_management_group": r.parent_management_group or None,
        }
    return out


# --------------------------------------------------------------------------
# summary_rollup
# --------------------------------------------------------------------------

def build_summary_rollup(findings: list[SubnetFinding]) -> dict:
    total_subnets = len(findings)
    by_verdict = Counter(f.verdict for f in findings)
    evaluated_subnets = sum(by_verdict.get(v, 0) for v in CONCLUSIVE_VERDICTS)

    def _pct(count: int, denom: int) -> float:
        return round(count / denom * 100, 1) if denom else 0.0

    by_verdict_out = {}
    for v in Verdict:
        count = by_verdict.get(v, 0)
        by_verdict_out[v.value] = {
            "count": count,
            "pct_of_total_subnets": _pct(count, total_subnets),
            "pct_of_evaluated_subnets": _pct(count, evaluated_subnets) if v in CONCLUSIVE_VERDICTS else None,
        }

    by_org: dict[str, Counter] = defaultdict(Counter)
    by_env: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        by_org[f.organization or "(blank)"][f.verdict] += 1
        by_env[f.environment or "(blank)"][f.verdict] += 1

    def _group_rollup(groups: dict[str, Counter]) -> dict:
        out = {}
        for key, counter in groups.items():
            grp_total = sum(counter.values())
            grp_evaluated = sum(counter.get(v, 0) for v in CONCLUSIVE_VERDICTS)
            out[key] = {
                "total_subnets": grp_total,
                "evaluated_subnets": grp_evaluated,
                "by_verdict": {v.value: counter.get(v, 0) for v in Verdict},
            }
        return out

    non_compliant = [f for f in findings if f.verdict == Verdict.NON_COMPLIANT]
    non_compliant.sort(
        key=lambda f: (f.environment.strip().lower() == "production", len(f.offending_routes)),
        reverse=True,
    )
    top_non_compliant = [
        {
            "subscription_id": f.subscription_id,
            "subscription_name": f.subscription_name,
            "organization": f.organization,
            "environment": f.environment,
            "vnet_name": f.vnet_name,
            "subnet_name": f.subnet_name,
            "offending_route_count": len(f.offending_routes),
            "default_route_next_hop_type": f.default_route_next_hop_type,
            "default_route_next_hop_ip": f.default_route_next_hop_ip,
        }
        for f in non_compliant[:TOP_N_NON_COMPLIANT]
    ]

    remaining_phase3_work = by_verdict.get(Verdict.NON_COMPLIANT, 0) + by_verdict.get(Verdict.NOT_EVALUATED, 0)

    return {
        "denominator_note": (
            "pct_of_total_subnets divides by ALL subnets evaluated-or-not "
            f"({total_subnets}). pct_of_evaluated_subnets divides by subnets with a "
            f"conclusive verdict only -- COMPLIANT+NON_COMPLIANT+EXPECTED_BYPASS "
            f"({evaluated_subnets}) -- and is None for NOT_EVALUATED/ERROR, which are "
            "never a % of 'evaluated' by definition. NOT_EVALUATED is never counted as "
            "compliant in either denominator."
        ),
        "total_subnets": total_subnets,
        "evaluated_subnets": evaluated_subnets,
        "by_verdict": by_verdict_out,
        "remaining_phase3_work": remaining_phase3_work,
        "by_organization": _group_rollup(by_org),
        "by_environment": _group_rollup(by_env),
        "top_non_compliant_subnets": top_non_compliant,
    }


# --------------------------------------------------------------------------
# capability_matrix (pre-flight RBAC probe, see capability_probe.py)
# --------------------------------------------------------------------------

def build_capability_matrix(capability_results: list) -> list:
    return [
        {
            "subscription_id": c.subscription_id,
            "subscription_name": c.subscription_name,
            "account": c.account,
            "role": c.role,
            "status": c.status.value,
            "reason": c.reason,
        }
        for c in capability_results
    ]


# --------------------------------------------------------------------------
# open_questions
# --------------------------------------------------------------------------

def build_open_questions(
    cmdb_rows: list[CmdbRow],
    baselines: list[VHubBaseline],
    errors: list[ErrorRecord],
    vwan_baseline_section: dict,
) -> list[str]:
    qs: list[str] = list(vwan_baseline_section.get("_open_questions", []))

    access_gap = [r for r in cmdb_rows if r.file_scope_bucket == FileScopeBucket.ONLY_IN_CMDB]
    if access_gap:
        qs.append(
            f"{len(access_gap)} subscription(s) are recorded in the CMDB export but absent from "
            "the Azure portal export (ACCESS_OR_TENANT_GAP) -- confirm whether these are stale "
            "ServiceNow records, a different tenant, or a missing export row, and correct the "
            "source of truth."
        )

    inferred = [r for r in cmdb_rows if r.organization_inferred]
    if inferred:
        qs.append(
            f"{len(inferred)} subscription(s) have an Organization inferred from the Azure Parent "
            "Management Group because the CMDB record was blank -- confirm and backfill the "
            "CMDB Organization field rather than relying on the inference long-term."
        )

    forbidden = Counter(e.status_code for e in errors if e.status_code == 403)
    if forbidden:
        qs.append(
            f"{forbidden[403]} call(s) failed with 403 AuthorizationFailed (see 'coverage' and the "
            "Errors sheet) -- most commonly missing the "
            "Microsoft.Network/networkInterfaces/effectiveRouteTable/action permission. Affected "
            "subnets show verdict ERROR rather than a real compliance result until RBAC is granted."
        )

    return qs


# --------------------------------------------------------------------------
# assembly + writers
# --------------------------------------------------------------------------

def build_report(
    *,
    run_metadata: dict,
    cmdb_rows: list[CmdbRow],
    only_in_azure: list[AzureExportRow],
    per_sub_classification: dict[str, dict],
    findings: list[SubnetFinding],
    errors: list[ErrorRecord],
    baselines: list[VHubBaseline],
    capability_results: Optional[list] = None,
) -> dict:
    vwan_baseline_section = build_vwan_baseline(baselines)
    open_questions = build_open_questions(cmdb_rows, baselines, errors, vwan_baseline_section)
    capability_results = capability_results or []
    cannot_read = [c for c in capability_results if c.status.value == "CANNOT_READ_ROUTES"]
    if cannot_read:
        open_questions.append(
            f"{len(cannot_read)} subscription(s) failed the pre-flight capability probe "
            "(CANNOT_READ_ROUTES) -- every subnet with a NIC in them was marked "
            "NOT_EVALUATED/INSUFFICIENT_ROLE without attempting the real effective-route "
            "call. Grant Contributor (or a custom role with "
            "Microsoft.Network/networkInterfaces/effectiveRouteTable/action) to the "
            "assigned account for these subscriptions and re-run -- see capability_matrix."
        )
    return {
        "run_metadata": run_metadata,
        "scope_reconciliation": build_scope_reconciliation(cmdb_rows, only_in_azure),
        "coverage": build_coverage(cmdb_rows, per_sub_classification, findings, errors),
        "vwan_baseline": {k: v for k, v in vwan_baseline_section.items() if not k.startswith("_")},
        "capability_matrix": build_capability_matrix(capability_results),
        "findings": build_findings_tree(findings),
        "ownership": build_ownership(cmdb_rows),
        "summary_rollup": build_summary_rollup(findings),
        "open_questions": open_questions,
    }


def write_report_json(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    log.info("AI-analysis JSON report written: %s", path)


def write_report_markdown(path: Path, report: dict) -> None:
    rollup = report["summary_rollup"]
    coverage = report["coverage"]["counts"]
    scope = report["scope_reconciliation"]["counts"]
    meta = report["run_metadata"]

    lines = []
    lines.append("# Phase 3 vWAN Compliance -- Report\n")
    lines.append(f"Generated {meta['generated_at_utc']} by script version {meta['script_version']}, "
                  f"identity `{meta['identity'].get('upn') or meta['identity'].get('app_id') or 'unknown'}` "
                  f"(tenant `{meta['identity'].get('tenant_id') or 'unknown'}`). "
                  f"Runtime: {meta['total_runtime_seconds']}s.\n")

    lines.append("## What was scanned\n")
    lines.append(
        f"- CMDB export: `{meta['inputs']['cmdb_file']}` ({meta['inputs']['cmdb_row_count']} rows)\n"
        f"- Azure export: `{meta['inputs']['azure_export_file'] or '(not supplied)'}`"
        + (f" ({meta['inputs']['azure_export_row_count']} rows)\n" if meta['inputs']['azure_export_file'] else "\n")
    )
    lines.append(
        f"- File-level reconciliation: IN_BOTH={scope['in_both']}, "
        f"ONLY_IN_CMDB(ACCESS_OR_TENANT_GAP)={scope['only_in_cmdb_access_or_tenant_gap']}, "
        f"ONLY_IN_AZURE={scope['only_in_azure_shadow']}, DISABLED={scope['disabled']}, "
        f"EXCLUDED={scope['excluded_by_pattern']}\n"
    )
    lines.append(
        f"- Coverage: {coverage['subscriptions_with_at_least_one_evaluated_subnet']} subscription(s) with "
        f"at least one evaluated subnet, {coverage['subscriptions_not_evaluated']} not evaluated, "
        f"{coverage['subscriptions_with_errors']} with errors.\n"
    )

    lines.append("\n## What was skipped and why\n")
    skip_reasons = Counter()
    # "ATTEMPTED_NO_SUBNETS_FOUND" was genuinely attempted (Resource Graph
    # sweep ran for it), it just has no subnets -- not a skip.
    evaluated_statuses = {"EVALUATED_THIS_RUN", "EVALUATED_FROM_PRIOR_RUN", "ATTEMPTED_NO_SUBNETS_FOUND"}
    for sub in report["coverage"]["per_subscription"]:
        if sub["status"] in evaluated_statuses:
            continue  # this one WAS evaluated -- its "reasons" are classification metadata, not a skip
        for reason in sub["reasons"]:
            key = reason.split(":")[0].split("(")[0].strip()
            skip_reasons[key] += 1
    if skip_reasons:
        for reason, count in skip_reasons.most_common():
            lines.append(f"- {reason}: {count} subscription(s)\n")
    else:
        lines.append("- Nothing skipped; every in-scope subscription was attempted.\n")

    lines.append("\n## Compliance rollup\n")
    lines.append(f"> {rollup['denominator_note']}\n")
    lines.append(f"\nTotal subnets: {rollup['total_subnets']}  |  Evaluated (conclusive verdict): {rollup['evaluated_subnets']}\n\n")
    lines.append("| Verdict | Count | % of total | % of evaluated |\n|---|---|---|---|\n")
    for verdict, v in rollup["by_verdict"].items():
        pct_eval = f"{v['pct_of_evaluated_subnets']}%" if v["pct_of_evaluated_subnets"] is not None else "n/a"
        lines.append(f"| {verdict} | {v['count']} | {v['pct_of_total_subnets']}% | {pct_eval} |\n")
    lines.append(f"\n**Remaining Phase 3 migration work (NON_COMPLIANT + NOT_EVALUATED): {rollup['remaining_phase3_work']}**\n")

    if rollup["top_non_compliant_subnets"]:
        lines.append("\n## Highest-impact NON_COMPLIANT subnets\n")
        lines.append("| Subscription | Organization | Environment | VNet/Subnet | Offending Routes |\n|---|---|---|---|---|\n")
        for row in rollup["top_non_compliant_subnets"]:
            lines.append(
                f"| {row['subscription_name']} | {row['organization'] or '(blank)'} | "
                f"{row['environment'] or '(blank)'} | {row['vnet_name']}/{row['subnet_name']} | "
                f"{row['offending_route_count']} |\n"
            )

    if report["open_questions"]:
        lines.append("\n## Open questions for a human\n")
        for q in report["open_questions"]:
            lines.append(f"- {q}\n")

    lines.append("\n## What to do next\n")
    lines.append(
        "1. Fix the highest-impact NON_COMPLIANT subnets above first (Production, most offending routes).\n"
        "2. Resolve `open_questions` -- config gaps and RBAC gaps block a trustworthy verdict for their scope.\n"
        "3. Re-run with `--retry-failed-only` once RBAC/API errors are fixed, or `--rescan-all` for a clean sweep.\n"
        "4. See `phase3_report.json` for the complete machine-readable detail behind this summary.\n"
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(lines), encoding="utf-8")
    log.info("AI-analysis Markdown report written: %s", path)

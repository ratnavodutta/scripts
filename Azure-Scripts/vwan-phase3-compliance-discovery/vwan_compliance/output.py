"""Excel / CSV / JSON / console output.

Excel workbook sheets: Summary, Subscription_Scope, Subnets,
Offending_Routes, vWAN_Baseline, Ownership_Gaps, Invalid_Rows,
Invalid_Azure_Rows, Errors, and (if a CMDB file was read) CMDB_Source_Raw --
the original CMDB export's rows verbatim, so the one output workbook is
fully self-contained and the source spreadsheet doesn't need to be kept
alongside it.
CSV and JSON mirrors are written from the same in-memory data so the three
outputs can never drift from each other.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

from .inventory import SubscriptionInfo
from .logging_config import get_logger
from .models import (
    AzureExportRow,
    CapabilityStatus,
    CmdbRow,
    ErrorRecord,
    FileScopeBucket,
    InvalidAzureExportRow,
    InvalidCmdbRow,
    ReconciliationBucket,
    SubnetFinding,
    VHubBaseline,
    Verdict,
)
from .serialize import finding_to_dict

log = get_logger("output")

SUBNET_HEADERS = [
    "Subscription Name", "Subscription ID", "Organization", "Environment",
    "Resource Group", "VNet", "Subnet", "Address Prefix", "Verdict",
    "Peered To Hub", "Hub Connection", "Route Table",
    "Default Route Next Hop Type", "Default Route Next Hop IP", "Offending Routes",
    "Evidence", "Notes", "Evaluated By Account",
]
CAPABILITY_HEADERS = [
    "Subscription Name", "Subscription ID", "Account Used", "Role", "Capability", "Reason",
]
OFFENDING_HEADERS = [
    "Subscription Name", "Subscription ID", "Organization", "Environment",
    "Resource Group", "VNet", "Subnet", "Address Prefix", "Next Hop Type",
    "Next Hop IP", "Route Source", "Route Table", "Route Name", "NIC ID",
]
BASELINE_HEADERS = [
    "Virtual WAN", "Virtual Hub", "Region", "Address Prefix", "Routing State",
    "Subscription Name", "Subscription ID", "Resource Group",
    "Firewall/NVA Type", "Firewall/NVA Private IP", "Hub Connections", "Gateways",
]
ERROR_HEADERS = ["Scope", "Operation", "Status Code", "Reason"]
SCOPE_HEADERS = [
    "CMDB Row #", "CMDB Name", "Subscription ID", "Organization", "Environment",
    "Install Status", "Supported By", "Owned By", "Reconciliation Bucket",
    "Azure Display Name", "File Scope Bucket", "My Role", "Azure Status",
    "Parent Management Group", "Org Inferred", "Inferred Organization",
    "Disabled", "Exclude Reason",
]
OWNERSHIP_GAP_HEADERS = [
    "CMDB Row #", "Name", "Subscription ID", "Organization", "Environment",
    "Supported By", "Owned By",
]
INVALID_ROW_HEADERS = ["Row #", "Name", "Raw Subscription ID", "Reason"]
AZURE_EXPORT_HEADERS = [
    "Row #", "Subscription Name", "Subscription ID", "My Role", "Current Cost",
    "Secure Score", "Parent Management Group", "Status",
]

VERDICT_FILL = {
    Verdict.COMPLIANT: "C6EFCE",
    Verdict.NON_COMPLIANT: "FFC7CE",
    Verdict.EXPECTED_BYPASS: "FFEB9C",
    Verdict.NOT_EVALUATED: "D9D9D9",
    Verdict.ERROR: "F4B084",
}
BUCKET_FILL = {
    ReconciliationBucket.IN_BOTH: "C6EFCE",
    ReconciliationBucket.IN_CMDB_NOT_VISIBLE: "FFC7CE",
    ReconciliationBucket.VISIBLE_NOT_IN_CMDB: "FFEB9C",
}
CAPABILITY_FILL = {
    CapabilityStatus.CAN_READ_ROUTES: "C6EFCE",
    CapabilityStatus.CANNOT_READ_ROUTES: "FFC7CE",
    CapabilityStatus.UNKNOWN: "D9D9D9",
}


def _shadow_scope_row(s: SubscriptionInfo) -> list:
    return ["", "", s.subscription_id, "", "", "", "", "",
            ReconciliationBucket.VISIBLE_NOT_IN_CMDB.value, s.display_name,
            "", "", "", "", "", "", "", ""]


def _azure_only_scope_row(az: AzureExportRow) -> list:
    disabled = bool(az.status) and az.status.strip().lower() != "active"
    return ["", "", az.subscription_id, "", "", "", "", "", "", "",
            FileScopeBucket.ONLY_IN_AZURE.value, az.my_role, az.status,
            az.parent_management_group, "", "", "DISABLED" if disabled else "", ""]


def build_summary_rows(
    findings: list[SubnetFinding],
    cmdb_rows: list[CmdbRow],
    shadow_subscriptions: list[SubscriptionInfo],
    only_in_azure: Optional[list[AzureExportRow]] = None,
) -> tuple[list[list], dict]:
    only_in_azure = only_in_azure or []
    total = len(findings)
    by_verdict = Counter(f.verdict for f in findings)
    by_sub_verdict: dict[str, Counter] = defaultdict(Counter)
    by_org_verdict: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        by_sub_verdict[f.subscription_name][f.verdict] += 1
        by_org_verdict[f.organization or "(blank)"][f.verdict] += 1

    bucket_counts = Counter(r.bucket for r in cmdb_rows if r.bucket)
    file_bucket_counts = Counter(r.file_scope_bucket for r in cmdb_rows if r.file_scope_bucket)
    gaps = [r for r in cmdb_rows if not r.organization or not r.environment]
    disabled_rows = [r for r in cmdb_rows if r.disabled]
    excluded_rows = [r for r in cmdb_rows if r.excluded_by_name_pattern]
    org_inferred_rows = [r for r in cmdb_rows if r.organization_inferred]

    rows = [["Metric", "Value"]]
    rows.append(["Total subnets evaluated", total])
    for v in Verdict:
        count = by_verdict.get(v, 0)
        pct = f"{(count / total * 100):.1f}%" if total else "0.0%"
        rows.append([v.value, f"{count} ({pct})"])

    remaining = by_verdict.get(Verdict.NON_COMPLIANT, 0) + by_verdict.get(Verdict.NOT_EVALUATED, 0)
    rows.append(["Remaining Phase 3 work (NON_COMPLIANT + NOT_EVALUATED)", remaining])

    rows.append([])
    rows.append(["CMDB Reconciliation", ""])
    rows.append(["IN_BOTH (scanned)", bucket_counts.get(ReconciliationBucket.IN_BOTH, 0)])
    rows.append(["IN_CMDB_NOT_VISIBLE (no RBAC / stale record)", bucket_counts.get(ReconciliationBucket.IN_CMDB_NOT_VISIBLE, 0)])
    rows.append(["VISIBLE_NOT_IN_CMDB (shadow subscriptions)", len(shadow_subscriptions)])
    rows.append(["OWNERSHIP_UNKNOWN (blank Organization/Environment)", len(gaps)])

    if file_bucket_counts or only_in_azure:
        rows.append([])
        rows.append(["Azure Export Reconciliation (file vs. file)", ""])
        rows.append(["IN_BOTH (CMDB + Azure export)", file_bucket_counts.get(FileScopeBucket.IN_BOTH, 0)])
        rows.append(["ONLY_IN_CMDB (ACCESS_OR_TENANT_GAP, cannot scan)", file_bucket_counts.get(FileScopeBucket.ONLY_IN_CMDB, 0)])
        rows.append(["ONLY_IN_AZURE (shadow, absent from CMDB)", len(only_in_azure)])
        rows.append(["DISABLED (excluded from scan by default)", len(disabled_rows)])
        rows.append(["Excluded by --exclude-name-pattern", len(excluded_rows)])
        rows.append(["ORG_INFERRED (from Azure Parent Management Group)", len(org_inferred_rows)])

    rows.append([])
    rows.append(["By Subscription", "COMPLIANT", "NON_COMPLIANT", "EXPECTED_BYPASS", "NOT_EVALUATED", "ERROR"])
    for sub_name, counter in sorted(by_sub_verdict.items()):
        rows.append([
            sub_name,
            counter.get(Verdict.COMPLIANT, 0),
            counter.get(Verdict.NON_COMPLIANT, 0),
            counter.get(Verdict.EXPECTED_BYPASS, 0),
            counter.get(Verdict.NOT_EVALUATED, 0),
            counter.get(Verdict.ERROR, 0),
        ])

    rows.append([])
    rows.append(["By Organization", "COMPLIANT", "NON_COMPLIANT", "EXPECTED_BYPASS", "NOT_EVALUATED", "ERROR"])
    for org, counter in sorted(by_org_verdict.items()):
        rows.append([
            org,
            counter.get(Verdict.COMPLIANT, 0),
            counter.get(Verdict.NON_COMPLIANT, 0),
            counter.get(Verdict.EXPECTED_BYPASS, 0),
            counter.get(Verdict.NOT_EVALUATED, 0),
            counter.get(Verdict.ERROR, 0),
        ])

    if shadow_subscriptions:
        rows.append([])
        rows.append(["Shadow Subscriptions (VISIBLE_NOT_IN_CMDB)"])
        for s in shadow_subscriptions:
            rows.append([f"{s.display_name} ({s.subscription_id})"])

    if only_in_azure:
        rows.append([])
        rows.append(["Azure-Export-Only Subscriptions (ONLY_IN_AZURE)"])
        for az in only_in_azure:
            rows.append([f"{az.name} ({az.subscription_id})"])

    stats = {
        "total": total,
        "by_verdict": {v.value: by_verdict.get(v, 0) for v in Verdict},
        "remaining_phase3_work": remaining,
        "reconciliation": {
            "in_both": bucket_counts.get(ReconciliationBucket.IN_BOTH, 0),
            "in_cmdb_not_visible": bucket_counts.get(ReconciliationBucket.IN_CMDB_NOT_VISIBLE, 0),
            "visible_not_in_cmdb": len(shadow_subscriptions),
        },
        "file_reconciliation": {
            "in_both": file_bucket_counts.get(FileScopeBucket.IN_BOTH, 0),
            "only_in_cmdb_access_or_tenant_gap": file_bucket_counts.get(FileScopeBucket.ONLY_IN_CMDB, 0),
            "only_in_azure": len(only_in_azure),
            "disabled": len(disabled_rows),
            "excluded_by_name_pattern": len(excluded_rows),
            "org_inferred": len(org_inferred_rows),
        },
        "ownership_unknown_count": len(gaps),
        "shadow_subscriptions": [{"id": s.subscription_id, "name": s.display_name} for s in shadow_subscriptions],
        "only_in_azure": [{"id": az.subscription_id, "name": az.name} for az in only_in_azure],
    }
    return rows, stats


def write_excel(
    path: Path,
    findings: list[SubnetFinding],
    baselines: list[VHubBaseline],
    errors: list[ErrorRecord],
    cmdb_rows: list[CmdbRow],
    shadow_subscriptions: list[SubscriptionInfo],
    invalid_rows: list[InvalidCmdbRow],
    only_in_azure: Optional[list[AzureExportRow]] = None,
    invalid_azure_rows: Optional[list[InvalidAzureExportRow]] = None,
    cmdb_raw_rows: Optional[list[tuple]] = None,
    capability_results: Optional[list] = None,
) -> None:
    only_in_azure = only_in_azure or []
    invalid_azure_rows = invalid_azure_rows or []
    cmdb_raw_rows = cmdb_raw_rows or []
    capability_results = capability_results or []
    wb = Workbook()

    ws_summary = wb.active
    ws_summary.title = "Summary"
    summary_rows, _ = build_summary_rows(findings, cmdb_rows, shadow_subscriptions, only_in_azure)
    for row in summary_rows:
        ws_summary.append(row)
    _bold_header(ws_summary, 1)
    _autosize(ws_summary)

    ws_scope = wb.create_sheet("Subscription_Scope")
    ws_scope.append(SCOPE_HEADERS)
    _bold_header(ws_scope, 1)
    bucket_col = SCOPE_HEADERS.index("Reconciliation Bucket") + 1
    for r in cmdb_rows:
        ws_scope.append(r.as_scope_row())
        if r.bucket:
            fill_hex = BUCKET_FILL.get(r.bucket)
            if fill_hex:
                cell = ws_scope.cell(row=ws_scope.max_row, column=bucket_col)
                cell.fill = PatternFill(start_color=fill_hex, end_color=fill_hex, fill_type="solid")
    for s in shadow_subscriptions:
        ws_scope.append(_shadow_scope_row(s))
        cell = ws_scope.cell(row=ws_scope.max_row, column=bucket_col)
        cell.fill = PatternFill(start_color=BUCKET_FILL[ReconciliationBucket.VISIBLE_NOT_IN_CMDB], end_color=BUCKET_FILL[ReconciliationBucket.VISIBLE_NOT_IN_CMDB], fill_type="solid")
    for az in only_in_azure:
        ws_scope.append(_azure_only_scope_row(az))
    _autosize(ws_scope)

    ws_subnets = wb.create_sheet("Subnets")
    ws_subnets.append(SUBNET_HEADERS)
    _bold_header(ws_subnets, 1)
    verdict_col = SUBNET_HEADERS.index("Verdict") + 1
    for f in findings:
        ws_subnets.append(f.as_row())
        fill_hex = VERDICT_FILL.get(f.verdict)
        if fill_hex:
            cell = ws_subnets.cell(row=ws_subnets.max_row, column=verdict_col)
            cell.fill = PatternFill(start_color=fill_hex, end_color=fill_hex, fill_type="solid")
    _autosize(ws_subnets)

    ws_offending = wb.create_sheet("Offending_Routes")
    ws_offending.append(OFFENDING_HEADERS)
    _bold_header(ws_offending, 1)
    for f in findings:
        for r in f.offending_routes:
            ws_offending.append(r.as_row())
    _autosize(ws_offending)

    ws_baseline = wb.create_sheet("vWAN_Baseline")
    ws_baseline.append(BASELINE_HEADERS)
    _bold_header(ws_baseline, 1)
    for b in baselines:
        ws_baseline.append(b.as_row())
    _autosize(ws_baseline)

    ws_gaps = wb.create_sheet("Ownership_Gaps")
    ws_gaps.append(OWNERSHIP_GAP_HEADERS)
    _bold_header(ws_gaps, 1)
    for r in cmdb_rows:
        if not r.organization or not r.environment:
            ws_gaps.append(r.as_ownership_gap_row())
    _autosize(ws_gaps)

    ws_invalid = wb.create_sheet("Invalid_Rows")
    ws_invalid.append(INVALID_ROW_HEADERS)
    _bold_header(ws_invalid, 1)
    for r in invalid_rows:
        ws_invalid.append(r.as_row())
    _autosize(ws_invalid)

    ws_invalid_az = wb.create_sheet("Invalid_Azure_Rows")
    ws_invalid_az.append(INVALID_ROW_HEADERS)
    _bold_header(ws_invalid_az, 1)
    for r in invalid_azure_rows:
        ws_invalid_az.append(r.as_row())
    _autosize(ws_invalid_az)

    ws_errors = wb.create_sheet("Errors")
    ws_errors.append(ERROR_HEADERS)
    _bold_header(ws_errors, 1)
    for e in errors:
        ws_errors.append(e.as_row())
    _autosize(ws_errors)

    if cmdb_raw_rows:
        ws_raw = wb.create_sheet("CMDB_Source_Raw")
        for row in cmdb_raw_rows:
            ws_raw.append(list(row))
        _bold_header(ws_raw, 1)
        _autosize(ws_raw)

    ws_cap = wb.create_sheet("Capability_Matrix")
    ws_cap.append(CAPABILITY_HEADERS)
    _bold_header(ws_cap, 1)
    cap_col = CAPABILITY_HEADERS.index("Capability") + 1
    for c in capability_results:
        ws_cap.append(c.as_row())
        fill_hex = CAPABILITY_FILL.get(c.status)
        if fill_hex:
            cell = ws_cap.cell(row=ws_cap.max_row, column=cap_col)
            cell.fill = PatternFill(start_color=fill_hex, end_color=fill_hex, fill_type="solid")
    _autosize(ws_cap)

    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    log.info("Excel workbook written: %s", path)


def write_csv(
    out_dir: Path,
    findings: list[SubnetFinding],
    baselines: list[VHubBaseline],
    errors: list[ErrorRecord],
    cmdb_rows: list[CmdbRow],
    shadow_subscriptions: list[SubscriptionInfo],
    invalid_rows: list[InvalidCmdbRow],
    only_in_azure: Optional[list[AzureExportRow]] = None,
    invalid_azure_rows: Optional[list[InvalidAzureExportRow]] = None,
    cmdb_raw_rows: Optional[list[tuple]] = None,
    capability_results: Optional[list] = None,
) -> None:
    only_in_azure = only_in_azure or []
    invalid_azure_rows = invalid_azure_rows or []
    cmdb_raw_rows = cmdb_raw_rows or []
    capability_results = capability_results or []
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(out_dir / "subnets.csv", SUBNET_HEADERS, [f.as_row() for f in findings])
    offending_rows = [r.as_row() for f in findings for r in f.offending_routes]
    _write_csv(out_dir / "offending_routes.csv", OFFENDING_HEADERS, offending_rows)
    _write_csv(out_dir / "vwan_baseline.csv", BASELINE_HEADERS, [b.as_row() for b in baselines])
    scope_rows = (
        [r.as_scope_row() for r in cmdb_rows]
        + [_shadow_scope_row(s) for s in shadow_subscriptions]
        + [_azure_only_scope_row(az) for az in only_in_azure]
    )
    _write_csv(out_dir / "subscription_scope.csv", SCOPE_HEADERS, scope_rows)
    gap_rows = [r.as_ownership_gap_row() for r in cmdb_rows if not r.organization or not r.environment]
    _write_csv(out_dir / "ownership_gaps.csv", OWNERSHIP_GAP_HEADERS, gap_rows)
    _write_csv(out_dir / "invalid_rows.csv", INVALID_ROW_HEADERS, [r.as_row() for r in invalid_rows])
    _write_csv(out_dir / "invalid_azure_rows.csv", INVALID_ROW_HEADERS, [r.as_row() for r in invalid_azure_rows])
    _write_csv(out_dir / "errors.csv", ERROR_HEADERS, [e.as_row() for e in errors])
    if cmdb_raw_rows:
        _write_csv(out_dir / "cmdb_source_raw.csv", list(cmdb_raw_rows[0]), [list(r) for r in cmdb_raw_rows[1:]])
    _write_csv(out_dir / "capability_matrix.csv", CAPABILITY_HEADERS, [c.as_row() for c in capability_results])
    log.info("CSV files written to: %s", out_dir)


def write_json(
    path: Path,
    findings: list[SubnetFinding],
    baselines: list[VHubBaseline],
    errors: list[ErrorRecord],
    cmdb_rows: list[CmdbRow],
    shadow_subscriptions: list[SubscriptionInfo],
    invalid_rows: list[InvalidCmdbRow],
    only_in_azure: Optional[list[AzureExportRow]] = None,
    invalid_azure_rows: Optional[list[InvalidAzureExportRow]] = None,
    cmdb_raw_rows: Optional[list[tuple]] = None,
    capability_results: Optional[list] = None,
) -> None:
    only_in_azure = only_in_azure or []
    invalid_azure_rows = invalid_azure_rows or []
    cmdb_raw_rows = cmdb_raw_rows or []
    capability_results = capability_results or []
    _, stats = build_summary_rows(findings, cmdb_rows, shadow_subscriptions, only_in_azure)
    payload = {
        "summary": stats,
        "subnets": [_finding_to_dict(f) for f in findings],
        "offending_routes": [asdict(r) for f in findings for r in f.offending_routes],
        "vwan_baseline": [_baseline_to_dict(b) for b in baselines],
        "subscription_scope": [_cmdb_row_to_dict(r) for r in cmdb_rows],
        "shadow_subscriptions": [asdict(s) for s in shadow_subscriptions],
        "only_in_azure": [asdict(az) for az in only_in_azure],
        "invalid_rows": [asdict(r) for r in invalid_rows],
        "invalid_azure_rows": [asdict(r) for r in invalid_azure_rows],
        "errors": [asdict(e) for e in errors],
        "cmdb_source_raw": {
            "headers": list(cmdb_raw_rows[0]) if cmdb_raw_rows else [],
            "rows": [list(r) for r in cmdb_raw_rows[1:]] if cmdb_raw_rows else [],
        },
        "capability_matrix": [_capability_to_dict(c) for c in capability_results],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    log.info("JSON written: %s", path)


def print_console_summary(
    findings: list[SubnetFinding],
    cmdb_rows: list[CmdbRow],
    shadow_subscriptions: list[SubscriptionInfo],
    only_in_azure: Optional[list[AzureExportRow]] = None,
) -> None:
    _, stats = build_summary_rows(findings, cmdb_rows, shadow_subscriptions, only_in_azure)
    print("\n=== Phase 3 Compliance Discovery: Console Summary ===")
    print(f"Total subnets evaluated: {stats['total']}")
    for verdict, count in stats["by_verdict"].items():
        pct = f"{(count / stats['total'] * 100):.1f}%" if stats["total"] else "0.0%"
        print(f"  {verdict:<16} {count:>6}  ({pct})")
    print(f"\nRemaining Phase 3 work (NON_COMPLIANT + NOT_EVALUATED): {stats['remaining_phase3_work']}")
    rec = stats["reconciliation"]
    print(
        f"\nCMDB reconciliation: IN_BOTH={rec['in_both']}  "
        f"IN_CMDB_NOT_VISIBLE={rec['in_cmdb_not_visible']}  "
        f"VISIBLE_NOT_IN_CMDB={rec['visible_not_in_cmdb']}"
    )
    print(f"OWNERSHIP_UNKNOWN (blank Organization/Environment): {stats['ownership_unknown_count']}")
    if stats["shadow_subscriptions"]:
        print("\nShadow subscriptions (visible in Azure, absent from CMDB):")
        for s in stats["shadow_subscriptions"]:
            print(f"  - {s['name']} ({s['id']})")
    fr = stats.get("file_reconciliation")
    if fr and (fr["only_in_cmdb_access_or_tenant_gap"] or fr["only_in_azure"] or fr["disabled"] or fr["excluded_by_name_pattern"]):
        print(
            f"\nAzure export reconciliation: IN_BOTH={fr['in_both']}  "
            f"ONLY_IN_CMDB(ACCESS_OR_TENANT_GAP)={fr['only_in_cmdb_access_or_tenant_gap']}  "
            f"ONLY_IN_AZURE={fr['only_in_azure']}  DISABLED={fr['disabled']}  "
            f"EXCLUDED={fr['excluded_by_name_pattern']}  ORG_INFERRED={fr['org_inferred']}"
        )
    print()


def _finding_to_dict(f: SubnetFinding) -> dict:
    return finding_to_dict(f)


def _baseline_to_dict(b: VHubBaseline) -> dict:
    d = asdict(b)
    d["compliant_next_hop_ips"] = sorted(b.compliant_next_hop_ips)
    return d


def _cmdb_row_to_dict(r: CmdbRow) -> dict:
    d = asdict(r)
    d["bucket"] = r.bucket.value if r.bucket else None
    d["file_scope_bucket"] = r.file_scope_bucket.value if r.file_scope_bucket else None
    return d


def _capability_to_dict(c) -> dict:
    d = asdict(c)
    d["status"] = c.status.value
    return d


def _write_csv(path: Path, headers: list[str], rows: list[list]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def _bold_header(ws, row: int) -> None:
    for cell in ws[row]:
        cell.font = Font(bold=True)


def _autosize(ws, max_width: int = 60) -> None:
    for col_cells in ws.columns:
        length = max((len(str(c.value)) for c in col_cells if c.value is not None), default=10)
        col_letter = get_column_letter(col_cells[0].column)
        ws.column_dimensions[col_letter].width = min(max_width, max(10, length + 2))

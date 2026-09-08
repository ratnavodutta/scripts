"""Phase 0b (optional): read the Azure portal's subscription-list export
(CSV, via "Download CSV" on the Subscriptions blade) and use it to enrich
and cross-check the ServiceNow CMDB scope from cmdb.py -- ownership (via
Parent Management Group), RBAC role, Active/Disabled status, and a second,
independent Azure-vs-CMDB reconciliation, all without an extra live Azure
call (see reconcile.py for how the two sources are joined).

Path handling is identical to the CMDB file (see path_utils.py): quotes and
whitespace stripped, `~` and relative paths expanded, WSL fallback, and a
bad path re-prompts up to 3 attempts -- except this file is OPTIONAL, so a
blank answer at the interactive prompt skips it cleanly instead of erroring.

Format quirk: the Azure portal's CSV export begins with a literal `SEP=,`
line (an Excel locale hint) before the real header row. That line is
skipped unconditionally if present.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .logging_config import get_logger
from .models import AzureExportRow, InvalidAzureExportRow
from .path_utils import FilePathError, resolve_path_interactive

log = get_logger("azure_export")

GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Header name -> canonical field. Matching is case-insensitive and ignores
# surrounding whitespace, same convention as cmdb.HEADER_ALIASES.
HEADER_ALIASES = {
    "subscription name": "name",
    "subscription id": "subscription_id",
    "my role": "my_role",
    "current cost": "current_cost",
    "secure score": "secure_score",
    "parent management group": "parent_management_group",
    "status": "status",
}
REQUIRED_FIELDS = {"name", "subscription_id"}
MAX_HEADER_SCAN_ROWS = 5


class AzureExportFileError(FilePathError):
    pass


@dataclass
class AzureExportLoadResult:
    rows: list[AzureExportRow] = field(default_factory=list)
    invalid_rows: list[InvalidAzureExportRow] = field(default_factory=list)
    duplicate_rows: list[InvalidAzureExportRow] = field(default_factory=list)
    total_data_rows: int = 0


def resolve_azure_export_path(cli_value: Optional[str], max_attempts: int = 3) -> Optional[Path]:
    """Return a validated Path to the Azure export CSV, from --azure-file or
    an interactive prompt -- or None if the file is being skipped (blank
    answer at the prompt). Unlike the CMDB file, this one is optional.
    """
    return resolve_path_interactive(
        cli_value,
        prompt_text="Path to the Azure portal subscription export CSV (optional -- press Enter to skip): ",
        valid_extensions=(".csv",),
        max_attempts=max_attempts,
        optional=True,
        error_cls=AzureExportFileError,
    )


def load_azure_export(path: Path) -> AzureExportLoadResult:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        text = f.read()

    lines = text.splitlines()
    if lines and lines[0].strip().lower().startswith("sep="):
        lines = lines[1:]

    rows = list(csv.reader(lines))
    return _parse_rows(rows)


def _parse_rows(rows: list[list[str]]) -> AzureExportLoadResult:
    rows = [r for r in rows if r is not None]
    if not rows:
        raise AzureExportFileError("Azure export CSV is empty.")

    header_row_idx, column_map = _detect_header_row(rows)
    if column_map is None:
        raise AzureExportFileError(
            f"Could not find a header row containing recognisable columns "
            f"(looked in the first {MAX_HEADER_SCAN_ROWS} rows). Expected at "
            f"least 'Subscription Name' and 'Subscription Id' columns."
        )

    result = AzureExportLoadResult()
    seen_ids: dict[str, int] = {}

    for row_num, row in enumerate(rows[header_row_idx + 1:], start=header_row_idx + 2):
        if not row or all((c or "").strip() == "" for c in row):
            continue
        result.total_data_rows += 1

        values = {fld: _cell(row, idx) for fld, idx in column_map.items()}
        name = values.get("name", "") or ""
        raw_id = (values.get("subscription_id") or "").strip()

        if not raw_id or not GUID_RE.match(raw_id):
            result.invalid_rows.append(InvalidAzureExportRow(
                row_number=row_num, name=name, raw_subscription_id=raw_id,
                reason="missing or malformed subscription ID (not a GUID)",
            ))
            continue

        sub_id = raw_id.lower()
        if sub_id in seen_ids:
            result.duplicate_rows.append(InvalidAzureExportRow(
                row_number=row_num, name=name, raw_subscription_id=raw_id,
                reason=f"duplicate of row {seen_ids[sub_id]} (first occurrence kept)",
            ))
            continue
        seen_ids[sub_id] = row_num

        result.rows.append(AzureExportRow(
            row_number=row_num,
            subscription_id=sub_id,
            name=name,
            my_role=values.get("my_role") or "",
            current_cost=values.get("current_cost") or "",
            secure_score=values.get("secure_score") or "",
            parent_management_group=values.get("parent_management_group") or "",
            status=(values.get("status") or "").strip(),
        ))

    return result


def _cell(row: list, idx: int) -> Optional[str]:
    if idx >= len(row):
        return None
    value = row[idx]
    if value is None:
        return None
    return str(value).strip()


def _detect_header_row(rows: list[list[str]]) -> tuple[int, Optional[dict[str, int]]]:
    for row_idx, row in enumerate(rows[:MAX_HEADER_SCAN_ROWS]):
        if row is None:
            continue
        column_map: dict[str, int] = {}
        for col_idx, cell in enumerate(row):
            if cell is None:
                continue
            key = str(cell).strip().lower()
            fld = HEADER_ALIASES.get(key)
            if fld:
                column_map[fld] = col_idx
        if REQUIRED_FIELDS.issubset(column_map.keys()):
            return row_idx, column_map
    return -1, None

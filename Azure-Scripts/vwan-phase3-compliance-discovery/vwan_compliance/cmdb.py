"""Phase 0: read the authoritative subscription scope from a ServiceNow CMDB
export (.xlsx/.xls).

The CMDB export -- not "every subscription the credential can see" -- is the
source of truth for what should be scanned. Everything downstream (Phase 1
auth check, Phase 2 baseline, Phase 3/4 walk) is driven off the subscription
IDs resolved here, then reconciled against what's actually visible in Azure
(see inventory.reconcile_subscriptions).

Path handling works the same way whether this runs on the engineer's Windows
laptop or a Linux CI runner: quotes and whitespace are stripped, `~` and
relative paths are expanded, and a Windows-style path handed to a Linux
interpreter (the WSL case: `az`/python running inside WSL while the user
pastes a Windows Explorer path) falls back to the `/mnt/<drive>/...`
translation before giving up.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from openpyxl import load_workbook

from .logging_config import get_logger
from .models import CmdbRow, InvalidCmdbRow
from .path_utils import FilePathError, resolve_path_interactive

log = get_logger("cmdb")

GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Header name -> canonical field. Matching is case-insensitive and ignores
# surrounding whitespace, so minor export-format drift (extra spaces, a
# trailing colon) doesn't break column detection.
HEADER_ALIASES = {
    "name": "name",
    "account id": "subscription_id",
    "accountid": "subscription_id",
    "subscription id": "subscription_id",
    "datacenter type": "datacenter_type",
    "organization": "organization",
    "environment": "environment",
    "supported by": "supported_by",
    "owned by": "owned_by",
    "install status": "install_status",
    "updated": "updated",
    "updated by": "updated_by",
    "short description": "short_description",
}
REQUIRED_FIELDS = {"name", "subscription_id"}
MAX_HEADER_SCAN_ROWS = 15


class CmdbFileError(FilePathError):
    pass


@dataclass
class CmdbLoadResult:
    rows: list[CmdbRow] = field(default_factory=list)
    invalid_rows: list[InvalidCmdbRow] = field(default_factory=list)
    duplicate_rows: list[InvalidCmdbRow] = field(default_factory=list)
    total_data_rows: int = 0
    # Verbatim header + data rows exactly as read from the source file (every
    # column, every row, unfiltered/unparsed) -- so the output workbook can
    # embed the original CMDB export as a sheet and be fully self-contained.
    raw_rows: list[tuple] = field(default_factory=list)


# --------------------------------------------------------------------------
# Path resolution
# --------------------------------------------------------------------------

def resolve_cmdb_path(cli_value: Optional[str], max_attempts: int = 3) -> Path:
    """Return a validated Path to the CMDB export, from --cmdb-file or an
    interactive prompt. Never raises on a bad path from a human -- it
    re-prompts up to max_attempts, then raises CmdbFileError. Also never
    raises a raw EOFError/KeyboardInterrupt when stdin can't be read (e.g. a
    bad --cmdb-file passed in CI with no terminal attached) -- that's turned
    into the same clean CmdbFileError instead of a traceback.
    """
    path = resolve_path_interactive(
        cli_value,
        prompt_text="Path to the ServiceNow CMDB export (.xlsx/.xls): ",
        valid_extensions=(".xlsx", ".xls"),
        max_attempts=max_attempts,
        optional=False,
        error_cls=CmdbFileError,
    )
    assert path is not None  # optional=False: resolve_path_interactive never returns None
    return path


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def load_cmdb(path: Path, sheet_name: Optional[str] = None) -> CmdbLoadResult:
    if path.suffix.lower() == ".xls":
        return _load_xls(path, sheet_name)
    return _load_xlsx(path, sheet_name)


def _load_xlsx(path: Path, sheet_name: Optional[str]) -> CmdbLoadResult:
    wb = load_workbook(filename=str(path), read_only=True, data_only=True)
    try:
        ws = wb[sheet_name] if sheet_name else wb.worksheets[0]
        rows_iter = ws.iter_rows(values_only=True)
        return _parse_rows(rows_iter)
    finally:
        wb.close()


def _load_xls(path: Path, sheet_name: Optional[str]) -> CmdbLoadResult:
    try:
        import xlrd  # noqa: F401  (optional legacy-format dependency)
    except ImportError as exc:
        raise CmdbFileError(
            "Reading legacy .xls files requires the 'xlrd' package "
            "(pip install xlrd). Re-export from ServiceNow as .xlsx instead, "
            "or install xlrd."
        ) from exc
    import xlrd

    book = xlrd.open_workbook(str(path))
    sheet = book.sheet_by_name(sheet_name) if sheet_name else book.sheet_by_index(0)

    def _row_gen():
        for r in range(sheet.nrows):
            yield tuple(sheet.row_values(r))

    return _parse_rows(_row_gen())


def _parse_rows(rows_iter) -> CmdbLoadResult:
    rows = [r for r in rows_iter if r is not None]
    if not rows:
        raise CmdbFileError("Worksheet is empty.")

    header_row_idx, column_map = _detect_header_row(rows)
    if column_map is None:
        raise CmdbFileError(
            f"Could not find a header row containing recognisable CMDB columns "
            f"(looked in the first {MAX_HEADER_SCAN_ROWS} rows). Expected at "
            f"least 'Name' and 'Account Id' columns. Use --cmdb-sheet if the "
            f"data is on a different worksheet."
        )

    result = CmdbLoadResult()
    result.raw_rows = rows[header_row_idx:]  # header row onward, verbatim
    seen_ids: dict[str, int] = {}  # subscription_id -> first row number

    for row_num, row in enumerate(rows[header_row_idx + 1:], start=header_row_idx + 2):
        if row is None or all(c is None or str(c).strip() == "" for c in row):
            continue
        result.total_data_rows += 1

        values = {field: _cell(row, idx) for field, idx in column_map.items()}
        name = values.get("name", "") or ""
        raw_id = (values.get("subscription_id") or "").strip()

        if not raw_id or not GUID_RE.match(raw_id):
            result.invalid_rows.append(InvalidCmdbRow(
                row_number=row_num, name=name, raw_subscription_id=raw_id,
                reason="missing or malformed subscription ID (not a GUID)",
            ))
            continue

        sub_id = raw_id.lower()
        if sub_id in seen_ids:
            result.duplicate_rows.append(InvalidCmdbRow(
                row_number=row_num, name=name, raw_subscription_id=raw_id,
                reason=f"duplicate of row {seen_ids[sub_id]} (first occurrence kept)",
            ))
            continue
        seen_ids[sub_id] = row_num

        result.rows.append(CmdbRow(
            row_number=row_num,
            subscription_id=sub_id,
            name=name,
            datacenter_type=values.get("datacenter_type") or "",
            organization=(values.get("organization") or "").strip(),
            environment=(values.get("environment") or "").strip(),
            supported_by=values.get("supported_by") or "",
            owned_by=values.get("owned_by") or "",
            install_status=(values.get("install_status") or "").strip(),
            updated=values.get("updated") or "",
            updated_by=values.get("updated_by") or "",
            short_description=values.get("short_description") or "",
        ))

    return result


def _cell(row: tuple, idx: int) -> Optional[str]:
    if idx >= len(row):
        return None
    value = row[idx]
    if value is None:
        return None
    return str(value).strip()


def _detect_header_row(rows: list[tuple]) -> tuple[int, Optional[dict[str, int]]]:
    for row_idx, row in enumerate(rows[:MAX_HEADER_SCAN_ROWS]):
        if row is None:
            continue
        column_map: dict[str, int] = {}
        for col_idx, cell in enumerate(row):
            if cell is None:
                continue
            key = str(cell).strip().lower()
            field = HEADER_ALIASES.get(key)
            if field:
                column_map[field] = col_idx
        if REQUIRED_FIELDS.issubset(column_map.keys()):
            return row_idx, column_map
    return -1, None


# --------------------------------------------------------------------------
# Filtering + scope summary
# --------------------------------------------------------------------------

def apply_filters(
    rows: list[CmdbRow],
    filter_org: Optional[list[str]],
    filter_environment: Optional[list[str]],
    filter_install_status: Optional[str],
) -> list[CmdbRow]:
    out = rows
    if filter_org:
        wanted = {o.lower() for o in filter_org}
        out = [r for r in out if r.organization.lower() in wanted]
    if filter_environment:
        wanted = {e.lower() for e in filter_environment}
        out = [r for r in out if r.environment.lower() in wanted]
    if filter_install_status:
        out = [r for r in out if r.install_status.lower() == filter_install_status.lower()]
    return out


def ownership_gaps(rows: list[CmdbRow]) -> list[CmdbRow]:
    return [r for r in rows if not r.organization or not r.environment]


def print_scope_summary(
    total_data_rows: int,
    valid_rows: list[CmdbRow],
    duplicate_rows: list[InvalidCmdbRow],
    invalid_rows: list[InvalidCmdbRow],
) -> None:
    print("\n=== Phase 0: CMDB Scope Summary ===")
    print(f"  Total data rows read:      {total_data_rows}")
    print(f"  Valid subscription IDs:    {len(valid_rows)}")
    print(f"  Duplicate rows:            {len(duplicate_rows)}")
    print(f"  Invalid rows:              {len(invalid_rows)}")

    by_org: dict[str, int] = {}
    by_env: dict[str, int] = {}
    for r in valid_rows:
        org = r.organization or "(blank)"
        env = r.environment or "(blank)"
        by_org[org] = by_org.get(org, 0) + 1
        by_env[env] = by_env.get(env, 0) + 1

    print("\n  By Organization:")
    for org, count in sorted(by_org.items()):
        print(f"    {org:<20} {count}")
    print("\n  By Environment:")
    for env, count in sorted(by_env.items()):
        print(f"    {env:<20} {count}")

    gaps = ownership_gaps(valid_rows)
    if gaps:
        print(f"\n  OWNERSHIP_UNKNOWN (blank Organization/Environment): {len(gaps)} row(s)")


def confirm_or_exit(assume_yes: bool) -> None:
    if assume_yes:
        return
    answer = input("\nProceed with this scope? [y/N]: ").strip().lower()
    if answer not in ("y", "yes"):
        print("Aborted by user.", file=sys.stderr)
        raise SystemExit(1)

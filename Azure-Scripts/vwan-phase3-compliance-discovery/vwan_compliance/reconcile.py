"""Phase 0.5 (optional): reconcile the ServiceNow CMDB export against the
Azure portal subscription export, joined on subscription ID. Purely
file-based -- no Azure calls -- so it runs even under --dry-run.

This is deliberately a SEPARATE layer from inventory.reconcile_subscriptions
(Phase 1), which reconciles the CMDB export against what the *live*
credential can actually see in Azure right now:

  - This module (file vs. file) catches ServiceNow/Azure inventory drift
    that exists independently of who is running the script, plus
    licensing-only subscriptions and disabled subscriptions.
  - inventory.reconcile_subscriptions (file vs. live API) catches RBAC/
    tenant visibility gaps for *this* credential specifically.

A subscription only ever reaches the scan target list if it clears BOTH
layers (see in_scan_scope() below, applied before the live check in main.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .logging_config import get_logger
from .models import AzureExportRow, CmdbRow, FileScopeBucket

log = get_logger("reconcile")

DEFAULT_EXCLUDE_NAME_PATTERNS = [r"(?i)visual studio", r"(?i)\bmsdn\b"]


@dataclass
class FileReconciliationResult:
    cmdb_rows: list[CmdbRow] = field(default_factory=list)              # enriched in place
    only_in_azure: list[AzureExportRow] = field(default_factory=list)   # ONLY_IN_AZURE


def reconcile_with_azure_export(
    cmdb_rows: list[CmdbRow],
    azure_rows: Optional[list[AzureExportRow]],
    exclude_name_patterns: list[str],
) -> FileReconciliationResult:
    """Enrich every cmdb_row in place with file_scope_bucket / my_role /
    azure_status / parent_management_group / organization_inferred /
    disabled / excluded_by_name_pattern, and return the Azure-export rows
    that have no CMDB match (ONLY_IN_AZURE).

    If azure_rows is None (no --azure-file supplied), this layer is a no-op
    except that --exclude-name-pattern still applies against the CMDB name
    alone.
    """
    patterns = [re.compile(p) for p in exclude_name_patterns]

    if azure_rows is None:
        for row in cmdb_rows:
            row.excluded_by_name_pattern, row.exclude_reason = _match_exclude(row.name, patterns)
        return FileReconciliationResult(cmdb_rows=cmdb_rows, only_in_azure=[])

    azure_by_id = {r.subscription_id: r for r in azure_rows}
    matched_azure_ids: set[str] = set()

    for row in cmdb_rows:
        az = azure_by_id.get(row.subscription_id)
        if az is not None:
            matched_azure_ids.add(row.subscription_id)
            row.file_scope_bucket = FileScopeBucket.IN_BOTH
            row.azure_export_name = az.name
            row.my_role = az.my_role
            row.azure_status = az.status
            row.parent_management_group = az.parent_management_group
            row.disabled = bool(az.status) and az.status.strip().lower() != "active"

            if not row.organization and az.parent_management_group:
                row.organization_inferred = True
                row.inferred_organization = az.parent_management_group
                log.info(
                    "ORG_INFERRED: '%s' (%s) has no CMDB Organization; inferring '%s' "
                    "from the Azure Parent Management Group.",
                    row.name, row.subscription_id, az.parent_management_group,
                )
        else:
            row.file_scope_bucket = FileScopeBucket.ONLY_IN_CMDB
            log.warning(
                "ONLY_IN_CMDB (ACCESS_OR_TENANT_GAP): '%s' (%s) is in the CMDB export but "
                "absent from the Azure portal export - cannot scan.",
                row.name, row.subscription_id,
            )

        row.excluded_by_name_pattern, row.exclude_reason = _match_exclude(
            row.name or row.azure_export_name, patterns,
        )

    only_in_azure = [az for az in azure_rows if az.subscription_id not in matched_azure_ids]
    for az in only_in_azure:
        log.warning(
            "ONLY_IN_AZURE: '%s' (%s) is in the Azure export but absent from the CMDB "
            "export - shadow/unmanaged subscription.",
            az.name, az.subscription_id,
        )

    return FileReconciliationResult(cmdb_rows=cmdb_rows, only_in_azure=only_in_azure)


def _match_exclude(name: str, patterns: list[re.Pattern]) -> tuple[bool, str]:
    for p in patterns:
        if p.search(name or ""):
            return True, f"matched --exclude-name-pattern '{p.pattern}'"
    return False, ""


def in_scan_scope(row: CmdbRow, *, include_disabled: bool) -> tuple[bool, str]:
    """Whether a CMDB row (after the existing --filter-org/--filter-environment
    /--filter-install-status filters) should be attempted at all, based on
    this file-level reconciliation. Returns (allowed, reason_if_not).

    Does NOT check live Azure RBAC visibility -- that is a separate,
    additional gate (see inventory.reconcile_subscriptions), applied
    afterwards in main.py.
    """
    if row.file_scope_bucket == FileScopeBucket.ONLY_IN_CMDB:
        return False, "ACCESS_OR_TENANT_GAP: absent from the Azure portal export"
    if row.excluded_by_name_pattern:
        return False, row.exclude_reason or "excluded by name pattern"
    if row.disabled and not include_disabled:
        return False, f"DISABLED (Azure export status='{row.azure_status}')"
    return True, ""

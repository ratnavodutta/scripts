"""Dataclasses shared across the discovery pipeline.

Keeping these in one module avoids circular imports between baseline.py,
inventory.py, compliance.py and output.py, and gives every sheet in the
Excel output a single, obvious source of truth for its row shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    EXPECTED_BYPASS = "EXPECTED_BYPASS"
    NOT_EVALUATED = "NOT_EVALUATED"
    ERROR = "ERROR"


class Evidence(str, Enum):
    MEASURED = "MEASURED"   # from begin_get_effective_route_table on a real NIC
    INFERRED = "INFERRED"   # from UDR / peering / hub-connection presence only
    NONE = "NONE"           # nothing to go on (e.g. ERROR verdict)


class ReconciliationBucket(str, Enum):
    IN_BOTH = "IN_BOTH"                       # in CMDB and visible to the credential - scanned
    IN_CMDB_NOT_VISIBLE = "IN_CMDB_NOT_VISIBLE"  # CMDB says it exists, credential can't see it
    VISIBLE_NOT_IN_CMDB = "VISIBLE_NOT_IN_CMDB"  # visible in Azure, absent from CMDB - shadow sub


class FileScopeBucket(str, Enum):
    """File-level reconciliation of the CMDB export against the (optional)
    Azure portal subscription export -- see reconcile.py. Distinct from
    ReconciliationBucket above, which reconciles against what the *live*
    credential can see right now via an Azure API call.
    """
    IN_BOTH = "IN_BOTH"
    ONLY_IN_CMDB = "ONLY_IN_CMDB"      # ACCESS_OR_TENANT_GAP: cannot scan
    ONLY_IN_AZURE = "ONLY_IN_AZURE"    # shadow/unmanaged subscription


class ScanOutcome(str, Enum):
    """Per-subscription outcome recorded in the incremental scan state file
    (see state.py)."""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"
    SKIPPED_DISABLED = "SKIPPED_DISABLED"
    SKIPPED_EXCLUDED = "SKIPPED_EXCLUDED"
    SKIPPED_ACCESS_GAP = "SKIPPED_ACCESS_GAP"


class CapabilityStatus(str, Enum):
    """Pre-flight capability-probe result for
    Microsoft.Network/networkInterfaces/effectiveRouteTable/action, per
    subscription+account (see capability_probe.py). Reader is EXPECTED to
    fail this probe -- Reader grants `*/read`, and effectiveRouteTable is an
    action, not a read; only Contributor or a custom role explicitly
    carrying that action passes."""
    CAN_READ_ROUTES = "CAN_READ_ROUTES"
    CANNOT_READ_ROUTES = "CANNOT_READ_ROUTES"
    UNKNOWN = "UNKNOWN"  # no NIC available anywhere in the subscription to probe with


# Subnet names Azure/Microsoft reserve for infrastructure that bypasses the
# transit hub by design. Matching is case-insensitive on the subnet name.
EXPECTED_BYPASS_SUBNET_NAMES = {
    "gatewaysubnet",
    "azurefirewallsubnet",
    "azurefirewallmanagementsubnet",
    "azurebastionsubnet",
    "routeserversubnet",
}


@dataclass
class OffendingRoute:
    subscription_id: str
    subscription_name: str
    resource_group: str
    vnet_name: str
    subnet_name: str
    address_prefix: str
    next_hop_type: str
    next_hop_ip: Optional[str]
    route_source: str  # Default / User / VirtualNetworkGateway / etc.
    route_table_name: Optional[str]
    route_name: Optional[str]
    nic_id: Optional[str] = None
    organization: str = ""
    environment: str = ""

    def as_row(self) -> list:
        return [
            self.subscription_name,
            self.subscription_id,
            self.organization,
            self.environment,
            self.resource_group,
            self.vnet_name,
            self.subnet_name,
            self.address_prefix,
            self.next_hop_type,
            self.next_hop_ip or "",
            self.route_source,
            self.route_table_name or "",
            self.route_name or "",
            self.nic_id or "",
        ]


@dataclass
class SubnetFinding:
    subscription_id: str
    subscription_name: str
    resource_group: str
    vnet_name: str
    organization: str = ""
    environment: str = ""
    vnet_address_space: list = field(default_factory=list)
    subnet_name: str = ""
    subnet_id: str = ""
    address_prefix: str = ""

    peered_to_hub: bool = False
    peering_state: Optional[str] = None
    hub_connection_name: Optional[str] = None
    associated_route_table: Optional[str] = None
    associated_nsg: Optional[str] = None
    delegations: list = field(default_factory=list)
    service_endpoints: list = field(default_factory=list)
    has_private_endpoints: bool = False
    nic_ids: list = field(default_factory=list)

    default_route_next_hop_type: Optional[str] = None
    default_route_next_hop_ip: Optional[str] = None
    default_route_source: Optional[str] = None

    offending_routes: list = field(default_factory=list)  # list[OffendingRoute]

    verdict: Verdict = Verdict.NOT_EVALUATED
    evidence: Evidence = Evidence.NONE
    notes: str = ""

    # Which signed-in account's credential actually produced this verdict.
    # Not cosmetic: with per-subscription credential routing, two subnets in
    # the same workbook can legitimately have been read by two different
    # identities, and a verdict is not interpretable without knowing which.
    evaluated_by_account: str = ""

    def offending_routes_concat(self) -> str:
        parts = []
        for r in self.offending_routes:
            parts.append(
                f"{r.address_prefix}->{r.next_hop_type}"
                f"({r.next_hop_ip or 'n/a'}) via {r.route_table_name or 'n/a'}"
                f"/{r.route_name or 'n/a'}"
            )
        return "; ".join(parts)

    def as_row(self) -> list:
        return [
            self.subscription_name,
            self.subscription_id,
            self.organization,
            self.environment,
            self.resource_group,
            self.vnet_name,
            self.subnet_name,
            self.address_prefix,
            self.verdict.value,
            self.peered_to_hub,
            self.hub_connection_name or "",
            self.associated_route_table or "",
            self.default_route_next_hop_type or "",
            self.default_route_next_hop_ip or "",
            self.offending_routes_concat(),
            self.evidence.value,
            self.notes,
            self.evaluated_by_account,
        ]


@dataclass
class ErrorRecord:
    scope: str  # subscription/resource-group/vnet/subnet/nic resource id or friendly path
    operation: str
    reason: str
    status_code: Optional[int] = None

    def as_row(self) -> list:
        return [self.scope, self.operation, str(self.status_code or ""), self.reason]


@dataclass
class HubFirewallInfo:
    resource_id: str
    resource_type: str  # "AzureFirewall" | "NVA" | "Unknown"
    private_ip: Optional[str]
    name: str


@dataclass
class VHubBaseline:
    vwan_name: str
    vwan_id: str
    hub_name: str
    hub_id: str
    region: str
    address_prefix: str
    routing_state: Optional[str]
    subscription_id: str
    subscription_name: str
    resource_group: str
    firewall: Optional[HubFirewallInfo] = None
    route_tables: list = field(default_factory=list)  # list[dict]
    connections: list = field(default_factory=list)   # list[dict]
    gateways: list = field(default_factory=list)       # list[dict]
    compliant_next_hop_ips: set = field(default_factory=set)

    def as_row(self) -> list:
        fw_ip = self.firewall.private_ip if self.firewall else ""
        fw_type = self.firewall.resource_type if self.firewall else "NONE_DETECTED"
        return [
            self.vwan_name,
            self.hub_name,
            self.region,
            self.address_prefix,
            self.routing_state or "",
            self.subscription_name,
            self.subscription_id,
            self.resource_group,
            fw_type,
            fw_ip or "",
            len(self.connections),
            len(self.gateways),
        ]


@dataclass
class CmdbRow:
    """One valid, de-duplicated row from the ServiceNow CMDB export."""
    row_number: int
    subscription_id: str  # lower-cased GUID
    name: str
    datacenter_type: str = ""
    organization: str = ""
    environment: str = ""
    supported_by: str = ""
    owned_by: str = ""
    install_status: str = ""
    updated: str = ""
    updated_by: str = ""
    short_description: str = ""

    # Populated during reconciliation (inventory.reconcile_subscriptions).
    bucket: Optional[ReconciliationBucket] = None
    azure_display_name: Optional[str] = None

    # Populated during Phase 0.5 file-level reconciliation against the
    # (optional) Azure portal export (reconcile.py). Left at defaults when no
    # --azure-file was supplied.
    file_scope_bucket: Optional[FileScopeBucket] = None
    azure_export_name: str = ""
    my_role: str = ""
    azure_status: str = ""
    parent_management_group: str = ""
    organization_inferred: bool = False
    inferred_organization: str = ""
    disabled: bool = False
    excluded_by_name_pattern: bool = False
    exclude_reason: str = ""

    def as_scope_row(self) -> list:
        return [
            self.row_number,
            self.name,
            self.subscription_id,
            self.organization or "",
            self.environment or "",
            self.install_status or "",
            self.supported_by or "",
            self.owned_by or "",
            self.bucket.value if self.bucket else "",
            self.azure_display_name or "",
            self.file_scope_bucket.value if self.file_scope_bucket else "",
            self.my_role or "",
            self.azure_status or "",
            self.parent_management_group or "",
            "ORG_INFERRED" if self.organization_inferred else "",
            self.inferred_organization or "",
            "DISABLED" if self.disabled else "",
            self.exclude_reason or "",
        ]

    def as_ownership_gap_row(self) -> list:
        return [
            self.row_number,
            self.name,
            self.subscription_id,
            self.organization or "(blank)",
            self.environment or "(blank)",
            self.supported_by or "",
            self.owned_by or "",
        ]


@dataclass
class InvalidCmdbRow:
    row_number: int
    name: str
    raw_subscription_id: str
    reason: str

    def as_row(self) -> list:
        return [self.row_number, self.name, self.raw_subscription_id, self.reason]


@dataclass
class AzureExportRow:
    """One valid, de-duplicated row from the Azure portal's subscription
    list export (CSV), see azure_export.py."""
    row_number: int
    subscription_id: str  # lower-cased GUID
    name: str
    my_role: str = ""
    current_cost: str = ""
    secure_score: str = ""
    parent_management_group: str = ""
    status: str = ""  # Active / Disabled

    def as_row(self) -> list:
        return [
            self.row_number,
            self.name,
            self.subscription_id,
            self.my_role,
            self.current_cost,
            self.secure_score,
            self.parent_management_group,
            self.status,
        ]


@dataclass
class InvalidAzureExportRow:
    row_number: int
    name: str
    raw_subscription_id: str
    reason: str

    def as_row(self) -> list:
        return [self.row_number, self.name, self.raw_subscription_id, self.reason]


@dataclass
class CapabilityResult:
    """Pre-flight capability-probe outcome for one subscription -- see
    capability_probe.py. Subscriptions classified CANNOT_READ_ROUTES have
    their real effective-route calls skipped entirely (every subnet with a
    NIC in that subscription is marked NOT_EVALUATED / INSUFFICIENT_ROLE
    instead), so the full scan isn't burned on guaranteed 403s."""
    subscription_id: str
    subscription_name: str
    account: str
    role: str  # best-effort; "UNKNOWN" if it couldn't be determined
    status: CapabilityStatus
    reason: str
    probed_nic_id: Optional[str] = None

    def as_row(self) -> list:
        return [
            self.subscription_name,
            self.subscription_id,
            self.account,
            self.role,
            self.status.value,
            self.reason,
        ]

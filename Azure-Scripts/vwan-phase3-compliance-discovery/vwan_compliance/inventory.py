"""Phase 0 reconciliation + Phase 3 broad VNet/subnet inventory sweep.

Scope is CMDB-driven (see cmdb.py), not "every subscription the credential
can see". This module reconciles the two sets and produces three buckets:

  IN_BOTH              - in the CMDB export AND visible to the credential.
                         These are the only subscriptions actually scanned.
  IN_CMDB_NOT_VISIBLE  - CMDB says it exists, credential can't see it
                         (missing RBAC, or a stale/decommissioned record).
  VISIBLE_NOT_IN_CMDB  - exists in Azure but absent from the CMDB export: an
                         unmanaged/shadow subscription. This is itself a
                         Phase 3 finding, not something to skip.

The broad VNet/subnet sweep for the IN_BOTH set uses Azure Resource Graph (a
single paged KQL query across every scanned subscription) because iterating
resource-group -> vnet -> subnet with the management SDK for a large tenant
is an O(n) chain of ARM calls that is both slow and heavily throttled.
Effective routes are NOT available via Resource Graph -- that part still
requires the management SDK, see compliance.py.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Optional

from azure.core.exceptions import HttpResponseError
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
from azure.mgmt.subscription import SubscriptionClient

from .credential_router import CredentialRoutingError
from .logging_config import get_logger
from .models import EXPECTED_BYPASS_SUBNET_NAMES, CmdbRow, ErrorRecord, ReconciliationBucket
from .retry import call_with_retry

log = get_logger("inventory")

_VNET_QUERY = """
Resources
| where type =~ 'microsoft.network/virtualnetworks'
| project id, name, resourceGroup, subscriptionId, location,
          addressSpace = properties.addressSpace.addressPrefixes,
          subnets = properties.subnets,
          peerings = properties.virtualNetworkPeerings,
          ddosProtectionPlan = properties.ddosProtectionPlan
"""


@dataclass
class SubscriptionInfo:
    subscription_id: str
    display_name: str
    state: str
    organization: str = ""
    environment: str = ""


@dataclass
class ReconciliationResult:
    scan_targets: list[SubscriptionInfo] = field(default_factory=list)   # IN_BOTH
    shadow_subscriptions: list[SubscriptionInfo] = field(default_factory=list)  # VISIBLE_NOT_IN_CMDB
    cmdb_rows: list[CmdbRow] = field(default_factory=list)  # every CMDB row, bucket set on each


@dataclass
class SubnetRecord:
    subscription_id: str
    subscription_name: str
    organization: str
    environment: str
    resource_group: str
    vnet_name: str
    vnet_id: str
    vnet_address_space: list
    subnet_name: str
    subnet_id: str
    address_prefix: str
    route_table_id: Optional[str]
    nsg_id: Optional[str]
    delegations: list
    service_endpoints: list
    private_endpoint_ids: list
    nic_ids: list  # candidate NICs (from ipConfigurations), for effective-route sampling
    peered_to_hub: bool
    peering_state: Optional[str]
    hub_connection_name: Optional[str]
    is_expected_bypass_by_name: bool


def reconcile_subscriptions(
    router,
    cmdb_rows: list[CmdbRow],
    errors: list,
) -> ReconciliationResult:
    """Compare the CMDB export against what is actually visible in Azure and
    produce the three reconciliation buckets. Only IN_BOTH subscriptions are
    returned as scan targets.

    `router` is a credential_router.CredentialRouter. In single-credential
    mode this behaves exactly as before (one `subscriptions.list()` call).
    In routed mode, "visible" is built directly from `az account list
    --all` (already fetched by router.preflight()) instead of an ARM call --
    that command already enumerates every subscription visible to every
    signed-in account, which is exactly the union we need, and avoids
    picking one arbitrary account's credential to ask ARM with.
    """
    if router.mode == "routed":
        az_accounts = router.cached_az_accounts()
        visible = {
            a.subscription_id: SimpleNamespace(subscription_id=a.subscription_id, display_name=a.subscription_name, state="Enabled")
            for a in az_accounts
        }
    else:
        sub_client = SubscriptionClient(router.any_credential())
        try:
            azure_subs = list(call_with_retry(
                lambda: list(sub_client.subscriptions.list()),
                context="subscriptions.list",
            ))
        except HttpResponseError as exc:
            errors.append(ErrorRecord(
                scope="tenant", operation="subscriptions.list",
                reason=getattr(exc, "message", str(exc)),
                status_code=getattr(exc, "status_code", None),
            ))
            azure_subs = []

        visible = {
            s.subscription_id.lower(): s
            for s in azure_subs
            if s.state == "Enabled"
        }

    scan_targets: list[SubscriptionInfo] = []
    for row in cmdb_rows:
        az_sub = visible.get(row.subscription_id)
        if az_sub is not None:
            row.bucket = ReconciliationBucket.IN_BOTH
            row.azure_display_name = az_sub.display_name
            scan_targets.append(SubscriptionInfo(
                subscription_id=row.subscription_id,
                display_name=az_sub.display_name or row.name,
                state="Enabled",
                organization=row.organization,
                environment=row.environment,
            ))
        else:
            row.bucket = ReconciliationBucket.IN_CMDB_NOT_VISIBLE
            log.warning(
                "IN_CMDB_NOT_VISIBLE: '%s' (%s) is in the CMDB export but not visible "
                "to this credential - missing RBAC or a stale record.",
                row.name, row.subscription_id,
            )

    cmdb_ids = {r.subscription_id for r in cmdb_rows}
    shadow = [
        SubscriptionInfo(subscription_id=sid, display_name=s.display_name, state="Enabled")
        for sid, s in visible.items()
        if sid not in cmdb_ids
    ]
    for s in shadow:
        log.warning(
            "VISIBLE_NOT_IN_CMDB: '%s' (%s) is visible to this credential but absent "
            "from the CMDB export - unmanaged/shadow subscription, recorded as a finding.",
            s.display_name, s.subscription_id,
        )

    return ReconciliationResult(scan_targets=scan_targets, shadow_subscriptions=shadow, cmdb_rows=cmdb_rows)


def sweep_vnets_and_subnets(
    router,
    subscriptions: list[SubscriptionInfo],
    hub_connection_vnet_ids: dict,  # remote_vnet_id -> connection_name
    errors: list,
    *,
    dry_run: bool = False,
) -> list[SubnetRecord]:
    """Run the Resource Graph sweep and flatten into one SubnetRecord per
    subnet. hub_connection_vnet_ids maps a VNet resource ID to the name of
    the hub connection that attaches it, as discovered in Phase 2 -- used to
    mark peered_to_hub / hub_connection_name even before effective routes
    are read.

    A single Resource Graph query can only see subscriptions visible to ONE
    identity's token. With --credential-map routing different subscriptions
    to different accounts, subscriptions are grouped by their resolved
    account and one query is issued per group, then merged -- functionally
    equivalent to the single-credential case when everything routes to the
    same account (one group).
    """
    if not subscriptions:
        return []

    sub_meta = {s.subscription_id: s for s in subscriptions}

    if dry_run:
        log.info("[dry-run] Would sweep %d subscriptions via Resource Graph.", len(subscriptions))
        return []

    groups: dict = defaultdict(list)  # account -> [sub_id, ...]
    creds_by_account: dict = {}
    for s in subscriptions:
        try:
            cred, account = router.resolve(s.subscription_id)
        except CredentialRoutingError as exc:
            errors.append(ErrorRecord(scope=s.subscription_id, operation="credential_routing.resolve", reason=str(exc)))
            continue
        groups[account].append(s.subscription_id)
        creds_by_account[account] = cred

    records: list[SubnetRecord] = []
    for account, sub_ids in groups.items():
        records.extend(_sweep_one_group(creds_by_account[account], sub_ids, sub_meta, hub_connection_vnet_ids, errors))
    return records


def _sweep_one_group(
    credential,
    sub_ids: list[str],
    sub_meta: dict,
    hub_connection_vnet_ids: dict,
    errors: list,
) -> list[SubnetRecord]:
    client = ResourceGraphClient(credential)
    records: list[SubnetRecord] = []
    skip_token = None
    page = 0

    while True:
        page += 1
        options = QueryRequestOptions(skip_token=skip_token, top=1000)
        request = QueryRequest(query=_VNET_QUERY, subscriptions=sub_ids, options=options)
        try:
            response = call_with_retry(
                lambda: client.resources(request),
                context="resourcegraph.resources [vnet sweep]",
            )
        except HttpResponseError as exc:
            errors.append(ErrorRecord(
                scope="resourcegraph", operation="resources",
                reason=getattr(exc, "message", str(exc)),
                status_code=getattr(exc, "status_code", None),
            ))
            break

        rows = response.data or []
        log.debug("Resource Graph page %d: %d VNets (group of %d subscription(s)).", page, len(rows), len(sub_ids))
        for row in rows:
            records.extend(_flatten_vnet(row, sub_meta, hub_connection_vnet_ids))

        skip_token = getattr(response, "skip_token", None)
        if not skip_token or not rows:
            break

    return records


def _flatten_vnet(row: dict, sub_meta: dict, hub_connection_vnet_ids: dict) -> list[SubnetRecord]:
    sub_id = row.get("subscriptionId", "")
    meta = sub_meta.get(sub_id)
    sub_name = meta.display_name if meta else sub_id
    organization = meta.organization if meta else ""
    environment = meta.environment if meta else ""
    vnet_id = row.get("id", "")
    vnet_name = row.get("name", "")
    rg_name = row.get("resourceGroup", "")
    address_space = row.get("addressSpace") or []
    peerings = row.get("peerings") or []
    subnets = row.get("subnets") or []

    peered_to_hub = False
    peering_state = None
    for peering in peerings:
        remote_id = (peering.get("properties", {}) or {}).get("remoteVirtualNetwork", {}).get("id", "")
        if remote_id in hub_connection_vnet_ids or vnet_id in hub_connection_vnet_ids:
            peered_to_hub = True
            peering_state = (peering.get("properties", {}) or {}).get("peeringState")

    hub_connection_name = hub_connection_vnet_ids.get(vnet_id)

    out = []
    for subnet in subnets:
        props = subnet.get("properties", {}) or {}
        subnet_name = subnet.get("name", "")
        ip_configs = props.get("ipConfigurations") or []
        nic_ids = []
        for ipc in ip_configs:
            ipc_id = ipc.get("id", "")
            if "/networkInterfaces/" in ipc_id:
                nic_ids.append(ipc_id.split("/ipConfigurations/")[0])
        private_endpoints = props.get("privateEndpoints") or []

        out.append(SubnetRecord(
            subscription_id=sub_id,
            subscription_name=sub_name,
            organization=organization,
            environment=environment,
            resource_group=rg_name,
            vnet_name=vnet_name,
            vnet_id=vnet_id,
            vnet_address_space=address_space,
            subnet_name=subnet_name,
            subnet_id=subnet.get("id", ""),
            address_prefix=props.get("addressPrefix") or ",".join(props.get("addressPrefixes") or []),
            route_table_id=(props.get("routeTable") or {}).get("id"),
            nsg_id=(props.get("networkSecurityGroup") or {}).get("id"),
            delegations=[d.get("properties", {}).get("serviceName") for d in (props.get("delegations") or [])],
            service_endpoints=[se.get("service") for se in (props.get("serviceEndpoints") or [])],
            private_endpoint_ids=[pe.get("id") for pe in private_endpoints],
            nic_ids=sorted(set(nic_ids)),
            peered_to_hub=peered_to_hub,
            peering_state=peering_state,
            hub_connection_name=hub_connection_name,
            is_expected_bypass_by_name=subnet_name.lower() in EXPECTED_BYPASS_SUBNET_NAMES,
        ))
    return out

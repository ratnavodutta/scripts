"""Phase A: discover the vWAN transit-hub topology and derive the baseline
set of "compliant next hops" that spoke traffic is expected to use.

Detection order for the secured-hub firewall/NVA, per hub:
  1. Read the hub's Routing Intent (`routing_intent.list`). If a
     "PrivateTraffic" (and/or "InternetTraffic") policy exists, its
     `next_hop` resource ID tells us definitively what compliant traffic
     should be routed to. This is authoritative when present.
  2. Resolve that resource: if it's a Microsoft.Network/azureFirewalls
     resource, read its private IP configuration(s) directly.
  3. If it's not an Azure Firewall (e.g. Microsoft.Network/
     networkVirtualAppliances, or a Microsoft.Network/loadBalancers front-end
     for a clustered NVA), record it as an NVA and best-effort resolve a
     private IP from its own properties.
  4. If a hub has no Routing Intent at all, fall back to scanning for an
     azureFirewalls resource whose `virtual_hub.id` matches the hub -- older
     "Secured Virtual Hub" deployments configure the firewall this way
     without Routing Intent.
  5. If nothing is found, the hub is recorded with firewall=None and shows
     up in vWAN_Baseline as NONE_DETECTED -- this is a configuration gap to
     flag, not a silent skip.

ASSUMPTION (confirm against your environment, see README):
  Several Blackbaud azure-core hubs configure Routing Intent with only a
  "PrivateTraffic" policy and no "InternetTraffic" policy. That means
  RFC1918-bound traffic is force-tunneled through the firewall, but
  internet-bound (0.0.0.0/0, non-RFC1918) traffic may legitimately take a
  different path (e.g. hub-local internet breakout or an NVA's own SNAT)
  without that being a Phase 3 violation. This script flags the default
  route (0.0.0.0/0) using whatever next hop is present, but does not assume
  0.0.0.0/0 must equal the firewall IP unless an "InternetTraffic" routing
  policy is also present on that hub. See --expected-next-hop / config file
  to override this per environment.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from azure.core.exceptions import HttpResponseError
from azure.mgmt.network import NetworkManagementClient

from .logging_config import get_logger
from .models import ErrorRecord, HubFirewallInfo, VHubBaseline
from .retry import call_with_retry

log = get_logger("baseline")


@dataclass
class BaselineConfig:
    additional_next_hop_ips: set
    additional_next_hop_types: set
    trusted_hub_ids: set
    manual_expected_bypass_subnet_ids: set

    @classmethod
    def load(cls, config_path: Optional[Path], cli_next_hops: list[str]) -> "BaselineConfig":
        data: dict = {}
        if config_path is not None:
            if not config_path.exists():
                raise FileNotFoundError(
                    f"--config file not found: {config_path}. Copy "
                    "config/expected_next_hops.example.json to get started."
                )
            data = json.loads(config_path.read_text(encoding="utf-8"))

        return cls(
            additional_next_hop_ips=set(data.get("additional_next_hop_ips", [])) | set(cli_next_hops),
            additional_next_hop_types=set(data.get("additional_next_hop_types", [])),
            trusted_hub_ids=set(data.get("trusted_hub_ids", [])),
            manual_expected_bypass_subnet_ids=set(data.get("manual_expected_bypass_subnet_ids", [])),
        )


def _first_private_ip_from_firewall(fw) -> Optional[str]:
    ip_configs = getattr(fw, "ip_configurations", None) or []
    for cfg in ip_configs:
        ip = getattr(cfg, "private_ip_address", None)
        if ip:
            return ip
    # Some SDK versions expose hub IP config separately.
    hub_ip_addresses = getattr(fw, "hub_ip_addresses", None)
    if hub_ip_addresses is not None:
        private_ips = getattr(hub_ip_addresses, "private_i_ps", None)
        addr = getattr(private_ips, "address", None) if private_ips else None
        if addr:
            return addr
    return None


def discover_baseline(
    router,
    subscription_ids: list[str],
    subscription_names: dict[str, str],
    config: BaselineConfig,
    errors: list,
    *,
    dry_run: bool = False,
) -> list[VHubBaseline]:
    """Enumerate every Virtual WAN / Virtual Hub across the given
    subscriptions and build a VHubBaseline per hub, including the derived
    compliant-next-hop set.

    `router` is a credential_router.CredentialRouter -- resolved per
    subscription so that, with --credential-map in effect, each
    subscription's hub topology is read with the identity actually assigned
    to it rather than a single shared credential.
    """
    baselines: list[VHubBaseline] = []

    for sub_id in subscription_ids:
        sub_name = subscription_names.get(sub_id, sub_id)
        try:
            credential, _account = router.resolve(sub_id)
        except Exception as exc:  # noqa: BLE001 - CredentialRoutingError et al.
            _record_generic_error(errors, sub_id, "credential_routing.resolve", str(exc))
            continue
        net_client = NetworkManagementClient(credential, sub_id)

        try:
            hubs = list(call_with_retry(
                lambda: list(net_client.virtual_hubs.list()),
                context=f"virtual_hubs.list [{sub_id}]",
            ))
        except HttpResponseError as exc:
            _record_error(errors, sub_id, "virtual_hubs.list", exc)
            continue

        if not hubs:
            continue

        for hub in hubs:
            rg_name = _rg_from_id(hub.id)
            baseline = VHubBaseline(
                vwan_name=_name_from_id(hub.virtual_wan.id) if hub.virtual_wan else "",
                vwan_id=hub.virtual_wan.id if hub.virtual_wan else "",
                hub_name=hub.name,
                hub_id=hub.id,
                region=hub.location,
                address_prefix=hub.address_prefix or "",
                routing_state=getattr(hub, "routing_state", None),
                subscription_id=sub_id,
                subscription_name=sub_name,
                resource_group=rg_name,
            )

            if dry_run:
                baselines.append(baseline)
                continue

            _populate_route_tables(net_client, baseline, rg_name, errors)
            _populate_connections(net_client, baseline, rg_name, errors)
            _populate_gateways(net_client, baseline, hub, errors)
            _populate_firewall(net_client, baseline, rg_name, errors, config)

            baseline.compliant_next_hop_ips = _derive_compliant_next_hops(baseline, config)
            baselines.append(baseline)

    return baselines


def _populate_route_tables(net_client, baseline: VHubBaseline, rg_name: str, errors: list) -> None:
    try:
        route_tables = list(call_with_retry(
            lambda: list(net_client.hub_route_tables.list(rg_name, baseline.hub_name)),
            context=f"hub_route_tables.list [{baseline.hub_id}]",
        ))
    except HttpResponseError as exc:
        _record_error(errors, baseline.hub_id, "hub_route_tables.list", exc)
        return

    for rt in route_tables:
        routes = []
        for route in (getattr(rt, "routes", None) or []):
            routes.append({
                "name": route.name,
                "destinations": list(route.destinations or []),
                "destination_type": route.destination_type,
                "next_hop_type": route.next_hop_type,
                "next_hop": route.next_hop,
            })
        baseline.route_tables.append({
            "name": rt.name,
            "id": rt.id,
            "routes": routes,
            "labels": list(getattr(rt, "labels", None) or []),
        })


def _populate_connections(net_client, baseline: VHubBaseline, rg_name: str, errors: list) -> None:
    try:
        connections = list(call_with_retry(
            lambda: list(net_client.hub_virtual_network_connections.list(rg_name, baseline.hub_name)),
            context=f"hub_virtual_network_connections.list [{baseline.hub_id}]",
        ))
    except HttpResponseError as exc:
        _record_error(errors, baseline.hub_id, "hub_virtual_network_connections.list", exc)
        return

    for conn in connections:
        remote_vnet_id = conn.remote_virtual_network.id if conn.remote_virtual_network else None
        rt_assoc = getattr(conn, "routing_configuration", None)
        associated_rt = None
        propagated_rts = []
        if rt_assoc:
            if getattr(rt_assoc, "associated_route_table", None):
                associated_rt = rt_assoc.associated_route_table.id
            plist = getattr(rt_assoc, "propagated_route_tables", None)
            if plist and getattr(plist, "ids", None):
                propagated_rts = [i.id for i in plist.ids]
        baseline.connections.append({
            "connection_name": conn.name,
            "id": conn.id,
            "remote_vnet_id": remote_vnet_id,
            "enable_internet_security": getattr(conn, "enable_internet_security", None),
            "associated_route_table": associated_rt,
            "propagated_route_tables": propagated_rts,
        })


def _populate_gateways(net_client, baseline: VHubBaseline, hub, errors: list) -> None:
    hub_id = hub.id
    try:
        # NOTE: unlike vpn_gateways/p2s_vpn_gateways, this operation returns a
        # single ExpressRouteGatewayList wrapper (with a `.value` list), not a
        # paged iterable of gateways directly.
        gw_list = call_with_retry(
            net_client.express_route_gateways.list_by_subscription,
            context="express_route_gateways.list_by_subscription",
        )
        for gw in (getattr(gw_list, "value", None) or []):
            if gw.virtual_hub and gw.virtual_hub.id == hub_id:
                baseline.gateways.append({"type": "ExpressRoute", "name": gw.name, "id": gw.id})
    except HttpResponseError as exc:
        _record_error(errors, hub_id, "express_route_gateways.list_by_subscription", exc)

    try:
        # This SDK version has no list_by_subscription() for vpn_gateways;
        # list() is already subscription-wide.
        for gw in call_with_retry(
            lambda: list(net_client.vpn_gateways.list()),
            context="vpn_gateways.list",
        ):
            if gw.virtual_hub and gw.virtual_hub.id == hub_id:
                baseline.gateways.append({"type": "VPN", "name": gw.name, "id": gw.id})
    except HttpResponseError as exc:
        _record_error(errors, hub_id, "vpn_gateways.list", exc)

    try:
        # Same as above: no list_by_subscription() for this operation group in
        # this SDK version; list() is already subscription-wide. Also note the
        # generated client attribute is `p2_svpn_gateways`, not
        # `p2s_vpn_gateways`.
        for gw in call_with_retry(
            lambda: list(net_client.p2_svpn_gateways.list()),
            context="p2_svpn_gateways.list",
        ):
            if gw.virtual_hub and gw.virtual_hub.id == hub_id:
                baseline.gateways.append({"type": "P2S VPN", "name": gw.name, "id": gw.id})
    except HttpResponseError as exc:
        _record_error(errors, hub_id, "p2_svpn_gateways.list", exc)


def _populate_firewall(net_client, baseline: VHubBaseline, rg_name: str, errors: list, config: BaselineConfig) -> None:
    # 1. Routing Intent is authoritative when present.
    next_hop_resource_id = None
    try:
        intents = list(call_with_retry(
            lambda: list(net_client.routing_intent.list(rg_name, baseline.hub_name)),
            context=f"routing_intent.list [{baseline.hub_id}]",
        ))
        for intent in intents:
            for policy in (getattr(intent, "routing_policies", None) or []):
                dests = [d.lower() for d in (policy.destinations or [])]
                if "privatetraffic" in dests or "internettraffic" in dests:
                    next_hop_resource_id = policy.next_hop
                    baseline.route_tables.append({
                        "name": f"routing-intent:{intent.name}",
                        "id": intent.id,
                        "routes": [{
                            "name": policy.name,
                            "destinations": policy.destinations,
                            "destination_type": "RoutingIntent",
                            "next_hop_type": "RoutingIntentNextHop",
                            "next_hop": policy.next_hop,
                        }],
                        "labels": [],
                    })
    except HttpResponseError as exc:
        _record_error(errors, baseline.hub_id, "routing_intent.list", exc)

    if next_hop_resource_id:
        fw = _resolve_firewall_by_id(net_client, next_hop_resource_id, errors)
        if fw is not None:
            baseline.firewall = fw
            return

    # 2. Fallback: scan azureFirewalls attached directly to this hub
    # (older "Secured Virtual Hub" pattern, no Routing Intent resource).
    try:
        firewalls = list(call_with_retry(
            lambda: list(net_client.azure_firewalls.list_all()),
            context="azure_firewalls.list_all",
        ))
    except HttpResponseError as exc:
        _record_error(errors, baseline.hub_id, "azure_firewalls.list_all", exc)
        firewalls = []

    for fw in firewalls:
        vh = getattr(fw, "virtual_hub", None)
        if vh and vh.id == baseline.hub_id:
            baseline.firewall = HubFirewallInfo(
                resource_id=fw.id,
                resource_type="AzureFirewall",
                private_ip=_first_private_ip_from_firewall(fw),
                name=fw.name,
            )
            return

    # 3. Nothing found -- config gap, recorded as NONE_DETECTED downstream.
    if baseline.hub_id in config.trusted_hub_ids:
        baseline.firewall = HubFirewallInfo(
            resource_id=baseline.hub_id,
            resource_type="Trusted-NoDirectRead",
            private_ip=None,
            name=f"{baseline.hub_name} (trusted, unreadable)",
        )


def _resolve_firewall_by_id(net_client, resource_id: str, errors: list) -> Optional[HubFirewallInfo]:
    resource_id_lower = resource_id.lower()
    if "/azurefirewalls/" in resource_id_lower:
        try:
            rg = _rg_from_id(resource_id)
            name = _name_from_id(resource_id)
            fw = call_with_retry(
                lambda: net_client.azure_firewalls.get(rg, name),
                context=f"azure_firewalls.get [{resource_id}]",
            )
            return HubFirewallInfo(
                resource_id=fw.id, resource_type="AzureFirewall",
                private_ip=_first_private_ip_from_firewall(fw), name=fw.name,
            )
        except HttpResponseError as exc:
            _record_error(errors, resource_id, "azure_firewalls.get", exc)
            return None

    if "/networkvirtualappliances/" in resource_id_lower:
        try:
            rg = _rg_from_id(resource_id)
            name = _name_from_id(resource_id)
            nva = call_with_retry(
                lambda: net_client.network_virtual_appliances.get(rg, name),
                context=f"network_virtual_appliances.get [{resource_id}]",
            )
            private_ip = None
            vfp = getattr(nva, "virtual_appliance_asn", None)  # not the IP; keep best-effort below
            nic_ips = getattr(nva, "virtual_appliance_nics", None) or []
            for n in nic_ips:
                addr = getattr(n, "private_ip_address", None)
                if addr:
                    private_ip = addr
                    break
            return HubFirewallInfo(
                resource_id=nva.id, resource_type="NVA",
                private_ip=private_ip, name=nva.name,
            )
        except HttpResponseError as exc:
            _record_error(errors, resource_id, "network_virtual_appliances.get", exc)
            return None

    # Unrecognized next-hop resource type (e.g. a load balancer front-end for
    # a clustered third-party NVA). Record it so the operator can add its IP
    # via config rather than silently dropping it.
    return HubFirewallInfo(resource_id=resource_id, resource_type="Unknown", private_ip=None, name=resource_id)


def _derive_compliant_next_hops(baseline: VHubBaseline, config: BaselineConfig) -> set:
    ips = set(config.additional_next_hop_ips)
    if baseline.firewall and baseline.firewall.private_ip:
        ips.add(baseline.firewall.private_ip)
    return ips


def _record_error(errors: list, scope: str, operation: str, exc: HttpResponseError) -> None:
    status = getattr(exc, "status_code", None)
    reason = getattr(exc, "message", None) or str(exc)
    errors.append(ErrorRecord(scope=scope, operation=operation, reason=reason, status_code=status))
    if status == 403:
        log.warning("Permission denied: %s on %s - recorded and continuing.", operation, scope)
    else:
        log.warning("Error calling %s on %s: %s", operation, scope, reason)


def _record_generic_error(errors: list, scope: str, operation: str, reason: str) -> None:
    errors.append(ErrorRecord(scope=scope, operation=operation, reason=reason))
    log.warning("Error during %s on %s: %s", operation, scope, reason)


def _rg_from_id(resource_id: str) -> str:
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""


def _name_from_id(resource_id: str) -> str:
    return resource_id.rstrip("/").split("/")[-1]


def print_baseline_summary(baselines: list[VHubBaseline]) -> None:
    print("\n=== Phase A: vWAN Transit Hub Baseline ===")
    if not baselines:
        print("  No Virtual Hubs discovered.")
        return
    for b in baselines:
        fw_desc = "NONE DETECTED (config gap)" if not b.firewall else (
            f"{b.firewall.resource_type} '{b.firewall.name}' -> {b.firewall.private_ip or 'IP unresolved'}"
        )
        print(
            f"  [{b.subscription_name}] {b.vwan_name}/{b.hub_name} ({b.region}, {b.address_prefix}) "
            f"- firewall: {fw_desc} - connections: {len(b.connections)} - gateways: {len(b.gateways)}"
        )
    all_ips = sorted({ip for b in baselines for ip in b.compliant_next_hop_ips})
    print(f"\n  Compliant next-hop IPs ({len(all_ips)}): {', '.join(all_ips) if all_ips else '(none resolved)'}")

"""The compliance verdict engine.

Peering to the hub is NOT proof of compliance -- a VNet can be peered and
still bypass it via a UDR. The authoritative signal is the EFFECTIVE route
table read from a real NIC in the subnet
(`network_interfaces.begin_get_effective_route_table`). Where no NIC exists,
we fall back to weaker, explicitly-labelled INFERRED evidence and keep the
verdict as NOT_EVALUATED -- we never let inference masquerade as a measured
COMPLIANT/NON_COMPLIANT result.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
from collections import Counter, defaultdict
from typing import Callable, Optional

from azure.core.exceptions import HttpResponseError
from azure.mgmt.network import NetworkManagementClient

from .baseline import BaselineConfig, _name_from_id, _rg_from_id  # reuse helpers
from .cache import RunCache
from .credential_router import CredentialRoutingError
from .inventory import SubnetRecord
from .logging_config import get_logger
from .models import ErrorRecord, Evidence, OffendingRoute, SubnetFinding, Verdict
from .retry import call_with_retry

log = get_logger("compliance")

DEFAULT_ROUTE_PREFIXES = {"0.0.0.0/0"}


def evaluate_subnets(
    router,
    subnets: list[SubnetRecord],
    compliant_next_hop_ips: set,
    additional_next_hop_types: set,
    config: BaselineConfig,
    cache: RunCache,
    *,
    sample_nics_per_subnet: int,
    evaluate_all_nics: bool,
    max_workers: int,
    dry_run: bool = False,
    insufficient_role_subscriptions: Optional[set] = None,
    on_subscription_complete: Optional[
        Callable[[str, list[SubnetFinding], list[OffendingRoute], list[ErrorRecord]], None]
    ] = None,
) -> tuple[list[SubnetFinding], list[OffendingRoute], list[ErrorRecord]]:
    """If on_subscription_complete is given, it's invoked exactly once per
    subscription_id represented in `subnets`, as soon as every subnet
    belonging to that subscription has finished evaluating (not necessarily
    in subnet order) -- so a caller can flush incremental scan state (see
    state.py) without waiting for the entire, possibly large, multi-hour run
    to complete.

    `router` is a credential_router.CredentialRouter, resolved per
    subscription. `insufficient_role_subscriptions` (subscription IDs, from
    capability_probe.py's CANNOT_READ_ROUTES results) short-circuits every
    subnet with a NIC in those subscriptions straight to NOT_EVALUATED /
    INSUFFICIENT_ROLE instead of making the (guaranteed-403) effective-route
    call hundreds of times.
    """
    findings: list[SubnetFinding] = []
    offending: list[OffendingRoute] = []
    errors: list[ErrorRecord] = []
    insufficient_role_subscriptions = insufficient_role_subscriptions or set()

    if dry_run:
        log.info("[dry-run] Would evaluate %d subnets.", len(subnets))
        return findings, offending, errors

    remaining_by_sub: Counter = Counter(s.subscription_id for s in subnets)
    per_sub_findings: dict[str, list] = defaultdict(list)
    per_sub_offending: dict[str, list] = defaultdict(list)
    per_sub_errors: dict[str, list] = defaultdict(list)

    # One NetworkManagementClient per subscription, reused across threads
    # (the SDK clients are safe for concurrent use for independent calls).
    clients: dict[str, NetworkManagementClient] = {}
    accounts_by_sub: dict[str, str] = {}

    def get_client(sub_id: str) -> tuple:
        if sub_id not in clients:
            try:
                credential, account = router.resolve(sub_id)
            except CredentialRoutingError as exc:
                errors.append(ErrorRecord(scope=sub_id, operation="credential_routing.resolve", reason=str(exc)))
                accounts_by_sub[sub_id] = "UNKNOWN"
                clients[sub_id] = None
                return None, "UNKNOWN"
            clients[sub_id] = NetworkManagementClient(credential, sub_id)
            accounts_by_sub[sub_id] = account
        return clients[sub_id], accounts_by_sub[sub_id]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {}
        for s in subnets:
            client, account = get_client(s.subscription_id)
            if client is None:
                future_map[pool.submit(lambda sub=s, acct=account: (
                    _error_finding(sub, "Credential routing failed for this subscription; see Errors sheet.", acct),
                    [], [],
                ))] = s
                continue
            future_map[pool.submit(
                _evaluate_one_subnet,
                client,
                s,
                account,
                compliant_next_hop_ips,
                additional_next_hop_types,
                config,
                cache,
                sample_nics_per_subnet,
                evaluate_all_nics,
                s.subscription_id in insufficient_role_subscriptions,
            )] = s
        for future in concurrent.futures.as_completed(future_map):
            subnet = future_map[future]
            try:
                finding, subnet_offending, subnet_errors = future.result()
            except Exception as exc:  # noqa: BLE001 - never let one subnet kill the run
                finding = _error_finding(subnet, f"Unhandled exception: {exc}", accounts_by_sub.get(subnet.subscription_id, "UNKNOWN"))
                subnet_offending, subnet_errors = [], [
                    ErrorRecord(scope=subnet.subnet_id, operation="evaluate_subnet", reason=str(exc))
                ]
            findings.append(finding)
            offending.extend(subnet_offending)
            errors.extend(subnet_errors)

            if on_subscription_complete is not None:
                sub_id = subnet.subscription_id
                per_sub_findings[sub_id].append(finding)
                per_sub_offending[sub_id].extend(subnet_offending)
                per_sub_errors[sub_id].extend(subnet_errors)
                remaining_by_sub[sub_id] -= 1
                if remaining_by_sub[sub_id] <= 0:
                    on_subscription_complete(
                        sub_id,
                        per_sub_findings.pop(sub_id),
                        per_sub_offending.pop(sub_id),
                        per_sub_errors.pop(sub_id),
                    )

    cache.flush()
    return findings, offending, errors


def _evaluate_one_subnet(
    net_client: NetworkManagementClient,
    subnet: SubnetRecord,
    account: str,
    compliant_ips: set,
    compliant_types: set,
    config: BaselineConfig,
    cache: RunCache,
    sample_nics_per_subnet: int,
    evaluate_all_nics: bool,
    insufficient_role: bool = False,
) -> tuple[SubnetFinding, list[OffendingRoute], list[ErrorRecord]]:
    finding = SubnetFinding(
        subscription_id=subnet.subscription_id,
        subscription_name=subnet.subscription_name,
        resource_group=subnet.resource_group,
        vnet_name=subnet.vnet_name,
        organization=subnet.organization,
        environment=subnet.environment,
        vnet_address_space=subnet.vnet_address_space,
        subnet_name=subnet.subnet_name,
        subnet_id=subnet.subnet_id,
        address_prefix=subnet.address_prefix,
        peered_to_hub=subnet.peered_to_hub,
        peering_state=subnet.peering_state,
        hub_connection_name=subnet.hub_connection_name,
        associated_route_table=subnet.route_table_id,
        associated_nsg=subnet.nsg_id,
        delegations=subnet.delegations,
        service_endpoints=subnet.service_endpoints,
        has_private_endpoints=bool(subnet.private_endpoint_ids),
        nic_ids=subnet.nic_ids,
        evaluated_by_account=account,
    )
    errors: list[ErrorRecord] = []
    offending: list[OffendingRoute] = []

    # --- EXPECTED_BYPASS: infra subnets, by name or explicit manual override
    if subnet.is_expected_bypass_by_name or subnet.subnet_id in config.manual_expected_bypass_subnet_ids:
        finding.verdict = Verdict.EXPECTED_BYPASS
        finding.evidence = Evidence.NONE
        finding.notes = "Infrastructure subnet - bypass by design."
        return finding, offending, errors

    # --- NOT_EVALUATED: no NIC to read effective routes from
    if not subnet.nic_ids:
        finding.verdict = Verdict.NOT_EVALUATED
        finding.evidence = Evidence.INFERRED
        finding.notes = _infer_notes(subnet)
        return finding, offending, errors

    # --- NOT_EVALUATED / INSUFFICIENT_ROLE: pre-flight capability probe
    # already confirmed this subscription's assigned account (`account`)
    # cannot read effective routes (see capability_probe.py). Skip the
    # guaranteed-403 call entirely rather than repeating it per subnet.
    if insufficient_role:
        finding.verdict = Verdict.NOT_EVALUATED
        finding.evidence = Evidence.INFERRED
        finding.notes = (
            f"INSUFFICIENT_ROLE: pre-flight capability probe determined account "
            f"'{account}' cannot read effective routes in this subscription (see "
            "Capability_Matrix sheet). Effective-route call skipped to avoid burning "
            "the scan on a guaranteed 403; grant Contributor (or a custom role with "
            "Microsoft.Network/networkInterfaces/effectiveRouteTable/action) and re-run."
        )
        return finding, offending, errors

    nic_ids_to_sample = subnet.nic_ids if evaluate_all_nics else subnet.nic_ids[:max(1, sample_nics_per_subnet)]

    any_success = False
    for nic_id in nic_ids_to_sample:
        cached = cache.get(nic_id)
        if cached is not None:
            route_entries = cached
        else:
            try:
                route_entries = _get_effective_routes(net_client, nic_id)
                cache.set(nic_id, route_entries)
            except HttpResponseError as exc:
                status = getattr(exc, "status_code", None)
                reason = getattr(exc, "message", None) or str(exc)
                errors.append(ErrorRecord(scope=nic_id, operation="begin_get_effective_route_table", reason=reason, status_code=status))
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append(ErrorRecord(scope=nic_id, operation="begin_get_effective_route_table", reason=str(exc)))
                continue

        any_success = True
        default_route, override_routes = _classify_routes(route_entries)

        if default_route:
            finding.default_route_next_hop_type = default_route["next_hop_type"]
            finding.default_route_next_hop_ip = default_route.get("next_hop_ip")
            finding.default_route_source = default_route.get("source")

        compliant = _is_compliant_next_hop(default_route, compliant_ips, compliant_types)

        if not compliant and default_route:
            offending.append(OffendingRoute(
                subscription_id=subnet.subscription_id,
                subscription_name=subnet.subscription_name,
                organization=subnet.organization,
                environment=subnet.environment,
                resource_group=subnet.resource_group,
                vnet_name=subnet.vnet_name,
                subnet_name=subnet.subnet_name,
                address_prefix=default_route["address_prefix"],
                next_hop_type=default_route["next_hop_type"],
                next_hop_ip=default_route.get("next_hop_ip"),
                route_source=default_route.get("source", ""),
                route_table_name=_name_from_id(subnet.route_table_id) if subnet.route_table_id else None,
                route_name=default_route.get("route_name"),
                nic_id=nic_id,
            ))

        for route in override_routes:
            if _is_compliant_next_hop(route, compliant_ips, compliant_types):
                continue
            offending.append(OffendingRoute(
                subscription_id=subnet.subscription_id,
                subscription_name=subnet.subscription_name,
                organization=subnet.organization,
                environment=subnet.environment,
                resource_group=subnet.resource_group,
                vnet_name=subnet.vnet_name,
                subnet_name=subnet.subnet_name,
                address_prefix=route["address_prefix"],
                next_hop_type=route["next_hop_type"],
                next_hop_ip=route.get("next_hop_ip"),
                route_source=route.get("source", ""),
                route_table_name=_name_from_id(subnet.route_table_id) if subnet.route_table_id else None,
                route_name=route.get("route_name"),
                nic_id=nic_id,
            ))

        finding.offending_routes = offending
        if compliant:
            finding.verdict = Verdict.COMPLIANT
            finding.evidence = Evidence.MEASURED
            finding.notes = f"Measured from NIC {nic_id}."
        else:
            finding.verdict = Verdict.NON_COMPLIANT
            finding.evidence = Evidence.MEASURED
            finding.notes = f"Measured from NIC {nic_id}; {len(offending)} offending route(s)."
        break  # first successfully-sampled NIC decides the verdict

    if not any_success:
        finding.verdict = Verdict.ERROR
        finding.evidence = Evidence.NONE
        finding.notes = "All effective-route calls failed; see Errors sheet."

    return finding, offending, errors


def _get_effective_routes(net_client: NetworkManagementClient, nic_id: str) -> list[dict]:
    rg = _rg_from_id(nic_id)
    nic_name = _name_from_id(nic_id)

    def _call():
        poller = net_client.network_interfaces.begin_get_effective_route_table(rg, nic_name)
        return poller.result()

    result = call_with_retry(_call, context=f"begin_get_effective_route_table [{nic_id}]")
    entries = []
    for route in (getattr(result, "value", None) or []):
        entries.append({
            "address_prefixes": list(route.address_prefix or []),
            "next_hop_type": route.next_hop_type,
            # The field is named next_hop_ip_address (singular) but is
            # actually a list[str], matching the real ARM API shape.
            "next_hop_ips": list(route.next_hop_ip_address or []),
            "source": route.source,
            "state": getattr(route, "state", None),
            "route_name": getattr(route, "name", None),
        })
    return entries


def _classify_routes(route_entries: list[dict]) -> tuple[Optional[dict], list[dict]]:
    """Return (default_route, override_routes). default_route is the entry
    matching 0.0.0.0/0. override_routes are User-sourced entries whose
    prefix is NOT the default route but could still capture egress traffic
    for parts of the address space (e.g. a UDR covering a large supernet
    that shadows the default route for most destinations) -- these are
    reported for visibility even though the primary verdict is driven by
    the default route.
    """
    default_route = None
    overrides = []
    for entry in route_entries:
        for prefix in entry["address_prefixes"]:
            flat = {
                "address_prefix": prefix,
                "next_hop_type": entry["next_hop_type"],
                "next_hop_ip": entry["next_hop_ips"][0] if entry["next_hop_ips"] else None,
                "source": entry["source"],
                "route_name": entry.get("route_name"),
            }
            if prefix in DEFAULT_ROUTE_PREFIXES:
                if default_route is None or entry["source"] == "User":
                    default_route = flat
            elif entry["source"] == "User" and _is_broad_prefix(prefix):
                overrides.append(flat)
    return default_route, overrides


def _is_broad_prefix(prefix: str) -> bool:
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        return net.prefixlen <= 8  # a /8 or broader user route is worth flagging alongside 0.0.0.0/0
    except ValueError:
        return False


def _is_compliant_next_hop(route: Optional[dict], compliant_ips: set, compliant_types: set) -> bool:
    if not route:
        return False
    if route.get("next_hop_ip") and route["next_hop_ip"] in compliant_ips:
        return True
    if route.get("next_hop_type") in compliant_types:
        return True
    return False


def _infer_notes(subnet: SubnetRecord) -> str:
    signals = []
    if subnet.route_table_id:
        signals.append(f"has UDR '{_name_from_id(subnet.route_table_id)}'")
    if subnet.peered_to_hub:
        state = subnet.peering_state or "unknown state"
        signals.append(f"VNet peered to hub ({state})")
    if subnet.hub_connection_name:
        signals.append(f"hub connection '{subnet.hub_connection_name}' present")
    if subnet.private_endpoint_ids:
        signals.append(f"{len(subnet.private_endpoint_ids)} private endpoint(s) - likely no egress")
    if subnet.delegations:
        signals.append(f"delegated to {', '.join(subnet.delegations)} - service-injected, no user NIC")
    if not signals:
        signals.append("empty subnet, no NIC/UDR/peering signal available")
    return "INFERRED (no NIC present): " + "; ".join(signals)


def _error_finding(subnet: SubnetRecord, reason: str, account: str = "") -> SubnetFinding:
    return SubnetFinding(
        subscription_id=subnet.subscription_id,
        subscription_name=subnet.subscription_name,
        organization=subnet.organization,
        environment=subnet.environment,
        resource_group=subnet.resource_group,
        vnet_name=subnet.vnet_name,
        subnet_name=subnet.subnet_name,
        subnet_id=subnet.subnet_id,
        address_prefix=subnet.address_prefix,
        verdict=Verdict.ERROR,
        evidence=Evidence.NONE,
        notes=reason,
        evaluated_by_account=account,
    )

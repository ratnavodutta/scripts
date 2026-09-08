"""Pre-flight capability probe: before burning the full scan on a
subscription, test -- with its assigned credential -- whether
Microsoft.Network/networkInterfaces/effectiveRouteTable/action is actually
permitted, using ONE cheap call against a single NIC.

Reader is EXPECTED to fail this probe: Reader grants `*/read`, and
effectiveRouteTable is an action, not a read. Only Contributor or a custom
role explicitly carrying that action passes. Subscriptions classified
CANNOT_READ_ROUTES have their real effective-route calls skipped for every
remaining subnet (marked NOT_EVALUATED / INSUFFICIENT_ROLE instead in
compliance.py) rather than repeating the same guaranteed 403 hundreds of
times.
"""
from __future__ import annotations

import json
import subprocess

from azure.core.exceptions import HttpResponseError
from azure.mgmt.network import NetworkManagementClient

from .baseline import _name_from_id, _rg_from_id
from .credential_router import CredentialRouter, CredentialRoutingError
from .logging_config import get_logger
from .models import CapabilityResult, CapabilityStatus, ErrorRecord
from .retry import call_with_retry

log = get_logger("capability_probe")


def probe_subscriptions(
    router: CredentialRouter,
    subscriptions: list,
    subnets: list,
    errors: list,
) -> list:
    """One probe per subscription in `subscriptions`, using the first
    available NIC among that subscription's subnets (from the Resource
    Graph sweep already run in Phase 3). A subscription with no NICs
    anywhere gets CapabilityStatus.UNKNOWN -- there is nothing to probe,
    and nothing to skip either (every subnet in it is necessarily
    NOT_EVALUATED for lack-of-NIC reasons already, independent of RBAC).
    """
    nic_by_sub: dict = {}
    for s in subnets:
        if s.nic_ids and s.subscription_id not in nic_by_sub:
            nic_by_sub[s.subscription_id] = s.nic_ids[0]

    results: list = []
    for sub in subscriptions:
        sub_id = sub.subscription_id
        nic_id = nic_by_sub.get(sub_id)

        try:
            credential, account = router.resolve(sub_id)
        except CredentialRoutingError as exc:
            errors.append(ErrorRecord(scope=sub_id, operation="capability_probe.resolve_credential", reason=str(exc)))
            results.append(CapabilityResult(
                subscription_id=sub_id, subscription_name=sub.display_name, account="UNKNOWN",
                role="UNKNOWN", status=CapabilityStatus.UNKNOWN, reason=f"credential routing failed: {exc}",
            ))
            continue

        role = _best_effort_role(account, sub_id)

        if nic_id is None:
            results.append(CapabilityResult(
                subscription_id=sub_id, subscription_name=sub.display_name, account=account, role=role,
                status=CapabilityStatus.UNKNOWN, reason="No NIC found anywhere in this subscription to probe with.",
            ))
            continue

        net_client = NetworkManagementClient(credential, sub_id)
        try:
            _probe_one_nic(net_client, nic_id)
            results.append(CapabilityResult(
                subscription_id=sub_id, subscription_name=sub.display_name, account=account, role=role,
                status=CapabilityStatus.CAN_READ_ROUTES, reason="Probe call succeeded.", probed_nic_id=nic_id,
            ))
        except HttpResponseError as exc:
            status_code = getattr(exc, "status_code", None)
            reason = getattr(exc, "message", None) or str(exc)
            results.append(CapabilityResult(
                subscription_id=sub_id, subscription_name=sub.display_name, account=account, role=role,
                status=CapabilityStatus.CANNOT_READ_ROUTES,
                reason=f"HTTP {status_code}: {reason}", probed_nic_id=nic_id,
            ))
        except Exception as exc:  # noqa: BLE001 - any failure means "can't confirm capability"
            results.append(CapabilityResult(
                subscription_id=sub_id, subscription_name=sub.display_name, account=account, role=role,
                status=CapabilityStatus.CANNOT_READ_ROUTES, reason=str(exc), probed_nic_id=nic_id,
            ))

    return results


def _probe_one_nic(net_client: NetworkManagementClient, nic_id: str) -> None:
    rg = _rg_from_id(nic_id)
    name = _name_from_id(nic_id)

    def _call():
        poller = net_client.network_interfaces.begin_get_effective_route_table(rg, name)
        return poller.result()

    call_with_retry(_call, context=f"capability_probe [{nic_id}]", max_attempts=2)


def _best_effort_role(account: str, subscription_id: str, timeout_seconds: int = 15) -> str:
    """Best-effort RBAC role lookup via `az role assignment list`. Never
    raises -- returns 'UNKNOWN' on any failure (az missing, timeout, no
    permission to list role assignments, ambiguous account string, etc.).
    Purely informational for the Capability_Matrix sheet; never used to
    make a scan decision (the actual probe call above is authoritative).
    """
    try:
        proc = subprocess.run(
            [
                "az", "role", "assignment", "list",
                "--assignee", account,
                "--subscription", subscription_id,
                "--query", "[].roleDefinitionName",
                "-o", "json",
            ],
            capture_output=True, text=True, timeout=timeout_seconds,
        )
        if proc.returncode != 0:
            return "UNKNOWN"
        roles = json.loads(proc.stdout)
        roles = sorted({r for r in roles if r})
        return "+".join(roles) if roles else "UNKNOWN (no assignment found)"
    except Exception:  # noqa: BLE001 - best-effort only
        return "UNKNOWN"


def print_capability_summary(results: list) -> None:
    can = [r for r in results if r.status == CapabilityStatus.CAN_READ_ROUTES]
    cannot = [r for r in results if r.status == CapabilityStatus.CANNOT_READ_ROUTES]
    unknown = [r for r in results if r.status == CapabilityStatus.UNKNOWN]
    print("\n=== Pre-flight Capability Probe (effectiveRouteTable/action) ===")
    print(f"  CAN_READ_ROUTES:    {len(can)}")
    print(f"  CANNOT_READ_ROUTES: {len(cannot)}  (full scan skipped for these -- see Capability_Matrix sheet)")
    print(f"  UNKNOWN:            {len(unknown)}  (no NIC available to probe with)")
    if cannot:
        print("\n  Subscriptions failing the probe (Reader-only is expected to fail):")
        for r in cannot:
            print(f"    {r.subscription_name} ({r.subscription_id}) - account={r.account} role={r.role}")

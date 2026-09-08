"""Per-subscription credential routing.

The problem this fixes: two accounts hold different RBAC scopes (e.g. an
"-adm" account with Contributor on one subscription and a normal account
with Contributor/Reader elsewhere). Running the whole script once per
account and merging results by hand is exactly how a subscription's earlier
MEASURED results get silently overwritten by a later run's all-403 results
for that same subscription (see state.py's merge-forward logic, which exists
because of that failure mode). The real fix is to never separate the runs:
resolve the correct credential PER SUBSCRIPTION inside one run.

Two modes:
  - "single": one already-validated credential (the pre-existing behavior,
    used when --credential-map is not supplied) is used for every
    subscription. `account_for`/`resolve` are trivial pass-throughs.
  - "routed": a JSON credential map (see config/credential_map.example.json)
    assigns specific Azure CLI accounts to specific subscriptions (a
    "default" account plus per-subscription overrides). Both accounts must
    already be signed in via separate `az login` calls -- Azure CLI keeps
    every previously signed-in account in its local token cache; a second
    `az login` does not remove the first, it only changes which one is
    reported as "active" by `az account show`. This module never relies on
    "active" -- it always asks explicitly for a token scoped to a specific
    subscription (`az account get-access-token --subscription <id>`, via
    `AzureCliCredential(subscription=<id>)`), which Azure CLI resolves
    against WHICHEVER signed-in account actually has that subscription,
    regardless of which one is "active".

Hard requirement (no silent fallback): before scanning anything, both
accounts referenced in the credential map must be verified as signed in
(`preflight()`), and every subscription's resolved account is cross-checked
against Azure CLI's own record of which account can see it (`resolve()`).
Any mismatch or missing account raises CredentialRoutingError -- the caller
is expected to print it and abort the run, never to substitute a different
credential.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .logging_config import get_logger

log = get_logger("credential_router")


class CredentialRoutingError(RuntimeError):
    pass


@dataclass
class CredentialMap:
    default_account: str
    overrides: dict  # lower-cased subscription_id -> account UPN

    @classmethod
    def load(cls, path: Path) -> "CredentialMap":
        if not path.exists():
            raise CredentialRoutingError(
                f"--credential-map file not found: {path}. See "
                "config/credential_map.example.json for the expected format."
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CredentialRoutingError(f"--credential-map {path} is not valid JSON: {exc}") from exc

        default_account = data.get("default")
        if not default_account:
            raise CredentialRoutingError(
                f"--credential-map {path}: missing required top-level 'default' account (a UPN)."
            )
        raw_overrides = data.get("overrides") or {}
        if not isinstance(raw_overrides, dict):
            raise CredentialRoutingError(f"--credential-map {path}: 'overrides' must be an object.")
        overrides = {str(k).strip().lower(): str(v).strip() for k, v in raw_overrides.items()}
        return cls(default_account=str(default_account).strip(), overrides=overrides)

    def account_for(self, subscription_id: str) -> str:
        return self.overrides.get(subscription_id.lower(), self.default_account)

    def all_accounts(self) -> set:
        return {self.default_account} | set(self.overrides.values())


@dataclass
class AzureCliAccountInfo:
    subscription_id: str  # lower-cased GUID
    subscription_name: str
    account: str  # signed-in user UPN (or SPN app ID for service principals)
    tenant_id: str
    is_default: bool = False


def list_az_cli_accounts(timeout_seconds: int = 30) -> list:
    """Shell out to `az account list --all -o json` -- this is the only
    reliable, documented way to see EVERY subscription visible to EVERY
    currently signed-in account (not just whichever one az considers
    "active"). Raises CredentialRoutingError on any failure (az missing,
    not logged in, timeout, bad JSON) -- there is no safe fallback here.
    """
    try:
        proc = subprocess.run(
            ["az", "account", "list", "--all", "-o", "json"],
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise CredentialRoutingError(
            "Azure CLI ('az') was not found on PATH. --credential-map requires the "
            "Azure CLI to be installed and both accounts signed in via `az login`."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise CredentialRoutingError(f"`az account list` timed out after {timeout_seconds}s.") from exc

    if proc.returncode != 0:
        raise CredentialRoutingError(
            f"`az account list` failed (exit {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise CredentialRoutingError(f"Could not parse `az account list` output as JSON: {exc}") from exc

    accounts = []
    for entry in raw:
        user = entry.get("user") or {}
        accounts.append(AzureCliAccountInfo(
            subscription_id=(entry.get("id") or "").lower(),
            subscription_name=entry.get("name") or "",
            account=user.get("name") or "",
            tenant_id=entry.get("tenantId") or "",
            is_default=bool(entry.get("isDefault")),
        ))
    return accounts


class CredentialRouter:
    """Uniform per-subscription credential resolution for both modes."""

    def __init__(
        self,
        *,
        single_credential=None,
        single_account_label: str = "default",
        credential_map: Optional[CredentialMap] = None,
    ):
        self._mode = "routed" if credential_map is not None else "single"
        self._single_credential = single_credential
        self._single_account_label = single_account_label
        self._map = credential_map
        self._az_accounts: list = []
        self._az_accounts_by_sub: dict = {}
        self._credentials_by_account: dict = {}  # account.lower() -> AzureCliCredential

    @property
    def mode(self) -> str:
        return self._mode

    def preflight(self) -> list:
        """Routed mode only: verify every account referenced in the
        credential map is currently signed in to Azure CLI. Raises
        CredentialRoutingError (never falls back) if any is missing.
        Returns the full `az account list` output for informational
        printing. No-op (returns []) in single mode.
        """
        if self._mode == "single":
            return []
        self._az_accounts = list_az_cli_accounts()
        self._az_accounts_by_sub = {a.subscription_id: a for a in self._az_accounts}
        seen_accounts = {a.account.lower() for a in self._az_accounts if a.account}
        required = self._map.all_accounts()
        missing = sorted(a for a in required if a.lower() not in seen_accounts)
        if missing:
            raise CredentialRoutingError(
                "The following account(s) referenced in --credential-map are not currently "
                "signed in to Azure CLI: " + ", ".join(missing) + ". Run `az login` once per "
                "account -- each `az login` adds to the CLI's signed-in account list rather "
                "than replacing the previous one. Aborting: this script will not silently "
                "scan a subscription with the wrong identity."
            )
        log.info(
            "Credential routing preflight OK: %d account(s) required, all signed in "
            "(%d subscription(s) visible across az CLI's account list).",
            len(required), len(self._az_accounts),
        )
        return self._az_accounts

    def cached_az_accounts(self) -> list:
        return self._az_accounts

    def account_for(self, subscription_id: str) -> str:
        if self._mode == "single":
            return self._single_account_label
        return self._map.account_for(subscription_id)

    def any_credential(self):
        """Single mode only: the one credential backing every subscription."""
        if self._mode != "single":
            raise CredentialRoutingError("any_credential() is only valid in single-credential mode.")
        return self._single_credential

    def resolve(self, subscription_id: str) -> tuple:
        """Return (credential, account_label) for this subscription.

        Routed mode cross-checks the credential map's assignment against
        Azure CLI's OWN record of which signed-in account can see this
        subscription. On any mismatch or absence, raises
        CredentialRoutingError rather than silently using a different
        account -- this is the fix for the original bug (a fallback
        overwriting good data from a different account's earlier run).
        """
        if self._mode == "single":
            return self._single_credential, self._single_account_label

        expected_account = self._map.account_for(subscription_id)
        az_info = self._az_accounts_by_sub.get(subscription_id.lower())
        if az_info is None:
            raise CredentialRoutingError(
                f"Subscription {subscription_id} is assigned to '{expected_account}' in "
                "--credential-map, but it is not visible to ANY Azure-CLI-signed-in account "
                "(checked via `az account list --all`). Refusing to scan it under a "
                "different/guessed identity."
            )
        if az_info.account.lower() != expected_account.lower():
            raise CredentialRoutingError(
                f"Subscription {subscription_id} is assigned to '{expected_account}' in "
                f"--credential-map, but Azure CLI resolves it to account '{az_info.account}' "
                "instead. Refusing to silently use the wrong identity -- fix the credential "
                "map (or verify the account's RBAC) and retry."
            )

        cred = self._credentials_by_account.get(expected_account.lower())
        if cred is None:
            from azure.identity import AzureCliCredential
            # Pinning via `subscription=` forces az CLI to resolve the token
            # from WHICHEVER signed-in account owns that subscription (i.e.
            # the one we just verified above), rather than whichever account
            # az currently considers "active". The resulting ARM bearer
            # token is valid for every subscription that identity can see in
            # its tenant, not just this one -- so one credential per account
            # is reused for every subscription assigned to that account.
            cred = AzureCliCredential(subscription=subscription_id, tenant_id=az_info.tenant_id or None)
            self._credentials_by_account[expected_account.lower()] = cred
        return cred, expected_account

    def all_expected_accounts(self) -> set:
        if self._mode == "single":
            return {self._single_account_label}
        return self._map.all_accounts()


def print_credential_routing_table(router: CredentialRouter, rows: list) -> None:
    """rows: list of (subscription_id, subscription_name, account) already
    resolved by the caller. Printed unconditionally, in both modes -- per
    the requirement that a verdict is not interpretable without knowing
    which identity produced it.
    """
    print("\n=== Credential Routing (mode: %s) ===" % router.mode)
    if router.mode == "single":
        accounts = router.all_expected_accounts()
        label = next(iter(accounts)) if accounts else "default"
        print(f"  Single credential for all {len(rows)} subscription(s): {label}")
        return
    print(f"  {len(rows)} subscription(s) resolved against --credential-map:")
    for sub_id, name, account in rows:
        print(f"    {name:<40.40} {sub_id}  ->  {account}")

"""Credential acquisition and fail-fast validation.

Uses DefaultAzureCredential so the same code path works with:
  - `az login` (AzureCliCredential, picked up automatically) for local runs
  - a system/user-assigned managed identity in an Azure Automation/Container
    Instance/VM context
  - a service principal via AZURE_CLIENT_ID / AZURE_CLIENT_SECRET /
    AZURE_TENANT_ID environment variables, in CI

We deliberately do NOT catch and swallow credential errors here: per the
requirement, missing/invalid credentials must fail fast with an actionable
message rather than let the run proceed and silently return partial (empty)
results.
"""
from __future__ import annotations

import base64
import json
from typing import Optional

from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient

from .logging_config import get_logger

log = get_logger("auth")


class AuthenticationFailure(RuntimeError):
    pass


def get_credential(tenant_id: Optional[str] = None) -> DefaultAzureCredential:
    """Build a DefaultAzureCredential, optionally pinned to a tenant, and
    prove it actually works by making one cheap call (list subscriptions,
    take the first page). This turns "wrong tenant / no az login / expired
    token" into a clear error at startup instead of 45 minutes into a scan.
    """
    kwargs = {}
    if tenant_id:
        kwargs["interactive_browser_tenant_id"] = tenant_id
        kwargs["visual_studio_code_tenant_id"] = tenant_id
        kwargs["shared_cache_tenant_id"] = tenant_id

    credential = DefaultAzureCredential(**kwargs)

    try:
        sub_client = SubscriptionClient(credential)
        first = next(iter(sub_client.subscriptions.list()), None)
    except ClientAuthenticationError as exc:
        raise AuthenticationFailure(
            "Could not authenticate to Azure. Run 'az login' (and 'az account "
            "set --subscription <id>' if needed) for local use, or verify "
            "AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID (or the "
            "managed identity assignment) in CI. "
            f"Underlying error: {exc}"
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise AuthenticationFailure(
            f"Unexpected error validating Azure credentials: {exc}"
        ) from exc

    if first is None:
        raise AuthenticationFailure(
            "Authenticated successfully but the credential cannot see ANY "
            "subscriptions. This usually means the signed-in identity has no "
            "role assignment (not even Reader) at any scope in this tenant. "
            "Grant at least Reader (or the custom asset-configuration-reader "
            "role) at the management-group or subscription scope and retry."
        )

    log.info("Credential validated (tenant=%s).", tenant_id or "default")
    return credential


def describe_identity(credential) -> dict:
    """Best-effort description of the signed-in identity for run_metadata
    (report.py) -- upn/app_id/tenant_id decoded directly from the ARM access
    token's claims, WITHOUT verifying its signature (we already trust it;
    this is descriptive/logging only, never used for an authorization
    decision). Avoids adding a JWT-library dependency for one read.
    Never raises -- returns whatever it could determine, "unknown" for the
    rest, on any failure.
    """
    result = {"upn": None, "app_id": None, "tenant_id": None}
    try:
        token = credential.get_token("https://management.azure.com/.default").token
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        result["upn"] = claims.get("upn") or claims.get("unique_name") or claims.get("preferred_username")
        result["app_id"] = claims.get("appid") or claims.get("azp")
        result["tenant_id"] = claims.get("tid")
    except Exception as exc:  # noqa: BLE001 - purely descriptive, never fatal
        log.debug("Could not decode identity claims from access token: %s", exc)
    return result

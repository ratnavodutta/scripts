"""Exponential-backoff retry helper for ARM throttling (HTTP 429) and
transient 5xx errors. Wraps any zero-arg callable.

Azure Resource Manager returns 429 with a `Retry-After` header (seconds) when
a subscription's request budget is exhausted; several management SDKs raise
this as an azure.core.exceptions.HttpResponseError with .status_code == 429
and .response.headers["Retry-After"] set. We honor that header when present
and fall back to exponential backoff with jitter otherwise.
"""
from __future__ import annotations

import random
import time
from typing import Callable, TypeVar

from azure.core.exceptions import HttpResponseError, ServiceRequestError

from .logging_config import get_logger

log = get_logger("retry")

T = TypeVar("T")

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class PermissionDenied(Exception):
    """Raised (by callers, not this module) to represent a 403 that should be
    recorded as a finding rather than retried or fatal."""

    def __init__(self, scope: str, operation: str, reason: str):
        self.scope = scope
        self.operation = operation
        self.reason = reason
        super().__init__(f"{operation} on {scope}: {reason}")


def call_with_retry(
    fn: Callable[[], T],
    *,
    max_attempts: int = 6,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    context: str = "",
) -> T:
    """Call fn(), retrying on throttling / transient errors with exponential
    backoff + jitter. Raises the last exception if attempts are exhausted.
    A 403 is never retried -- it is re-raised immediately so the caller can
    convert it into a recorded finding.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except HttpResponseError as exc:
            status = getattr(exc, "status_code", None)
            if status == 403:
                raise
            if status in RETRYABLE_STATUS_CODES and attempt < max_attempts:
                delay = _delay_for(exc, attempt, base_delay, max_delay)
                log.warning(
                    "Retryable error (%s) on %s, attempt %d/%d, sleeping %.1fs",
                    status, context, attempt, max_attempts, delay,
                )
                time.sleep(delay)
                continue
            raise
        except ServiceRequestError:
            if attempt < max_attempts:
                delay = min(max_delay, base_delay * (2 ** (attempt - 1))) + random.uniform(0, 1)
                log.warning(
                    "Network/service error on %s, attempt %d/%d, sleeping %.1fs",
                    context, attempt, max_attempts, delay,
                )
                time.sleep(delay)
                continue
            raise


def _delay_for(exc: HttpResponseError, attempt: int, base_delay: float, max_delay: float) -> float:
    retry_after = None
    try:
        headers = exc.response.headers if exc.response is not None else {}
        retry_after = headers.get("Retry-After") or headers.get("retry-after")
    except Exception:  # noqa: BLE001 - defensive, header access is best-effort
        retry_after = None
    if retry_after:
        try:
            return min(max_delay, float(retry_after))
        except ValueError:
            pass
    return min(max_delay, base_delay * (2 ** (attempt - 1))) + random.uniform(0, base_delay)

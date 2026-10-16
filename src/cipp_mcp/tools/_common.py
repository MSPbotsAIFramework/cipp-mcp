# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Shared argument types, helpers and the error-handling wrapper."""

import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import CippClient, CippError

logger = logging.getLogger("cipp_mcp.tools")

ClientFactory = Callable[[], CippClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
READ_ONLY_RUN = ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=True)
WRITES = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
WRITES_IDEMPOTENT = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True)
DESTRUCTIVE_ONCE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured",
    "CIPP credentials are missing for this request (X-Base-Url plus X-Api-Key or OAuth headers).",
    False,
)

TenantFilter = Annotated[
    str, Field(description="Tenant default domain (e.g. example.onmicrosoft.com) or tenant id, from cipp_list_tenants.")
]
UserId = Annotated[str, Field(description="User object id or UPN.")]
Upn = Annotated[str, Field(description="Mailbox user principal name (or object id).")]

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_FAILURE = re.compile(r"fail|error|could not|unable|not permitted|already exists|does not exist", re.IGNORECASE)


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


def label_value(value: str) -> dict[str, str]:
    """CIPP's select shape; the backend reads .value and ignores bare strings."""
    return {"label": value, "value": value}


def is_all_tenants(tenant: str) -> bool:
    return tenant.strip().lower() == "alltenants"


def rows(payload: Any) -> list:
    """List rows from a bare array or a {Results: [...]} wrapper."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("Results"), list):
        return payload["Results"]
    return []


def interpret_results(payload: Any) -> tuple[list[str], list[str]]:
    """CIPP often answers HTTP 200 with failures described in Results."""
    value = payload.get("Results") if isinstance(payload, dict) else payload
    if value is None:
        items: list = []
    elif isinstance(value, list):
        items = value
    else:
        items = [value]
    texts = [v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str) for v in items]
    return texts, [t for t in texts if _FAILURE.search(t)]


def to_unix_seconds(value: str, field: str) -> int:
    text = str(value).strip()
    if re.fullmatch(r"\d+", text):
        return int(text)
    try:
        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
    except ValueError as e:
        raise ValueError(
            f'{field} must be an ISO 8601 datetime (e.g. "2026-06-01T09:00:00Z") or Unix epoch seconds; got "{value}".'
        ) from e


async def resolve_user(client: CippClient, tenant: str, user: str, reason: str) -> dict[str, str]:
    """Look a user up by object id or UPN; returns id, userPrincipalName, username and domain."""
    text = user.strip()
    if _GUID.match(text):
        found = rows(await client.get("ListUsers", {"tenantFilter": tenant, "UserID": text}))[:1]
    else:
        escaped = text.replace("'", "''")
        candidates = rows(
            await client.get("ListUsers", {"tenantFilter": tenant, "graphFilter": f"userPrincipalName eq '{escaped}'"})
        )
        found = [r for r in candidates if isinstance(r, dict) and str(r.get("userPrincipalName", "")).lower() == text.lower()][:1]
    row = found[0] if found else {}
    upn = row.get("userPrincipalName") if isinstance(row, dict) else None
    uid = row.get("id") if isinstance(row, dict) else None
    if not (isinstance(upn, str) and "@" in upn and isinstance(uid, str)):
        raise ValueError(f'Could not resolve user "{user}" to a current UPN in tenant {tenant}. {reason}')
    local, _, domain = upn.rpartition("@")
    return {"id": uid, "userPrincipalName": upn, "username": local, "domain": domain}


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[CippClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        result = await action(client)
    except CippError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if result is None:
        result = {"result": None, "note": "CIPP returned an empty response."}
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)

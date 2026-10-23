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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import CippClient, CippCredentials
from .config import Settings

HEADER_BASE_URL = "X-Base-Url"
HEADER_API_KEY = "X-Api-Key"
HEADER_TENANT_ID = "X-Tenant-Id"
HEADER_CLIENT_ID = "X-Client-Id"
HEADER_CLIENT_SECRET = "X-Client-Secret"
HEADER_TOKEN_SCOPE = "X-Token-Scope"
HEADER_TOKEN_URL = "X-Token-Url"
HEADER_SCOPE_FALLBACK = "X-Token-Scope-Fallback"

_FALSE = re.compile(r"^(0|false|off|no)$", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"^\$\{.*\}$")
_INVALID_URL = "https://invalid.example.com"

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[CippCredentials | None] = contextvars.ContextVar(
    "cipp_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("cipp_request_id", default="-")

INSTRUCTIONS = (
    "CIPP (CyberDrain Improved Partner Portal) is the MSP console for managing "
    "many Microsoft 365 tenants through GDAP: users and licences, mailboxes, "
    "conditional access, standards (baseline configurations) and alerts. Every "
    "tenant-scoped tool takes tenantFilter = the tenant's default domain (e.g. "
    "example.onmicrosoft.com) or tenant id; get them from cipp_list_tenants. "
    "Some tools accept tenantFilter='AllTenants'.\n"
    "Typical flows:\n"
    "- User lookup: cipp_list_users(searchField, searchValue) -> "
    "cipp_list_user_groups / cipp_list_user_devices / cipp_list_user_signin_logs.\n"
    "- Suspected compromise: cipp_bec_check, cipp_list_user_signin_logs, then on "
    "request cipp_revoke_sessions, cipp_reset_password, cipp_disable_user.\n"
    "- Leaver: cipp_offboard_user with the chosen actions (queued job).\n"
    "- Mail: cipp_list_mailboxes, cipp_list_mailbox_usage (cached sizes), "
    "cipp_get_mailbox_usage (live), cipp_set_out_of_office, "
    "cipp_set_email_forwarding.\n"
    "- Posture: cipp_list_conditional_access_policies, cipp_get_tenant_alignment, "
    "cipp_get_tenant_drift, cipp_list_domain_health, cipp_list_mfa_users, "
    "cipp_get_secure_score, cipp_list_secure_score_controls.\n"
    "Tools that create, edit, disable, reset, offboard, forward, schedule or run "
    "standards change live Microsoft 365 tenants: call them only when the user "
    "explicitly asks, with the exact values given."
)


def get_client_from_context() -> CippClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return CippClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def _https_url(value: str | None) -> str | None:
    if not value:
        return None
    parts = urlsplit(value)
    return value if parts.scheme == "https" and parts.netloc else ""


class GatewayCredentialsMiddleware:
    """Reads the CIPP headers on /mcp requests into the request context.

    Needs X-Base-Url plus either X-Api-Key or X-Tenant-Id + X-Client-Id +
    X-Client-Secret; otherwise 401. A non-https URL does not block the request
    (tools/list must work with any values); tools report it and never call it.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        def header(name: str) -> str | None:
            return _clean(request.headers.get(name))

        base_url = _https_url(header(HEADER_BASE_URL))
        token_url = _https_url(header(HEADER_TOKEN_URL))
        api_key = header(HEADER_API_KEY)
        tenant_id, client_id, client_secret = header(HEADER_TENANT_ID), header(HEADER_CLIENT_ID), header(HEADER_CLIENT_SECRET)

        header_error = None
        if base_url == "" or token_url == "":
            header_error = f"{HEADER_BASE_URL} and {HEADER_TOKEN_URL} must be https URLs"
            # Harmless stand-ins so the client can be built; the client refuses
            # every request while header_error is set.
            base_url = _INVALID_URL if base_url == "" else base_url
            token_url = _INVALID_URL if token_url == "" else token_url
        if not base_url or not (api_key or (tenant_id and client_id and client_secret)):
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Send {HEADER_BASE_URL} plus either {HEADER_API_KEY} or "
                    f"{HEADER_TENANT_ID} + {HEADER_CLIENT_ID} + {HEADER_CLIENT_SECRET}",
                    "required_headers": [HEADER_BASE_URL],
                    "required_one_of": [[HEADER_API_KEY], [HEADER_TENANT_ID, HEADER_CLIENT_ID, HEADER_CLIENT_SECRET]],
                    "optional_headers": [HEADER_TOKEN_SCOPE, HEADER_TOKEN_URL, HEADER_SCOPE_FALLBACK],
                },
                status_code=401,
            )(scope, receive, send)
            return

        fallback = header(HEADER_SCOPE_FALLBACK)
        credentials = CippCredentials(
            base_url=base_url,
            api_key=api_key,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            token_scope=header(HEADER_TOKEN_SCOPE),
            token_url=token_url,
            scope_fallback=not (fallback and _FALSE.match(fallback)),
            header_error=header_error,
        )
        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(credentials)
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = EnvelopeFastMCP(
        name="cipp-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], CippClient | None] = get_client_from_context

    from .tools import core, groups, identity, mailboxes, operations, security, standards, tenants

    for module in (core, tenants, identity, groups, mailboxes, security, standards, operations):
        module.register(mcp, client_factory)

    return mcp

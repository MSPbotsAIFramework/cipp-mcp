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
"""Credential middleware: 401 on missing headers, deferred URL errors, per-request isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from cipp_mcp.__main__ import build_http_app
from cipp_mcp.api_client import CippError
from cipp_mcp.server import (
    GatewayCredentialsMiddleware,
    _credentials_var,
    create_mcp_server,
    get_client_from_context,
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
BASE = {"X-Base-Url": "https://cipp.example.com"}
OAUTH = {"X-Tenant-Id": "partner-tenant-id", "X-Client-Id": "client-id", "X-Client-Secret": "client-secret"}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Api-Key": "key"},
        BASE,
        BASE | {"X-Tenant-Id": "t", "X-Client-Id": "c"},
        BASE | {"X-Api-Key": "${CIPP_API_KEY}"},
    ],
)
def test_missing_credentials_return_401(headers):
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 401
    body = resp.json()
    assert body["required_headers"] == ["X-Base-Url"]
    assert ["X-Tenant-Id", "X-Client-Id", "X-Client-Secret"] in body["required_one_of"]


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Base-Url": "http://cipp.example.com", "X-Api-Key": "key"},
        BASE | OAUTH | {"X-Token-Url": "http://login.example.com/token"},
    ],
)
def test_non_https_urls_are_reported_by_tools(headers):
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cipp_list_tenants", "arguments": {}}}
    with _client() as client:
        resp = client.post("/mcp", json=call, headers=MCP_HEADERS | headers)
    assert resp.status_code == 200
    assert '\\"invalid_argument\\"' in resp.text and "must be https URLs" in resp.text


def test_placeholder_headers_still_list_tools():
    # The admin console refreshes the tool catalog with placeholder header values.
    names = ["X-Base-Url", "X-Api-Key", "X-Tenant-Id", "X-Client-Id", "X-Client-Secret", "X-Token-Scope", "X-Token-Url", "X-Token-Scope-Fallback"]
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | {h: "placeholder" for h in names})
    assert resp.status_code == 200
    assert "cipp_list_tenants" in resp.text


def test_malformed_url_never_reaches_the_network():
    seen = _run_middleware([(b"x-base-url", b"http://cipp.example.com"), (b"x-api-key", b"key")])
    client = seen["client"]
    assert "must be https URLs" in client.header_error
    client._http = object()  # any network use would fail loudly
    with pytest.raises(CippError) as exc:
        asyncio.run(client.get("ListTenants"))
    assert exc.value.status_code == 400


@pytest.mark.parametrize("auth", [{"X-Api-Key": "key"}, OAUTH])
def test_tools_list_over_http(auth):
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | BASE | auth)
    assert resp.status_code == 200
    for name in ("cipp_list_tenants", "cipp_list_users", "cipp_offboard_user", "cipp_add_scheduled_item"):
        assert name in resp.text


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


def test_oauth_headers_reach_request_context_and_are_reset():
    seen = _run_middleware(
        [
            (b"x-base-url", b"https://cipp.example.com/"),
            (b"x-tenant-id", b" partner-tenant-id "),
            (b"x-client-id", b"client-id"),
            (b"x-client-secret", b"client-secret"),
            (b"x-token-scope-fallback", b"false"),
        ]
    )
    creds = seen["credentials"]
    assert (creds.tenant_id, creds.client_id, creds.client_secret) == ("partner-tenant-id", "client-id", "client-secret")
    assert creds.scope_fallback is False
    assert creds.uses_api_key is False
    assert seen["client"].base_url == "https://cipp.example.com"
    assert _credentials_var.get() is None


def test_api_key_mode():
    seen = _run_middleware([(b"x-base-url", b"https://cipp.example.com"), (b"x-api-key", b"key-123")])
    assert seen["credentials"].uses_api_key is True
    assert seen["credentials"].scope_fallback is True


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().api_key
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().api_key))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(key: bytes) -> dict:
        return {"type": "http", "path": "/mcp", "headers": [(b"x-base-url", b"https://cipp.example.com"), (b"x-api-key", key)]}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), receive, send), middleware(scope(b"tenant-b"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_secrets():
    seen = _run_middleware(
        [
            (b"x-base-url", b"https://cipp.example.com"),
            (b"x-tenant-id", b"t"),
            (b"x-client-id", b"c"),
            (b"x-client-secret", b"very-secret-value"),
        ]
    )
    assert "very-secret-value" not in repr(seen["credentials"])

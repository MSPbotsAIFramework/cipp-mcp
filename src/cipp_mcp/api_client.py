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
"""Async client for a CIPP instance's API ({base}/api/{Function})."""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from ._json import error_envelope
from .config import TOKEN_URL_TEMPLATE

logger = logging.getLogger("cipp_mcp.api")

# CIPP actions can be slow; stay below the gateway's 120 s per-call limit.
_TIMEOUT = httpx.Timeout(connect=5.0, read=90.0, write=10.0, pool=5.0)
_MAX_RETRIES = 2
_MAX_BACKOFF_SECONDS = 15.0
_CALL_BUDGET_SECONDS = 100.0

_shared_http_client: httpx.AsyncClient | None = None


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _shared_http_client


_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class CippError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"CIPP API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class CippCredentials:
    base_url: str
    api_key: str | None = None
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    token_scope: str | None = None
    token_url: str | None = None
    scope_fallback: bool = True
    # Set when a header value is malformed: tools then return invalid_argument
    # instead of calling CIPP, while tools/list still works.
    header_error: str | None = None

    @property
    def uses_api_key(self) -> bool:
        return bool(self.api_key)

    def __repr__(self) -> str:  # never leak secrets into logs or tracebacks
        mode = "api_key" if self.uses_api_key else "oauth"
        return f"CippCredentials(base_url={self.base_url!r}, mode={mode!r}, secrets=<redacted>)"


class CippClient:
    """CIPP API wrapper for one caller's credentials.

    OAuth tokens are fetched lazily and kept only on this instance, which lives
    for a single MCP request; nothing is cached across requests.
    """

    def __init__(self, credentials: CippCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self.header_error = credentials.header_error
        self.base_url = credentials.base_url.rstrip("/")
        self._tokens: dict[str, str] = {}

    def _client(self) -> httpx.AsyncClient:
        return self._http or _get_shared_http_client()

    # ---- authentication -------------------------------------------------

    def _scopes(self) -> list[str]:
        """Scopes to try, in order. An explicit scope disables the fallback."""
        creds = self._credentials
        if creds.token_scope:
            return [creds.token_scope]
        primary = f"api://{creds.client_id}/.default"
        return [primary, f"{creds.client_id}/.default"] if creds.scope_fallback else [primary]

    async def _token(self, scope: str) -> str:
        if scope in self._tokens:
            return self._tokens[scope]
        creds = self._credentials
        url = creds.token_url or TOKEN_URL_TEMPLATE.format(tenant=quote(creds.tenant_id or "", safe=""))
        form = {
            "grant_type": "client_credentials",
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scope": scope,
        }
        try:
            resp = await self._client().post(url, data=form, headers={"Accept": "application/json"})
        except httpx.RequestError as e:
            raise CippError(0, f"Network error requesting a CIPP access token: {type(e).__name__}") from e
        logger.info("cipp_api method=POST path=token status=%s", resp.status_code)
        if resp.status_code in (400, 401, 403):
            raise CippError(401, "Entra ID rejected the CIPP API client id / secret (token request failed)")
        if resp.status_code >= 400:
            raise CippError(resp.status_code, f"Token endpoint returned HTTP {resp.status_code}")
        try:
            token = resp.json().get("access_token")
        except (ValueError, AttributeError):
            token = None
        if not token:
            raise CippError(502, "Token response had no access_token")
        self._tokens[scope] = token
        return token

    async def _bearers(self) -> list[str]:
        if self._credentials.uses_api_key:
            return [self._credentials.api_key or ""]
        scopes = self._scopes()
        try:
            return [await self._token(scopes[0])]
        except CippError as e:
            # An app without the api:// identifier URI cannot issue the primary
            # scope; Entra rejects the token request, so try the bare client id.
            if e.status_code != 401 or len(scopes) < 2:
                raise
            return [await self._token(scopes[1])]

    # ---- requests -------------------------------------------------------

    async def get(self, function: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", function, params=params)

    async def post(self, function: str, body: Any = None, params: dict[str, Any] | None = None) -> Any:
        return await self.request("POST", function, params=params, body={} if body is None else body)

    async def request(self, method: str, function: str, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        """Call ``{base}/api/{function}``; retries once with the alternate OAuth scope on 401."""
        if self.header_error:
            # A malformed URL header must never reach the network, token request included.
            raise CippError(400, self.header_error)
        resp = await self._send(method, function, params, body, await self._bearers())
        if (
            resp.status_code == 401
            and not self._credentials.uses_api_key
            and len(self._scopes()) > 1
            and self._scopes()[1] not in self._tokens
        ):
            alternate = await self._token(self._scopes()[1])
            resp = await self._send(method, function, params, body, [alternate])
        return _handle(resp, method, function)

    async def _send(
        self, method: str, function: str, params: dict[str, Any] | None, body: Any, bearers: list[str]
    ) -> httpx.Response:
        url = f"{self.base_url}/api/{function}"
        query = {k: _param_value(v) for k, v in (params or {}).items() if v is not None}
        headers = {"Authorization": f"Bearer {bearers[0]}", "Accept": "application/json"}
        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            resp: httpx.Response | None = None
            error: CippError | None = None
            try:
                resp = await self._client().request(method, url, params=query, json=body, headers=headers)
                status = resp.status_code
            except httpx.TimeoutException:
                status, error = 0, CippError(0, f"Timed out calling CIPP ({method} {function})")
            except httpx.RequestError as e:
                status = 0
                error = CippError(0, f"Network error calling CIPP ({method} {function}): {type(e).__name__}")

            logger.info(
                "cipp_api method=%s path=/api/%s status=%s ms=%d attempt=%d",
                method, function, status, (time.monotonic() - t0) * 1000, attempt,
            )

            # 429 is refused before processing, so any method may retry it; other
            # failures are retried only for reads, so a write never runs twice.
            retryable = status == 429 or (method == "GET" and (status == 0 or status >= 500))
            if retryable and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue
            if error is not None:
                raise error
            assert resp is not None
            return resp


def _param_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _handle(resp: httpx.Response, method: str, function: str) -> Any:
    if resp.status_code >= 400:
        raise CippError(resp.status_code, _error_message(resp, function))
    if not resp.content or not resp.content.strip():
        return None
    try:
        return resp.json()
    except ValueError:
        return {"raw_response": resp.text[:2000]}


def _error_message(resp: httpx.Response, function: str) -> str:
    fallback = f"CIPP returned HTTP {resp.status_code} for {function}"
    try:
        payload = resp.json()
    except ValueError:
        text = resp.text.strip()
        return f"{fallback}: {text[:300]}" if text else fallback
    if isinstance(payload, dict):
        for key in ("Results", "results", "message", "error", "Error"):
            value = payload.get(key)
            if value:
                return f"{fallback}: {str(value)[:500]}"
    return fallback

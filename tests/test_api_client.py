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
"""Authentication, retries and tool request shapes against a mocked CIPP API."""

import dataclasses
import json
from urllib.parse import parse_qs

import httpx
import pytest

from cipp_mcp import api_client
from cipp_mcp.api_client import CippClient, CippCredentials, CippError
from cipp_mcp.server import _credentials_var, create_mcp_server

BASE = "https://cipp.example.com"
API_KEY = CippCredentials(base_url=BASE, api_key="key-123")
OAUTH = CippCredentials(base_url=BASE, tenant_id="partner-tenant-id", client_id="client-id", client_secret="client-secret")
USER_ID = "11111111-2222-3333-4444-555555555555"
USER_ROW = {"id": USER_ID, "userPrincipalName": "jane@example.com"}
GIB = 1024**3


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


class Recorder:
    """Mock transport: replies by the last path segment (CIPP function or 'token')."""

    def __init__(self, routes=None, default=None):
        self.requests: list[httpx.Request] = []
        self.routes = routes or {}
        self.default = default if default is not None else []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        reply = self.routes.get(request.url.path.rsplit("/", 1)[-1], self.default)
        if callable(reply):
            return reply(request)
        return httpx.Response(200, json=reply)

    def calls(self, function: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == f"/api/{function}"]


def body(request: httpx.Request):
    return json.loads(request.content) if request.content else None


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict, credentials: CippCredentials = API_KEY):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(credentials)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


def _client(recorder: Recorder, credentials: CippCredentials) -> CippClient:
    return CippClient(credentials, httpx.AsyncClient(transport=httpx.MockTransport(recorder)))


def _token_route(seen: list[str], reject: frozenset[str] = frozenset()):
    def reply(request: httpx.Request) -> httpx.Response:
        scope = parse_qs(request.content.decode())["scope"][0]
        seen.append(scope)
        if scope in reject:
            return httpx.Response(400, json={"error": "invalid_scope"})
        return httpx.Response(200, json={"access_token": f"token-for-{scope}"})

    return reply


# ---- authentication --------------------------------------------------------


async def test_api_key_is_sent_as_bearer():
    rec = Recorder(default={"ok": True})
    await _client(rec, API_KEY).get("ListTenants", {"AllTenantSelector": True})
    request = rec.requests[0]
    assert request.headers["Authorization"] == "Bearer key-123"
    assert str(request.url) == f"{BASE}/api/ListTenants?AllTenantSelector=true"


async def test_oauth_client_credentials_flow():
    scopes: list[str] = []
    rec = Recorder({"token": _token_route(scopes)}, default={"ok": True})
    await _client(rec, OAUTH).get("ListTenants")
    token_request = rec.requests[0]
    assert str(token_request.url) == "https://login.microsoftonline.com/partner-tenant-id/oauth2/v2.0/token"
    form = parse_qs(token_request.content.decode())
    assert form["grant_type"] == ["client_credentials"]
    assert form["client_id"] == ["client-id"]
    assert scopes == ["api://client-id/.default"]
    assert rec.requests[1].headers["Authorization"] == "Bearer token-for-api://client-id/.default"


async def test_oauth_falls_back_to_bare_client_id_scope_on_api_401():
    scopes: list[str] = []

    def api(request: httpx.Request) -> httpx.Response:
        ok = request.headers["Authorization"] == "Bearer token-for-client-id/.default"
        return httpx.Response(200 if ok else 401, json={"ok": ok})

    rec = Recorder({"token": _token_route(scopes), "ListTenants": api})
    assert await _client(rec, OAUTH).get("ListTenants") == {"ok": True}
    assert scopes == ["api://client-id/.default", "client-id/.default"]


async def test_oauth_falls_back_when_primary_scope_cannot_be_issued():
    scopes: list[str] = []
    rec = Recorder({"token": _token_route(scopes, frozenset({"api://client-id/.default"}))}, default={"ok": True})
    assert await _client(rec, OAUTH).get("ListTenants") == {"ok": True}
    assert scopes == ["api://client-id/.default", "client-id/.default"]
    assert len(rec.calls("ListTenants")) == 1


async def test_explicit_scope_disables_fallback():
    scopes: list[str] = []
    creds = dataclasses.replace(OAUTH, token_scope="api://custom/.default")
    rec = Recorder({"token": _token_route(scopes), "ListTenants": lambda r: httpx.Response(401, json={})})
    with pytest.raises(CippError) as err:
        await _client(rec, creds).get("ListTenants")
    assert err.value.status_code == 401
    assert scopes == ["api://custom/.default"]


async def test_bad_client_secret_is_unauthorized(monkeypatch):
    rec = Recorder({"token": lambda r: httpx.Response(401, json={"error": "invalid_client"})})
    result = await _call(monkeypatch, rec, "cipp_list_tenants", {}, OAUTH)
    assert result["error"]["code"] == "unauthorized"
    assert "client-secret" not in json.dumps(result)


# ---- retries ---------------------------------------------------------------


async def test_get_retries_5xx_then_succeeds():
    replies = iter([httpx.Response(503), httpx.Response(200, json=[1])])
    rec = Recorder({"ListTenants": lambda r: next(replies)})
    assert await _client(rec, API_KEY).get("ListTenants") == [1]
    assert len(rec.requests) == 2


async def test_post_is_not_retried_on_5xx():
    rec = Recorder({"AddUser": lambda r: httpx.Response(500, json={"Results": "server error"})})
    with pytest.raises(CippError) as err:
        await _client(rec, API_KEY).post("AddUser", {"x": 1})
    assert err.value.status_code == 500
    assert "server error" in err.value.message
    assert len(rec.requests) == 1


async def test_post_is_retried_on_429():
    replies = iter([httpx.Response(429, headers={"Retry-After": "1"}), httpx.Response(200, json={"Results": "ok"})])
    rec = Recorder({"AddUser": lambda r: next(replies)})
    assert await _client(rec, API_KEY).post("AddUser", {}) == {"Results": "ok"}
    assert len(rec.requests) == 2


async def test_empty_body_becomes_none():
    rec = Recorder({"PublicPing": lambda r: httpx.Response(200, content=b"")})
    assert await _client(rec, API_KEY).get("PublicPing") is None


# ---- tools -----------------------------------------------------------------


async def test_list_tenants_all_selector(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "cipp_list_tenants", {"allTenants": True})
    assert rec.requests[0].url.params["AllTenantSelector"] == "true"


async def test_reset_password_refuses_a_chosen_password(monkeypatch):
    rec = Recorder()
    args = {"tenantFilter": "example.com", "userId": USER_ID, "newPassword": "x"}
    result = await _call(monkeypatch, rec, "cipp_reset_password", args)
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_offboard_user_sends_resolved_upn_and_selected_flags(monkeypatch):
    rec = Recorder({"ListUsers": [USER_ROW], "ExecOffboardUser": {"Results": ["Offboarding task queued"]}})
    args = {
        "tenantFilter": "example.com",
        "userId": USER_ID,
        "DisableSignIn": True,
        "RemoveLicenses": False,
        "forward": "boss@example.com",
    }
    result = await _call(monkeypatch, rec, "cipp_offboard_user", args)
    sent = body(rec.calls("ExecOffboardUser")[0])
    assert sent["user"] == [{"label": "jane@example.com", "value": "jane@example.com"}]
    assert sent["DisableSignIn"] is True
    assert "RemoveLicenses" not in sent
    assert sent["forward"] == {"value": "boss@example.com"}
    assert sent["KeepCopy"] is False
    assert result["status"] == "queued"


async def test_offboard_user_needs_an_action(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "cipp_offboard_user", {"tenantFilter": "example.com", "userId": USER_ID})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_out_of_office_rejects_schedule_fields_unless_scheduled(monkeypatch):
    rec = Recorder()
    args = {"tenantFilter": "example.com", "upn": "jane@example.com", "state": "Enabled", "startTime": "2026-06-01T09:00:00Z"}
    result = await _call(monkeypatch, rec, "cipp_set_out_of_office", args)
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_out_of_office_scheduled_body(monkeypatch):
    rec = Recorder(default={"Results": "Set out of office"})
    args = {
        "tenantFilter": "example.com",
        "upn": "jane@example.com",
        "state": "Scheduled",
        "internalMessage": "Away",
        "startTime": "2026-06-01T00:00:00Z",
        "endTime": "1780704000",
    }
    await _call(monkeypatch, rec, "cipp_set_out_of_office", args)
    sent = body(rec.calls("ExecSetOoO")[0])
    assert sent["userId"] == "jane@example.com"
    assert sent["AutoReplyState"] == {"label": "Scheduled", "value": "Scheduled"}
    assert sent["StartTime"] == 1780272000
    assert sent["EndTime"] == 1780704000
    assert "ExternalMessage" not in sent


@pytest.mark.parametrize(
    "target,option,field,value",
    [
        ("boss@example.com", "internalAddress", "ForwardInternal", {"label": "boss@example.com", "value": "boss@example.com"}),
        ("me@example.org", "ExternalAddress", "ForwardExternal", "me@example.org"),
    ],
)
async def test_email_forwarding_internal_vs_external(monkeypatch, target, option, field, value):
    rec = Recorder({"ListDomains": [{"id": "example.com"}, {"id": "example.onmicrosoft.com"}]}, default={"Results": "ok"})
    args = {"tenantFilter": "example.com", "upn": "jane@example.com", "forwardTo": target}
    await _call(monkeypatch, rec, "cipp_set_email_forwarding", args)
    sent = body(rec.calls("ExecEmailForward")[0])
    assert sent["forwardOption"] == option
    assert sent[field] == value
    assert sent["KeepCopy"] is True


async def test_email_forwarding_disable(monkeypatch):
    rec = Recorder(default={"Results": "ok"})
    await _call(monkeypatch, rec, "cipp_set_email_forwarding", {"tenantFilter": "example.com", "upn": "jane@example.com"})
    assert body(rec.calls("ExecEmailForward")[0])["forwardOption"] == "disabled"
    assert rec.calls("ListDomains") == []


async def test_mailbox_usage_ranks_and_summarises(monkeypatch):
    cache = [
        {
            "UPN": "a@example.com",
            "storageUsedInBytes": 2 * GIB,
            "prohibitSendReceiveQuotaInBytes": 50 * GIB,
            "ArchiveEnabled": False,
        },
        {
            "UPN": "b@example.com",
            "storageUsedInBytes": 49 * GIB,
            "prohibitSendReceiveQuotaInBytes": 50 * GIB,
            "ArchiveEnabled": True,
            "ArchiveSize": "1 GB (1,073,741,824 bytes)",
            "CacheTimestamp": "2026-06-01T02:00:00Z",
        },
    ]
    rec = Recorder({"ListMailboxes": cache})
    args = {"tenantFilter": "example.com", "sortBy": "totalSize", "limit": 1}
    result = await _call(monkeypatch, rec, "cipp_list_mailbox_usage", args)
    assert rec.requests[0].url.params["UseReportDB"] == "true"
    assert [m["userPrincipalName"] for m in result["mailboxes"]] == ["b@example.com"]
    assert result["mailboxes"][0]["archive"]["bytes"] == GIB
    assert result["summary"]["mailboxCount"] == 2
    assert result["summary"]["nearQuotaCount"] == 1
    assert result["cachedAt"] == "2026-06-01T02:00:00Z"


async def test_mailbox_usage_explains_empty_cache(monkeypatch):
    def empty(_request):
        return httpx.Response(500, json={"Results": "No mailbox data found in reporting database"})

    rec = Recorder({"ListMailboxes": empty})
    result = await _call(monkeypatch, rec, "cipp_list_mailbox_usage", {"tenantFilter": "example.com"})
    assert result["error"]["code"] == "not_found"
    assert "cipp_get_mailbox_usage" in result["error"]["message"]


async def test_enterprise_apps_hide_first_party_apps_by_default(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "cipp_list_enterprise_apps", {"tenantFilter": "example.com"})
    params = rec.requests[0].url.params
    assert params["Endpoint"] == "/servicePrincipals"
    assert params["$filter"] == "appOwnerOrganizationId ne f8cdef31-a31e-4b4a-93e4-5f571e91255a"


async def test_domain_health_skips_onmicrosoft_and_isolates_failures(monkeypatch):
    def health(request: httpx.Request) -> httpx.Response:
        if request.url.params["Action"] == "ReadDkimRecord":
            return httpx.Response(404, json={"Results": "no record"})
        return httpx.Response(200, json={"record": request.url.params["Action"]})

    rec = Recorder({"ListDomains": [{"id": "example.com"}, {"id": "example.onmicrosoft.com"}], "ListDomainHealth": health})
    result = await _call(monkeypatch, rec, "cipp_list_domain_health", {"tenantFilter": "example.com"})
    assert [d["domain"] for d in result] == ["example.com"]
    assert result[0]["spf"] == {"record": "ReadSpfRecord"}
    assert "error" in result[0]["dkim"]


async def test_run_standards_check_puts_tenant_in_query(monkeypatch):
    rec = Recorder(default={"Results": "started"})
    await _call(monkeypatch, rec, "cipp_run_standards_check", {"tenantFilter": "example.com"})
    request = rec.calls("ExecStandardsRun")[0]
    assert request.method == "POST"
    assert request.url.params["tenantFilter"] == "example.com"
    assert body(request) == {}


async def test_bpa_404_points_to_alignment(monkeypatch):
    rec = Recorder({"ListBPA": lambda r: httpx.Response(404, content=b"")})
    result = await _call(monkeypatch, rec, "cipp_list_bpa", {"tenantFilter": "example.com"})
    assert result["error"]["code"] == "not_found"
    assert "cipp_get_tenant_alignment" in result["error"]["message"]


async def test_tenant_alignment_filters_client_side(monkeypatch):
    rows = [{"tenantFilter": "example.com", "alignmentScore": 90}, {"tenantFilter": "sample.com"}]
    rec = Recorder({"ListTenantAlignment": rows})
    result = await _call(monkeypatch, rec, "cipp_get_tenant_alignment", {"tenantFilter": "Example.com"})
    assert "tenantFilter" not in rec.requests[0].url.params
    assert result == [{"tenantFilter": "example.com", "alignmentScore": 90}]


async def test_add_scheduled_item_body_and_failure_detection(monkeypatch):
    rec = Recorder({"AddScheduledItem": {"Results": "Failed to add task: duplicate name"}})
    args = {
        "taskName": "Weekly",
        "command": "Get-CIPPAlertMFAAdmins",
        "scheduledTime": "1780272000",
        "recurrence": "7d",
        "tenantFilter": "example.com",
    }
    result = await _call(monkeypatch, rec, "cipp_add_scheduled_item", args)
    assert body(rec.calls("AddScheduledItem")[0]) == {
        "Name": "Weekly",
        "Command": {"label": "Get-CIPPAlertMFAAdmins", "value": "Get-CIPPAlertMFAAdmins"},
        "ScheduledTime": 1780272000,
        "Recurrence": "7d",
        "TenantFilter": "example.com",
    }
    assert result["status"] == "failed"


async def test_delete_standard_template_body(monkeypatch):
    rec = Recorder(default={"Results": "Removed"})
    await _call(monkeypatch, rec, "cipp_delete_standard_template", {"templateId": "tpl-1"})
    assert body(rec.calls("RemoveStandardTemplate")[0]) == {"ID": "tpl-1"}


SCORES = {
    "Results": [
        {
            "createdDateTime": "2026-06-01T00:00:00Z",
            "currentScore": 40.0,
            "maxScore": 80.0,
            "enabledServices": ["HasExchange"],
            "averageComparativeScores": [{"basis": "AllTenants", "averageScore": 35.5}],
            "controlScores": [{"controlName": "MFARegistrationV2", "score": 9.0}],
        },
        {
            "createdDateTime": "2026-06-02T00:00:00Z",
            "currentScore": 50.0,
            "maxScore": 80.0,
            "enabledServices": ["HasExchange"],
            "averageComparativeScores": [
                {"basis": "AllTenants", "averageScore": 36.0, "appsScore": 1.0},
                {"basis": "TotalSeats", "averageScore": 42.0, "seatSizeRangeLowerValue": "1"},
            ],
            "controlScores": [{"controlName": "MFARegistrationV2", "score": 10.0}],
        },
    ]
}


async def test_secure_score_request_shape_and_summary(monkeypatch):
    rec = Recorder({"ListGraphRequest": SCORES})
    result = await _call(monkeypatch, rec, "cipp_get_secure_score", {"tenantFilter": "example.com", "top": 30})
    params = rec.calls("ListGraphRequest")[0].url.params
    assert params["tenantFilter"] == "example.com"
    assert params["Endpoint"] == "/security/secureScores"
    assert params["$top"] == "30"
    assert result["latest"] == {
        "date": "2026-06-02",
        "currentScore": 50.0,
        "maxScore": 80.0,
        "percent": 62.5,
        "enabledServices": ["HasExchange"],
    }
    assert result["comparisons"] == [
        {"basis": "AllTenants", "averageScore": 36.0},
        {"basis": "TotalSeats", "averageScore": 42.0},
    ]
    assert [h["date"] for h in result["history"]] == ["2026-06-02", "2026-06-01"]
    assert "controlScores" not in json.dumps(result)


async def test_secure_score_defaults_to_seven_snapshots(monkeypatch):
    rec = Recorder({"ListGraphRequest": SCORES})
    await _call(monkeypatch, rec, "cipp_get_secure_score", {"tenantFilter": "example.com"})
    assert rec.calls("ListGraphRequest")[0].url.params["$top"] == "7"


async def test_secure_score_empty_collection_is_not_an_error(monkeypatch):
    rec = Recorder({"ListGraphRequest": {"Results": []}})
    result = await _call(monkeypatch, rec, "cipp_get_secure_score", {"tenantFilter": "example.com"})
    assert "error" not in result
    assert result["latest"] is None
    assert result["history"] == []
    assert "No Secure Score" in result["note"]


@pytest.mark.parametrize("tool", ["cipp_get_secure_score", "cipp_list_secure_score_controls"])
async def test_secure_score_tools_reject_all_tenants(monkeypatch, tool):
    rec = Recorder()
    result = await _call(monkeypatch, rec, tool, {"tenantFilter": "AllTenants"})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_secure_score_controls_sorted_by_rank_and_trimmed(monkeypatch):
    profiles = [
        {"id": "b", "title": "Second", "controlCategory": "Data", "rank": 20, "maxScore": 5.0, "remediation": "<p>Do   " + "x" * 400 + "</p>"},
        {"id": "z", "title": "Unranked", "controlCategory": "Apps"},
        {
            "id": "a",
            "title": "First",
            "controlCategory": "Identity",
            "rank": 1,
            "maxScore": 10.0,
            "userImpact": "Moderate",
            "implementationCost": "Low",
            "tier": "Core",
            "threats": ["Password Cracking"],
            "deprecated": False,
            "remediation": "<p>Turn on <b>MFA</b>.</p>",
            "controlStateUpdates": [{"state": "Default"}],
        },
    ]
    rec = Recorder({"ListGraphRequest": {"Results": profiles}})
    result = await _call(monkeypatch, rec, "cipp_list_secure_score_controls", {"tenantFilter": "example.com"})
    params = rec.calls("ListGraphRequest")[0].url.params
    assert params["tenantFilter"] == "example.com"
    assert params["Endpoint"] == "/security/secureScoreControlProfiles"
    assert result["count"] == 3
    assert [c["id"] for c in result["controls"]] == ["a", "b", "z"]
    first = result["controls"][0]
    assert first["category"] == "Identity"
    assert first["remediation"] == "Turn on MFA."
    assert "controlStateUpdates" not in first
    assert len(result["controls"][1]["remediation"]) <= 200


async def test_secure_score_controls_empty_collection(monkeypatch):
    rec = Recorder({"ListGraphRequest": {"Results": []}})
    result = await _call(monkeypatch, rec, "cipp_list_secure_score_controls", {"tenantFilter": "example.com"})
    assert result == {"count": 0, "controls": []}

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
"""tools/list snapshot and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from cipp_mcp.api_client import CippError
from cipp_mcp.server import INSTRUCTIONS, create_mcp_server

# Tool names are a public contract: existing agents and tenant connections
# depend on them. Changing this snapshot is a breaking change.
T = {"tenantFilter"}
TU = {"tenantFilter", "userId"}
TP = {"tenantFilter", "upn"}
EXPECTED_TOOLS: dict[str, set[str]] = {
    "cipp_ping": set(),
    "cipp_get_version": set(),
    "cipp_list_logs": set(),
    "cipp_list_tenants": set(),
    "cipp_get_tenant_details": T,
    "cipp_list_users": T,
    "cipp_create_user": {"tenantFilter", "displayName", "userPrincipalName", "password"},
    "cipp_edit_user": TU,
    "cipp_disable_user": TU,
    "cipp_reset_password": TU,
    "cipp_reset_mfa": TU,
    "cipp_revoke_sessions": TU,
    "cipp_offboard_user": TU,
    "cipp_bec_check": TU,
    "cipp_list_mfa_users": T,
    "cipp_list_user_devices": TU,
    "cipp_list_user_groups": TU,
    "cipp_list_user_signin_logs": TU,
    "cipp_list_groups": T,
    "cipp_create_group": {"tenantFilter", "displayName"},
    "cipp_list_mailboxes": T,
    "cipp_list_mailbox_permissions": TP,
    "cipp_list_trusted_blocked_senders": TP,
    "cipp_list_mailbox_usage": T,
    "cipp_get_mailbox_usage": TP,
    "cipp_set_out_of_office": TP | {"state"},
    "cipp_set_email_forwarding": TP,
    "cipp_list_conditional_access_policies": T,
    "cipp_list_named_locations": T,
    "cipp_list_enterprise_apps": T,
    "cipp_list_domain_health": T,
    "cipp_list_audit_logs": T,
    "cipp_list_alert_queue": set(),
    "cipp_list_standards": T,
    "cipp_run_standards_check": T,
    "cipp_list_standard_templates": set(),
    "cipp_get_tenant_drift": set(),
    "cipp_get_tenant_alignment": set(),
    "cipp_create_standard_template": {"template"},
    "cipp_delete_standard_template": {"templateId"},
    "cipp_list_bpa": T,
    "cipp_list_licenses": T,
    "cipp_list_csp_licenses": set(),
    "cipp_list_gdap_roles": set(),
    "cipp_list_gdap_invites": set(),
    "cipp_list_scheduled_items": set(),
    "cipp_add_scheduled_item": {"taskName", "command", "scheduledTime"},
}

WRITE_TOOLS = {
    "cipp_create_user",
    "cipp_edit_user",
    "cipp_disable_user",
    "cipp_reset_password",
    "cipp_reset_mfa",
    "cipp_revoke_sessions",
    "cipp_offboard_user",
    "cipp_create_group",
    "cipp_set_out_of_office",
    "cipp_set_email_forwarding",
    "cipp_run_standards_check",
    "cipp_create_standard_template",
    "cipp_delete_standard_template",
    "cipp_add_scheduled_item",
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_are_stable(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_annotations_match_side_effects(tools, name):
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is (name not in WRITE_TOOLS)


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
def test_write_tools_say_when_to_use_them(tools, name):
    text = (tools[name].description or "").lower()
    assert "explicit" in text


def test_destructive_flags(tools):
    assert tools["cipp_delete_standard_template"].annotations.destructiveHint is True
    assert tools["cipp_offboard_user"].annotations.destructiveHint is True


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500


@pytest.mark.parametrize(
    "status,code,retryable",
    [
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (400, "invalid_argument", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (0, "upstream_error", True),
    ],
)
def test_error_envelope(status, code, retryable):
    envelope = json.loads(CippError(status, "boom").to_envelope())
    assert envelope == {"error": {"code": code, "message": "boom", "retryable": retryable}}


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("cipp_ping", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"

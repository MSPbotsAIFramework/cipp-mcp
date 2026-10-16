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
"""Groups."""

import re
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient
from ._common import READ_ONLY, WRITES, ClientFactory, TenantFilter, compact, label_value, rows, run_tool


def group_type(security_enabled: bool | None, mail_enabled: bool | None) -> str:
    """Map the two Graph flags onto CIPP's group types."""
    if mail_enabled and security_enabled:
        return "Mail-Enabled Security"
    if mail_enabled:
        return "M365"
    return "Generic"


def mail_alias(display_name: str) -> str:
    alias = re.sub(r"[^A-Za-z0-9._-]", "", display_name.replace(" ", "."))
    return alias.strip(".")[:64] or "group"


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_groups(
        tenantFilter: TenantFilter,
        search: Annotated[str | None, Field(description="Text the group's display name contains.")] = None,
    ) -> str:
        """List groups of a tenant: name, type (security, M365, distribution), mail, membership rule."""

        async def action(client: CippClient) -> Any:
            payload = await client.get("ListGroups", {"tenantFilter": tenantFilter})
            if not search:
                return payload
            needle = search.lower()
            return [g for g in rows(payload) if isinstance(g, dict) and needle in str(g.get("displayName", "")).lower()]

        return await run_tool("cipp_list_groups", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def cipp_create_group(
        tenantFilter: TenantFilter,
        displayName: Annotated[str, Field(description="Group display name.")],
        description: Annotated[str | None, Field(description="Group description.")] = None,
        securityEnabled: Annotated[bool | None, Field(description="Security group (default true).")] = None,
        mailEnabled: Annotated[
            bool | None, Field(description="Mail-enabled: alone gives a Microsoft 365 group, with securityEnabled a mail-enabled security group.")
        ] = None,
        mailNickname: Annotated[str | None, Field(description="Mail alias (defaults from the display name).")] = None,
    ) -> str:
        """Create a group in a tenant. Changes the tenant: only when the user explicitly asks."""

        async def action(client: CippClient) -> Any:
            security = True if securityEnabled is None else securityEnabled
            body = compact(
                {
                    "tenantFilter": label_value(tenantFilter),
                    "displayName": displayName,
                    "description": description,
                    "groupType": group_type(security, mailEnabled),
                    "username": (mailNickname or mail_alias(displayName)).strip(),
                }
            )
            return await client.post("AddGroup", body)

        return await run_tool("cipp_create_group", client_factory, action)

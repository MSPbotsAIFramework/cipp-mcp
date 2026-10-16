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
"""Licences, GDAP relationships and CIPP's task scheduler."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient
from ._common import READ_ONLY, WRITES, ClientFactory, TenantFilter, compact, interpret_results, run_tool, to_unix_seconds


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_licenses(tenantFilter: TenantFilter) -> str:
        """List a tenant's licence SKUs with purchased, assigned and available counts."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListLicenses", {"tenantFilter": tenantFilter})

        return await run_tool("cipp_list_licenses", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_csp_licenses(
        tenantFilter: Annotated[str | None, Field(description="Tenant default domain or id (default AllTenants).")] = None,
    ) -> str:
        """List CSP licence subscriptions bought through the CSP integration for tenants."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListCSPLicenses", {"tenantFilter": tenantFilter or "AllTenants"})

        return await run_tool("cipp_list_csp_licenses", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_gdap_roles() -> str:
        """List the GDAP role mappings (Entra roles to partner security groups) set up in CIPP."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListGDAPRoles")

        return await run_tool("cipp_list_gdap_roles", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_gdap_invites() -> str:
        """List GDAP relationship invites created in CIPP and their status."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListGDAPInvite", {"tenantFilter": "AllTenants"})

        return await run_tool("cipp_list_gdap_invites", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_scheduled_items() -> str:
        """List tasks in CIPP's scheduler: name, command, tenant, next run, state and results."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListScheduledItems")

        return await run_tool("cipp_list_scheduled_items", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def cipp_add_scheduled_item(
        taskName: Annotated[str, Field(description="Task name.")],
        command: Annotated[str, Field(description="CIPP command to run, e.g. Set-CIPPMailboxAccess.")],
        scheduledTime: Annotated[str, Field(description="First run, ISO 8601 or epoch seconds.")],
        recurrence: Annotated[str | None, Field(description="Repeat interval, e.g. 1d or 7d; omit for once.")] = None,
        tenantFilter: Annotated[str | None, Field(description="Tenant to run against.")] = None,
        parameters: Annotated[dict[str, Any] | None, Field(description="Parameters for the command.")] = None,
    ) -> str:
        """Schedule a CIPP command to run once or on a recurrence. Changes tenants: only on explicit request."""

        async def action(client: CippClient) -> dict:
            body = compact(
                {
                    "Name": taskName,
                    "Command": {"label": command, "value": command},
                    "ScheduledTime": to_unix_seconds(scheduledTime, "scheduledTime"),
                    "Recurrence": recurrence,
                    "TenantFilter": tenantFilter,
                    "Parameters": parameters,
                }
            )
            results, failures = interpret_results(await client.post("AddScheduledItem", body))
            failed = bool(failures)
            return {
                "status": "failed" if failed else "added",
                "taskName": taskName,
                "results": results,
                "failures": failures,
                "message": (
                    f'CIPP reported a failure adding scheduled task "{taskName}". Do NOT report success: {" | ".join(failures)}'
                    if failed
                    else f'Scheduled task "{taskName}" added.'
                ),
            }

        return await run_tool("cipp_add_scheduled_item", client_factory, action)

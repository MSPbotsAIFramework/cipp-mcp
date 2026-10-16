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
"""Standards (baseline configurations), templates, alignment and drift."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient, CippError
from ._common import DESTRUCTIVE_ONCE, READ_ONLY, WRITES, WRITES_IDEMPOTENT, ClientFactory, TenantFilter, rows, run_tool

OptionalTenant = Annotated[str | None, Field(description="Tenant default domain or id; omit for all tenants.")]


def _row_tenant(row: dict) -> str:
    for key in ("tenantFilter", "TenantFilter", "tenant", "Tenant", "defaultDomainName"):
        value = row.get(key)
        if isinstance(value, str):
            return value.lower()
    return ""


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_standards(tenantFilter: TenantFilter) -> str:
        """List the standards applied to a tenant and their settings."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListStandards", {"tenantFilter": tenantFilter})

        return await run_tool("cipp_list_standards", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def cipp_run_standards_check(tenantFilter: TenantFilter) -> str:
        """Run the standards assigned to a tenant now; remediating standards change the tenant.

        Only when the user explicitly asks.
        """

        async def action(client: CippClient) -> Any:
            return await client.post("ExecStandardsRun", {}, params={"tenantFilter": tenantFilter})

        return await run_tool("cipp_run_standards_check", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_standard_templates() -> str:
        """List the standards templates (id, name, assigned tenants, standards)."""

        async def action(client: CippClient) -> Any:
            return await client.get("listStandardTemplates")

        return await run_tool("cipp_list_standard_templates", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_get_tenant_drift(tenantFilter: OptionalTenant = None) -> str:
        """Show where tenants have drifted from their drift-standard templates (accepted / denied deviations)."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListTenantDrift", {"tenantFilter": tenantFilter or "AllTenants"})

        return await run_tool("cipp_get_tenant_drift", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_get_tenant_alignment(tenantFilter: OptionalTenant = None) -> str:
        """Show how well tenants align with their standards templates (percentage compliant per template)."""

        async def action(client: CippClient) -> Any:
            payload = await client.get("ListTenantAlignment")
            if not tenantFilter:
                return payload
            wanted = tenantFilter.lower()
            return [r for r in rows(payload) if isinstance(r, dict) and _row_tenant(r) == wanted]

        return await run_tool("cipp_get_tenant_alignment", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def cipp_create_standard_template(
        template: Annotated[
            dict[str, Any],
            Field(description="Template object as CIPP stores it: templateName, tenantFilter (assigned tenants), standards, ..."),
        ],
    ) -> str:
        """Create a standards template; standards apply to its tenants on the next run.

        Only when the user explicitly asks.
        """

        async def action(client: CippClient) -> Any:
            if template.get("tenantFilter") is None:
                raise ValueError('The template must include "tenantFilter" assigning it to at least one tenant.')
            return await client.post("AddStandardsTemplate", template)

        return await run_tool("cipp_create_standard_template", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE_ONCE)
    async def cipp_delete_standard_template(
        templateId: Annotated[str, Field(description="Template id from cipp_list_standard_templates.")],
    ) -> str:
        """Delete a standards template. Irreversible: only when the user explicitly asks for that template id."""

        async def action(client: CippClient) -> Any:
            return await client.post("RemoveStandardTemplate", {"ID": templateId})

        return await run_tool("cipp_delete_standard_template", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_bpa(tenantFilter: TenantFilter) -> str:
        """Get the Best Practice Analyser report for a tenant (older CIPP versions only).

        Newer CIPP replaced it with standards alignment: use cipp_get_tenant_alignment.
        """

        async def action(client: CippClient) -> Any:
            try:
                return await client.get("ListBPA", {"tenantFilter": tenantFilter})
            except CippError as e:
                if e.status_code == 404:
                    raise CippError(404, "This CIPP version has no Best Practice Analyser; use cipp_get_tenant_alignment.") from e
                raise

        return await run_tool("cipp_list_bpa", client_factory, action)

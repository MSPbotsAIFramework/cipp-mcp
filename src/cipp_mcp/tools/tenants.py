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
"""Managed tenants."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient
from ._common import (
    READ_ONLY,
    ClientFactory,
    Limit,
    Offset,
    TenantFilter,
    paged,
    run_tool,
)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_tenants(
        allTenants: Annotated[bool | None, Field(description='true adds the "All Tenants" entry at the top.')] = None,
        offset: Offset = None,
        limit: Limit = None,
    ) -> str:
        """List the customer tenants managed through CIPP: name, default domain and tenant id."""

        async def action(client: CippClient) -> Any:
            params = {"AllTenantSelector": allTenants} if isinstance(allTenants, bool) else {}
            return await client.get("ListTenants", params)

        return await run_tool("cipp_list_tenants", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_get_tenant_details(tenantFilter: TenantFilter) -> str:
        """Get a tenant's organisation details: verified domains, address, technical contacts, sync settings."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListTenantDetails", {"tenantFilter": tenantFilter})

        return await run_tool("cipp_get_tenant_details", client_factory, action)

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
"""Security posture: conditional access, apps, domain mail records, audit and alerts."""

import asyncio
import json
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient, CippError
from ._common import READ_ONLY, ClientFactory, TenantFilter, rows, run_tool

MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
_DNS_CHECKS = {"spf": "ReadSpfRecord", "dmarc": "ReadDmarcPolicy", "dkim": "ReadDkimRecord"}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_conditional_access_policies(tenantFilter: TenantFilter) -> str:
        """List a tenant's conditional access policies with state, conditions and grant controls."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListConditionalAccessPolicies", {"tenantFilter": tenantFilter})

        return await run_tool("cipp_list_conditional_access_policies", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_named_locations(tenantFilter: TenantFilter) -> str:
        """List conditional access named locations (trusted IP ranges and countries)."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListNamedLocations", {"tenantFilter": tenantFilter})

        return await run_tool("cipp_list_named_locations", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_enterprise_apps(
        tenantFilter: Annotated[str, Field(description="Tenant default domain or id, or AllTenants.")],
        includeBuiltIn: Annotated[bool | None, Field(description="Include Microsoft's own first-party apps (default false).")] = None,
    ) -> str:
        """List enterprise applications (service principals) consented in a tenant: name, publisher, created."""

        async def action(client: CippClient) -> Any:
            params: dict[str, Any] = {
                "tenantFilter": tenantFilter,
                "Endpoint": "/servicePrincipals",
                "$select": "appId,displayName,publisherName,appOwnerOrganizationId,signInAudience,tags,createdDateTime",
            }
            if not includeBuiltIn:
                params["$filter"] = f"appOwnerOrganizationId ne {MICROSOFT_TENANT_ID}"
            return await client.get("ListGraphRequest", params)

        return await run_tool("cipp_list_enterprise_apps", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_domain_health(tenantFilter: TenantFilter) -> str:
        """Check SPF, DMARC and DKIM records for each custom domain of a tenant."""

        async def action(client: CippClient) -> list:
            domains = [
                d["id"]
                for d in rows(await client.get("ListDomains", {"tenantFilter": tenantFilter}))
                if isinstance(d, dict) and isinstance(d.get("id"), str) and d["id"] and not d["id"].lower().endswith(".onmicrosoft.com")
            ]

            async def check(domain: str, name: str) -> Any:
                try:
                    return await asyncio.wait_for(client.get("ListDomainHealth", {"Action": name, "Domain": domain}), 15)
                except (CippError, asyncio.TimeoutError) as e:
                    return {"error": getattr(e, "message", "timed out")}

            async def one(domain: str) -> dict:
                results = await asyncio.gather(*(check(domain, name) for name in _DNS_CHECKS.values()))
                return {"domain": domain, **dict(zip(_DNS_CHECKS, results, strict=True))}

            return list(await asyncio.gather(*(one(d) for d in domains)))

        return await run_tool("cipp_list_domain_health", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_audit_logs(
        tenantFilter: Annotated[str, Field(description="Tenant default domain or id, or AllTenants.")],
        days: Annotated[int | None, Field(description="Look back this many days (default 7).", ge=1, le=90)] = None,
        type: Annotated[str | None, Field(description="Only entries whose content mentions this text (e.g. an operation name).")] = None,
    ) -> str:
        """List audit-log alert entries CIPP collected for a tenant (sign-in, mailbox rule, admin changes)."""

        async def action(client: CippClient) -> Any:
            payload = await client.get("ListAuditLogs", {"tenantFilter": tenantFilter, "RelativeTime": f"{days or 7}d"})
            if not type:
                return payload
            needle = type.lower()
            return [r for r in rows(payload) if needle in json.dumps(r, ensure_ascii=False, default=str).lower()]

        return await run_tool("cipp_list_audit_logs", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_alert_queue() -> str:
        """List the alert rules and scheduled alert jobs configured in CIPP."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListAlertsQueue")

        return await run_tool("cipp_list_alert_queue", client_factory, action)

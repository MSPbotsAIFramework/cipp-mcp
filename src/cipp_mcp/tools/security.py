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
"""Security posture: conditional access, apps, domain mail records, secure score, audit and alerts."""

import asyncio
import json
import re
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient, CippError
from ._common import (
    READ_ONLY,
    ClientFactory,
    Limit,
    Offset,
    TenantFilter,
    is_all_tenants,
    paged,
    rows,
    run_tool,
)

MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
_DNS_CHECKS = {"spf": "ReadSpfRecord", "dmarc": "ReadDmarcPolicy", "dkim": "ReadDkimRecord"}
_REMEDIATION_CHARS = 200
_TAG = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"\s+")
_SPACE_BEFORE_PUNCT = re.compile(r"\s+([.,;:!?])")

SingleTenant = Annotated[
    str,
    Field(description="One tenant's default domain (e.g. example.onmicrosoft.com) or tenant id; AllTenants is not accepted."),
]


def _single_tenant(tool: str, tenant: str) -> str:
    if is_all_tenants(tenant):
        raise ValueError(f"{tool} reads one tenant at a time; pass a tenant default domain or id, not AllTenants.")
    return tenant


def _date(value: Any) -> Any:
    return value[:10] if isinstance(value, str) else value


def _percent(current: Any, maximum: Any) -> float | None:
    if isinstance(current, (int, float)) and isinstance(maximum, (int, float)) and maximum > 0:
        return round(current * 100 / maximum, 1)
    return None


def summarize_secure_scores(snapshots: list) -> dict[str, Any]:
    """Latest score, peer comparisons and a newest-first history from Graph secureScore records."""
    records = sorted(
        (s for s in snapshots if isinstance(s, dict)),
        key=lambda s: str(s.get("createdDateTime") or ""),
        reverse=True,
    )
    if not records:
        return {
            "latest": None,
            "comparisons": [],
            "history": [],
            "note": "No Secure Score snapshots yet; Microsoft computes the first score about a day after a tenant is set up.",
        }
    latest = records[0]
    comparisons = [
        {"basis": c.get("basis"), "averageScore": c.get("averageScore")}
        for c in latest.get("averageComparativeScores") or []
        if isinstance(c, dict)
    ]
    return {
        "latest": {
            "date": _date(latest.get("createdDateTime")),
            "currentScore": latest.get("currentScore"),
            "maxScore": latest.get("maxScore"),
            "percent": _percent(latest.get("currentScore"), latest.get("maxScore")),
            "enabledServices": latest.get("enabledServices"),
        },
        "comparisons": comparisons,
        "history": [
            {"date": _date(s.get("createdDateTime")), "currentScore": s.get("currentScore"), "maxScore": s.get("maxScore")}
            for s in records
        ],
    }


def _short_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = _SPACE_BEFORE_PUNCT.sub(r"\1", _SPACE.sub(" ", _TAG.sub(" ", value))).strip()
    if len(text) > _REMEDIATION_CHARS:
        text = text[: _REMEDIATION_CHARS - 3].rstrip() + "..."
    return text or None


def summarize_control_profiles(profiles: list) -> list[dict[str, Any]]:
    """Useful fields of Graph secureScoreControlProfile records, highest priority (lowest rank) first."""
    items = [
        {
            "id": p.get("id"),
            "title": p.get("title"),
            "category": p.get("controlCategory"),
            "rank": p.get("rank"),
            "maxScore": p.get("maxScore"),
            "userImpact": p.get("userImpact"),
            "implementationCost": p.get("implementationCost"),
            "tier": p.get("tier"),
            "threats": p.get("threats"),
            "deprecated": p.get("deprecated"),
            "remediation": _short_text(p.get("remediation")),
        }
        for p in profiles
        if isinstance(p, dict)
    ]

    def order(item: dict[str, Any]) -> tuple:
        rank = item["rank"]
        return (not isinstance(rank, (int, float)), rank if isinstance(rank, (int, float)) else 0, str(item["title"] or ""))

    return sorted(items, key=order)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_conditional_access_policies(tenantFilter: TenantFilter, offset: Offset = None, limit: Limit = None) -> str:
        """List a tenant's conditional access policies with state, conditions and grant controls."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListConditionalAccessPolicies", {"tenantFilter": tenantFilter})

        return await run_tool("cipp_list_conditional_access_policies", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_named_locations(tenantFilter: TenantFilter, offset: Offset = None, limit: Limit = None) -> str:
        """List conditional access named locations (trusted IP ranges and countries)."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListNamedLocations", {"tenantFilter": tenantFilter})

        return await run_tool("cipp_list_named_locations", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_enterprise_apps(
        tenantFilter: Annotated[str, Field(description="Tenant default domain or id, or AllTenants.")],
        includeBuiltIn: Annotated[bool | None, Field(description="Include Microsoft's own first-party apps (default false).")] = None,
        offset: Offset = None,
        limit: Limit = None,
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

        return await run_tool("cipp_list_enterprise_apps", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_domain_health(tenantFilter: TenantFilter, offset: Offset = None, limit: Limit = None) -> str:
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

        return await run_tool("cipp_list_domain_health", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_get_secure_score(
        tenantFilter: SingleTenant,
        top: Annotated[
            int,
            Field(description="How many daily score snapshots to read (default 7; Graph keeps about 90 days).", ge=1, le=90),
        ] = 7,
    ) -> str:
        """Get a tenant's Microsoft Secure Score: latest score and percent, peer averages, daily history.

        History is newest first. A new tenant may have no score yet.
        """

        async def action(client: CippClient) -> Any:
            tenant = _single_tenant("cipp_get_secure_score", tenantFilter)
            payload = await client.get(
                "ListGraphRequest",
                {"tenantFilter": tenant, "Endpoint": "/security/secureScores", "$top": str(top), "noPagination": "true"},
            )
            return summarize_secure_scores(rows(payload))

        return await run_tool("cipp_get_secure_score", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_secure_score_controls(tenantFilter: SingleTenant, offset: Offset = None, limit: Limit = None) -> str:
        """List a tenant's Secure Score improvement actions, highest priority (lowest rank) first.

        Each has category, max points, user impact, cost, tier, deprecated flag and a short remediation.
        """

        async def action(client: CippClient) -> Any:
            tenant = _single_tenant("cipp_list_secure_score_controls", tenantFilter)
            payload = await client.get(
                "ListGraphRequest", {"tenantFilter": tenant, "Endpoint": "/security/secureScoreControlProfiles"}
            )
            controls = summarize_control_profiles(rows(payload))
            return {"count": len(controls), "controls": controls}

        return await run_tool("cipp_list_secure_score_controls", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_audit_logs(
        tenantFilter: Annotated[str, Field(description="Tenant default domain or id, or AllTenants.")],
        days: Annotated[int | None, Field(description="Look back this many days (default 7).", ge=1, le=90)] = None,
        type: Annotated[str | None, Field(description="Only entries whose content mentions this text (e.g. an operation name).")] = None,
        offset: Offset = None,
        limit: Limit = None,
    ) -> str:
        """List audit-log alert entries CIPP collected for a tenant (sign-in, mailbox rule, admin changes)."""

        async def action(client: CippClient) -> Any:
            payload = await client.get("ListAuditLogs", {"tenantFilter": tenantFilter, "RelativeTime": f"{days or 7}d"})
            if not type:
                return payload
            needle = type.lower()
            return [r for r in rows(payload) if needle in json.dumps(r, ensure_ascii=False, default=str).lower()]

        return await run_tool("cipp_list_audit_logs", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_alert_queue(offset: Offset = None, limit: Limit = None) -> str:
        """List the alert rules and scheduled alert jobs configured in CIPP."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListAlertsQueue")

        return await run_tool("cipp_list_alert_queue", client_factory, paged(action, offset, limit))

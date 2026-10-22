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
"""Exchange mailboxes: inventory, permissions, sizes, auto-reply and forwarding."""

import math
import re
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient, CippError
from ._common import (
    READ_ONLY,
    WRITES_IDEMPOTENT,
    ClientFactory,
    Fields,
    Limit,
    Offset,
    TenantFilter,
    Upn,
    compact,
    is_all_tenants,
    label_value,
    paged,
    resolve_user,
    rows,
    run_tool,
    to_unix_seconds,
)

GIB = 1024**3
_SCHEDULED_ONLY = (
    "startTime",
    "endTime",
    "createOOFEvent",
    "oofEventSubject",
    "autoDeclineFutureRequestsWhenOOF",
    "declineEventsForScheduledOOF",
    "declineMeetingMessage",
)


def to_bytes(value: Any) -> int | None:
    """Bytes from a number, a numeric string or an Exchange size like '49.5 GB (53,150,220,288 bytes)'."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        match = re.search(r"\(([\d,]+) bytes\)", text)
        if match:
            return int(match.group(1).replace(",", ""))
        try:
            return int(float(text))
        except ValueError:
            return None
    return None


def from_gigabytes(value: Any) -> int | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return round(number * GIB) if math.isfinite(number) else None


def to_number(value: Any) -> float | int | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return int(number) if number.is_integer() else number


def format_bytes(value: int | None) -> str | None:
    if value is None:
        return None
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return None


def size_block(used: int | None, quota: int | None, items: Any) -> dict:
    quota = quota if quota and quota > 0 else None
    percent = round(used / quota * 100, 2) if used is not None and quota else None
    return compact(
        {
            "bytes": used,
            "size": format_bytes(used),
            "itemCount": to_number(items),
            "quotaBytes": quota,
            "quota": format_bytes(quota),
            "percentOfQuota": percent,
        }
    )


def archive_block(enabled: bool, used: int | None, quota: int | None, items: Any, auto: Any, scope: Any = None) -> dict:
    block: dict[str, Any] = {"enabled": enabled}
    if enabled:
        block |= size_block(used, quota, items)
    if isinstance(auto, bool):
        block["autoExpanding"] = auto
    if isinstance(scope, str) and scope.strip():
        block["autoExpandingScope"] = scope
    return block


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_mailboxes(
        tenantFilter: TenantFilter,
        type: Annotated[
            Literal["UserMailbox", "SharedMailbox", "RoomMailbox", "EquipmentMailbox"] | None,
            Field(description="Only this mailbox type."),
        ] = None,
        offset: Offset = None,
        limit: Limit = None,
        fields: Fields = None,
    ) -> str:
        """List Exchange mailboxes of a tenant: UPN, display name, type, aliases."""

        async def action(client: CippClient) -> Any:
            payload = await client.get("ListMailboxes", {"tenantFilter": tenantFilter})
            if not type:
                return payload
            return [m for m in rows(payload) if isinstance(m, dict) and m.get("recipientTypeDetails") == type]

        return await run_tool("cipp_list_mailboxes", client_factory, paged(action, offset, limit, fields))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_mailbox_permissions(tenantFilter: TenantFilter, upn: Upn, offset: Offset = None, limit: Limit = None) -> str:
        """List who has full access, send-as or send-on-behalf permission on a mailbox."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListmailboxPermissions", {"tenantFilter": tenantFilter, "userId": upn})

        return await run_tool("cipp_list_mailbox_permissions", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_trusted_blocked_senders(tenantFilter: TenantFilter, upn: Upn, offset: Offset = None, limit: Limit = None) -> str:
        """List a mailbox's personal trusted (safe) and blocked senders and domains. Empty means none set."""

        async def action(client: CippClient) -> Any:
            params = {"tenantFilter": tenantFilter, "UserID": upn, "userPrincipalName": upn}
            return await client.get("ListUserTrustedBlockedSenders", params)

        return await run_tool("cipp_list_trusted_blocked_senders", client_factory, paged(action, offset, limit))

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_mailbox_usage(
        tenantFilter: Annotated[str, Field(description="Tenant default domain or id, or AllTenants.")],
        sortBy: Annotated[
            Literal["mailboxSize", "archiveSize", "totalSize", "percentOfQuota"] | None,
            Field(description="Sort key, largest first (default mailboxSize)."),
        ] = None,
        limit: Annotated[int | None, Field(description="Mailboxes to return (1-1000, default 50).", ge=1, le=1000)] = None,
        minSizeGB: Annotated[float | None, Field(description="Only mailboxes whose mailbox+archive size is at least this.", ge=0)] = None,
    ) -> str:
        """Rank mailboxes by size, archive size or quota use, with tenant totals, from CIPP's daily cache.

        Data can be up to 24 h old; use cipp_get_mailbox_usage for one mailbox live.
        """

        async def action(client: CippClient) -> dict:
            sort_key = sortBy or "mailboxSize"
            top = limit or 50
            try:
                payload = await client.get("ListMailboxes", {"tenantFilter": tenantFilter, "UseReportDB": True})
            except CippError as e:
                if re.search(r"No mailbox data found in reporting database", e.message, re.IGNORECASE):
                    raise CippError(
                        404,
                        f"CIPP has no cached mailbox data for {tenantFilter}. Sync the mailbox report cache in CIPP "
                        "(Reports > Report Settings) or use cipp_get_mailbox_usage for a single mailbox.",
                    ) from e
                raise
            raw = [r for r in rows(payload) if isinstance(r, dict)]
            stamps = [str(r["CacheTimestamp"]) for r in raw if r.get("CacheTimestamp")]
            mailboxes = []
            for r in raw:
                enabled = r.get("ArchiveEnabled") is True
                mailboxes.append(
                    compact(
                        {
                            "userPrincipalName": r.get("UPN"),
                            "displayName": r.get("displayName"),
                            "recipientTypeDetails": r.get("recipientTypeDetails"),
                            "tenant": r.get("Tenant"),
                            "mailbox": size_block(
                                to_bytes(r.get("storageUsedInBytes")), to_bytes(r.get("prohibitSendReceiveQuotaInBytes")), r.get("MailboxItemCount")
                            ),
                            "archive": archive_block(
                                enabled, to_bytes(r.get("ArchiveSize")), to_bytes(r.get("ArchiveQuota")), r.get("ArchiveItemCount"), r.get("AutoExpandingArchive")
                            ),
                        }
                    )
                )

            def total(m: dict) -> int:
                return (m["mailbox"].get("bytes") or 0) + (m["archive"].get("bytes") or 0)

            mailbox_bytes = sum(m["mailbox"].get("bytes") or 0 for m in mailboxes)
            archive_bytes = sum(m["archive"].get("bytes") or 0 for m in mailboxes)
            summary = {
                "mailboxCount": len(mailboxes),
                "archivesEnabled": sum(1 for m in mailboxes if m["archive"]["enabled"]),
                "mailboxBytes": mailbox_bytes,
                "mailboxSize": format_bytes(mailbox_bytes),
                "archiveBytes": archive_bytes,
                "archiveSize": format_bytes(archive_bytes),
                "totalBytes": mailbox_bytes + archive_bytes,
                "totalSize": format_bytes(mailbox_bytes + archive_bytes),
                "nearQuotaCount": sum(1 for m in mailboxes if (m["mailbox"].get("percentOfQuota") or 0) >= 90),
                "nearQuotaPercent": 90,
            }
            warnings = []
            if mailboxes and all(not m["mailbox"].get("bytes") for m in mailboxes):
                warnings.append(
                    "Every mailbox reports 0 bytes, which usually means the usage merge failed (report name concealment "
                    "is on in the Microsoft 365 admin centre, or the cache synced too early). Re-sync, or use cipp_get_mailbox_usage."
                )
            if any(re.fullmatch(r"[0-9A-Fa-f]{32}", str(m.get("userPrincipalName", ""))) for m in mailboxes):
                warnings.append("Some mailboxes show a 32-character hash instead of a UPN because the tenant conceals names in usage reports.")
            matching = [m for m in mailboxes if minSizeGB is None or total(m) >= minSizeGB * GIB]
            sort_value = {
                "mailboxSize": lambda m: m["mailbox"].get("bytes"),
                "archiveSize": lambda m: m["archive"].get("bytes"),
                "totalSize": total,
                "percentOfQuota": lambda m: m["mailbox"].get("percentOfQuota"),
            }[sort_key]
            ranked = sorted(matching, key=lambda m: (sort_value(m) is None, -(sort_value(m) or 0)))
            return compact(
                {
                    "tenantFilter": tenantFilter,
                    "source": "reportDatabase",
                    "cachedAt": max(stamps) if stamps else None,
                    "summary": summary,
                    "warnings": warnings or None,
                    "sortedBy": sort_key,
                    "minSizeGB": minSizeGB,
                    "totalMatching": len(matching),
                    "returned": min(top, len(ranked)),
                    "mailboxes": ranked[:top],
                }
            )

        return await run_tool("cipp_list_mailbox_usage", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_get_mailbox_usage(tenantFilter: TenantFilter, upn: Upn) -> str:
        """Get one mailbox's live size, item count, quota use and archive status."""

        async def action(client: CippClient) -> dict:
            if is_all_tenants(tenantFilter):
                raise ValueError("cipp_get_mailbox_usage reads one mailbox in one tenant; use cipp_list_mailbox_usage for AllTenants.")
            user = await resolve_user(client, tenantFilter, upn, "Mailbox usage is looked up by object id.")
            raw = await client.get(
                "ListUserMailboxDetails", {"tenantFilter": tenantFilter, "UserID": user["id"], "userMail": user["userPrincipalName"]}
            ) or {}
            if isinstance(raw, list):
                raw = raw[0] if raw and isinstance(raw[0], dict) else {}
            mb = raw.get("Mailbox") if isinstance(raw.get("Mailbox"), dict) else {}
            quota = to_bytes(mb.get("ProhibitSendReceiveQuota")) or from_gigabytes(raw.get("ProhibitSendReceiveQuota"))
            return compact(
                {
                    "tenantFilter": tenantFilter,
                    "source": "live",
                    "userPrincipalName": user["userPrincipalName"],
                    "displayName": mb.get("DisplayName"),
                    "recipientTypeDetails": raw.get("RecipientTypeDetails"),
                    "mailbox": size_block(from_gigabytes(raw.get("TotalItemSize")), quota, raw.get("ItemCount")),
                    "archive": archive_block(
                        raw.get("ArchiveMailBox") is True,
                        from_gigabytes(raw.get("TotalArchiveItemSize")),
                        to_bytes(mb.get("ArchiveQuota")),
                        raw.get("TotalArchiveItemCount"),
                        raw.get("AutoExpandingArchive"),
                        raw.get("AutoExpandingArchiveScope"),
                    ),
                }
            )

        return await run_tool("cipp_get_mailbox_usage", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def cipp_set_out_of_office(
        tenantFilter: TenantFilter,
        upn: Upn,
        state: Annotated[Literal["Enabled", "Disabled", "Scheduled"], Field(description="Auto-reply state.")],
        internalMessage: Annotated[str | None, Field(description="Reply to internal senders (blank keeps current).")] = None,
        externalMessage: Annotated[str | None, Field(description="Reply to external senders (blank keeps current).")] = None,
        startTime: Annotated[str | None, Field(description="Scheduled only: start, ISO 8601 or epoch seconds (default now).")] = None,
        endTime: Annotated[str | None, Field(description="Scheduled only: end, ISO 8601 or epoch seconds (default start + 7 days).")] = None,
        timezone: Annotated[str | None, Field(description="Windows time zone name for the times.")] = None,
        createOOFEvent: Annotated[bool | None, Field(description="Scheduled only: add a calendar event.")] = None,
        oofEventSubject: Annotated[str | None, Field(description="Scheduled only: subject of that event.")] = None,
        autoDeclineFutureRequestsWhenOOF: Annotated[bool | None, Field(description="Scheduled only: decline new invites.")] = None,
        declineEventsForScheduledOOF: Annotated[bool | None, Field(description="Scheduled only: decline existing meetings.")] = None,
        declineMeetingMessage: Annotated[str | None, Field(description="Scheduled only: decline message.")] = None,
    ) -> str:
        """Turn a mailbox's automatic replies on, off or on a schedule. Only when the user explicitly asks."""

        async def action(client: CippClient) -> Any:
            given = {
                "startTime": startTime,
                "endTime": endTime,
                "createOOFEvent": createOOFEvent,
                "oofEventSubject": oofEventSubject,
                "autoDeclineFutureRequestsWhenOOF": autoDeclineFutureRequestsWhenOOF,
                "declineEventsForScheduledOOF": declineEventsForScheduledOOF,
                "declineMeetingMessage": declineMeetingMessage,
            }
            extra = [k for k in _SCHEDULED_ONLY if given[k] is not None]
            if state != "Scheduled" and extra:
                raise ValueError(f'{", ".join(extra)} can only be used when state is "Scheduled".')
            body: dict[str, Any] = {"tenantFilter": tenantFilter, "userId": upn, "AutoReplyState": label_value(state)}
            if internalMessage and internalMessage.strip():
                body["InternalMessage"] = internalMessage
            if externalMessage and externalMessage.strip():
                body["ExternalMessage"] = externalMessage
            if timezone and timezone.strip():
                body["timezone"] = timezone
            if state == "Scheduled":
                start = to_unix_seconds(startTime, "startTime") if startTime else None
                end = to_unix_seconds(endTime, "endTime") if endTime else None
                if start is not None and end is not None and end <= start:
                    raise ValueError(f"endTime ({endTime}) must be after startTime ({startTime}).")
                body |= compact(
                    {
                        "StartTime": start,
                        "EndTime": end,
                        "CreateOOFEvent": createOOFEvent,
                        "OOFEventSubject": oofEventSubject if oofEventSubject and oofEventSubject.strip() else None,
                        "AutoDeclineFutureRequestsWhenOOF": autoDeclineFutureRequestsWhenOOF,
                        "DeclineEventsForScheduledOOF": declineEventsForScheduledOOF,
                        "DeclineMeetingMessage": declineMeetingMessage if declineMeetingMessage and declineMeetingMessage.strip() else None,
                    }
                )
            return await client.post("ExecSetOoO", body)

        return await run_tool("cipp_set_out_of_office", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def cipp_set_email_forwarding(
        tenantFilter: TenantFilter,
        upn: Upn,
        forwardTo: Annotated[str | None, Field(description="Address to forward to; omit to turn forwarding off.")] = None,
        keepCopy: Annotated[bool | None, Field(description="Keep a copy in the mailbox (default true).")] = None,
    ) -> str:
        """Set or remove mailbox forwarding (internal or external address). Only when the user explicitly asks."""

        async def action(client: CippClient) -> Any:
            target = (forwardTo or "").strip()
            body: dict[str, Any] = {"tenantFilter": tenantFilter, "userID": upn, "KeepCopy": keepCopy is not False}
            if not target:
                body["forwardOption"] = "disabled"
                return await client.post("ExecEmailForward", body)
            if target.rfind("@") < 1:
                raise ValueError(f'forwardTo must be a full email address (got "{forwardTo}"). Omit it to disable forwarding.')
            domain = target.rpartition("@")[2].lower()
            domains = rows(await client.get("ListDomains", {"tenantFilter": tenantFilter}))
            internal = any(isinstance(d, dict) and str(d.get("id", "")).lower() == domain for d in domains)
            if internal:
                body |= {"forwardOption": "internalAddress", "ForwardInternal": label_value(target)}
            else:
                body |= {"forwardOption": "ExternalAddress", "ForwardExternal": target}
            return await client.post("ExecEmailForward", body)

        return await run_tool("cipp_set_email_forwarding", client_factory, action)

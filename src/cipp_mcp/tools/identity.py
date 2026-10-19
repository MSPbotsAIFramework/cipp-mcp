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
"""Users: lookup, lifecycle, security actions and sign-in history."""

import re
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient, CippError
from ._common import (
    DESTRUCTIVE,
    DESTRUCTIVE_ONCE,
    READ_ONLY,
    READ_ONLY_RUN,
    WRITES,
    WRITES_IDEMPOTENT,
    ClientFactory,
    TenantFilter,
    UserId,
    compact,
    interpret_results,
    is_all_tenants,
    label_value,
    resolve_user,
    run_tool,
)

Flag = Annotated[bool | None, Field(description="Set true to include this offboarding step.")]
Text = Annotated[str | None, Field(description="Optional.")]

# Offboarding switches, in the order they are sent.
_OFFBOARD_FLAGS = (
    "ConvertToShared",
    "HideFromGAL",
    "removeCalendarInvites",
    "removePermissions",
    "removeCalendarPermissions",
    "RemoveRules",
    "RemoveMobile",
    "RemoveGroups",
    "RemoveLicenses",
    "RevokeSessions",
    "DisableSignIn",
    "ClearImmutableId",
    "ResetPass",
    "RemoveMFADevices",
    "RemoveTeamsPhoneDID",
    "DeleteUser",
    "DisableOneDriveSharing",
    "disableForwarding",
)
_PREMIUM = re.compile(
    r"RequestFromNonPremiumTenant|(?:doesn't|does not|don't|do not) have (?:a |an )?premium licen[cs]e|premium licen[cs]e is required",
    re.IGNORECASE,
)


def _outcome(payload: Any, ok_status: str, ok_message: str, fail_prefix: str, **extra: Any) -> dict:
    results, failures = interpret_results(payload)
    failed = bool(failures)
    return {
        "status": "failed" if failed else ok_status,
        **extra,
        "results": results,
        "failures": failures,
        "message": f"{fail_prefix}. Do NOT report success to the caller: {' | '.join(failures)}" if failed else ok_message,
    }


def _sign_in_row(e: dict) -> dict:
    status = e.get("status") if isinstance(e.get("status"), dict) else {}
    code = status.get("errorCode")
    location = e.get("location") if isinstance(e.get("location"), dict) else {}
    place = ", ".join(str(location[k]) for k in ("city", "state", "countryOrRegion") if location.get(k))
    device = e.get("deviceDetail") if isinstance(e.get("deviceDetail"), dict) else {}
    policies = [
        compact({"name": p.get("displayName"), "result": p.get("result")})
        for p in e.get("appliedConditionalAccessPolicies") or []
        if isinstance(p, dict) and p.get("result") not in ("notApplied", "notEnabled", "unknownFutureValue")
    ]
    steps = [
        compact({"method": s.get("authenticationMethod"), "succeeded": s.get("succeeded"), "detail": s.get("authenticationStepResultDetail")})
        for s in e.get("authenticationDetails") or []
        if isinstance(s, dict)
    ]
    mfa = e.get("mfaDetail") if isinstance(e.get("mfaDetail"), dict) else {}
    methods = list(dict.fromkeys([s["method"] for s in steps if s.get("method")] + ([mfa["authMethod"]] if mfa.get("authMethod") else [])))
    risk = compact(
        {
            "level": next((v for v in (e.get("riskLevelDuringSignIn"), e.get("riskLevelAggregated")) if v not in (None, "", "none", "hidden", "unknownFutureValue")), None),
            "state": e.get("riskState") if e.get("riskState") not in (None, "", "none", "unknownFutureValue") else None,
            "detail": e.get("riskDetail") if e.get("riskDetail") not in (None, "", "none", "hidden", "unknownFutureValue") else None,
        }
    )
    return compact(
        {
            "time": e.get("createdDateTime") or None,
            "app": e.get("appDisplayName") or None,
            "resource": e.get("resourceDisplayName") or None,
            "ipAddress": e.get("ipAddress") or None,
            "location": place or None,
            "status": ("success" if code == 0 else "failure") if isinstance(code, int) else None,
            "errorCode": code if isinstance(code, int) else None,
            "failureReason": status.get("failureReason") if code not in (0, None) else None,
            "clientApp": e.get("clientAppUsed") or None,
            "conditionalAccessStatus": e.get("conditionalAccessStatus") or None,
            "conditionalAccessPolicies": [p for p in policies if p] or None,
            "authenticationRequirement": e.get("authenticationRequirement") or None,
            "authentication": compact({"steps": [s for s in steps if s] or None, "methods": methods or None, "detail": mfa.get("authDetail")}) or None,
            "device": compact(
                {
                    "name": device.get("displayName") or None,
                    "operatingSystem": device.get("operatingSystem") or None,
                    "browser": device.get("browser") or None,
                    "isCompliant": device.get("isCompliant") if isinstance(device.get("isCompliant"), bool) else None,
                    "isManaged": device.get("isManaged") if isinstance(device.get("isManaged"), bool) else None,
                    "trustType": device.get("trustType") or None,
                }
            ) or None,
            "risk": risk or None,
            "isInteractive": e.get("isInteractive") if isinstance(e.get("isInteractive"), bool) else None,
            "correlationId": e.get("correlationId") or None,
            "id": e.get("id") or None,
        }
    )


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_users(
        tenantFilter: TenantFilter,
        searchField: Annotated[
            Literal["displayName", "userPrincipalName", "mail"] | None, Field(description="Field to search.")
        ] = None,
        searchValue: Annotated[str | None, Field(description="Value to search for (displayName matches by prefix).")] = None,
    ) -> str:
        """List users of a tenant, optionally searched by display name (prefix), UPN or mail (exact)."""

        async def action(client: CippClient) -> Any:
            if (searchField is None) != (searchValue is None):
                raise ValueError("searchField and searchValue must be supplied together.")
            params: dict[str, Any] = {"tenantFilter": tenantFilter}
            if searchField and searchValue:
                value = searchValue.replace("'", "''")
                params["graphFilter"] = (
                    f"startsWith(displayName, '{value}')" if searchField == "displayName" else f"{searchField} eq '{value}'"
                )
            return await client.get("ListUsers", params)

        return await run_tool("cipp_list_users", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def cipp_create_user(
        tenantFilter: TenantFilter,
        displayName: Annotated[str, Field(description="Display name.")],
        userPrincipalName: Annotated[str, Field(description="Full UPN, user@domain.")],
        password: Annotated[str, Field(description="Initial password.")],
        givenName: Text = None,
        surname: Text = None,
        jobTitle: Text = None,
        department: Text = None,
        country: Annotated[str | None, Field(description="Country (ISO 3166 alpha-2).")] = None,
    ) -> str:
        """Create a Microsoft 365 user in a tenant. Changes the tenant: only when the user explicitly asks."""

        async def action(client: CippClient) -> Any:
            local, at, domain = userPrincipalName.strip().rpartition("@")
            if not at or not local or not domain:
                raise ValueError(f'userPrincipalName "{userPrincipalName}" must be a full UPN of the form user@domain.')
            body = compact(
                {
                    "tenantFilter": tenantFilter,
                    "username": local,
                    "Domain": domain,
                    "displayName": displayName,
                    "password": password,
                    "givenName": givenName,
                    "surname": surname,
                    "jobTitle": jobTitle,
                    "department": department,
                    "country": country,
                }
            )
            return await client.post("AddUser", body)

        return await run_tool("cipp_create_user", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def cipp_edit_user(
        tenantFilter: TenantFilter,
        userId: UserId,
        displayName: Text = None,
        jobTitle: Text = None,
        department: Text = None,
        usageLocation: Annotated[str | None, Field(description="Usage location, ISO 3166 alpha-2 (needed for licensing).")] = None,
        licenses: Annotated[list[str] | None, Field(description="License SKU ids to assign.")] = None,
        removeLicenses: Annotated[bool | None, Field(description="true removes every assigned licence.")] = None,
    ) -> str:
        """Edit a user's name, job, department, usage location or licences.

        Changes the tenant: only when the user explicitly asks.
        """

        async def action(client: CippClient) -> dict:
            if licenses and removeLicenses:
                raise ValueError("licenses and removeLicenses=true are mutually exclusive.")
            user = await resolve_user(
                client, tenantFilter, userId, "Refusing to edit: CIPP rewrites the UPN on every edit and needs the current one."
            )
            body: dict[str, Any] = {
                "tenantFilter": tenantFilter,
                "id": user["id"],
                "username": user["username"],
                "Domain": user["domain"],
            }
            body |= compact({"displayName": displayName, "jobTitle": jobTitle, "department": department})
            if usageLocation:
                body["usageLocation"] = label_value(usageLocation.strip().upper())
            if licenses:
                body["licenses"] = [{"value": sku} for sku in licenses]
                body["removeLicenses"] = False
            elif removeLicenses is not None:
                body["removeLicenses"] = removeLicenses
            upn = user["userPrincipalName"]
            return _outcome(
                await client.post("EditUser", body),
                "edited",
                f"User {upn} edited in {tenantFilter}.",
                f"CIPP returned HTTP 200 but reported failures editing {upn}",
                userPrincipalName=upn,
            )

        return await run_tool("cipp_edit_user", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def cipp_disable_user(tenantFilter: TenantFilter, userId: UserId) -> str:
        """Block sign-in for a user. Locks the person out: only when the user explicitly asks."""

        async def action(client: CippClient) -> Any:
            return await client.post("ExecDisableUser", {"tenantFilter": tenantFilter, "ID": userId})

        return await run_tool("cipp_disable_user", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE_ONCE)
    async def cipp_reset_password(
        tenantFilter: TenantFilter,
        userId: UserId,
        newPassword: Annotated[
            str | None, Field(description="Not supported: CIPP always generates the new password. Leave empty.")
        ] = None,
    ) -> str:
        """Reset a user's password; CIPP generates the new one and returns it.

        Locks out current sessions using the old password. Only when the user explicitly asks.
        """

        async def action(client: CippClient) -> Any:
            if newPassword:
                raise ValueError("CIPP generates the new password itself; newPassword cannot be set. Call again without it.")
            return await client.post("ExecResetPass", {"tenantFilter": tenantFilter, "ID": userId})

        return await run_tool("cipp_reset_password", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def cipp_reset_mfa(tenantFilter: TenantFilter, userId: UserId) -> str:
        """Remove a user's registered MFA methods so they must register again. Only when explicitly asked."""

        async def action(client: CippClient) -> Any:
            return await client.post("ExecResetMFA", {"tenantFilter": tenantFilter, "ID": userId})

        return await run_tool("cipp_reset_mfa", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def cipp_revoke_sessions(tenantFilter: TenantFilter, userId: UserId) -> str:
        """Sign a user out everywhere by revoking all refresh tokens. Only when the user explicitly asks."""

        async def action(client: CippClient) -> Any:
            body = {"tenantFilter": tenantFilter, "id": userId}
            if "@" in userId:
                body["Username"] = userId
            return await client.post("ExecRevokeSessions", body)

        return await run_tool("cipp_revoke_sessions", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE_ONCE)
    async def cipp_offboard_user(
        tenantFilter: TenantFilter,
        userId: UserId,
        DisableSignIn: Flag = None,
        RevokeSessions: Flag = None,
        ResetPass: Flag = None,
        RemoveLicenses: Flag = None,
        RemoveGroups: Flag = None,
        RemoveMFADevices: Flag = None,
        RemoveMobile: Flag = None,
        RemoveRules: Flag = None,
        RemoveTeamsPhoneDID: Flag = None,
        removeCalendarInvites: Flag = None,
        removePermissions: Flag = None,
        removeCalendarPermissions: Flag = None,
        ConvertToShared: Flag = None,
        HideFromGAL: Flag = None,
        disableForwarding: Flag = None,
        DisableOneDriveSharing: Flag = None,
        ClearImmutableId: Flag = None,
        DeleteUser: Flag = None,
        forward: Annotated[str | None, Field(description="Forward the mailbox to this UPN.")] = None,
        KeepCopy: Annotated[bool | None, Field(description="With forward: keep a copy in the mailbox.")] = None,
        OOO: Annotated[str | None, Field(description="Out-of-office message to set.")] = None,
        AccessAutomap: Annotated[list[str] | None, Field(description="UPNs to get full access (automapped).")] = None,
        AccessNoAutomap: Annotated[list[str] | None, Field(description="UPNs to get full access (not automapped).")] = None,
        OnedriveAccess: Annotated[list[str] | None, Field(description="UPNs to get access to the OneDrive.")] = None,
    ) -> str:
        """Queue an offboarding job for a leaver with the chosen steps (disable, licences, mailbox, ...).

        Irreversible steps included: only when the user explicitly asks. Success means queued, not done.
        """

        values = {
            "DisableSignIn": DisableSignIn, "RevokeSessions": RevokeSessions, "ResetPass": ResetPass,
            "RemoveLicenses": RemoveLicenses, "RemoveGroups": RemoveGroups, "RemoveMFADevices": RemoveMFADevices,
            "RemoveMobile": RemoveMobile, "RemoveRules": RemoveRules, "RemoveTeamsPhoneDID": RemoveTeamsPhoneDID,
            "removeCalendarInvites": removeCalendarInvites, "removePermissions": removePermissions,
            "removeCalendarPermissions": removeCalendarPermissions, "ConvertToShared": ConvertToShared,
            "HideFromGAL": HideFromGAL, "disableForwarding": disableForwarding,
            "DisableOneDriveSharing": DisableOneDriveSharing, "ClearImmutableId": ClearImmutableId,
            "DeleteUser": DeleteUser, "AccessAutomap": AccessAutomap, "AccessNoAutomap": AccessNoAutomap,
            "OnedriveAccess": OnedriveAccess,
        }

        async def action(client: CippClient) -> dict:
            body: dict[str, Any] = {}
            actions: list[str] = []
            for flag in _OFFBOARD_FLAGS:
                if values.get(flag) is True:
                    body[flag] = True
                    actions.append(flag)
            for key in ("AccessNoAutomap", "AccessAutomap", "OnedriveAccess"):
                if values.get(key):
                    body[key] = values[key]
                    actions.append(key)
            if forward and forward.strip():
                body["forward"] = {"value": forward.strip()}
                body["KeepCopy"] = KeepCopy is True
                actions.append("forward")
            if OOO and OOO.strip():
                body["OOO"] = OOO
                actions.append("OOO")
            if not actions:
                raise ValueError("No offboarding actions were selected; enable at least one (e.g. DisableSignIn, RemoveLicenses).")
            user = await resolve_user(
                client, tenantFilter, userId, "Refusing to queue offboarding: the job needs the account's current UPN."
            )
            upn = user["userPrincipalName"]
            payload = await client.post("ExecOffboardUser", {"tenantFilter": tenantFilter, "user": [label_value(upn)], **body})
            return _outcome(
                payload,
                "queued",
                f"Offboarding QUEUED for {upn} in {tenantFilter} with {len(actions)} action(s): {', '.join(actions)}. "
                "CIPP reports task creation, not completion; check CIPP's offboarding view before confirming.",
                f"CIPP returned HTTP 200 but reported failures queueing offboarding for {upn}",
                userPrincipalName=upn,
                actions=actions,
            )

        return await run_tool("cipp_offboard_user", client_factory, action)

    @mcp.tool(annotations=READ_ONLY_RUN)
    async def cipp_bec_check(
        tenantFilter: TenantFilter,
        userId: UserId,
        guid: Annotated[
            str | None, Field(description="Run id returned by an earlier call, to read that run's progress or results.")
        ] = None,
    ) -> str:
        """Run a business-email-compromise check for a user (rules, sign-ins, MFA changes, ...).

        The first call starts the run; call again with the returned GUID until Waiting is false.
        """

        async def action(client: CippClient) -> Any:
            if guid:
                return await client.get("ExecBECCheck", {"tenantFilter": tenantFilter, "GUID": guid})
            user = await resolve_user(client, tenantFilter, userId, "The check needs the user's object id and UPN.")
            body = {"tenantFilter": tenantFilter, "userid": user["id"], "userName": user["userPrincipalName"]}
            return await client.post("ExecBECCheck", body)

        return await run_tool("cipp_bec_check", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_mfa_users(tenantFilter: TenantFilter) -> str:
        """List users with their MFA registration and enforcement state (per-user MFA, CA, defaults)."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListMFAUsers", {"tenantFilter": tenantFilter})

        return await run_tool("cipp_list_mfa_users", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_user_devices(tenantFilter: TenantFilter, userId: UserId) -> str:
        """List the devices registered to or owned by a user."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListUserDevices", {"tenantFilter": tenantFilter, "UserID": userId})

        return await run_tool("cipp_list_user_devices", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_user_groups(tenantFilter: TenantFilter, userId: UserId) -> str:
        """List the groups a user belongs to."""

        async def action(client: CippClient) -> Any:
            return await client.get("ListUserGroups", {"tenantFilter": tenantFilter, "userId": userId})

        return await run_tool("cipp_list_user_groups", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_user_signin_logs(
        tenantFilter: TenantFilter,
        userId: UserId,
        top: Annotated[int | None, Field(description="Most recent sign-ins to return (1-1000, default 50).", ge=1, le=1000)] = None,
    ) -> str:
        """Get a user's recent interactive sign-ins: time, app, IP, location, result, MFA and CA outcome.

        Needs Entra ID P1/P2 in the tenant; one tenant only.
        """

        async def action(client: CippClient) -> dict:
            if is_all_tenants(tenantFilter):
                raise ValueError("cipp_list_user_signin_logs works on one tenant; name the user's own tenant.")
            limit = top or 50
            user = await resolve_user(client, tenantFilter, userId, "Sign-in logs are filtered by object id.")
            try:
                payload = await client.get("ListUserSigninLogs", {"tenantFilter": tenantFilter, "UserID": user["id"], "top": limit})
            except CippError as e:
                if _PREMIUM.search(e.message):
                    raise CippError(
                        400, f"Tenant {tenantFilter} needs an Entra ID P1 or P2 licence to serve sign-in logs through the API."
                    ) from e
                raise
            entries = payload if isinstance(payload, list) else ([] if payload is None else [payload])
            texts = [e for e in entries if isinstance(e, str)]
            if texts:
                raise CippError(502, f"CIPP returned a message instead of sign-in records: {'; '.join(texts)[:500]}")
            records = [e for e in entries if isinstance(e, dict)]
            sign_ins = [_sign_in_row(e) for e in records]
            times = sorted(s["time"] for s in sign_ins if s.get("time"))
            warnings = []
            if not sign_ins:
                warnings.append("No interactive sign-ins were returned (logs are kept for 30 days; non-interactive sign-ins are not included).")
            elif len(sign_ins) >= limit:
                warnings.append(f"Returned the {limit} most recent sign-ins; older ones may exist (raise top, max 1000).")
            return compact(
                {
                    "tenantFilter": tenantFilter,
                    "userId": user["id"],
                    "userPrincipalName": user["userPrincipalName"],
                    "requested": limit,
                    "returned": len(sign_ins),
                    "summary": {
                        "successful": sum(1 for s in sign_ins if s.get("status") == "success"),
                        "failed": sum(1 for s in sign_ins if s.get("status") == "failure"),
                        "distinctIpAddresses": len({s["ipAddress"] for s in sign_ins if s.get("ipAddress")}),
                        "countries": sorted(
                            {str(e["location"]["countryOrRegion"]) for e in records if isinstance(e.get("location"), dict) and e["location"].get("countryOrRegion")}
                        ),
                        "newest": times[-1] if times else None,
                        "oldest": times[0] if times else None,
                    },
                    "warnings": warnings or None,
                    "signIns": sign_ins,
                }
            )

        return await run_tool("cipp_list_user_signin_logs", client_factory, action)

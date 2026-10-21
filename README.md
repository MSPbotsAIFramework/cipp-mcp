# CIPP MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [CIPP](https://cipp.app) API
(CyberDrain Improved Partner Portal), the console MSPs use to manage many Microsoft 365
tenants through GDAP. It lets an AI agent read tenants, users, groups, mailboxes, conditional
access, standards, licences and GDAP data from a CIPP instance and, on explicit request, make
changes such as creating or editing users, resetting passwords, offboarding leavers, setting
auto-replies or forwarding, and running standards.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored; OAuth tokens live only for the duration of one request
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

## Authentication headers

`X-Base-Url` is always required. Then send **either** `X-Api-Key` **or** the three OAuth
headers `X-Tenant-Id` + `X-Client-Id` + `X-Client-Secret`.

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Base-Url` | Yes | string | none | https URL | URL of the CIPP API backend (Azure Function App) | `https://cipp.example.com` |
| `X-Api-Key` | One of | string | none | - | A pre-issued bearer token for the CIPP API | `your-cipp-token` |
| `X-Tenant-Id` | One of | string | none | - | Partner (MSP) Entra tenant id that hosts the CIPP API client | `00000000-0000-0000-0000-000000000000` |
| `X-Client-Id` | One of | string | none | - | Application (client) id of the CIPP API client | `00000000-0000-0000-0000-000000000000` |
| `X-Client-Secret` | One of | string | none | - | Client secret of the CIPP API client | `your-client-secret` |
| `X-Token-Scope` | No | string | `api://{clientId}/.default` | - | Override the OAuth scope (disables the fallback) | `api://00000000-0000-0000-0000-000000000000/.default` |
| `X-Token-Url` | No | string | `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token` | https URL | Override the token endpoint | - |
| `X-Token-Scope-Fallback` | No | string | on | `0`, `false`, `off`, `no` to disable | Retry once with scope `{clientId}/.default` when the first scope is rejected | `false` |

Where to get them:

- In CIPP open **Settings -> Integrations -> CIPP-API** (API client management) and create a
  new API client. CIPP shows the application (client) id and secret once;
  copy them together with your partner tenant id. Assign the client a role that covers the
  tools you want (read-only roles are enough for the list tools).
- The base URL must be the CIPP API backend (the Azure Function App URL), not the address of
  the CIPP web front end.
- CIPP checks each API client against its allowed IP range; allow the public egress IP of the environment
  that runs this server.

How credentials are sent to CIPP: every call is `Authorization: Bearer <token>` to
`{X-Base-Url}/api/{Function}`. With the OAuth headers the server runs the client-credentials
flow against Entra ID first; values that look like unresolved templates (`${...}`) are treated
as missing.

A request to `/mcp` without the required headers gets HTTP 401 listing them. A non-https URL
does not block `tools/list`; tool calls then return an `invalid_argument` error and the URL is
never called.

## Tools

All tools return a JSON string. `tenantFilter` is a tenant's default domain (for example
`example.onmicrosoft.com`) or tenant id from `cipp_list_tenants`; tools that say so accept
`AllTenants`. `userId` accepts an object id or a UPN.

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `cipp_ping` | Check the CIPP instance is reachable (no auth check; use cipp_get_version for that) | - |
| `cipp_get_version` | Get the CIPP frontend/API versions and whether an update is available (also validates credentials) | - |
| `cipp_list_logs` | List CIPP's own activity log (actions run, standards applied, errors) for one day | dateFilter |
| `cipp_list_tenants` | List the customer tenants managed through CIPP: name, default domain and tenant id | allTenants |
| `cipp_get_tenant_details` | Get a tenant's organisation details: verified domains, address, technical contacts, sync settings | **tenantFilter** |
| `cipp_list_users` | List users of a tenant, optionally searched by display name (prefix), UPN or mail (exact) | **tenantFilter**, searchField (`displayName`, `userPrincipalName`, `mail`), searchValue |
| `cipp_create_user` | Create a Microsoft 365 user in a tenant (**write**) | **tenantFilter**, **displayName**, **userPrincipalName**, **password**, givenName, surname, jobTitle, department, country |
| `cipp_edit_user` | Edit a user's name, job, department, usage location or licences (**write**) | **tenantFilter**, **userId**, displayName, jobTitle, department, usageLocation, licenses, removeLicenses |
| `cipp_disable_user` | Block sign-in for a user (**write**) | **tenantFilter**, **userId** |
| `cipp_reset_password` | Reset a user's password; CIPP generates the new one and returns it (**write**) | **tenantFilter**, **userId**, newPassword |
| `cipp_reset_mfa` | Remove a user's registered MFA methods so they must register again (**write**) | **tenantFilter**, **userId** |
| `cipp_revoke_sessions` | Sign a user out everywhere by revoking all refresh tokens (**write**) | **tenantFilter**, **userId** |
| `cipp_offboard_user` | Queue an offboarding job for a leaver with the chosen steps (disable, licences, mailbox, ...) (**write**) | **tenantFilter**, **userId**, DisableSignIn, RevokeSessions, ResetPass, RemoveLicenses, RemoveGroups, RemoveMFADevices, RemoveMobile, RemoveRules, RemoveTeamsPhoneDID, removeCalendarInvites, removePermissions, removeCalendarPermissions, ConvertToShared, HideFromGAL, disableForwarding, DisableOneDriveSharing, ClearImmutableId, DeleteUser, forward, KeepCopy, OOO, AccessAutomap, AccessNoAutomap, OnedriveAccess |
| `cipp_bec_check` | Run a business-email-compromise check for a user (rules, sign-ins, MFA changes, ...) | **tenantFilter**, **userId**, guid |
| `cipp_list_mfa_users` | List users with their MFA registration and enforcement state (per-user MFA, CA, defaults) | **tenantFilter** |
| `cipp_list_user_devices` | List the devices registered to or owned by a user | **tenantFilter**, **userId** |
| `cipp_list_user_groups` | List the groups a user belongs to | **tenantFilter**, **userId** |
| `cipp_list_user_signin_logs` | Get a user's recent interactive sign-ins: time, app, IP, location, result, MFA and CA outcome | **tenantFilter**, **userId**, top |
| `cipp_list_groups` | List groups of a tenant: name, type (security, M365, distribution), mail, membership rule | **tenantFilter**, search |
| `cipp_create_group` | Create a group in a tenant (**write**) | **tenantFilter**, **displayName**, description, securityEnabled, mailEnabled, mailNickname |
| `cipp_list_mailboxes` | List Exchange mailboxes of a tenant: UPN, display name, type, aliases | **tenantFilter**, type (`UserMailbox`, `SharedMailbox`, `RoomMailbox`, `EquipmentMailbox`) |
| `cipp_list_mailbox_permissions` | List who has full access, send-as or send-on-behalf permission on a mailbox | **tenantFilter**, **upn** |
| `cipp_list_trusted_blocked_senders` | List a mailbox's personal trusted (safe) and blocked senders and domains. Empty means none set | **tenantFilter**, **upn** |
| `cipp_list_mailbox_usage` | Rank mailboxes by size, archive size or quota use, with tenant totals, from CIPP's daily cache | **tenantFilter**, sortBy (`mailboxSize`, `archiveSize`, `totalSize`, `percentOfQuota`), limit, minSizeGB |
| `cipp_get_mailbox_usage` | Get one mailbox's live size, item count, quota use and archive status | **tenantFilter**, **upn** |
| `cipp_set_out_of_office` | Turn a mailbox's automatic replies on, off or on a schedule (**write**) | **tenantFilter**, **upn**, **state** (`Enabled`, `Disabled`, `Scheduled`), internalMessage, externalMessage, startTime, endTime, timezone, createOOFEvent, oofEventSubject, autoDeclineFutureRequestsWhenOOF, declineEventsForScheduledOOF, declineMeetingMessage |
| `cipp_set_email_forwarding` | Set or remove mailbox forwarding (internal or external address) (**write**) | **tenantFilter**, **upn**, forwardTo, keepCopy |
| `cipp_list_conditional_access_policies` | List a tenant's conditional access policies with state, conditions and grant controls | **tenantFilter** |
| `cipp_list_named_locations` | List conditional access named locations (trusted IP ranges and countries) | **tenantFilter** |
| `cipp_list_enterprise_apps` | List enterprise applications (service principals) consented in a tenant: name, publisher, created | **tenantFilter**, includeBuiltIn |
| `cipp_list_domain_health` | Check SPF, DMARC and DKIM records for each custom domain of a tenant | **tenantFilter** |
| `cipp_get_secure_score` | Get a tenant's Microsoft Secure Score: latest score and percent, peer averages, daily history (newest first) | **tenantFilter** (one tenant, not AllTenants), top (1-90, default 7) |
| `cipp_list_secure_score_controls` | List a tenant's Secure Score improvement actions by rank: category, max points, user impact, cost, tier, short remediation | **tenantFilter** (one tenant, not AllTenants) |
| `cipp_list_audit_logs` | List audit-log alert entries CIPP collected for a tenant (sign-in, mailbox rule, admin changes) | **tenantFilter**, days, type |
| `cipp_list_alert_queue` | List the alert rules and scheduled alert jobs configured in CIPP | - |
| `cipp_list_standards` | List the standards applied to a tenant and their settings | **tenantFilter** |
| `cipp_run_standards_check` | Run the standards assigned to a tenant now; remediating standards change the tenant (**write**) | **tenantFilter** |
| `cipp_list_standard_templates` | List the standards templates (id, name, assigned tenants, standards) | - |
| `cipp_get_tenant_drift` | Show where tenants have drifted from their drift-standard templates (accepted / denied deviations) | tenantFilter |
| `cipp_get_tenant_alignment` | Show how well tenants align with their standards templates (percentage compliant per template) | tenantFilter |
| `cipp_create_standard_template` | Create a standards template; standards apply to its tenants on the next run (**write**) | **template** |
| `cipp_delete_standard_template` | Delete a standards template (**write**) | **templateId** |
| `cipp_list_bpa` | Get the Best Practice Analyser report for a tenant (older CIPP versions only) | **tenantFilter** |
| `cipp_list_licenses` | List a tenant's licence SKUs with purchased, assigned and available counts | **tenantFilter** |
| `cipp_list_csp_licenses` | List CSP licence subscriptions bought through the CSP integration for tenants | tenantFilter |
| `cipp_list_gdap_roles` | List the GDAP role mappings (Entra roles to partner security groups) set up in CIPP | - |
| `cipp_list_gdap_invites` | List GDAP relationship invites created in CIPP and their status | - |
| `cipp_list_scheduled_items` | List tasks in CIPP's scheduler: name, command, tenant, next run, state and results | - |
| `cipp_add_scheduled_item` | Schedule a CIPP command to run once or on a recurrence (**write**) | **taskName**, **command**, **scheduledTime**, recurrence, tenantFilter, parameters |

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "CIPP returned HTTP 401 for ListTenants", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`. Reads are retried with backoff on 429, 5xx and network
errors; writes are retried only on 429, so a write never runs twice.

## Run locally

```bash
uv sync
uv run python -m cipp_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t cipp-mcp:dev .
docker run --rm -p 8080:8080 cipp-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). Credentials are never read
from the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Base-Url: https://cipp.example.com" \
  -H "X-Tenant-Id: your-partner-tenant-id" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# managed tenants
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Base-Url: https://cipp.example.com" \
  -H "X-Api-Key: your-cipp-token" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cipp_list_tenants","arguments":{}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool count (47).** Kept as is because the tool names are an existing contract.
- **Write tools.** The 14 tools marked **write** change live Microsoft 365 tenants; their
  descriptions tell the agent to use them only on explicit request. `cipp_disable_user`,
  `cipp_reset_password`, `cipp_reset_mfa`, `cipp_revoke_sessions`, `cipp_offboard_user` and
  `cipp_delete_standard_template` are annotated destructive.
- **Queued jobs.** `cipp_offboard_user` and `cipp_add_scheduled_item` report whether CIPP
  accepted the job, not whether it finished; CIPP failures returned with HTTP 200 are detected
  and reported as `failed`.
- **Passwords.** `cipp_reset_password` lets CIPP generate the new password; a caller-chosen
  `newPassword` is rejected rather than silently ignored.
- **Cached vs live sizes.** `cipp_list_mailbox_usage` reads CIPP's daily report cache (fast,
  whole tenant, up to 24 h old); `cipp_get_mailbox_usage` reads one mailbox live.
- **Result size exception (SOP 2.5).** `cipp_list_user_signin_logs` (`top`) and
  `cipp_list_mailbox_usage` (`limit`) have no paging in the API, so they keep a maximum of 1000
  (default 50); results are still cut to 20,000 characters with a truncation notice.
- **Version differences.** `cipp_list_bpa` exists only on older CIPP versions and returns a
  clear `not_found` pointing to `cipp_get_tenant_alignment` otherwise.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).

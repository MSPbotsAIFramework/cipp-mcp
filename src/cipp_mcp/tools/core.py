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
"""Instance health, version and CIPP's own activity log."""

import re
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import CippClient
from ._common import READ_ONLY, ClientFactory, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def cipp_ping() -> str:
        """Check the CIPP instance is reachable (no auth check; use cipp_get_version for that)."""

        async def action(client: CippClient) -> Any:
            result = await client.get("PublicPing")
            return {"reachable": True, "base_url": client.base_url, "response": result}

        return await run_tool("cipp_ping", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_get_version() -> str:
        """Get the CIPP frontend/API versions and whether an update is available (also validates credentials)."""

        async def action(client: CippClient) -> Any:
            return await client.get("GetVersion")

        return await run_tool("cipp_get_version", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def cipp_list_logs(
        dateFilter: Annotated[str | None, Field(description="Day to read, YYYY-MM-DD or YYYYMMDD (default today).")] = None,
    ) -> str:
        """List CIPP's own activity log (actions run, standards applied, errors) for one day."""

        async def action(client: CippClient) -> Any:
            params: dict[str, Any] = {}
            if dateFilter:
                day = re.sub(r"[^0-9]", "", dateFilter)
                if len(day) != 8:
                    raise ValueError(f'dateFilter must be a date like "2026-06-01"; got "{dateFilter}".')
                params = {"Filter": True, "DateFilter": day}
            return await client.get("ListLogs", params)

        return await run_tool("cipp_list_logs", client_factory, action)

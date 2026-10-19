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
"""Tool discovery (kept for compatibility) and the connection check."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import compact as to_json
from ..api_client import SpamTitanClient
from ._common import LOCAL, READ_ONLY, ClientFactory, run_tool

DOMAINS: dict[str, tuple[str, list[str]]] = {
    "quarantine": (
        "Quarantined mail: list, inspect, release, delete.",
        ["spamtitan_get_queue", "spamtitan_get_message", "spamtitan_release_message", "spamtitan_delete_message"],
    ),
    "lists": ("Sender allow / block lists: list, add, remove.", ["spamtitan_manage_allowlist", "spamtitan_manage_blocklist"]),
    "stats": ("Mail flow statistics over a period.", ["spamtitan_get_stats"]),
}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=LOCAL)
    async def spamtitan_navigate(
        domain: Annotated[Literal["quarantine", "lists", "stats"], Field(description="Area to describe.")],
    ) -> str:
        """Describe the tools of one SpamTitan area. All tools are already callable; this changes nothing."""
        summary, tools = DOMAINS[domain]
        return to_json({"domain": domain, "summary": summary, "tools": tools})

    @mcp.tool(annotations=READ_ONLY)
    async def spamtitan_status() -> str:
        """Check the SpamTitan connection (server reachable, token accepted) and list the tool areas."""

        async def action(client: SpamTitanClient) -> dict:
            await client.get("quarantine", {"results": 1, "page": 1})
            return {
                "connected": True,
                "server": client.base_url,
                "domains": {name: summary for name, (summary, _tools) in DOMAINS.items()},
            }

        return await run_tool("spamtitan_status", client_factory, action)

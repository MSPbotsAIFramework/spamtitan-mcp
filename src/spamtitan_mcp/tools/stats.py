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
"""Mail flow statistics (scan summary report)."""

from datetime import date, timedelta
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import SpamTitanClient
from ._common import READ_ONLY, ClientFactory, compact, run_tool, strip_meta

Period = Literal["today", "yesterday", "last_7_days", "last_30_days", "last_90_days"]
_ROLLING_DAYS = {"last_7_days": 7, "last_30_days": 30, "last_90_days": 90}
_COUNTERS = ("clean_messages", "spam_messages", "virus_messages", "banned_messages")


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def spamtitan_get_stats(
        period: Annotated[Period | None, Field(description="Time period (default today).")] = None,
        domain: Annotated[str | None, Field(description="Only mail for this domain, e.g. example.com.")] = None,
    ) -> str:
        """Mail flow totals for a period: clean, spam, virus and banned messages, and rejected connections."""

        async def action(client: SpamTitanClient) -> dict:
            chosen = period or "today"
            if chosen in _ROLLING_DAYS:
                today = date.today()
                params = {"start": (today - timedelta(days=_ROLLING_DAYS[chosen] - 1)).isoformat(), "end": today.isoformat()}
            else:
                params = {"period": chosen}
            params |= compact({"domain": (domain or "").strip().lower() or None})
            report = strip_meta(await client.get("reports/scan-summary", params)) or {}
            scanned = sum(v for k in _COUNTERS if isinstance(v := report.get(k), int))
            blocked = sum(v for k in _COUNTERS[1:] if isinstance(v := report.get(k), int))
            return compact(
                {
                    "period": chosen,
                    "domain": domain or "all",
                    "stats": report,
                    "scanned_messages": scanned,
                    "blocked_percent": round(blocked / scanned * 100, 1) if scanned else None,
                }
            )

        return await run_tool("spamtitan_get_stats", client_factory, action)

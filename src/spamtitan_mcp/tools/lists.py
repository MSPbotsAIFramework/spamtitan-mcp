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
"""Global sender allow list and block list."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import SpamTitanClient, SpamTitanError
from ._common import LIST_CHANGE, ClientFactory, compact, rows, run_tool, strip_meta

Action = Annotated[Literal["add", "remove", "list"], Field(description="add, remove or list entries.")]
Sender = Annotated[
    str | None,
    Field(description="Sender address or domain, e.g. user@example.com or @example.com. Needed for add / remove; filters list."),
]
Note = Annotated[str | None, Field(description="Comment stored with an added entry.")]

_LIST_SIZE = 500
_ENTRY_FIELDS = ("id", "sender", "include_subdomains", "comment", "created_at", "lastmodified")


def _entry(record: dict) -> dict:
    entry = {k: record.get(k) for k in _ENTRY_FIELDS if k in record}
    recipient = record.get("recipient")
    if isinstance(recipient, dict):
        entry["applies_to"] = recipient.get("comment") or recipient.get("email")
    return entry


def _sender(value: str | None, action: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        raise ValueError(f"sender is required when action is '{action}'.")
    if " " in text or "@" not in text:
        raise ValueError(f"sender must be an address (user@example.com) or a domain written as @example.com (got {value!r}).")
    return text


async def _manage(client: SpamTitanClient, path: str, label: str, action: str, sender: str | None, note: str | None) -> Any:
    if action == "list":
        params = compact({"filter": (sender or "").strip() or None, "results": _LIST_SIZE, "page": 1, "sortdir": "asc"})
        payload = await client.get(path, params)
        entries = [_entry(r) for r in rows(payload)]
        total = payload.get("total") if isinstance(payload, dict) else None
        return compact({label: entries, "count": len(entries), "total": total, "has_more": isinstance(total, int) and total > len(entries)})

    address = _sender(sender, action)
    if action == "add":
        created = await client.post(path, compact({"sender": address, "comment": (note or "").strip() or None}))
        return {"status": "added", "list": label, "sender": address, "entry": _entry(strip_meta(created) or {})}

    # Entries are deleted by id, so find the ones for this sender first.
    payload = await client.get(path, {"filter": address, "results": _LIST_SIZE, "page": 1})
    matches = [r for r in rows(payload) if str(r.get("sender") or "").lower() == address and r.get("id") is not None]
    if not matches:
        raise SpamTitanError(404, f"{address} is not on the {label}.")
    for record in matches:
        await client.delete(f"{path}/{int(record['id'])}")
    return {"status": "removed", "list": label, "sender": address, "removed_ids": [r["id"] for r in matches]}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=LIST_CHANGE)
    async def spamtitan_manage_allowlist(action: Action, sender: Sender = None, note: Note = None) -> str:
        """View or change the sender allow list; allowed senders bypass spam filtering.

        add / remove change delivery for everyone covered: only when the user explicitly asks.
        """

        async def run(client: SpamTitanClient) -> Any:
            return await _manage(client, "allow-list", "allowlist", action, sender, note)

        return await run_tool("spamtitan_manage_allowlist", client_factory, run)

    @mcp.tool(annotations=LIST_CHANGE)
    async def spamtitan_manage_blocklist(action: Action, sender: Sender = None, note: Note = None) -> str:
        """View or change the sender block list; blocked senders are always rejected or held.

        add / remove change delivery for everyone covered: only when the user explicitly asks.
        """

        async def run(client: SpamTitanClient) -> Any:
            return await _manage(client, "block-list", "blocklist", action, sender, note)

        return await run_tool("spamtitan_manage_blocklist", client_factory, run)

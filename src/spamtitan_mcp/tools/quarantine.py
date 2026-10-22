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
"""Quarantine: list, inspect, release and delete held mail."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import SpamTitanClient, SpamTitanError
from ._common import message_id as clean_message_id
from ._common import (
    DELETE,
    READ_ONLY,
    RELEASE,
    ClientFactory,
    MessageId,
    Offset,
    compact,
    enum_value,
    locate,
    rows,
    run_tool,
    strip_meta,
)

# Fields kept in queue listings; the full record is available from get_message.
_SUMMARY_FIELDS = (
    "id", "sender", "recipient", "subject", "spam_level", "content_type", "virus", "content_filter",
    "message_received", "country_of_origin", "client_address", "quarantined",
)
_CONTENT_TYPES = {"S": "spam", "V": "virus", "B": "banned", "C": "clean", "H": "bad header", "O": "oversized", "U": "unchecked"}

Reason = Literal["spam", "virus", "banned", "content-filter", "archive", "all"]


def _summary(message: dict) -> dict:
    summary = {k: message.get(k) for k in _SUMMARY_FIELDS if message.get(k) is not None}
    kind = _CONTENT_TYPES.get(str(message.get("content_type") or ""))
    if kind:
        summary["category"] = kind
    return summary


async def _secret_id(client: SpamTitanClient, mid: str) -> str:
    """Release and delete need the message's secret_id, which only the detail record carries."""
    record = await client.get(f"quarantine/{mid}")
    secret = record.get("secret_id") if isinstance(record, dict) else None
    if not secret:
        raise SpamTitanError(404, f"Quarantined message {mid} was not found or has no secret_id.")
    return str(secret)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def spamtitan_get_queue(
        page: Annotated[int | None, Field(description="Page number, from 1.", ge=1)] = None,
        per_page: Annotated[int | None, Field(description="Messages per page (1-200, default 50).", ge=1, le=200)] = None,
        sender: Annotated[str | None, Field(description="Sender address; * is a wildcard, e.g. *@example.com.")] = None,
        recipient: Annotated[str | None, Field(description="Recipient address; * is a wildcard.")] = None,
        subject: Annotated[str | None, Field(description="Subject; * is a wildcard, e.g. *invoice*.")] = None,
        reason: Annotated[Reason | str | None, Field(description="Why it was held (default all).")] = None,
        offset: Offset = None,
    ) -> str:
        """List quarantined mail, newest first: sender, recipient, subject, spam score and category."""

        async def action(client: SpamTitanClient) -> dict:
            current, size, start = locate(offset, page, per_page)
            held = enum_value(reason, Reason)
            params = compact(
                {
                    "sender": sender,
                    "recipient": recipient,
                    "subject": subject,
                    "type": held if held and held != "all" else None,
                    "sortkey": "message_received",
                    "sortdir": "desc",
                    "results": size,
                    "page": current,
                }
            )
            payload = await client.get("quarantine", params)
            listed = [_summary(m) for m in rows(payload)]
            messages = listed[start - (current - 1) * size :]
            total = payload.get("total") if isinstance(payload, dict) else None
            more = (current * size < total) if isinstance(total, int) else len(listed) >= size
            return compact(
                {
                    "messages": messages,
                    "count": len(messages),
                    "total": total,
                    "page": current,
                    "per_page": size,
                    "has_more": more,
                    "offset": start,
                    # Continues right after the last message returned, also when the result is cut
                    # to fit the size limit (a page number cannot: the rest of a cut page is on no other page).
                    "next_offset": start + len(messages) if more else None,
                    "_resume": {"key": "next_offset", "start": start},
                }
            )

        return await run_tool("spamtitan_get_queue", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def spamtitan_get_message(message_id: MessageId) -> str:
        """Get one quarantined message: sender, recipient, subject, spam score, virus / filter hit, country."""

        async def action(client: SpamTitanClient) -> Any:
            record = strip_meta(await client.get(f"quarantine/{clean_message_id(message_id)}"))
            if isinstance(record, dict):
                record.pop("secret_id", None)
                kind = _CONTENT_TYPES.get(str(record.get("content_type") or ""))
                if kind:
                    record["category"] = kind
            return record

        return await run_tool("spamtitan_get_message", client_factory, action)

    @mcp.tool(annotations=RELEASE)
    async def spamtitan_release_message(
        message_id: MessageId,
        forward_to: Annotated[str | None, Field(description="Deliver to this address instead of the original recipient.")] = None,
    ) -> str:
        """Release a quarantined message to its recipient (or forward_to). Only when the user explicitly asks.

        Held mail can be malicious: release only the exact message the user confirmed.
        """

        async def action(client: SpamTitanClient) -> dict:
            mid = clean_message_id(message_id)
            body = compact({"secret_id": await _secret_id(client, mid), "forward_to": (forward_to or "").strip() or None})
            result = await client.post(f"quarantine/{mid}", body) or {}
            released = result.get("released") if isinstance(result, dict) else None
            return compact(
                {
                    "message_id": mid,
                    "released": released if isinstance(released, bool) else True,
                    "delivered_to": body.get("forward_to") or "original recipient",
                }
            )

        return await run_tool("spamtitan_release_message", client_factory, action)

    @mcp.tool(annotations=DELETE)
    async def spamtitan_delete_message(message_id: MessageId) -> str:
        """Permanently delete a quarantined message. Irreversible: only when the user explicitly asks for it."""

        async def action(client: SpamTitanClient) -> dict:
            mid = clean_message_id(message_id)
            result = await client.delete(f"quarantine/{mid}", {"secret_id": await _secret_id(client, mid)}) or {}
            deleted = result.get("deleted") if isinstance(result, dict) else None
            return {"message_id": mid, "deleted": deleted if isinstance(deleted, bool) else True}

        return await run_tool("spamtitan_delete_message", client_factory, action)


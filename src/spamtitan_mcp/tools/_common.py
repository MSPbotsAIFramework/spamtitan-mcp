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
"""Shared argument types, response helpers and the error-handling wrapper."""

import logging
import re
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, get_args

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import SpamTitanClient, SpamTitanError

logger = logging.getLogger("spamtitan_mcp.tools")

ClientFactory = Callable[[], SpamTitanClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
LOCAL = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
RELEASE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True)
DELETE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)
LIST_CHANGE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured", "SpamTitan credentials are missing for this request (X-SpamTitan-API-Key and X-SpamTitan-Base-URL).", False
)

_MESSAGE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

MessageId = Annotated[str, Field(description="Quarantined message id from spamtitan_get_queue.", min_length=1)]
Offset = Annotated[
    int | None,
    Field(description="Record position to start from (0-based, overrides page); pass next_offset from the previous result.", ge=0),
]

DEFAULT_PAGE_SIZE = 50


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


def locate(offset: int | None, page: int | None, page_size: int | None) -> tuple[int, int, int]:
    """(page, page size, start) for a read from record ``start``.

    SpamTitan pages by number only, so a position is reached by asking for the page that
    holds it (same page size) and skipping the records before it.
    """
    size = page_size or DEFAULT_PAGE_SIZE
    start = offset if offset is not None else ((page or 1) - 1) * size
    return start // size + 1, size, start


def message_id(value: str) -> str:
    """Message ids go into the URL path; SpamTitan uses short alphanumeric ids."""
    text = value.strip()
    if not _MESSAGE_ID.match(text):
        raise ValueError(f"message_id must be the id from spamtitan_get_queue (got {value!r}).")
    return text


def rows(payload: Any) -> list[dict]:
    items = payload.get("data") if isinstance(payload, dict) else payload
    return [i for i in items or [] if isinstance(i, dict)] if isinstance(items, list) else []


def strip_meta(record: Any) -> Any:
    """Drop the "object" / "code" envelope keys SpamTitan adds to single records."""
    if isinstance(record, dict):
        return {k: v for k, v in record.items() if k not in ("object", "code")}
    return record


def enum_value(value: Any, choices: Any) -> Any:
    """Canonical spelling of a case-insensitive match in ``choices`` (a Literal type).

    Any other value passes through unchanged, so the API decides (older callers sent free text).
    """
    if not isinstance(value, str):
        return value
    wanted = value.strip().lower()
    return next((c for c in get_args(choices) if isinstance(c, str) and c.lower() == wanted), value)


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[SpamTitanClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        result = await action(client)
    except SpamTitanError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if result is None:
        result = {"result": None, "note": "SpamTitan returned an empty response."}
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)

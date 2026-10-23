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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import SpamTitanClient, SpamTitanCredentials
from .config import Settings

HEADER_API_KEY = "X-SpamTitan-API-Key"
HEADER_BASE_URL = "X-SpamTitan-Base-URL"
REQUIRED_HEADERS = [HEADER_API_KEY, HEADER_BASE_URL]

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")
_BEARER = re.compile(r"^bearer(\s+|$)", re.IGNORECASE)
_API_SUFFIX = re.compile(r"/restapi/?$", re.IGNORECASE)
_LOCAL_HOSTS = {"localhost", "127.0.0.1"}

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[SpamTitanCredentials | None] = contextvars.ContextVar(
    "spamtitan_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("spamtitan_request_id", default="-")

INSTRUCTIONS = (
    "SpamTitan filters inbound email for an MSP's customers: it quarantines "
    "spam, viruses and banned content and applies allow / block lists. This "
    "server works with one SpamTitan server through its REST API.\n"
    "Usage:\n"
    "- Find held mail: spamtitan_get_queue(recipient / sender / subject, "
    "wildcards with *), then spamtitan_get_message(message_id) for details "
    "such as spam score and the reason it was held.\n"
    "- A user asking for a missing email: search the queue by recipient, show "
    "the candidates, and release only the message the user confirms.\n"
    "- spamtitan_manage_allowlist / spamtitan_manage_blocklist with "
    "action=list to view entries, add / remove to change them.\n"
    "- spamtitan_get_stats for mail flow totals (clean, spam, virus, banned, "
    "rejected) over a period.\n"
    "Releasing delivers mail that may be malicious, deleting is permanent, and "
    "list changes alter delivery for everyone they cover: call those only "
    "when the user explicitly asks, for the exact message or sender named."
)


def get_client_from_context() -> SpamTitanClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return SpamTitanClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def normalize_base_url(value: str) -> str | None:
    """https root of the SpamTitan server (no trailing /restapi), or None when unusable."""
    text = value.strip()
    if "://" not in text:
        text = f"https://{text}"
    parts = urlsplit(text)
    if not parts.hostname:
        return None
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS):
        return None
    path = _API_SUFFIX.sub("", parts.path.rstrip("/"))
    return f"{parts.scheme}://{parts.netloc}{path}".rstrip("/")


class GatewayCredentialsMiddleware:
    """Reads the SpamTitan headers on /mcp requests into the request context.

    Needs X-SpamTitan-API-Key and X-SpamTitan-Base-URL; otherwise 401.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        api_key = _clean(request.headers.get(HEADER_API_KEY))
        if api_key:
            api_key = _clean(_BEARER.sub("", api_key))
        base_raw = _clean(request.headers.get(HEADER_BASE_URL))
        missing = [name for name, value in ((HEADER_API_KEY, api_key), (HEADER_BASE_URL, base_raw)) if not value]
        if missing:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Missing header(s): {', '.join(missing)}",
                    "required_headers": REQUIRED_HEADERS,
                },
                status_code=401,
            )(scope, receive, send)
            return

        base_url = normalize_base_url(base_raw or "")
        if base_url is None:
            await JSONResponse(
                {"error": "Invalid header", "message": f"{HEADER_BASE_URL} must be an https URL such as https://spamtitan.example.com"},
                status_code=400,
            )(scope, receive, send)
            return

        credentials = SpamTitanCredentials(base_url=base_url, api_key=api_key or "")
        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(credentials)
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = EnvelopeFastMCP(
        name="spamtitan-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], SpamTitanClient | None] = get_client_from_context

    from .tools import lists, navigation, quarantine, stats

    for module in (navigation, quarantine, lists, stats):
        module.register(mcp, client_factory)

    return mcp

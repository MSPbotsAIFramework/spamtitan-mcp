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
"""Auth, retries and request shapes against a mocked SpamTitan REST API."""

import json
from datetime import date, timedelta

import httpx
import pytest

from spamtitan_mcp import api_client
from spamtitan_mcp.api_client import SpamTitanClient, SpamTitanCredentials, SpamTitanError
from spamtitan_mcp.server import _credentials_var, create_mcp_server

BASE = "https://spamtitan.example.com"
CREDS = SpamTitanCredentials(base_url=BASE, api_key="tok-1")
MESSAGE = {
    "id": "0c7fuE5s87wJ",
    "secret_id": "U86w74oNRPbq",
    "sender": "offers@example.org",
    "recipient": "jane@example.com",
    "subject": "Your booking",
    "spam_level": 7.5,
    "content_type": "S",
    "smtp_response": "250 ok",
    "object": "quarantined mail",
    "code": 200,
}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


class Recorder:
    """Mock transport: replies by "METHOD path" or path below /restapi/."""

    def __init__(self, routes=None, default=None):
        self.requests: list[httpx.Request] = []
        self.routes = routes or {}
        self.default = default if default is not None else {"data": [], "total": 0, "count": 0}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix("/restapi").strip("/")
        reply = self.routes.get(f"{request.method} {path}", self.routes.get(path, self.default))
        if callable(reply):
            return reply(request)
        return httpx.Response(200, json=reply)

    def calls(self, path: str, method: str | None = None) -> list[httpx.Request]:
        return [
            r for r in self.requests
            if r.url.path.removeprefix("/restapi").strip("/") == path and (method is None or r.method == method)
        ]


def body(request: httpx.Request):
    return json.loads(request.content) if request.content else None


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(CREDS)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


# ---- transport -------------------------------------------------------------


async def test_bearer_token_and_restapi_base():
    rec = Recorder()
    client = SpamTitanClient(CREDS, httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    await client.get("quarantine", {"results": 5, "show_deleted": False})
    request = rec.requests[0]
    assert request.headers["Authorization"] == "Bearer tok-1"
    assert "X-SpamTitan-API-Key" not in request.headers
    assert str(request.url) == f"{BASE}/restapi/quarantine?results=5&show_deleted=false"


async def test_unauthorized_is_mapped(monkeypatch):
    rec = Recorder({"quarantine": lambda r: httpx.Response(401, json={"code": 401, "error": "Unauthorized."})})
    result = await _call(monkeypatch, rec, "spamtitan_status", {})
    assert result["error"]["code"] == "unauthorized"
    assert "Unauthorized." in result["error"]["message"]


async def test_wrong_base_url_is_explained(monkeypatch):
    rec = Recorder({"quarantine": lambda r: httpx.Response(404, text="<html><body>Not Found</body></html>")})
    result = await _call(monkeypatch, rec, "spamtitan_status", {})
    assert result["error"]["code"] == "not_found"
    assert "X-SpamTitan-Base-URL" in result["error"]["message"]


async def test_get_retries_5xx_but_writes_do_not():
    replies = iter([httpx.Response(503), httpx.Response(200, json={"data": []})])
    rec = Recorder({"GET quarantine": lambda r: next(replies), "POST allow-list": lambda r: httpx.Response(500, json={})})
    client = SpamTitanClient(CREDS, httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    assert await client.get("quarantine") == {"data": []}
    with pytest.raises(SpamTitanError):
        await client.post("allow-list", {"sender": "x@example.com"})
    assert len(rec.calls("quarantine")) == 2 and len(rec.calls("allow-list")) == 1


# ---- quarantine ------------------------------------------------------------


async def test_queue_filters_paging_and_summary(monkeypatch):
    rec = Recorder({"quarantine": {"data": [MESSAGE], "total": 120, "count": 1}})
    args = {"recipient": "jane@example.com", "subject": "*booking*", "reason": "spam", "page": 2, "per_page": 50}
    result = await _call(monkeypatch, rec, "spamtitan_get_queue", args)
    params = rec.requests[0].url.params
    assert (params["recipient"], params["subject"], params["type"]) == ("jane@example.com", "*booking*", "spam")
    assert (params["results"], params["page"], params["sortkey"], params["sortdir"]) == ("50", "2", "message_received", "desc")
    message = result["messages"][0]
    assert message["category"] == "spam" and "secret_id" not in message and "smtp_response" not in message
    assert result["has_more"] is True and result["total"] == 120


async def test_queue_reason_all_sends_no_type(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "spamtitan_get_queue", {"reason": "all"})
    assert "type" not in rec.requests[0].url.params


async def test_get_message_hides_secret(monkeypatch):
    rec = Recorder({"quarantine/0c7fuE5s87wJ": MESSAGE})
    result = await _call(monkeypatch, rec, "spamtitan_get_message", {"message_id": "0c7fuE5s87wJ"})
    assert result["subject"] == "Your booking" and result["category"] == "spam"
    assert "secret_id" not in result and "code" not in result


async def test_message_id_is_validated(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "spamtitan_get_message", {"message_id": "../users"})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_release_fetches_secret_and_posts(monkeypatch):
    rec = Recorder(
        {
            "GET quarantine/0c7fuE5s87wJ": MESSAGE,
            "POST quarantine/0c7fuE5s87wJ": {"code": 200, "released": True, "id": "0c7fuE5s87wJ"},
        }
    )
    result = await _call(monkeypatch, rec, "spamtitan_release_message", {"message_id": "0c7fuE5s87wJ", "forward_to": "admin@example.com"})
    assert body(rec.calls("quarantine/0c7fuE5s87wJ", "POST")[0]) == {"secret_id": "U86w74oNRPbq", "forward_to": "admin@example.com"}
    assert result == {"message_id": "0c7fuE5s87wJ", "released": True, "delivered_to": "admin@example.com"}


async def test_delete_sends_secret_in_body(monkeypatch):
    rec = Recorder(
        {
            "GET quarantine/0c7fuE5s87wJ": MESSAGE,
            "DELETE quarantine/0c7fuE5s87wJ": {"id": "0c7fuE5s87wJ", "deleted": True, "code": 200},
        }
    )
    result = await _call(monkeypatch, rec, "spamtitan_delete_message", {"message_id": "0c7fuE5s87wJ"})
    assert body(rec.calls("quarantine/0c7fuE5s87wJ", "DELETE")[0]) == {"secret_id": "U86w74oNRPbq"}
    assert result == {"message_id": "0c7fuE5s87wJ", "deleted": True}


async def test_release_of_unknown_message(monkeypatch):
    rec = Recorder({"GET quarantine/abc123": lambda r: httpx.Response(404, json={"code": 404, "error": "Not found."})})
    result = await _call(monkeypatch, rec, "spamtitan_release_message", {"message_id": "abc123"})
    assert result["error"]["code"] == "not_found"
    assert rec.calls("quarantine/abc123", "POST") == []


# ---- lists -----------------------------------------------------------------


ENTRY = {"id": 41, "sender": "@partner.example.com", "include_subdomains": False, "comment": "", "recipient": {"email": "@.", "comment": "Global Match"}}


async def test_list_entries(monkeypatch):
    rec = Recorder({"allow-list": {"data": [ENTRY], "total": 1, "count": 1}})
    result = await _call(monkeypatch, rec, "spamtitan_manage_allowlist", {"action": "list", "sender": "partner"})
    assert rec.requests[0].url.params["filter"] == "partner"
    assert result["allowlist"] == [{"id": 41, "sender": "@partner.example.com", "include_subdomains": False, "comment": "", "applies_to": "Global Match"}]


async def test_add_entry_maps_note_to_comment(monkeypatch):
    rec = Recorder({"POST block-list": {**ENTRY, "id": 40, "sender": "spam@bad.example", "object": "x", "code": 201}})
    result = await _call(monkeypatch, rec, "spamtitan_manage_blocklist", {"action": "add", "sender": "Spam@Bad.example", "note": "phishing"})
    assert body(rec.calls("block-list", "POST")[0]) == {"sender": "spam@bad.example", "comment": "phishing"}
    assert result["status"] == "added" and result["entry"]["id"] == 40


async def test_remove_entry_looks_up_ids(monkeypatch):
    other = {**ENTRY, "id": 42, "sender": "@partner.example.com.evil"}
    rec = Recorder({"GET allow-list": {"data": [ENTRY, other], "total": 2}, "DELETE allow-list/41": {"deleted": True, "id": 41}})
    result = await _call(monkeypatch, rec, "spamtitan_manage_allowlist", {"action": "remove", "sender": "@partner.example.com"})
    assert [r.url.path for r in rec.requests if r.method == "DELETE"] == ["/restapi/allow-list/41"]
    assert result == {"status": "removed", "list": "allowlist", "sender": "@partner.example.com", "removed_ids": [41]}


async def test_remove_missing_entry(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "spamtitan_manage_allowlist", {"action": "remove", "sender": "nobody@example.com"})
    assert result["error"]["code"] == "not_found"


@pytest.mark.parametrize("args", [{"action": "add"}, {"action": "add", "sender": "not an address"}, {"action": "remove", "sender": "example.com"}])
async def test_add_remove_need_a_sender(monkeypatch, args):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "spamtitan_manage_blocklist", args)
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


# ---- stats -----------------------------------------------------------------


REPORT = {"clean_messages": 90, "spam_messages": 8, "virus_messages": 1, "banned_messages": 1, "invalid_recipients": 5, "object": "report", "code": 200}


async def test_stats_named_period(monkeypatch):
    rec = Recorder({"reports/scan-summary": REPORT})
    result = await _call(monkeypatch, rec, "spamtitan_get_stats", {"period": "yesterday", "domain": "Example.com"})
    params = rec.requests[0].url.params
    assert (params["period"], params["domain"]) == ("yesterday", "example.com")
    assert result["scanned_messages"] == 100 and result["blocked_percent"] == 10.0
    assert "code" not in result["stats"]


async def test_stats_rolling_period_uses_dates(monkeypatch):
    rec = Recorder({"reports/scan-summary": REPORT})
    await _call(monkeypatch, rec, "spamtitan_get_stats", {"period": "last_7_days"})
    params = rec.requests[0].url.params
    today = date.today()
    assert (params["start"], params["end"]) == ((today - timedelta(days=6)).isoformat(), today.isoformat())
    assert "period" not in params


async def test_stats_default_today(monkeypatch):
    rec = Recorder({"reports/scan-summary": REPORT})
    result = await _call(monkeypatch, rec, "spamtitan_get_stats", {})
    assert rec.requests[0].url.params["period"] == "today" and result["domain"] == "all"

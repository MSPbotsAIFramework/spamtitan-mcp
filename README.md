# SpamTitan MCP Server

An [MCP](https://modelcontextprotocol.io) server for the SpamTitan REST API (v3), the email
security gateway MSPs use to filter inbound mail. It lets an AI agent search the quarantine,
inspect held messages, read the sender allow and block lists and mail flow statistics and, on
explicit request, release or delete quarantined messages and change the allow / block lists.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored; every tool is listed from the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-SpamTitan-API-Key` | Yes | string | none | - | SpamTitan REST API token (a leading `Bearer ` is accepted and ignored) | `your-api-key` |
| `X-SpamTitan-Base-URL` | Yes | string | none | https URL | Root URL of the SpamTitan server (a bare host name gets `https://`; a trailing `/restapi` is removed) | `https://spamtitan.example.com` |

Where to get them:

- In the SpamTitan web interface open **Settings -> User Management -> RestAPI Keys** and add a
  token for an account with access to quarantine, allow / block lists and reports.
- The base URL is the address of the SpamTitan web interface. If SpamTitan is served under a
  path, include it (for example `https://mail.example.com/spamtitan`).

How the token is sent to SpamTitan: as `Authorization: Bearer <token>` to
`{X-SpamTitan-Base-URL}/restapi/...`. Values that look like unresolved templates (`${...}`)
are treated as missing.

A request to `/mcp` without both headers gets HTTP 401 listing them; a non-https base URL gets
HTTP 400.

## Tools

All tools return a JSON string.

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `spamtitan_navigate` | Describe the tools of one area (changes nothing) | **domain** (`quarantine`, `lists`, `stats`) |
| `spamtitan_status` | Check the connection: server reachable, token accepted | - |
| `spamtitan_get_queue` | List quarantined mail, newest first: sender, recipient, subject, spam score, category | page, per_page, offset, sender, recipient, subject, reason (`spam`, `virus`, `banned`, `content-filter`, `archive`, `all`) |
| `spamtitan_get_message` | One quarantined message: score, virus / filter hit, country, SMTP details | **message_id** |
| `spamtitan_release_message` | Release a message to its recipient or another address (**write**) | **message_id**, forward_to |
| `spamtitan_delete_message` | Permanently delete a quarantined message (**write**, irreversible) | **message_id** |
| `spamtitan_manage_allowlist` | List, add or remove allowed senders (**write** for add / remove) | **action** (`add`, `remove`, `list`), sender, note |
| `spamtitan_manage_blocklist` | List, add or remove blocked senders (**write** for add / remove) | **action** (`add`, `remove`, `list`), sender, note |
| `spamtitan_get_stats` | Mail flow totals: clean, spam, virus, banned, rejected, blocked percent | period (`today`, `yesterday`, `last_7_days`, `last_30_days`, `last_90_days`), domain |

`sender`, `recipient` and `subject` filters accept `*` as a wildcard. Allow / block list
entries are addresses (`user@example.com`) or domains written as `@example.com`.

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "SpamTitan returned HTTP 401 for quarantine: Unauthorized.", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`. Reads are retried with backoff on 429, 5xx and network
errors; writes only on 429.

## Run locally

```bash
uv sync
uv run python -m spamtitan_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t spamtitan-mcp:dev .
docker run --rm -p 8080:8080 spamtitan-mcp:dev
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
  -H "X-SpamTitan-API-Key: your-api-key" \
  -H "X-SpamTitan-Base-URL: https://spamtitan.example.com" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# quarantined mail for one recipient
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-SpamTitan-API-Key: your-api-key" \
  -H "X-SpamTitan-Base-URL: https://spamtitan.example.com" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"spamtitan_get_queue","arguments":{"recipient":"jane@example.com"}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Built on the documented REST API.** Every call follows the SpamTitan RESTful API v3
  reference (`/restapi` with a Bearer token): `/quarantine`, `/quarantine/{id}` (show,
  release with `POST`, delete with `DELETE`), `/allow-list`, `/block-list` and
  `/reports/scan-summary`.
- **Release and delete** need the message's `secret_id`; the server reads it from the message
  record first, so callers only pass `message_id`. `spamtitan_release_message` gained an
  optional `forward_to`.
- **Removing list entries** looks the sender up and deletes the matching entry ids, as the API
  deletes by id.
- **Rolling periods** (`last_7_days`, `last_30_days`, `last_90_days`) are sent as a start / end
  date range; `today` and `yesterday` use the report's named periods.
- **Tool count (9).** Tool names and required parameters are unchanged. `reason` is now the
  set of quarantine types the API knows.
- **Write tools.** Release, delete and list changes are annotated and their descriptions tell
  the agent to act only on explicit request; delete is irreversible. There are no other write
  tools.
- **No interactive prompts.** Older versions asked the user for a recipient before an
  unfiltered queue listing, which a stateless gateway cannot relay; the queue now pages
  instead.
- **Queue paging.** SpamTitan pages by number only. The queue also takes `offset` (a message
  position that overrides `page`) and returns `next_offset`: when a page is too large for one
  response and is cut, `next_offset` starts right after the last message returned, which no page
  number can.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).

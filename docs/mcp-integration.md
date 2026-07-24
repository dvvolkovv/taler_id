# TalerID MCP Server — Integration Guide

TalerID exposes its platform features (calendar, notes, messaging) to AI agents via the
[Model Context Protocol](https://modelcontextprotocol.io). Any MCP-capable client —
Claude (claude.ai / Desktop), ChatGPT, or your own agent built on an MCP SDK — can act
on behalf of a TalerID user with their explicit OAuth consent.

## Endpoints

| Environment | MCP endpoint | Authorization server |
|-------------|--------------|----------------------|
| DEV (staging) | `https://staging.id.taler.tirol/mcp` | `https://staging.id.taler.tirol/oauth` |
| TEST | `https://id.taler.tirol/mcp` *(after rollout)* | `https://id.taler.tirol/oauth` |
| PROD | `https://api.talerid.io/mcp` *(after rollout)* | `https://api.talerid.io/oauth` |

- **Transport:** Streamable HTTP, stateless (`POST /mcp` only; no `Mcp-Session-Id`).
  `GET`/`DELETE /mcp` return `405`. Safe behind load balancers without sticky sessions.
- **Discovery:** `GET /.well-known/oauth-protected-resource` (RFC 9728) advertises the
  resource, the authorization server, and supported scopes. Unauthenticated requests to
  `/mcp` receive `401` with a `WWW-Authenticate: Bearer resource_metadata="…"` header —
  standard MCP clients bootstrap authorization from it automatically.

## Authorization

Standard **OAuth 2.1 authorization code flow with PKCE (S256, mandatory)**.

1. **Client registration** — Dynamic Client Registration (RFC 7591) is open:
   `POST /oauth/reg` with e.g.

   ```json
   {
     "client_name": "My Agent",
     "redirect_uris": ["https://example.com/callback"],
     "token_endpoint_auth_method": "none",
     "grant_types": ["authorization_code"],
     "response_types": ["code"],
     "scope": "openid mcp:calendar mcp:notes mcp:messages.read mcp:messages.send"
   }
   ```

   Clients like Claude register themselves — no manual step needed.
   Rate limit: 10 registrations/min per IP.

2. **Authorization** — the user logs in to TalerID and sees a consent screen listing the
   requested scopes with human-readable descriptions (ru/en). Partial consent is
   supported: the user may untick individual scopes.

3. **Token** — `POST /oauth/token` (authorization code + PKCE verifier).
   Access tokens are short-lived (**15 min**); MCP clients re-authorize transparently.
   `offline_access` (refresh tokens, 30 days) is **not** granted to dynamically
   registered clients — it is reserved for verified B2B partners (see below).

Client auth methods: `none` (public clients + PKCE), `client_secret_basic`,
`client_secret_post`.

### Scopes

| Scope | Grants |
|-------|--------|
| `mcp:calendar` | Read/write the user's calendar events and reminders |
| `mcp:notes` | Read/write the user's notes |
| `mcp:messages.read` | Read conversations, message history, contact list |
| `mcp:messages.send` | Send text messages **to the user's contacts only** |

`tools/list` returns only tools covered by the token's scopes — a token without
`mcp:messages.send` never sees `send_message`.

## Tools

All tool results are JSON serialized into a `text` content block. Errors that the agent
can act on (not found, no permission, not a contact) come back as `isError` results with
a human-readable message; infrastructure failures surface as JSON-RPC errors.

### Calendar (`mcp:calendar`)

| Tool | Input | Notes |
|------|-------|-------|
| `list_calendar_events` | `from?`, `to?` (ISO date/datetime) | |
| `get_calendar_event` | `id` | |
| `create_calendar_event` | `title`, `type` (`CALL`\|`EVENT`\|`REMINDER`), `startAt` (ISO 8601 with offset), `endAt?`, `description?`, `allDay?`, `reminder_minutes_before?` | reminder computed as `startAt − N min` |
| `update_calendar_event` | `id` + any of the above (partial) | `reminder_minutes_before` requires `startAt` in the same call |
| `delete_calendar_event` | `id` | |

### Notes (`mcp:notes`)

| Tool | Input |
|------|-------|
| `list_notes` | `limit?` (≤100, default 50), `offset?` |
| `create_note` | `title`, `content`, `source?` |
| `update_note` | `id`, `title?`, `content?` |
| `delete_note` | `id` |

### Messaging (`mcp:messages.read` / `mcp:messages.send`)

| Tool | Scope | Input | Notes |
|------|-------|-------|-------|
| `list_contacts` | read | — | the only valid recipients for `send_message` |
| `list_conversations` | read | — | with last-message preview |
| `get_messages` | read | `conversation_id`, `cursor?`, `limit?` (≤100, default 30) | membership enforced server-side |
| `search_messages` | read | `query` (min 2 chars) | searches all the user's conversations |
| `send_message` | send | `contact_id`, `text` | **contact-gated**: refuses recipients outside the user's accepted contacts; blocked users refused; recipients get full delivery (socket + push) identical to in-app messages |

## Rate limits

| Surface | Limit |
|---------|-------|
| `POST /mcp` | 30/s, 600/min, 10 000/h per IP |
| `POST /oauth/reg` (DCR) | 10/min per IP |

## Verified B2B partners

Dynamically registered clients cover the personal-assistant use case. Service partners
that need long-lived access (`offline_access` refresh tokens) are registered manually
with a *verified partner* flag — contact the TalerID team. Everything else (flow,
scopes, endpoints) is identical.

## Kill switch (ops)

Dynamic Client Registration is gated by the backend env var `OIDC_DCR_ENABLED`
(default off; process restart required to toggle). Disabling it stops **new** client
registrations only — existing clients and tokens keep working.

## E2E reference

A complete working flow (DCR → PKCE code flow → initialize → tools/list →
CRUD → send) lives in the tests repo: `taler_id_tests/mcp_test.ts`
(`npm run test:mcp`). Use it as executable documentation.

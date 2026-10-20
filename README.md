# wa-gateway

Self-hosted WhatsApp gateway for Claude agents. One linked device, many read-only clients.

```
WhatsApp ── WAHA (WEBJS: real WhatsApp Web in Chrome, pinned build) ──webhooks──▶ gateway (SQLite + FTS)
                                                                                      │ MCP /mcp
                                         cloudflared ◀── Cloudflare Access service tokens ── Claude sessions
```

- **Read-only.** The gateway's WAHA client has an allowlist (`ALLOWED` in `gateway/app.py`); send, presence, read
  receipts and typing are unreachable. WAHA itself runs with auto-online, apps, dashboard and media download off.
- **Scoped clients.** `clients.json` maps a Cloudflare service token to `{"name", "chats": "*" | [chat ids]}`.
  Identity comes from the signed `Cf-Access-Jwt-Assertion` header, verified against the Access app's AUD.
- **Pinned.** WAHA by image digest (`waha/Dockerfile`); WhatsApp Web by build (`scripts/pin-webversion.sh`, builds
  live ~2 months). The page bypasses WhatsApp's service worker, which otherwise loads the latest build after login.
- **Self-healing, then loud.** The watchdog restarts a failed session (backoff, `MAX_RESTARTS_PER_DAY`); a logout,
  wrong account or too many restarts stops the session and notifies (`NOTIFY_BACKENDS`). Every tool response
  carries a `warning` while unhealthy.

## Tools

`get_status`, `list_chats`, `get_messages(chat_id, before_seq)`, `search_messages(query, chat_id)`,
`get_new_messages()` (cursor kept server-side per client).

## Operate (LXC, `/opt/wa-gateway`)

```sh
CT=<id> scripts/deploy.sh                          # on the Proxmox host: push repo into the LXC
docker compose up -d --build                       # in the LXC
docker compose exec gateway python app.py pair     # link: prints an 8-digit code for your phone
scripts/pin-webversion.sh <version> && docker compose up -d waha   # move to another WhatsApp Web build
docker compose --profile tunnel up -d              # with TUNNEL_TOKEN set
```

Client config (Claude Code):

```sh
claude mcp add --scope user --transport http wa https://wa.example.com/mcp \
  --header "CF-Access-Client-Id: $WA_CF_ID" --header "CF-Access-Client-Secret: $WA_CF_SECRET"
```

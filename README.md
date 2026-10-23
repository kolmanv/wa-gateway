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
- **Media, modestly.** New voice notes, audio, images and documents (yours too, unless `save_own` is false) are saved as they arrive: one at a
  time, after a random 3-30 s pause, at most `max_per_hour`, stored once per checksum, deleted after `keep_days`.
  Everything else (video, stickers, large files, chats in `skip_chats`) is fetched only on request. In groups, WAHA
  also reads the receipts of your own messages when fetching them (like opening Message info).
  Rules in `media.json` (see `media.example.json`); `skip_chats` takes chat ids with `"*"` or a list of types.
  The only extra WAHA calls are "get one message with its file" and "fetch that file"; WAHA's own bulk media
  download stays off.
- **Transcripts, locally.** With `KATZRAN_URL`/`KATZRAN_TOKEN` set, saved voice notes and audio up to
  `transcribe_max_minutes` are sent to [katzran](https://github.com/kolmanv/katzran), a self-hosted speech-to-text
  service (Hebrew, Russian, English, switching mid-note), one at a time; longer ones and video on `request_media`.
  Transcripts are stored per checksum next to the file, shown in message listings, searched with the text, and
  deleted with the file. Nothing leaves the network.
- **Self-healing, then loud.** The watchdog restarts a failed session (backoff, `MAX_RESTARTS_PER_DAY`); a logout,
  wrong account or too many restarts stops the session and notifies (`NOTIFY_BACKENDS`). Every tool response
  carries a `warning` while unhealthy.

## Tools

`get_status`, `list_chats`, `get_messages(chat_id, before_seq)`, `search_messages(query, chat_id)`,
`get_new_messages()` (cursor kept server-side per client), `list_media(chat_id, type, status)`,
`get_media(message_id)` (details; images as images, PDF and text as text, audio as its transcript),
`request_media(message_id)` (fetch now; audio and video also get a transcript),
`get_file(message_id)` (the original file, to pass on as it is; up to 50 MB).
Messages show their media status (`saved`, `on_demand`, `waiting`, `expired`, `failed`, `skipped`) and, for voice
notes, `transcript_status` and the transcript (`[he 0:12] ...` lines). Search covers transcripts too.

`get_file` returns the file as an MCP embedded resource: Claude Code saves it to disk and gives the session only
the path (the bytes never enter the conversation), so a session can attach it to a Telegram message or a mail.

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

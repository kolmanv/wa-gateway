"""Smoke test for wa-gateway, run inside the gateway image with a throwaway DB:
    docker compose run --rm -v "$PWD/tests:/tests" gateway python /tests/smoke.py
"""
import asyncio, hashlib, hmac, json, os, threading, time
os.environ.update(DB_PATH="/tmp/t.db", MEDIA_FILE="/tmp/media.json", MEDIA_DIR="/tmp/media", CLIENTS_FILE="/tmp/clients.json", CF_TEAM_DOMAIN="test.cloudflareaccess.com",
                  CF_AUD="aud1", PUBLIC_HOST="wa.test", WEBHOOK_HMAC_KEY="k", NOTIFY_BACKENDS="")
json.dump({"pid.access": {"name": "personal", "chats": "*"},
           "oid.access": {"name": "org", "chats": ["g1@g.us"]},
           "mid.access": {"name": "monitor", "chats": []}}, open("/tmp/clients.json", "w"))
json.dump({"skip_chats": {"noisy@g.us": "*", "g2@g.us": ["image"]}, "delay_seconds": [0, 0]},
          open("/tmp/media.json", "w"))
import sys; sys.path.insert(0, "/app")
import jwt, httpx2, uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
import app

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
class FakeJWKS:
    def get_signing_key_from_jwt(self, t): return type("K", (), {"key": key.public_key()})
app.jwks = FakeJWKS()
def tok(cid, aud="aud1"):
    return jwt.encode({"common_name": cid, "aud": aud, "iss": "https://test.cloudflareaccess.com",
                       "exp": int(time.time()) + 300}, key, algorithm="RS256")

async def noop(*a, **k): return None
app.resolve_chat_name = noop
app.kv_set("state", {"status": "ok", "detail": "", "since": time.time()})

srv = uvicorn.Server(uvicorn.Config(app.mcp.streamable_http_app(stateless_http=True, json_response=True,
      transport_security=app.TransportSecuritySettings(allowed_hosts=["wa.test"])), port=8099, log_level="error"))
threading.Thread(target=srv.run, daemon=True).start(); time.sleep(2)
H = httpx2.Client(base_url="http://127.0.0.1:8099", headers={"Host": "wa.test"})

def hook(ev, payload, sig=None):
    b = json.dumps({"event": ev, "session": "default", "payload": payload}).encode()
    s = sig or hmac.new(b"k", b, hashlib.sha512).hexdigest()
    return H.post("/webhook", content=b, headers={"x-webhook-hmac": s, "content-type": "application/json"}).status_code

def call(cid, tool, **args):
    h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
         "MCP-Protocol-Version": "2025-06-18"}
    if cid: h["Cf-Access-Jwt-Assertion"] = tok(cid) if cid != "badaud" else tok("pid.access", aud="other")
    r = H.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                        "params": {"name": tool, "arguments": args}})
    res = r.json().get("result", r.json())
    if res.get("isError"): return "ERROR: " + res["content"][0]["text"][:90]
    return res.get("structuredContent") or json.loads(res["content"][0]["text"])

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m)
m = lambda i, frm, to, body, me=False, part=None: {"id": i, "from": frm, "to": to, "fromMe": me, "participant": part,
    "timestamp": int(time.time()), "body": body, "hasMedia": False, "_data": {"notifyName": "Dana", "type": "chat"}}

ok(hook("message.any", m("a", "x@c.us", "me@c.us", "hello"), sig="bad") == 401, "bad HMAC rejected")
ok(hook("message.any", m("1", "x@c.us", "me@c.us", "lunch tomorrow?")) == 200, "webhook accepted")
hook("message.any", m("2", "g1@g.us", "me@c.us", "work: deploy at five", part="y@c.us"))
hook("message.any", m("3", "me@c.us", "g2@g.us", "family dinner", me=True))
hook("message.any", m("1", "x@c.us", "me@c.us", "lunch tomorrow?"))  # duplicate delivery
hook("message.any", m("s", "status@broadcast", "me@c.us", "story"))
ok(app.db.execute("select count(*) from messages").fetchone()[0] == 3, "dedupe + status@broadcast skipped")
hook("message.edited", {"id": "e", "body": "work: deploy at six", "editedMessageId": "2"})
hook("message.revoked", {"revokedMessageId": "3", "before": {"id": "3"}})

ok(call(None, "list_chats").startswith("ERROR"), "no token -> refused")
ok(call("badaud", "list_chats").startswith("ERROR"), "wrong audience -> refused")
ok(call("zzz.access", "list_chats").startswith("ERROR"), "unknown client -> refused")
p = call("pid.access", "list_chats"); ok(len(p["chats"]) == 3, f"personal sees 3 chats")
o = call("oid.access", "list_chats"); ok([c["chat_id"] for c in o["chats"]] == ["g1@g.us"], "org sees only allowlisted chat")
ok(call("oid.access", "get_messages", chat_id="x@c.us")["messages"] == [], "org cannot read other chat by id")
ok(call("oid.access", "search_messages", query="lunch")["messages"] == [], "org search scoped")
ok(call("mid.access", "list_chats")["chats"] == [], "monitor sees no chats")
ok(call("mid.access", "get_status")["status"] == "ok", "monitor can read status")
s = call("pid.access", "search_messages", query="deploy six")["messages"]
ok(len(s) == 1 and s[0]["edited"] == 1, "edit updates body and FTS")
r = call("pid.access", "get_messages", chat_id="g2@g.us")["messages"][0]
ok(r["revoked"] == 1 and r["body"] is None, "revoked message text dropped")
ok(call("pid.access", "search_messages", query='lunch" OR "x')["messages"] == [], "FTS syntax is escaped")

n1 = call("pid.access", "get_new_messages"); n2 = call("pid.access", "get_new_messages")
ok(len(n1["messages"]) == 3 and n2["messages"] == [], "cursor: personal gets 3 then nothing")
hook("message.any", m("4", "g1@g.us", "me@c.us", "standup moved", part="y@c.us"))
o1 = call("oid.access", "get_new_messages")
ok([x["body"] for x in o1["messages"]] == ["work: deploy at six", "standup moved"], "cursor: org gets only its chat")
ok([x["id"] for x in call("pid.access", "get_new_messages")["messages"]] == ["4"], "cursor: personal resumes after restart point")

app.kv_set("state", {"status": "needs_human", "detail": "logged out", "since": time.time()})
ok("warning" in call("pid.access", "list_chats"), "status banner shown when unhealthy")

try: asyncio.run(app.waha("POST", "/api/sendText", json={})); ok(False, "guard")
except PermissionError: ok(True, "guard blocks sendText")
for path in ["/api/default/presence", "/api/sendSeen", "/api/default/chats/x/messages/read"]:
    try: app.guard("POST", path); ok(False, f"guard {path}")
    except PermissionError: pass
ok(app.kv_get("guard_blocks") == 4, "guard counts blocks")
r = H.post("/mcp", headers={"Host": "evil.example", "Content-Type": "application/json",
           "Accept": "application/json, text/event-stream"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
ok(r.status_code in (400, 403, 421), f"foreign Host header rejected ({r.status_code})")

# --- media -------------------------------------------------------------------
import base64
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
files = {"/api/files/default/p.png": PNG, "/api/files/default/v.oga": b"OggS voice"}
seen = []
async def fake_waha(method, path, raw=False, **kw):
    app.guard(method, path); seen.append(path)
    if raw: return files[path]
    mid = path.rsplit("/", 1)[1]
    url = {"img1": "p.png", "img2": "p.png", "ptt1": "v.oga", "old1": "p.png"}.get(mid)
    if not url: return {"media": {"url": None, "error": "media expired"}}
    return {"media": {"url": f"http://waha:3000/api/files/default/{url}",
                      "mimetype": "image/png" if url.endswith("png") else "audio/ogg; codecs=opus"}}
app.waha = fake_waha
app.kv_set("state", {"status": "ok", "detail": "", "since": time.time()})
def mm(i, chat, kind, mime, **d):
    x = m(i, chat, "me@c.us", "caption " + i); x["hasMedia"] = True
    x["_data"] = {"notifyName": "Dana", "type": kind, "mimetype": mime, **d}; return x
hook("message.any", mm("img1", "x@c.us", "image", "image/png", size=70, width=1, height=1))
hook("message.any", mm("img2", "g1@g.us", "image", "image/png", isForwarded=True, forwardingScore=5))
hook("message.any", mm("ptt1", "x@c.us", "ptt", "audio/ogg; codecs=opus", duration="7"))
hook("message.any", mm("vid1", "x@c.us", "video", "video/mp4"))
hook("message.any", mm("big1", "x@c.us", "image", "image/png", size=30 * 2**20))
hook("message.any", mm("skip1", "noisy@g.us", "ptt", "audio/ogg"))
hook("message.any", mm("img3", "g2@g.us", "image", "image/png"))
hook("message.any", mm("ptt2", "g2@g.us", "ptt", "audio/ogg"))
hook("message.any", mm("vo1", "x@c.us", "image", "image/jpeg", isViewOnce=True))
hook("message.any", mm("gone1", "x@c.us", "document", "application/pdf"))
hook("message.any", {**mm("mine1", "me@c.us", "image", "image/png"), "to": "g1@g.us", "fromMe": True})
st = dict(app.db.execute("select msg_id, status from media").fetchall())
ok(st == {"img1": "waiting", "img2": "waiting", "ptt1": "waiting", "vid1": "on_demand", "big1": "on_demand",
          "skip1": "on_demand", "img3": "on_demand", "ptt2": "waiting", "vo1": "skipped", "gone1": "waiting",
          "mine1": "waiting"},
   f"auto rules: types, size, skip_chats (all and per type), view-once, own media ({st})")
for i in ("img1", "img2", "ptt1", "gone1"): asyncio.run(app.save_media(i))
r = app.db.execute("select * from media where msg_id='img1'").fetchone()
ok(r["status"] == "saved" and os.path.exists(f"/tmp/media/{r['path']}"), "image saved under its checksum")
ok(app.db.execute("select count(distinct path) from media where msg_id in ('img1','img2')").fetchone()[0] == 1,
   "forwarded copy stored once")
ok(app.db.execute("select duration from media where msg_id='ptt1'").fetchone()[0] == 7.0, "voice note duration kept")
ok(app.db.execute("select status from media where msg_id='gone1'").fetchone()[0] == "expired", "expired media marked")
def raw(cid, tool, **args):
    h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
         "MCP-Protocol-Version": "2025-06-18", "Cf-Access-Jwt-Assertion": tok(cid)}
    return H.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": tool, "arguments": args}}).json()["result"]
g = raw("pid.access", "get_media", message_id="img1")["content"]
ok([c["type"] for c in g] == ["text", "image"] and json.loads(g[0]["text"])["forwarded"] == 0, "get_media returns details + image")
ok("error" in raw("oid.access", "get_media", message_id="img1")["content"][0]["text"], "get_media scoped to client's chats")
n = len(seen); v = raw("pid.access", "request_media", message_id="vid1")["content"]
ok(json.loads(v[0]["text"])["status"] == "expired" and len(seen) == n + 1, "request_media tries an on-demand file")
hook("message.any", {**m("old1", "x@c.us", "me@c.us", ""), "hasMedia": True, "_data": {"type": "image"}})
app.db.execute("delete from media where msg_id='old1'")  # as if it arrived before media saving existed
o = raw("pid.access", "request_media", message_id="old1")["content"]
ok([c["type"] for c in o] == ["text", "image"], "request_media fetches media that predates the feature")
l = call("pid.access", "list_media", type="image", status="saved")["media"]
ok({x["msg_id"] for x in l} == {"img1", "img2", "old1"} and "path" not in l[0], "list_media filters, hides paths")
gm = call("pid.access", "get_messages", chat_id="x@c.us")["messages"]
ok(any(x["id"] == "ptt1" and x["media"] == "saved" and x["duration"] == 7.0 for x in gm), "messages show media status")
for path in ["/api/default/chats/x@c.us/messages/abc", "/api/files/default/f.oga"]: app.guard("GET", path)
for meth, path in [("POST", "/api/default/chats/x@c.us/messages/abc"), ("GET", "/api/default/chats/x/messages"),
                   ("DELETE", "/api/default/chats/x@c.us/messages/abc")]:
    try: app.guard(meth, path); ok(False, f"guard {meth} {path}")
    except PermissionError: pass
ok(True, "guard: only GET of one message and its file are new")
app.db.execute("update media set delete_after=0 where msg_id='img1'"); app.cleanup_media()
p = app.db.execute("select path from media where msg_id='img2'").fetchone()[0]
ok(os.path.exists(f"/tmp/media/{p}"), "cleanup keeps a file another message still uses")

# --- transcripts (katzran) ----------------------------------------------------
kz = {"posted": 0, "polls": 0}
async def fake_katzran(method, path, **kw):
    if method == "POST":
        kz["posted"] += 1; return {"id": "j1", "status": "queued"}
    if method == "DELETE": return None
    kz["polls"] += 1
    if kz["polls"] < 2: return {"id": "j1", "status": "working"}
    return {"id": "j1", "status": "done", "seconds": 4.2, "segments": [
        {"start": 0.0, "end": 9.5, "lang": "he", "model": "he", "text": "נפגשים מחר בשמונה"},
        {"start": 61.0, "end": 70.0, "lang": "ru", "model": "general", "text": "встреча завтра",
         "alt": {"lang": "he", "model": "he", "text": "בסטרצ'ה"}}]}
async def no_sleep(s): pass
app.katzran = fake_katzran
app.KATZRAN["base_url"] = "http://katzran:9000"
sha = app.db.execute("select sha256 from media where msg_id='ptt1'").fetchone()[0]
app.want_transcript("ptt", sha, 7.0)
ok(app.db.execute("select status from transcripts where sha256=?", (sha,)).fetchone()[0] == "waiting",
   "saved voice note queued for a transcript")
app.want_transcript("ptt", "longsha", 3600)
ok(app.db.execute("select status from transcripts where sha256='longsha'").fetchone()[0] == "on_demand",
   "voice note over transcribe_max_minutes waits for a request")
real_sleep = asyncio.sleep; app.asyncio.sleep = no_sleep
asyncio.run(app.transcribe(sha)); app.asyncio.sleep = real_sleep
t = app.db.execute("select * from transcripts where sha256=?", (sha,)).fetchone()
ok(t["status"] == "done" and t["languages"] == "he,ru" and "[ru 1:01] встреча завтра" in t["text"]
   and "(or, read as he: בסטרצ'ה)" in t["text"], "transcript stored with language lines and the alt reading")
gm = call("pid.access", "get_messages", chat_id="x@c.us")["messages"]
ok(any(x["id"] == "ptt1" and "נפגשים מחר" in (x["transcript"] or "") for x in gm), "messages show the transcript")
s = call("pid.access", "search_messages", query="встреча")["messages"]
ok([x["id"] for x in s] == ["ptt1"], "search finds words inside transcripts")
ok(call("oid.access", "search_messages", query="встреча")["messages"] == [], "transcript search stays scoped")
g = raw("pid.access", "get_media", message_id="ptt1")["content"]
ok(len(g) == 2 and "[he 0:00]" in g[1]["text"], "get_media returns the voice note's transcript")
async def down(method, path, **kw): raise app.httpx2.ConnectError("katzran unreachable")
app.katzran = down; app.transcripts_q = asyncio.Queue()
app.db.execute("update transcripts set status='waiting' where sha256='longsha'")
app.db.execute("update media set sha256='longsha', status='saved', path=(select path from media where msg_id='ptt1') where msg_id='ptt2'")
async def once(): await app.transcribe("longsha")
asyncio.run(once())
t = app.db.execute("select status, attempts from transcripts where sha256='longsha'").fetchone()
ok(t["status"] == "waiting" and t["attempts"] == 1, "katzran down: transcript retried later, not lost")

# --- files as they are (get_file) ------------------------------------------------
import base64
gf = raw("pid.access", "get_file", message_id="img2")["content"]
res = gf[1]["resource"] if len(gf) == 2 and gf[1]["type"] == "resource" else {}
ok(base64.b64decode(res.get("blob", "")) == PNG and res.get("mimeType") == "image/png"
   and json.loads(gf[0]["text"])["filename"].startswith("Dana ") and res["uri"].endswith(".png"),
   "get_file: the original file as an embedded resource, with a readable name")
ok("error" in raw("pid.access", "get_file", message_id="vid1")["content"][0]["text"], "get_file: not saved, says to request_media")
ok("error" in raw("oid.access", "get_file", message_id="ptt1")["content"][0]["text"], "get_file: scoped to client's chats")

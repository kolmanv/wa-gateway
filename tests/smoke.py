"""Smoke test for wa-gateway, run inside the gateway image with a throwaway DB:
    docker compose run --rm -v "$PWD/tests:/tests" gateway python /tests/smoke.py
"""
import asyncio, hashlib, hmac, json, os, threading, time
os.environ.update(DB_PATH="/tmp/t.db", CLIENTS_FILE="/tmp/clients.json", CF_TEAM_DOMAIN="test.cloudflareaccess.com",
                  CF_AUD="aud1", PUBLIC_HOST="wa.test", WEBHOOK_HMAC_KEY="k", NOTIFY_BACKENDS="")
json.dump({"pid.access": {"name": "personal", "chats": "*"},
           "oid.access": {"name": "org", "chats": ["g1@g.us"]},
           "mid.access": {"name": "monitor", "chats": []}}, open("/tmp/clients.json", "w"))
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

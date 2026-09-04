#!/usr/bin/env python3
# @id: mcp-broken-token-validation
# @name: MCP Broken Token Validation (Accepts Forged Tokens)
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. Detects MCP token-verification tools that accept forged, never-issued tokens (broken authentication)
# @tags: mcp, ai, agent, broken-auth, token-validation, intrusive, active, cwe-287
# @cwe: CWE-287
# @cvss: 8.1
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/287.html
# @confidence: 80
# @version: 1.1.0
"""
ACTIVE / INTRUSIVE check.

Detects broken token validation in MCP servers: a verify/validate tool that
reports a forged, never-issued token as valid. It sends only harmless junk
tokens (all-zeros, fixed fakes) to tools it has identified as *token
verifiers* -- never authenticators, never tools whose name/description imply
a mutation (write/delete/send/charge/provision/...). On a hit it also reports
the "blast radius": mutating tools the bypass could reach, derived purely
from tool metadata and NOT invoked. Speaks streamable HTTP and legacy SSE.
Maps to CWE-287 (Improper Authentication).
"""

import os, sys, json, ssl, re, threading, queue, time
import urllib.request, urllib.error
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-broken-token-validation",
    "name": "MCP Broken Token Validation (Accepts Forged Tokens)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": "ACTIVE check: detects MCP token-verification tools that accept forged, never-issued tokens",
    "tags": ["mcp", "ai", "agent", "broken-auth", "token-validation", "intrusive", "active", "cwe-287"],
    "language": "python",
    "active": True,
    "confidence": 80,
    "cwe": ["CWE-287"],
    "references": ["https://modelcontextprotocol.io/specification", "https://cwe.mitre.org/data/definitions/287.html"],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"
FORGED_TOKENS = ["0" * 32, "deadbeef" * 4, "cxg-invalid-token-000"]

VERIFY_VERB = re.compile(r"verify|validat|is[_-]?valid|\bcheck\b", re.I)
TOKENISH = re.compile(r"token|session|credential|jwt|api[_-]?key|bearer", re.I)
MUTATION = re.compile(r"write|delete|remove|drop|send|email|post|charge|pay|transfer|provision|"
                      r"create|deploy|execut|\bexec\b|\brun\b|install|modif|overwrit|rename|move|"
                      r"kill|terminat|shutdown|reset|revoke|grant", re.I)
# A verdict word, and the negations that flip it.  `response_accepted` used to
# read `{"valid": false}` and "token is not valid" as ACCEPTANCES: ACCEPT
# matched `valid`, REJECT's `\binvalid\b` did not match `false` or `not valid`,
# so a rejecting verifier was reported as broken - the exact opposite of the
# truth.  The oracle below is structural and negation-aware instead: it reads a
# boolean verdict FIELD when the response is JSON, and applies negation to a
# verdict WORD when it is prose.
ACCEPT_WORDS = ["valid", "authenticated", "authorized", "success", "succeeded",
                "welcome", "granted", "verified", "active", "accepted", "allowed",
                "ok", "authentic", "legitimate"]
REJECT_WORDS = ["invalid", "denied", "rejected", "failure", "failed", "incorrect",
                "unauthorized", "unauthenticated", "expired", "unrecognized",
                "not recognized", "forbidden", "error", "revoked"]
# Fields whose truthiness IS the verdict, when the response parses as JSON.
VERDICT_TRUE_KEYS = {"valid", "authenticated", "authorized", "success", "ok",
                     "active", "verified", "allowed", "accepted", "authentic"}
VERDICT_FALSE_KEYS = {"invalid", "expired", "denied", "rejected", "revoked",
                      "error", "failed"}
# A word carrying a verdict is inverted when one of these immediately precedes
# it (within a few tokens): "not valid", "no active session", "is not authorized".
NEGATION = re.compile(r"\b(not|no|never|isn'?t|aren'?t|wasn'?t|cannot|can'?t|"
                      r"couldn'?t|without|un)\W*$", re.I)
ACCEPT_RE = re.compile(r"\b(%s)\b" % "|".join(ACCEPT_WORDS), re.I)
REJECT_RE = re.compile(r"\b(%s)\b" % "|".join(w.replace(" ", r"\s+") for w in REJECT_WORDS), re.I)

# blast-radius capability classifier (mutating / high-risk)
CAP_RULES = [
    ("command/code execution", r"(execute|run)\s+(a\s+|the\s+)?(system\s+)?(command|shell|code|script)|shell\s+command|arbitrary\s+code|\beval\b|subprocess", {"command", "cmd", "code", "script", "shell"}),
    ("filesystem write/delete", r"\b(write|delete|remove|overwrite|modify|rename|move)\b[^.]{0,40}\bfiles?\b|\bfiles?\b[^.]{0,20}\b(write|delete|remove)", set()),
    ("raw database write", r"\bsql\b|execute\s+(a\s+)?query|run\s+(a\s+)?query|database\s+(insert|update|delete|write)|(insert|update|delete)\s+(into|from|row|record|table)", {"sql", "query"}),
    ("outbound/exfil channel", r"send\s+(an?\s+)?(email|message|request|webhook)|post\s+to|upload|transfer|fetch\s+(a\s+)?url", {"url", "endpoint", "recipient"}),
]
CAP_RE = [(cap, re.compile(rx, re.I), params) for cap, rx, params in CAP_RULES]


def classify_mutations(tool):
    name = (tool.get("name") or ""); desc = (tool.get("description") or "")
    props = {p.lower() for p in (tool.get("inputSchema", {}) or {}).get("properties", {}).keys()}
    text = f"{name} {desc}"
    caps = []
    for cap, rx, decisive in CAP_RE:
        if rx.search(text) or (decisive & props):
            caps.append(cap)
    return caps


def is_verify_tool(tool):
    name = (tool.get("name") or "").lower(); desc = (tool.get("description") or "").lower()
    props = {p.lower() for p in (tool.get("inputSchema", {}) or {}).get("properties", {}).keys()}
    text = name + " " + desc
    if MUTATION.search(text):
        return False  # mutation-skip: never invoke a tool that implies side effects
    tokenish = TOKENISH.search(text) or (props & {"token", "session", "jwt", "credential", "apikey", "api_key", "session_id", "access_token", "bearer"})
    return bool(VERIFY_VERB.search(text) and tokenish)


def _json_verdict(text):
    """If `text` (or a fenced/embedded object in it) parses as JSON, read a
    boolean verdict field. Returns True (accepted), False (rejected) or None
    (no structured verdict). A rejecting object like {"valid": false} or
    {"error": "expired"} must never read as an acceptance."""
    candidates = [text.strip()]
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        candidates.append(m.group(0))
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        flat = {str(k).lower(): v for k, v in obj.items()}
        # An explicit rejection field settles it, whatever else is present.
        for k in VERDICT_FALSE_KEYS:
            if k in flat and _truthy(flat[k]):
                return False
        for k in VERDICT_TRUE_KEYS:
            if k in flat:
                return _truthy(flat[k])
        return None
    return None


def _truthy(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "valid", "ok", "success",
                                     "authenticated", "authorized", "active")
    return bool(v)


def response_accepted(text):
    """Did the verifier report the forged token as VALID?

    Structured verdict first; only then a negation-aware word scan, so
    "token is not valid" and "no active session" read as rejections."""
    if not text:
        return False
    verdict = _json_verdict(text)
    if verdict is not None:
        return verdict
    # Prose. An explicit rejection word anywhere is decisive.
    if REJECT_RE.search(text):
        return False
    # An acceptance word counts only if it is not locally negated.
    for m in ACCEPT_RE.finditer(text):
        if not NEGATION.search(text[:m.start()]):
            return True
    return False


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def _extract_json(body):
    body = (body or "").strip()
    if not body:
        return None
    if "data:" in body:
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except Exception:
                    continue
    try:
        return json.loads(body)
    except Exception:
        return None


def _post(url, payload, timeout, session_id=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if session_id:
        headers["mcp-session-id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=_ctx())
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, {}, ""
    except Exception:
        return None, {}, ""


class Session:
    def __init__(self, transport, base, timeout, endpoint=None, sid=None, post_url=None, responses=None, stop=None):
        self.transport = transport; self.base = base; self.timeout = timeout
        self.endpoint = endpoint; self.sid = sid
        self.post_url = post_url; self.responses = responses; self.stop = stop
        self._rid = 10; self._seen = {}; self.info = {}

    def call(self, method, params=None):
        self._rid += 1; rid = self._rid
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        if self.transport == "streamable-http":
            _, _, body = _post(self.base + self.endpoint, payload, self.timeout, self.sid)
            return (_extract_json(body) or {}).get("result")
        try:
            urllib.request.urlopen(urllib.request.Request(self.post_url, data=json.dumps(payload).encode(),
                                   headers={"Content-Type": "application/json"}, method="POST"),
                                   timeout=self.timeout, context=_ctx()).read()
        except Exception:
            pass
        end = time.time() + min(self.timeout, 6)
        while time.time() < end:
            if rid in self._seen:
                return self._seen.pop(rid)
            try:
                msg = self.responses.get(timeout=0.5)
                if isinstance(msg, dict) and "id" in msg:
                    self._seen[msg["id"]] = msg.get("result")
            except queue.Empty:
                continue
        return self._seen.pop(rid, None)

    def close(self):
        if self.stop:
            self.stop.set()


def open_session(host, port, timeout, scheme):
    base = f"{scheme}://{host}:{port}"
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTO_VERSION, "capabilities": {}, "clientInfo": {"name": "cxg", "version": "1.0"}}}
    for path in MCP_PATHS:
        status, headers, body = _post(base + path, init, timeout)
        if status == 200:
            obj = _extract_json(body)
            if obj and "result" in obj:
                sid = headers.get("mcp-session-id")
                _post(base + path, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, sid)
                s = Session("streamable-http", base, timeout, endpoint=path, sid=sid)
                s.info = (obj.get("result") or {}).get("serverInfo") or {}
                return s
    responses = queue.Queue(); endpoint = {}; stop = threading.Event()

    def reader():
        try:
            resp = urllib.request.urlopen(urllib.request.Request(base + "/sse", headers={"Accept": "text/event-stream"}), timeout=timeout, context=_ctx())
            event = None
            for raw in resp:
                if stop.is_set():
                    break
                line = raw.decode("utf-8", "ignore").rstrip("\n")
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    d = line[5:].strip()
                    if event == "endpoint":
                        endpoint["url"] = d
                    else:
                        try:
                            responses.put(json.loads(d))
                        except Exception:
                            pass
                elif line == "":
                    event = None
        except Exception:
            pass

    threading.Thread(target=reader, daemon=True).start()
    for _ in range(int(timeout * 10)):
        if "url" in endpoint:
            break
        time.sleep(0.1)
    if "url" not in endpoint:
        stop.set(); return None
    post_url = base + endpoint["url"]
    for p in [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTO_VERSION, "capabilities": {}, "clientInfo": {"name": "cxg", "version": "1.0"}}},
              {"jsonrpc": "2.0", "method": "notifications/initialized"}]:
        try:
            urllib.request.urlopen(urllib.request.Request(post_url, data=json.dumps(p).encode(), headers={"Content-Type": "application/json"}, method="POST"), timeout=timeout, context=_ctx()).read()
        except Exception:
            pass
    s = Session("http+sse", base, timeout, post_url=post_url, responses=responses, stop=stop)
    end = time.time() + 4
    while time.time() < end:
        try:
            msg = responses.get(timeout=0.5)
            if msg.get("id") == 1:
                s.info = (msg.get("result") or {}).get("serverInfo") or {}
                break
        except queue.Empty:
            continue
    return s


def _result_text(res):
    if not isinstance(res, dict):
        return ""
    return " ".join(c.get("text", "") for c in (res.get("content") or []) if isinstance(c, dict))


def probe(session, tool):
    props = (tool.get("inputSchema", {}) or {}).get("properties", {}) or {}
    token_param = None
    for p in props:
        if re.search(r"token|session|jwt|credential|access|bearer", p, re.I):
            token_param = p; break
    if not token_param and props:
        token_param = list(props.keys())[0]
    for forged in FORGED_TOKENS:
        args = {p: (forged if p == token_param else "cxg-test") for p in props}
        res = session.call("tools/call", {"name": tool.get("name"), "arguments": args})
        if isinstance(res, dict) and res.get("isError"):
            continue
        text = _result_text(res)
        if response_accepted(text):
            return {"tool": tool.get("name"), "forged_token": forged, "response": text[:200]}
    return None


def test_mcp(host, port, timeout=12, scheme="http"):
    findings = []
    s = open_session(host, port, timeout, scheme)
    if not s:
        return findings
    try:
        tlist = s.call("tools/list") or {}
        tools = tlist.get("tools") or []
        verifiers = [t for t in tools if isinstance(t, dict) and is_verify_tool(t)]
        hit = None
        for t in verifiers:
            hit = probe(s, t)
            if hit:
                break
        if not hit:
            return findings
        # blast radius: mutating tools the bypass could reach (metadata only, not invoked)
        reachable = []
        for t in tools:
            if not isinstance(t, dict):
                continue
            for cap in classify_mutations(t):
                reachable.append({"tool": t.get("name"), "capability": cap})
        info = s.info or {}
        # human-readable impact -> stderr (never stdout, which carries findings JSON)
        sys.stderr.write(f"\n[!] Impact - forged token accepted by '{hit['tool']}' on "
                         f"{info.get('name','unknown')}. Mutating operations this bypass could reach:\n")
        if reachable:
            for m in reachable:
                sys.stderr.write(f"      - {m['tool']}: {m['capability']}\n")
        else:
            sys.stderr.write("      (no mutating tools exposed)\n")
        sys.stderr.write("      (enumerated from tool metadata; NOT invoked by this template)\n")
        sys.stderr.flush()
        findings.append({
            "target": f"{scheme}://{host}:{port}{s.endpoint or '/sse'}",
            "template_id": METADATA["id"],
            "severity": METADATA["severity"],
            "confidence": METADATA["confidence"],
            "title": METADATA["name"],
            "description": (f"MCP server '{info.get('name','unknown')}' tool '{hit['tool']}' reported a forged, "
                            f"never-issued token as valid (broken token validation). "
                            + (f"Bypass blast radius - {len(reachable)} mutating tool(s) reachable: "
                               f"{', '.join(sorted({m['tool'] for m in reachable}))}." if reachable
                               else "No mutating tools are exposed on this server.")),
            "evidence": {
                "request": f"{s.transport} tools/call {hit['tool']} (forged token: {hit['forged_token']})",
                "response": hit["response"],
                "matched_patterns": ["forged-token-accepted"],
                "data": {"protocol": scheme, "port": port, "transport": s.transport,
                         "server_name": info.get("name"), "verifier_tool": hit["tool"],
                         "forged_token": hit["forged_token"], "reachable_mutations": reachable},
            },
            "cwe_ids": METADATA["cwe"],
            "tags": METADATA["tags"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    finally:
        s.close()
    return findings


def main():
    sys.stderr.write("[!] mcp-broken-token-validation is an ACTIVE check: it sends forged (junk) tokens to "
                     "token-verification tools on the target. Make sure you are authorized to test this system.\n")
    sys.stderr.flush()
    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST")
        port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "8000"))
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        if not host:
            print(json.dumps({"error": "CERT_X_GEN_TARGET_HOST not set"})); sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({"error": "Usage: mcp-broken-token-validation.py <host> [port] [scheme]"})); sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"
    print(json.dumps({"findings": test_mcp(host, port, scheme=scheme), "metadata": METADATA}, indent=2))


if __name__ == "__main__":
    main()

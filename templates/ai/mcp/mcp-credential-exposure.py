#!/usr/bin/env python3
# @id: mcp-credential-exposure
# @name: MCP Credential / Secret Exposure via Resources
# @author: Bugb Research
# @severity: critical
# @description: Detects MCP servers that expose an OBSERVED credential through a readable resource - a structurally valid API key, private key, JWT or connection-string password read back over resources/read, never a resource whose name merely sounds credential-ish
# @tags: mcp, ai, agent, credential-exposure, secrets, cwe-522
# @cwe: CWE-522
# @cvss: 9.1
# @target_kinds: http
# @oracles: property
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/522.html
# @confidence: 95
# @version: 2.0.0
"""
MCP credential exposure - a secret this template actually read back.

An MCP server advertises resources and serves them to any connected client via
`resources/read`.  A resource that returns a live API key, a private key or a
database URL with a password in it hands that secret to every agent on the
other end of the session, and to whatever the agent's transcript is stored in.
Maps to CWE-522.

WHAT CHANGED IN 2.0.0, AND WHY (this repo's issue #32)

v1 reported a medium finding when a resource's NAME looked credential-ish, even
when it had read the resource and found nothing:

    if secrets or meta_hit:        # meta_hit alone was enough
        exposed.append(...)

`CRED_KEYWORDS` contains `token`, `password`, `secret`, `.env`, so a server
exposing "Token Usage Stats", "Password Reset Policy" or "Secret Santa Roster"
produced a finding whose own evidence field conceded no secret was observed
(`matched_patterns: ["credential-named-resource"]`).  Templated URIs made it
worse: `secrets://{key}` is never read, so nothing but the name could ever fire.

And `password-assignment` was `pass(?:word|wd)?\\s*[:=]\\s*\\S{6,}` - any six
non-space characters - which matches every line of documentation and every
`.env.example` a repository has ever shipped, escalating the finding to
critical:

    password: your-password-here      password = <redacted>
    password: ${DB_PASSWORD}          passwd: changeme
    password: ********                password: **REDACTED**

THE ORACLE IN 2.0.0

  A finding requires an OBSERVED SECRET: a string that this template read back
  over `resources/read` and that is structurally a credential.  Two conditions,
  both necessary:

  O1 observed    The bytes were returned by the server in this run.  A name, a
                 description, a URI, and a resource that could not be read are
                 none of them evidence.  `meta_hit` survives only as a TARGETING
                 hint - it decides which resources to read first under MAX_READS
                 - and is reported as an observation, never as a finding.

  O2 structural  The match is a credential by shape, not by neighbouring words.
                 Six of the eight patterns already were: `AKIA[0-9A-Z]{16}`,
                 `sk-[A-Za-z0-9]{16,}`, `AIza...`, the JWT triple, the PEM
                 header, the `scheme://user:pass@` authority.  The two
                 assignment patterns are now gated by `is_live_secret()`, which
                 rejects a value that is a placeholder (`<...>`, `${...}`,
                 `****`, `changeme`, `your-*`, `redacted`, `example`, `xxxx`,
                 a bare `null`/`none`/`true`) or that has too little character
                 variety to be a real secret.  A value that fails that gate is
                 recorded as a `placeholder-assignment` observation.

  A resource that was read and yielded no observed secret is REFUTED, and the
  refutation says how many resources were read.  A resource that could not be
  read - a templated URI, an error, a binary body - is named in the skip
  reasons, because a resource this template never opened is not a clean bill of
  health for that resource.

Non-invasive: enumerates `resources/list` and reads static resources via
`resources/read`.  Both are read-only reads of data the server advertises as
readable; it never invokes a tool.  Matched secrets are REDACTED in the output.
Speaks streamable HTTP and legacy HTTP+SSE.

Verdict contract:
  confirmed  a structurally valid secret was read back, with its type and a
             redacted preview
  refuted    resources were read and none returned a secret; unread resources
             and credential-named resources are named as observations
  skipped    no MCP server answered, the server advertises no resources, or
             every advertised resource was unreadable
  errored    the target could not be reached at all
"""

import json
import math
import os
import queue
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-credential-exposure",
    "name": "MCP Credential / Secret Exposure via Resources",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "critical",
    "description": (
        "Detects MCP servers exposing an OBSERVED credential through a readable resource: a "
        "structurally valid API key, private key, JWT or connection-string password read back "
        "over resources/read"
    ),
    "tags": ["mcp", "ai", "agent", "credential-exposure", "secrets", "cwe-522"],
    "language": "python",
    "confidence": 95,
    "cwe": ["CWE-522"],
    "references": ["https://modelcontextprotocol.io/specification",
                   "https://cwe.mitre.org/data/definitions/522.html"],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"
MAX_READS = 25

# A targeting hint ONLY.  It decides read order under MAX_READS; it can never
# produce a finding.  This is issue #32's first half.
CRED_KEYWORDS = ["credential", "secret", "token", "password", "passwd", "api_key",
                 "apikey", "api-key", ".env", "private_key", "private-key", "priv_key"]

# Structural patterns: a credential by shape, independent of surrounding words.
STRUCTURAL_PATTERNS = [
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    ("openai-style-key", r"sk-[A-Za-z0-9]{16,}"),
    ("google-api-key", r"AIza[0-9A-Za-z_\-]{20,}"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}"),
    ("db-connection-string",
     r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:([^@\s]+)@"),
]
# Assignment patterns: the NAME carries the meaning, so the VALUE has to earn
# it.  Group 1 is the value, and it is passed through is_live_secret().
ASSIGNMENT_PATTERNS = [
    ("password-assignment", r"(?i)pass(?:word|wd)?\s*[:=]\s*[\"']?([^\s\"',;]{6,})"),
    ("generic-api-key", r"(?i)api[_-]?key\s*[:=]\s*[\"']?([A-Za-z0-9\-_]{12,})"),
]
STRUCTURAL_RE = [(n, re.compile(p)) for n, p in STRUCTURAL_PATTERNS]
ASSIGNMENT_RE = [(n, re.compile(p)) for n, p in ASSIGNMENT_PATTERNS]

# Every one of these is what documentation, a .env.example or a redacted export
# puts after `password:`.  None is a secret; all matched v1's `\S{6,}`.
PLACEHOLDER_EXACT = {
    "password", "passwd", "secret", "changeme", "change_me", "change-me",
    "redacted", "example", "placeholder", "null", "none", "true", "false",
    "hunter2", "notset", "unset", "todo", "tbd", "string", "value",
}
PLACEHOLDER_SHAPE = re.compile(
    r"^(?:"
    r"<.*>"                     # <redacted>, <your-password>
    r"|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"   # ${DB_PASSWORD}, $PGPASSWORD
    r"|%[A-Za-z_]+%"            # %PASSWORD%
    r"|\{\{?[A-Za-z_. ]+\}?\}"  # {{password}}, {password}
    r"|[*x•.\-_#?]+"       # ********, xxxxxxxx, ------, ......
    r"|\*+[A-Za-z]+\*+"         # **REDACTED**
    r"|(?:your|my|the|some|a)[-_.].*"     # your-password-here
    r"|.*(?:here|goes[-_.]?here)$"        # password-goes-here
    r")$", re.I)


def _variety(value):
    """How many character classes the value draws on (lower, upper, digit, other)."""
    return sum([
        bool(re.search(r"[a-z]", value)),
        bool(re.search(r"[A-Z]", value)),
        bool(re.search(r"[0-9]", value)),
        bool(re.search(r"[^A-Za-z0-9]", value)),
    ])


def _entropy(value):
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def is_live_secret(value):
    """Could this string be a real credential? Returns (bool, reason).

    Deliberately conservative in the direction that costs least: a rejected
    real secret is a missed finding on ONE pattern that six structural patterns
    still cover, while an accepted placeholder is issue #32 all over again.
    """
    # Quotes, markdown backticks and sentence punctuation are delimiters, not
    # part of the value.  A policy document that writes ``password:
    # **REDACTED**`.`` captures ``**REDACTED**`.`` and, unstripped, none of the
    # placeholder shapes below anchor against it.
    v = (value or "").strip()
    while v and v[-1] in "`\"'.,;:!?":
        v = v[:-1]
    while v and v[0] in "`\"'":
        v = v[1:]
    if not v:
        return False, "empty"
    if v.lower() in PLACEHOLDER_EXACT:
        return False, "well-known placeholder %r" % v
    if PLACEHOLDER_SHAPE.match(v):
        return False, "placeholder shape %r" % v
    if len(set(v)) <= 2:
        return False, "fewer than three distinct characters (%r)" % v[:12]
    if _variety(v) < 2 and _entropy(v) < 3.0:
        return False, ("one character class and %.2f bits/char - reads as a word, "
                       "not a secret (%r)" % (_entropy(v), v[:12]))
    return True, "%d chars, %d character classes, %.2f bits/char" % (
        len(v), _variety(v), _entropy(v))


def redact(s):
    s = (s or "").strip()
    return "****" if len(s) <= 8 else s[:5] + "…" + s[-2:]


def scan_secrets(text):
    """(secrets, observations) for one resource body.

    A secret is a structural match, or an assignment whose VALUE passes
    is_live_secret().  A rejected assignment becomes an observation so the
    report says what was seen and why it was not reported.
    """
    secrets, observations = [], []
    text = text or ""
    for name, rx in STRUCTURAL_RE:
        m = rx.search(text)
        if not m:
            continue
        if name == "db-connection-string":
            live, why = is_live_secret(m.group(1))
            if not live:
                observations.append({"type": name, "reason":
                                     "connection string carries a %s" % why})
                continue
        secrets.append({"type": name, "basis": "structural",
                        "preview": redact(m.group(0))})
    for name, rx in ASSIGNMENT_RE:
        for m in rx.finditer(text):
            live, why = is_live_secret(m.group(1))
            if live:
                secrets.append({"type": name, "basis": "assignment (%s)" % why,
                                "preview": redact(m.group(0))})
                break
            observations.append({"type": "placeholder-assignment",
                                 "reason": "%s matched but the value is a %s"
                                           % (name, why)})
    return secrets, observations


# ---------------------------------------------------------------------------
# Transport.  Unchanged from 1.0.0: two MCP dialects, read-only calls.
# ---------------------------------------------------------------------------

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
        self._rid = 10; self._seen = {}

    def call(self, method, params=None):
        self._rid += 1
        rid = self._rid
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        if self.transport == "streamable-http":
            _, _, body = _post(self.base + self.endpoint, payload, self.timeout, self.sid)
            obj = _extract_json(body) or {}
            return obj.get("result")
        # SSE
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
    # streamable first
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
    # legacy SSE
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
    info = {}; end = time.time() + 4
    while time.time() < end:
        try:
            msg = responses.get(timeout=0.5)
            if msg.get("id") == 1:
                info = (msg.get("result") or {}).get("serverInfo") or {}
                break
        except queue.Empty:
            continue
    s = Session("http+sse", base, timeout, post_url=post_url, responses=responses, stop=stop)
    s.info = info
    return s



# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------

def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def _body_text(content):
    """Text parts of a resources/read result. Binary (`blob`) parts are unread."""
    parts, binary = [], 0
    for c in (content or {}).get("contents") or []:
        if not isinstance(c, dict):
            continue
        if isinstance(c.get("text"), str):
            parts.append(c["text"])
        elif c.get("blob") is not None:
            binary += 1
    return " ".join(parts), binary


def scan(host, port, timeout=12, scheme="http"):
    session = open_session(host, port, timeout, scheme)
    if not session:
        return "skipped", "no-mcp-server-answered(%s://%s:%d)" % (scheme, host, port), [], None

    try:
        listing = session.call("resources/list") or {}
        resources = [r for r in (listing.get("resources") or []) if isinstance(r, dict)]
        info = getattr(session, "info", {}) or {}
        endpoint = "%s://%s:%d%s" % (scheme, host, port, session.endpoint or "/sse")
        transport = session.transport
        if not resources:
            return ("skipped",
                    "server-advertises-no-resources(a server with nothing readable is not a "
                    "clean bill of health for its tools)", [], None)

        # meta_hit is a TARGETING hint: it only decides read order under
        # MAX_READS.  It can never produce a finding.  Issue #32, part 1.
        def cred_named(r):
            meta = "%s %s %s" % (r.get("uri") or "", r.get("name") or "",
                                 r.get("description") or "")
            return any(k in meta.lower() for k in CRED_KEYWORDS)

        ordered = sorted(resources, key=lambda r: not cred_named(r))
        exposed, unread, observations = [], [], []
        read_count = 0

        for r in ordered[:MAX_READS]:
            uri = r.get("uri") or ""
            named = cred_named(r)
            if named:
                observations.append({
                    "uri": uri, "class": "credential-named-resource",
                    "detail": "name/URI matches a credential keyword; used to read this "
                              "resource first, never to report it"})
            if not uri:
                unread.append({"uri": uri, "reason": "resource advertised with no uri"})
                continue
            if "{" in uri or "}" in uri:
                unread.append({"uri": uri, "reason":
                               "templated uri - resources/read needs concrete arguments "
                               "this template does not invent"})
                continue
            content = session.call("resources/read", {"uri": uri})
            if not isinstance(content, dict):
                unread.append({"uri": uri, "reason": "resources/read returned no result"})
                continue
            read_count += 1
            text, binary = _body_text(content)
            if binary and not text:
                unread.append({"uri": uri, "reason":
                               "%d binary (blob) part(s) only - not scanned" % binary})
                continue
            secrets, soft = scan_secrets(text)
            for s in soft:
                observations.append({"uri": uri, "class": s["type"],
                                     "detail": s["reason"]})
            if secrets:
                exposed.append({"uri": uri, "name": r.get("name"),
                                "credential_named": named, "secrets_found": secrets})
    finally:
        session.close()

    surface = "transport=%s advertised=%d read=%d unread=%d" % (
        transport, len(resources), read_count, len(unread))
    ctx = {"endpoint": endpoint, "transport": transport, "info": info,
           "surface": surface, "unread": unread, "observations": observations,
           "read_count": read_count, "advertised": len(resources)}

    if not exposed:
        if read_count == 0:
            return ("skipped",
                    "no-resource-could-be-read (%s); unread: %s" % (
                        surface, "; ".join("%s (%s)" % (u["uri"], u["reason"])
                                           for u in unread[:5])),
                    [], ctx)
        detail = "no-secret-observed-in-any-readable-resource (%s)" % surface
        if observations:
            detail += "; %d observation(s) recorded and deliberately not reported: %s" % (
                len(observations), ", ".join(sorted({o["class"] for o in observations})))
        if unread:
            detail += "; %d resource(s) not read and therefore not cleared: %s" % (
                len(unread), ", ".join(u["uri"] for u in unread[:5]))
        return "refuted", detail, [], ctx

    return "confirmed", None, exposed, ctx


def build_finding(exposed, ctx, scheme, port):
    info = ctx["info"]
    secret_types = sorted({s["type"] for e in exposed for s in e["secrets_found"]})
    return {
        "target": ctx["endpoint"],
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (
            "MCP server '%s' returned %d resource(s) containing a credential this scan read "
            "back over resources/read, readable by any connected client: %s. Secret types: %s."
            % (info.get("name", "unknown"), len(exposed),
               ", ".join(str(e["uri"]) for e in exposed), ", ".join(secret_types))),
        "evidence": {
            "request": "%s resources/list -> resources/read" % ctx["transport"],
            "response": json.dumps({"serverInfo": info,
                                    "exposed_resources": [e["uri"] for e in exposed]})[:1000],
            "matched_patterns": secret_types,
            "data": {
                "protocol": scheme,
                "port": port,
                "transport": ctx["transport"],
                "server_name": info.get("name"),
                "resources_advertised": ctx["advertised"],
                "resources_read": ctx["read_count"],
                "exposed_resources": exposed,
                "resources_not_read": ctx["unread"],
                "observations_not_reported": ctx["observations"],
            },
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main():
    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST")
        port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "8000"))
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        if not host:
            emit("errored", "CERT_X_GEN_TARGET_HOST not set")
            sys.exit(0)
    else:
        if len(sys.argv) < 2:
            emit("errored", "Usage: mcp-credential-exposure.py <host> [port] [scheme]")
            sys.exit(0)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"

    status, detail, exposed, ctx = scan(host, port, scheme=scheme)
    if status != "confirmed":
        emit(status, detail)
        return
    finding = build_finding(exposed, ctx, scheme, port)
    types = sorted({s["type"] for e in exposed for s in e["secrets_found"]})
    emit("confirmed", "secret-read-back(%s) resources=%d (%s)"
         % (",".join(types), len(exposed), ctx["surface"]), [finding])


if __name__ == "__main__":
    main()

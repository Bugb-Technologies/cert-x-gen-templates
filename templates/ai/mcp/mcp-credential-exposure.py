#!/usr/bin/env python3
# @id: mcp-credential-exposure
# @name: MCP Credential / Secret Exposure via Resources
# @author: Bugb Research
# @severity: critical
# @description: Detects MCP servers that expose credentials or secrets through readable resources (API keys, passwords, private keys, DB connection strings, JWTs)
# @tags: mcp, ai, agent, credential-exposure, secrets, cwe-522
# @cwe: CWE-522
# @cvss: 9.1
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/522.html
# @confidence: 90
# @version: 1.0.0
"""
Detects credential/secret exposure through MCP *resources*.

Non-invasive: enumerates resources/list and reads static (non-templated)
resources via resources/read -- both are read-only reads of data the server
advertises as readable. It never invokes a tool. Resource content is scanned
for high-confidence secret patterns; matched secrets are REDACTED in output.
Speaks both Streamable HTTP and legacy HTTP+SSE. Maps to CWE-522.
"""

import os, sys, json, ssl, re, threading, queue, time
import urllib.request, urllib.error
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-credential-exposure",
    "name": "MCP Credential / Secret Exposure via Resources",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "critical",
    "description": "Detects MCP servers exposing credentials/secrets through readable resources",
    "tags": ["mcp", "ai", "agent", "credential-exposure", "secrets", "cwe-522"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-522"],
    "references": ["https://modelcontextprotocol.io/specification", "https://cwe.mitre.org/data/definitions/522.html"],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"
MAX_READS = 25

CRED_KEYWORDS = ["credential", "secret", "token", "password", "passwd", "api_key",
                 "apikey", "api-key", ".env", "private_key", "private-key", "priv_key"]
SECRET_PATTERNS = [
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    ("openai-style-key", r"sk-[A-Za-z0-9]{16,}"),
    ("google-api-key", r"AIza[0-9A-Za-z_\-]{20,}"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}"),
    ("db-connection-string", r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]+@"),
    ("password-assignment", r"(?i)pass(?:word|wd)?\s*[:=]\s*\S{6,}"),
    ("generic-api-key", r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9\-_]{12,}"),
]
SECRET_RE = [(n, re.compile(p)) for n, p in SECRET_PATTERNS]


def redact(s):
    s = s.strip()
    if len(s) <= 8:
        return "****"
    return s[:5] + "\u2026" + s[-2:]


def scan_secrets(text):
    hits = []
    for name, rx in SECRET_RE:
        m = rx.search(text or "")
        if m:
            hits.append({"type": name, "preview": redact(m.group(0))})
    return hits


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


def test_mcp(host, port, timeout=12, scheme="http"):
    findings = []
    s = open_session(host, port, timeout, scheme)
    if not s:
        return findings
    try:
        rlist = s.call("resources/list") or {}
        resources = rlist.get("resources") or []
        exposed = []
        for r in resources[:MAX_READS]:
            uri = r.get("uri") or ""
            meta = f"{uri} {r.get('name','')} {r.get('description','')}".lower()
            meta_hit = any(k in meta for k in CRED_KEYWORDS)
            secrets = []
            if "{" not in uri and "}" not in uri:  # skip templated URIs
                content = s.call("resources/read", {"uri": uri}) or {}
                text = " ".join(c.get("text", "") for c in (content.get("contents") or []) if isinstance(c, dict))
                secrets = scan_secrets(text)
            if secrets or meta_hit:
                exposed.append({"uri": uri, "name": r.get("name"),
                                "credential_named": meta_hit, "secrets_found": secrets})
    finally:
        s.close()
    if not exposed:
        return findings
    confirmed = [e for e in exposed if e["secrets_found"]]
    severity = "critical" if confirmed else "medium"
    info = getattr(s, "info", {}) or {}
    secret_types = sorted({sec["type"] for e in exposed for sec in e["secrets_found"]})
    findings.append({
        "target": f"{scheme}://{host}:{port}{s.endpoint or '/sse'}",
        "template_id": METADATA["id"],
        "severity": severity,
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (f"MCP server '{info.get('name','unknown')}' exposes {len(exposed)} resource(s) that "
                        f"{'leak secrets' if confirmed else 'appear to hold credentials'} readable by any connected client: "
                        f"{', '.join(str(e['uri']) for e in exposed)}."
                        + (f" Secret types: {', '.join(secret_types)}." if secret_types else "")),
        "evidence": {
            "request": f"{s.transport} resources/list -> resources/read",
            "response": json.dumps({"serverInfo": info, "exposed_resources": [e["uri"] for e in exposed]})[:1000],
            "matched_patterns": secret_types or ["credential-named-resource"],
            "data": {"protocol": scheme, "port": port, "transport": s.transport,
                     "server_name": info.get("name"), "exposed_resources": exposed},
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return findings


def main():
    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST")
        port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "8000"))
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        if not host:
            print(json.dumps({"error": "CERT_X_GEN_TARGET_HOST not set"})); sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({"error": "Usage: mcp-credential-exposure.py <host> [port] [scheme]"})); sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"
    print(json.dumps({"findings": test_mcp(host, port, scheme=scheme), "metadata": METADATA}, indent=2))


if __name__ == "__main__":
    main()

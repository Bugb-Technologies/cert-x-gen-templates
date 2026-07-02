#!/usr/bin/env python3
# @id: mcp-excessive-tool-permissions
# @name: MCP Excessive Tool Permissions (Dangerous Capability Exposure)
# @author: Bugb Research
# @severity: high
# @description: Detects MCP tools whose declared interface exposes high-risk capabilities (command execution, filesystem write/delete, raw SQL, arbitrary network fetch) beyond least privilege
# @tags: mcp, ai, agent, excessive-permissions, least-privilege, cwe-250
# @cwe: CWE-250
# @cvss: 7.4
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/250.html
# @confidence: 80
# @version: 1.0.0
"""
Detects MCP "excessive permission scope": tools that advertise high-risk,
unconstrained capabilities in their declared interface (name, description,
input schema) -- e.g. a file_manager tool that can read, WRITE and DELETE
files via a free-form path, or a tool that executes shell commands.

Non-invasive: inspects only the advertised tool metadata (tools/list). It
never invokes a tool. Speaks both Streamable HTTP and legacy HTTP+SSE.
Maps to CWE-250 (Execution with Unnecessary Privileges).
"""

import os, sys, json, ssl, re, threading, queue, time
import urllib.request, urllib.error
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-excessive-tool-permissions",
    "name": "MCP Excessive Tool Permissions (Dangerous Capability Exposure)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": "Detects MCP tools exposing high-risk capabilities (exec, file write/delete, raw SQL, SSRF) in their declared interface",
    "tags": ["mcp", "ai", "agent", "excessive-permissions", "least-privilege", "cwe-250"],
    "language": "python",
    "confidence": 80,
    "cwe": ["CWE-250"],
    "references": ["https://modelcontextprotocol.io/specification", "https://cwe.mitre.org/data/definitions/250.html"],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# capability -> (severity, description-regex, decisive-param-names)
CAP_RULES = [
    ("command/code execution", "high",
     r"(execute|run)\s+(a\s+|the\s+)?(system\s+)?(command|shell|code|script)|shell\s+command|arbitrary\s+code|\beval\b|subprocess|os\.system",
     {"command", "cmd", "code", "script", "shell"}),
    ("filesystem write/delete", "high",
     r"\b(write|delete|remove|overwrite|modify|rename|move)\b[^.]{0,40}\bfiles?\b|\bfiles?\b[^.]{0,20}\b(write|delete|remove|overwrite)",
     set()),
    ("raw database query", "high",
     r"\b(sql\b|execute\s+(a\s+)?query|run\s+(a\s+)?query|database\s+query|arbitrary\s+query)",
     {"sql", "query"}),
    ("filesystem read", "medium",
     r"read\s+(a\s+|the\s+)?file|file\s+contents?|read\s+from\s+(the\s+)?(disk|filesystem)",
     set()),
    ("arbitrary network fetch (SSRF)", "medium",
     r"fetch\s+(a\s+)?(url|http|web|remote)|make\s+(an?\s+)?(http\s+)?request|download\s+(a\s+)?url|call\s+(an?\s+)?(external\s+)?(api|endpoint|url)",
     {"url", "uri", "endpoint"}),
]
CAP_RE = [(cap, sev, re.compile(rx, re.I), params) for cap, sev, rx, params in CAP_RULES]


def classify(tool):
    name = tool.get("name") or ""
    desc = tool.get("description") or ""
    props = set((tool.get("inputSchema", {}) or {}).get("properties", {}).keys())
    text = f"{name} {desc}"
    caps = []
    for cap, sev, rx, decisive in CAP_RE:
        by_text = bool(rx.search(text))
        by_param = bool(decisive & {p.lower() for p in props})
        if by_text or by_param:
            caps.append({"capability": cap, "severity": sev,
                         "matched": ("description" if by_text else "") + ("+param" if by_param else "")})
    return caps


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


def enum_streamable(base, timeout):
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTO_VERSION, "capabilities": {}, "clientInfo": {"name": "cxg", "version": "1.0"}}}
    for path in MCP_PATHS:
        status, headers, body = _post(base + path, init, timeout)
        if status != 200:
            continue
        obj = _extract_json(body)
        if not obj or "result" not in obj:
            continue
        sid = headers.get("mcp-session-id")
        info = (obj.get("result") or {}).get("serverInfo") or {}
        _post(base + path, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, sid)
        _, _, tb = _post(base + path, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, timeout, sid)
        tools = ((_extract_json(tb) or {}).get("result") or {}).get("tools") or []
        return {"transport": "streamable-http", "endpoint": path, "serverInfo": info, "tools": tools}
    return None


def enum_sse(base, timeout):
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

    def post(p):
        try:
            urllib.request.urlopen(urllib.request.Request(post_url, data=json.dumps(p).encode(), headers={"Content-Type": "application/json"}, method="POST"), timeout=timeout, context=_ctx()).read()
        except Exception:
            pass

    post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTO_VERSION, "capabilities": {}, "clientInfo": {"name": "cxg", "version": "1.0"}}})
    post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    post({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    info = {}; tools = None; end = time.time() + min(timeout, 8)
    while time.time() < end:
        try:
            msg = responses.get(timeout=1)
        except queue.Empty:
            continue
        if msg.get("id") == 1:
            info = (msg.get("result") or {}).get("serverInfo") or {}
        if msg.get("id") == 2:
            tools = (msg.get("result") or {}).get("tools") or []
            break
    stop.set()
    if tools is None:
        return None
    return {"transport": "http+sse", "endpoint": "/sse", "serverInfo": info, "tools": tools}


def enumerate_mcp(host, port, timeout=12, scheme="http"):
    base = f"{scheme}://{host}:{port}"
    return enum_streamable(base, timeout) or enum_sse(base, timeout)


def test_mcp(host, port, timeout=12, scheme="http"):
    findings = []
    result = enumerate_mcp(host, port, timeout, scheme)
    if not result:
        return findings
    base = f"{scheme}://{host}:{port}"
    risky = []
    worst = "info"
    for t in result.get("tools") or []:
        if not isinstance(t, dict):
            continue
        caps = classify(t)
        if caps:
            risky.append({"tool": t.get("name"), "capabilities": caps})
            for c in caps:
                if SEV_RANK[c["severity"]] > SEV_RANK[worst]:
                    worst = c["severity"]
    if not risky:
        return findings
    info = result.get("serverInfo") or {}
    cap_summary = sorted({c["capability"] for r in risky for c in r["capabilities"]})
    findings.append({
        "target": f"{base}{result.get('endpoint','')}",
        "template_id": METADATA["id"],
        "severity": worst,
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (f"MCP server '{info.get('name','unknown')}' exposes {len(risky)} tool(s) advertising high-risk "
                        f"capabilities [{', '.join(cap_summary)}]: {', '.join(str(r['tool']) for r in risky)}. "
                        f"Review against least privilege."),
        "evidence": {
            "request": f"{result.get('transport')} initialize -> tools/list",
            "response": json.dumps({"serverInfo": info, "risky_tools": [r["tool"] for r in risky]})[:1000],
            "matched_patterns": cap_summary,
            "data": {"protocol": scheme, "port": port, "transport": result.get("transport"),
                     "server_name": info.get("name"), "risky_tools": risky},
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
            print(json.dumps({"error": "Usage: mcp-excessive-tool-permissions.py <host> [port] [scheme]"})); sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"
    print(json.dumps({"findings": test_mcp(host, port, scheme=scheme), "metadata": METADATA}, indent=2))


if __name__ == "__main__":
    main()

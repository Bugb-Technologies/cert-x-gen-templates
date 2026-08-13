#!/usr/bin/env python3
# @id: mcp-tool-poisoning
# @name: MCP Tool Poisoning (Hidden Instructions in Tool Metadata)
# @author: Bugb Research
# @severity: high
# @description: Detects MCP servers whose tool, prompt, or resource descriptions embed hidden instructions that manipulate the connected LLM (tool poisoning)
# @tags: mcp, ai, agent, tool-poisoning, prompt-injection, cwe-1427
# @cwe: CWE-1427
# @cvss: 8.2
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/1427.html
# @confidence: 85
# @version: 1.0.0
"""
Detects MCP "tool poisoning": tool/prompt/resource descriptions returned by an
MCP server that embed instructions aimed at the LLM (e.g. hidden <IMPORTANT>
blocks telling the model to read confidential resources and not mention it).

Speaks both MCP transports:
  - Streamable HTTP  (single endpoint, POST initialize -> tools/list)
  - Legacy HTTP+SSE  (GET /sse for the stream, POST to /messages/)

The tool implementation is irrelevant; the weakness is in the metadata the
server advertises, which the agent ingests as trusted context. Maps to
CWE-1427 (Improper Neutralization of Input Used for LLM Prompting).
"""

import os, sys, json, ssl, re, threading, queue, time
import urllib.request, urllib.error
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-tool-poisoning",
    "name": "MCP Tool Poisoning (Hidden Instructions in Tool Metadata)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": "Detects MCP servers advertising tool/prompt/resource descriptions that embed hidden instructions to manipulate the connected LLM",
    "tags": ["mcp", "ai", "agent", "tool-poisoning", "prompt-injection", "cwe-1427"],
    "language": "python",
    "confidence": 85,
    "cwe": ["CWE-1427"],
    "references": ["https://modelcontextprotocol.io/specification", "https://cwe.mitre.org/data/definitions/1427.html"],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"

HIDDEN_TAG = re.compile(r"<\s*(important|hidden|secret|system|instructions?|admin|override|ai)\s*>", re.I)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
IMPERATIVE = [
    r"ignore\s+(all|any|the|your|previous|prior|above)\s+(instruction|prompt|rule)",
    r"disregard\s+(all|any|the|your|previous|prior|above)",
    r"do\s*not\s+(mention|tell|reveal|disclose|inform|notify|say)",
    r"without\s+(telling|mentioning|informing|notifying|the user)",
    r"present\s+it\s+as\s+if",
    r"as\s+part\s+of\s+(the|your)\s+(normal|response)",
    r"when\s+this\s+tool\s+is\s+(called|invoked|used)",
    r"before\s+(you\s+)?respond",
    r"you\s+must\s+(first\s+)?(read|access|call|include|return|use)",
    r"system\s+prompt",
]
RESOURCE_ACCESS = [
    r"access(ing)?\s+the\s+resource", r"read\s+the\s+(confidential|secret|private|restricted)",
    r"include\s+it\s+in\s+your\s+response", r"return\s+it\s+as\s+part", r"exfiltrat",
]
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
IMPERATIVE_RE = [re.compile(p, re.I) for p in IMPERATIVE]
RESOURCE_RE = [re.compile(p, re.I) for p in RESOURCE_ACCESS]


def analyze(text):
    if not text:
        return []
    hits = []
    m = HIDDEN_TAG.search(text)
    if m:
        hits.append(("hidden-instruction-tag", m.group(0)))
    if HTML_COMMENT.search(text) and any(r.search(text) for r in IMPERATIVE_RE):
        hits.append(("instruction-in-html-comment", "<!-- ... -->"))
    if ZERO_WIDTH.search(text):
        hits.append(("zero-width-characters", "hidden unicode"))
    imp = [r.pattern for r in IMPERATIVE_RE if r.search(text)]
    res = [r.pattern for r in RESOURCE_RE if r.search(text)]
    if imp and (res or len(imp) >= 2):
        hits.append(("model-directed-instructions", "; ".join((imp + res)[:3])))
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


def enum_streamable(base, timeout):
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTO_VERSION, "capabilities": {}, "clientInfo": {"name": "cxg", "version": "1.0"}}}
    for path in MCP_PATHS:
        url = base + path
        status, headers, body = _post(url, init, timeout)
        if status != 200:
            continue
        obj = _extract_json(body)
        if not obj or "result" not in obj:
            continue
        sid = headers.get("mcp-session-id")
        info = (obj.get("result") or {}).get("serverInfo") or {}
        _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, sid)
        _, _, tb = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, timeout, sid)
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
    poisoned = []
    for t in result.get("tools") or []:
        if not isinstance(t, dict):
            continue
        hits = analyze(t.get("description") or "")
        if hits:
            poisoned.append({"tool": t.get("name"), "indicators": hits})
    if not poisoned:
        return findings
    info = result.get("serverInfo") or {}
    indicator_names = sorted({h[0] for p in poisoned for h in p["indicators"]})
    findings.append({
        "target": f"{base}{result.get('endpoint','')}",
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (f"MCP server '{info.get('name','unknown')}' advertises {len(poisoned)} tool(s) whose "
                        f"descriptions embed hidden instructions to the LLM (tool poisoning): "
                        f"{', '.join(str(p['tool']) for p in poisoned)}."),
        "evidence": {
            "request": f"{result.get('transport')} initialize -> tools/list",
            "response": json.dumps({"serverInfo": info, "poisoned_tools": [p["tool"] for p in poisoned]})[:1000],
            "matched_patterns": indicator_names,
            "data": {"protocol": scheme, "port": port, "transport": result.get("transport"),
                     "server_name": info.get("name"), "poisoned_tools": poisoned},
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
            print(json.dumps({"error": "Usage: mcp-tool-poisoning.py <host> [port] [scheme]"})); sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"
    print(json.dumps({"findings": test_mcp(host, port, scheme=scheme), "metadata": METADATA}, indent=2))


if __name__ == "__main__":
    main()

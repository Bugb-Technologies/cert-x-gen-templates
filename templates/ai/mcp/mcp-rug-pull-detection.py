#!/usr/bin/env python3
# @id: mcp-rug-pull-detection
# @name: MCP Rug Pull (Silent Tool Definition Mutation)
# @author: Bugb Research
# @severity: high
# @description: Stateful multi-run check. Baselines each tool's definition on first scan and flags silent mutations (rug pulls) or newly appearing tools on re-scan
# @tags: mcp, ai, agent, rug-pull, supply-chain, tool-mutation, cwe-345
# @cwe: CWE-345
# @cvss: 7.5
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/345.html
# @confidence: 90
# @version: 1.0.0
"""
Workflow / stateful check (exemplar).

A "rug pull" is an MCP tool that changes its behavior or description AFTER it
was approved -- the definition the agent trusts silently mutates. A single
scan can't see it; you need memory. This template keeps a per-target baseline
of each tool's fingerprint (name + description + input schema) and, on every
later run, flags any tool whose definition drifted from the approved baseline,
plus tools that newly appeared (addition / shadowing).

Passive: enumerates tools/list only -- never invokes a tool. Baseline lives
under ~/.cxg-mcp-rugpull/ and is stable (drift is flagged every run until you
re-approve with CXG_RUGPULL_RESET=1). Speaks streamable HTTP and legacy SSE.
Maps to CWE-345 (Insufficient Verification of Data Authenticity).
"""

import os, sys, json, ssl, re, time, hashlib, threading, queue
import urllib.request, urllib.error
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-rug-pull-detection",
    "name": "MCP Rug Pull (Silent Tool Definition Mutation)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": "Stateful check: baselines tool definitions and flags silent mutations (rug pulls) or newly appearing tools on re-scan",
    "tags": ["mcp", "ai", "agent", "rug-pull", "supply-chain", "tool-mutation", "cwe-345"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-345"],
    "references": ["https://modelcontextprotocol.io/specification", "https://cwe.mitre.org/data/definitions/345.html"],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"
BASELINE_DIR = os.path.expanduser("~/.cxg-mcp-rugpull")


def fingerprint(tool):
    core = {"name": tool.get("name"), "description": tool.get("description"), "inputSchema": tool.get("inputSchema")}
    return hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode()).hexdigest()


def baseline_path(host, port):
    os.makedirs(BASELINE_DIR, exist_ok=True)
    return os.path.join(BASELINE_DIR, re.sub(r"[^A-Za-z0-9]", "_", f"{host}_{port}") + ".json")


def load_baseline(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def save_baseline(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


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


def enum_tools(host, port, timeout, scheme):
    base = f"{scheme}://{host}:{port}"
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTO_VERSION, "capabilities": {}, "clientInfo": {"name": "cxg", "version": "1.0"}}}
    # streamable
    for path in MCP_PATHS:
        status, headers, body = _post(base + path, init, timeout)
        if status == 200:
            obj = _extract_json(body)
            if obj and "result" in obj:
                sid = headers.get("mcp-session-id")
                _post(base + path, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, sid)
                _, _, tb = _post(base + path, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, timeout, sid)
                info = (obj.get("result") or {}).get("serverInfo") or {}
                return info, (((_extract_json(tb) or {}).get("result") or {}).get("tools") or [])
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
        stop.set(); return None, None
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
    return info, tools


def test_mcp(host, port, timeout=12, scheme="http"):
    findings = []
    info, tools = enum_tools(host, port, timeout, scheme)
    if tools is None:
        return findings
    current = {}
    for t in tools:
        if isinstance(t, dict) and t.get("name"):
            current[t["name"]] = {"hash": fingerprint(t), "desc": (t.get("description") or "")[:280]}
    path = baseline_path(host, port)
    prior = load_baseline(path)
    if prior is None or os.getenv("CXG_RUGPULL_RESET"):
        save_baseline(path, {"server": (info or {}).get("name"), "ts": datetime.now(timezone.utc).isoformat(), "tools": current})
        sys.stderr.write(f"[i] mcp-rug-pull-detection: baseline recorded for {len(current)} tool(s) on "
                         f"{(info or {}).get('name','target')}. Re-run later to detect silent mutations.\n")
        sys.stderr.flush()
        return findings
    prior_tools = prior.get("tools", {})
    changed, added = [], []
    for name, cur in current.items():
        if name in prior_tools:
            if cur["hash"] != prior_tools[name]["hash"]:
                changed.append({"tool": name, "approved_desc": prior_tools[name].get("desc", ""), "current_desc": cur["desc"]})
        else:
            added.append(name)
    removed = [n for n in prior_tools if n not in current]
    if not (changed or added):
        return findings
    severity = "high" if changed else "medium"
    parts = []
    if changed:
        parts.append(f"{len(changed)} tool(s) silently mutated since approval: {', '.join(c['tool'] for c in changed)}")
    if added:
        parts.append(f"{len(added)} new tool(s) appeared: {', '.join(added)}")
    if removed:
        parts.append(f"{len(removed)} removed: {', '.join(removed)}")
    findings.append({
        "target": f"{scheme}://{host}:{port}",
        "template_id": METADATA["id"],
        "severity": severity,
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": ("MCP server '" + str((info or {}).get("name", "unknown")) + "': " + "; ".join(parts)
                        + ". Tool definitions changed from the approved baseline without re-approval (rug pull)."),
        "evidence": {
            "request": f"tools/list compared against approved baseline ({prior.get('ts','?')})",
            "response": json.dumps({"changed": [c["tool"] for c in changed], "added": added, "removed": removed})[:1000],
            "matched_patterns": (["tool-definition-mutation"] if changed else []) + (["new-tool-appeared"] if added else []),
            "data": {"protocol": scheme, "port": port, "server_name": (info or {}).get("name"),
                     "baseline_ts": prior.get("ts"), "changed": changed, "added": added, "removed": removed},
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
            print(json.dumps({"error": "Usage: mcp-rug-pull-detection.py <host> [port] [scheme]"})); sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"
    print(json.dumps({"findings": test_mcp(host, port, scheme=scheme), "metadata": METADATA}, indent=2))


if __name__ == "__main__":
    main()

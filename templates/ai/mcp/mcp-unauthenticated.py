#!/usr/bin/env python3
# @id: mcp-unauthenticated-access
# @name: Unauthenticated MCP Server Exposure
# @author: Bugb Research
# @severity: high
# @description: Detects Model Context Protocol (MCP) servers that complete the JSON-RPC initialize handshake and enumerate tools without any authentication
# @tags: mcp, ai, agent, unauthenticated, jsonrpc, cwe-306
# @cwe: CWE-306
# @cvss: 8.6
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/306.html
# @confidence: 90
# @version: 1.0.0
"""
Detects unauthenticated MCP servers (Streamable HTTP / SSE transport).

An MCP server that answers `initialize` and `tools/list` with no credentials
hands any anonymous client the ability to enumerate - and call - its tools.
Maps to CWE-306 (Missing Authentication for Critical Function).
A 401/403 on initialize is treated as PROTECTED and is never reported.
"""

import os, sys, json, ssl
import urllib.request, urllib.error
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-unauthenticated-access",
    "name": "Unauthenticated MCP Server Exposure",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": "Detects MCP servers that complete the initialize handshake and expose tools without authentication",
    "tags": ["mcp", "ai", "agent", "unauthenticated", "jsonrpc", "cwe-306"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-306"],
    "references": [
        "https://modelcontextprotocol.io/specification",
        "https://cwe.mitre.org/data/definitions/306.html",
    ],
}

MCP_PATHS = ["/mcp", "/", "/sse", "/message", "/messages", "/rpc"]
PROTO_VERSION = "2025-06-18"


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
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if session_id:
        headers["mcp-session-id"] = session_id
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", "ignore")
        except Exception:
            pass
        return e.code, {k.lower(): v for k, v in dict(e.headers or {}).items()}, raw
    except Exception:
        return None, {}, ""


def test_mcp(host, port, timeout=10, scheme="http"):
    findings = []
    base = f"{scheme}://{host}:{port}"
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTO_VERSION, "capabilities": {},
                       "clientInfo": {"name": "cxg", "version": "1.0"}}}
    for path in MCP_PATHS:
        url = base + path
        status, headers, body = _post(url, init, timeout)
        if status is None:
            continue
        if status in (401, 403):
            return findings  # protected: never report
        if status != 200:
            continue
        obj = _extract_json(body)
        if not obj or "result" not in obj:
            continue
        result = obj.get("result", {}) or {}
        server_info = result.get("serverInfo") or {}
        if "protocolVersion" not in result and not server_info:
            continue  # not MCP
        session_id = headers.get("mcp-session-id")
        _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, session_id)
        _, _, tb = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, timeout, session_id)
        tobj = _extract_json(tb) or {}
        tools = [t["name"] for t in ((tobj.get("result", {}) or {}).get("tools", []) or [])
                 if isinstance(t, dict) and t.get("name")]
        findings.append({
            "target": f"{base}{path}",
            "template_id": METADATA["id"],
            "severity": METADATA["severity"],
            "confidence": METADATA["confidence"],
            "title": METADATA["name"],
            "description": (f"MCP server '{server_info.get('name','unknown')}' "
                            f"v{server_info.get('version','?')} completed the initialize "
                            f"handshake with no authentication and exposed {len(tools)} tool(s)."),
            "evidence": {
                "request": f"POST {path} (initialize -> tools/list, no credentials)",
                "response": json.dumps({"serverInfo": server_info,
                                        "protocolVersion": result.get("protocolVersion")})[:1000],
                "matched_patterns": ["protocolVersion", "serverInfo"] + (["tools/list"] if tools else []),
                "data": {"protocol": scheme, "port": port, "endpoint": path,
                         "server_name": server_info.get("name"),
                         "server_version": server_info.get("version"),
                         "tool_count": len(tools), "tools_exposed": tools[:50]},
            },
            "cwe_ids": METADATA["cwe"],
            "tags": METADATA["tags"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return findings
    return findings


def main():
    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST")
        port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "3001"))
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        if not host:
            print(json.dumps({"error": "CERT_X_GEN_TARGET_HOST not set"}))
            sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({"error": "Usage: mcp-unauthenticated.py <host> [port] [scheme]"}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 3001
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"
    print(json.dumps({"findings": test_mcp(host, port, scheme=scheme), "metadata": METADATA}, indent=2))


if __name__ == "__main__":
    main()

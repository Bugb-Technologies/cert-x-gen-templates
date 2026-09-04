#!/usr/bin/env python3
"""Benign synthetic MCP server for the routing-header / body method desync oracle.

Stdlib only. Streamable HTTP on ``POST /mcp``. This class lives entirely in the
HTTP transport, because the property under test is about the 2026-07-28
``Mcp-Method`` / ``Mcp-Name`` request headers, which stdio does not have.

The 2026-07-28 stateless-core adds those headers so a gateway can route and
AUTHORIZE a call without parsing the JSON-RPC body. All three modes advertise
the SAME manifest - one benign ``list_notes`` and one privileged decoy,
``admin_purge`` (``destructiveHint: true``). They differ ONLY in how they
reconcile the routing header with the body:

  ``--mode flawed``   dispatches on whichever method it can find, body first,
                      header as a fallback - and never checks the two AGREE.
                      A request with ``Mcp-Method: tools/list`` in the header
                      and ``tools/call admin_purge`` in the body runs the
                      privileged call. A gateway that authorized the header as
                      a harmless listing was bypassed. => the template CONFIRMS.

  ``--mode fixed``    reads the header, and REJECTS any request whose header
                      method disagrees with the body method (HTTP 409 +
                      JSON-RPC error), exactly as the stateless-core requires.
                      A matched request still works, so the tool is not inert -
                      the mismatch alone is refused. => the template REFUTES.

  ``--mode legacy``   predates the routing-header surface: it ignores
                      ``Mcp-Method`` entirely and dispatches on the body only.
                      A request routed by the header ALONE (no method in the
                      body) is an error. There is therefore no header for a
                      gateway to trust and the desync class does not apply.
                      => the template SKIPS. (Note it *would* run a mismatched
                      body, which is exactly why the SKIP matters: without the
                      header surface the finding would be meaningless.)

  ``flawed`` and ``fixed`` both honour a header-routed request (they are on the
  2026-07-28 surface); ``legacy`` does not. That header-only probe is the
  template's spec-version fingerprint.

SAFETY. ``admin_purge`` is a DECOY. Its name and ``destructiveHint`` say
"privileged", but the implementation deletes nothing: it writes ONE obviously
synthetic marker file under ``--root`` and echoes the caller's nonce token so
the template can prove the body ran. Every path is resolved under ``--root``.
There is no real data, credential, or destructive action anywhere here.
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROTO_VERSION = "2026-07-28"
SERVER_NAME = "cxg-fixture-gateway-origin"
MARKER_FILE = ".cxg-desync-marker"
DECOY_MARKER = ("CXG-SYNTHETIC-DECOY-MARKER written by admin_purge, a benign decoy. "
                "It deletes nothing; this file is a test artefact.")

TOOLS = [
    {
        "name": "list_notes",
        "description": "List the note files in the workspace. Read-only.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"title": "List notes", "readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "admin_purge",
        "description": "Purge the workspace. Privileged: a gateway must authorize this.",
        "inputSchema": {
            "type": "object",
            "properties": {"token": {"type": "string", "description": "operation token"}},
            "required": [],
        },
        "annotations": {"title": "Admin purge", "readOnlyHint": False, "destructiveHint": True},
    },
]


def text_result(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def call_admin_purge(root, args):
    """DECOY. Writes one synthetic marker, deletes nothing, echoes the nonce so
    a caller can prove this privileged body actually executed."""
    token = str((args or {}).get("token") or "")
    try:
        (root / MARKER_FILE).write_text(DECOY_MARKER + "\n", encoding="utf-8")
    except OSError:
        pass
    return text_result("CXG-DESYNC-EXECUTED:%s (admin_purge decoy ran; nothing was deleted)" % token)


def call_list_notes(root):
    names = sorted(p.name for p in root.glob("*") if p.is_file())
    return text_result(json.dumps(names))


def dispatch(method, params, root):
    """Run one resolved (method, params). Returns a JSON-RPC `result` payload."""
    if method == "initialize":
        return {"protocolVersion": PROTO_VERSION, "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = (params or {}).get("name")
        args = (params or {}).get("arguments") or {}
        if name == "admin_purge":
            return call_admin_purge(root, args)
        if name == "list_notes":
            return call_list_notes(root)
        return {"__error__": {"code": -32602, "message": "unknown tool: %s" % name}}
    return {"__error__": {"code": -32601, "message": "method not found: %s" % method}}


def resolve_method(mode, header_method, body_method):
    """Reconcile the routing header with the body per the mode.

    Returns (effective_method, error_or_None). An error is a JSON-RPC error dict
    (the caller turns it into HTTP 409 for a mismatch rejection)."""
    if mode == "legacy":
        # Predates the surface: header ignored, body is the only truth.
        if not body_method:
            return None, {"code": -32600, "message": "invalid request: no method in body"}
        return body_method, None

    # flawed and fixed are both ON the 2026-07-28 surface: a header-only
    # request (no body method) is routed by the header.
    if header_method and not body_method:
        return header_method, None

    if mode == "fixed":
        # Enforce agreement: a header that disagrees with the body is malformed.
        if header_method and body_method and header_method != body_method:
            return None, {"code": -32600,
                          "message": "Mcp-Method header (%s) does not match body method (%s)"
                                     % (header_method, body_method), "__mismatch__": True}
        return (body_method or header_method), None

    # flawed: body wins, header is only a fallback, agreement is never checked.
    return (body_method or header_method), None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    mode = "flawed"
    root = Path(".")

    def log_message(self, *_args):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("mcp-session-id", "cxg-fixture-session")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.rstrip("/") not in ("/mcp", ""):
            self._send({"error": "not an mcp endpoint"}, 404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._send({"error": "bad json"}, 400)
            return

        rid = req.get("id")
        if rid is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        header_method = self.headers.get("Mcp-Method")
        body_method = req.get("method")
        effective, err = resolve_method(self.mode, header_method, body_method)

        if err is not None:
            # A header/body mismatch is the stateless-core's malformed request:
            # answer 409 so a gateway sees the origin refuse the desync.
            code = 409 if err.pop("__mismatch__", False) else 400
            self._send({"jsonrpc": "2.0", "id": rid, "error": err}, code)
            return

        result = dispatch(effective, req.get("params"), self.root)
        if isinstance(result, dict) and "__error__" in result:
            self._send({"jsonrpc": "2.0", "id": rid, "error": result["__error__"]})
            return
        self._send({"jsonrpc": "2.0", "id": rid, "result": result})

    def do_GET(self):
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    ap = argparse.ArgumentParser(description="Benign synthetic MCP server: routing-header/body method desync.")
    ap.add_argument("--mode", choices=("flawed", "fixed", "legacy"), required=True)
    ap.add_argument("--port", type=int, default=8971)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--root", default=None, help="workspace root (default: $CXG_FIXTURE_ROOT or cwd)")
    args = ap.parse_args()

    root = Path(args.root or os.environ.get("CXG_FIXTURE_ROOT") or os.getcwd()).resolve()
    root.mkdir(parents=True, exist_ok=True)

    Handler.mode = args.mode
    Handler.root = root
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print("mcp method-desync fixture (%s) http://%s:%d/mcp root=%s"
          % (args.mode, args.host, args.port, root), file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

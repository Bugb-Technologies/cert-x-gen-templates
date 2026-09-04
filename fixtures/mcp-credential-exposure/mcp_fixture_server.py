#!/usr/bin/env python3
"""
Benign synthetic MCP server - the fixture for `mcp-credential-exposure`.

Two modes, advertising the SAME resource list:

  --mode flawed   one resource returns a synthetic credential when read.  The
                  template must CONFIRM, naming the type it read back.
  --mode fixed    the same resources, the same credential-sounding names, and
                  the same documentation - with the credential replaced by the
                  placeholder a correctly configured server would serve.  The
                  template must REFUTE.

The resource list is issue #32 turned into a server.  Both modes advertise
"Token Usage Stats", "Password Reset Policy", ".env.example", a `secrets://{key}`
template and a "Secret Santa Roster": every one of them trips v1's `meta_hit`
branch and produces a medium finding with no secret observed.  In 2.0.0 they are
read first (the name is a targeting hint) and then reported as observations, and
the templated URI is named as unread rather than silently cleared.

Every credential here is invented for this fixture.  The AWS key id, the API
keys, the JWT and the database password are syntactically valid and
semantically meaningless; the private key is a two-line PEM header with no key
material at all; no host, account or service named exists.  Nothing here
reproduces a real leak.

Transport: MCP streamable HTTP on POST /mcp.  Stdlib only, no dependencies.

    python3 mcp_fixture_server.py --mode flawed --port 8951
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- the resource catalogue, identical in both modes -----------------------
# Names chosen from issue #32: each matches CRED_KEYWORDS and none of them is,
# by itself, evidence of anything.
RESOURCES = [
    {"uri": "stats://token-usage", "name": "Token Usage Stats",
     "mimeType": "application/json",
     "description": "Per-model token counts for the current billing period."},
    {"uri": "docs://password-policy", "name": "Password Reset Policy",
     "mimeType": "text/markdown",
     "description": "How to rotate a password and who to ask for help."},
    {"uri": "config://env-example", "name": ".env.example",
     "mimeType": "text/plain",
     "description": "Template environment file checked into the repository."},
    {"uri": "fun://secret-santa", "name": "Secret Santa Roster",
     "mimeType": "text/plain",
     "description": "Who is buying a gift for whom this December."},
    {"uri": "secrets://{key}", "name": "Secret lookup",
     "mimeType": "text/plain",
     "description": "Templated resource: reads one secret by key."},
    {"uri": "config://service-connection", "name": "Service connection settings",
     "mimeType": "text/plain",
     "description": "Connection settings the worker pool uses at startup."},
]

# --- bodies -----------------------------------------------------------------
TOKEN_USAGE = json.dumps({"period": "2026-08", "input_tokens": 812344,
                          "output_tokens": 94021, "tools": ["notes_search"]})

PASSWORD_POLICY = (
    "# Password reset policy\n\n"
    "Rotate the password every 90 days. Never commit one. In examples we write\n"
    "`password: your-password-here` or `password = <redacted>`; in a rendered\n"
    "export it appears as `password: **REDACTED**`.\n"
)

# The .env.example a repository ships: every line matched v1's `\S{6,}` and
# escalated the finding to critical.
ENV_EXAMPLE_FIXED = (
    "# copy to .env and fill in\n"
    "DB_HOST=db.internal\n"
    "password=${DB_PASSWORD}\n"
    "API_KEY=your-api-key-here\n"
    "SMTP_PASSWORD=********\n"
)
# The same file with a real-shaped value left in it, which is the actual bug.
ENV_EXAMPLE_FLAWED = (
    "# copy to .env and fill in\n"
    "DB_HOST=db.internal\n"
    "password=R7x-Qv2_Lm9Zt4Wb\n"          # synthetic, 16 chars, 4 char classes
    "API_KEY=cxg7Kq2Zt9Lm4Wb0Rv3X\n"       # synthetic
    "AWS_ACCESS_KEY_ID=AKIAZZZZFIXTUREZZZZQ\n"   # synthetic, valid AKIA shape
)

SECRET_SANTA = "alice -> bob\nbob -> carol\ncarol -> alice\n"

CONNECTION_FIXED = "postgres://app:${DB_PASSWORD}@db.internal:5432/app\n"
CONNECTION_FLAWED = "postgres://app:R7x-Qv2_Lm9Zt4Wb@db.internal:5432/app\n"


def body_for(uri, mode):
    flawed = mode == "flawed"
    return {
        "stats://token-usage": TOKEN_USAGE,
        "docs://password-policy": PASSWORD_POLICY,
        "fun://secret-santa": SECRET_SANTA,
        "config://env-example": ENV_EXAMPLE_FLAWED if flawed else ENV_EXAMPLE_FIXED,
        "config://service-connection": CONNECTION_FLAWED if flawed else CONNECTION_FIXED,
    }.get(uri)


def handler_for(mode):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

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

            method, rid, params = req.get("method"), req.get("id"), req.get("params") or {}
            if rid is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if method == "initialize":
                self._send({"jsonrpc": "2.0", "id": rid, "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "cxg-fixture-config", "version": "1.0.0"},
                }})
            elif method == "resources/list":
                self._send({"jsonrpc": "2.0", "id": rid, "result": {"resources": RESOURCES}})
            elif method == "resources/read":
                uri = params.get("uri")
                text = body_for(uri, mode)
                if text is None:
                    self._send({"jsonrpc": "2.0", "id": rid,
                                "error": {"code": -32002, "message": "resource not found"}})
                else:
                    self._send({"jsonrpc": "2.0", "id": rid, "result": {
                        "contents": [{"uri": uri, "mimeType": "text/plain", "text": text}]}})
            else:
                self._send({"jsonrpc": "2.0", "id": rid,
                            "error": {"code": -32601, "message": "method not found"}})

        def do_GET(self):
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=("flawed", "fixed"), required=True)
    ap.add_argument("--port", type=int, default=8951)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), handler_for(args.mode))
    print("mcp fixture (%s) on http://%s:%d/mcp" % (args.mode, args.host, args.port),
          file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

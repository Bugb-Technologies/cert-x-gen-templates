#!/usr/bin/env python3
"""Benign synthetic MCP server for the token-audience-confusion oracle.

Streamable-HTTP MCP on ``POST /mcp``, stdlib only. Two modes advertise the
same two tools and behave identically to a request that carries no
Authorization header (both answer 401). They differ in ONE decision, and it is
the whole point of the class:

    given a Bearer token, does the server check that the token's ``aud``
    (audience) claim names THIS server before it serves the request?

  ``--mode flawed``  A token is present -> serve. The ``aud`` claim is never
                     read. This is token passthrough / audience confusion: a
                     token minted for some other resource operates this
                     server. The June 2025 MCP spec forbids exactly this
                     ("MCP servers MUST only accept tokens specifically
                     intended for themselves and MUST reject tokens that do
                     not include them in the audience claim").

  ``--mode fixed``   Decode the JWT payload, require that ``aud`` contains this
                     server's own canonical resource URI, else 401. A token
                     scoped for another resource is rejected.

The tokens are dummy, self-issued, unsigned JWTs. Nothing here is a real
credential, nothing is forwarded to a third party, and the tools have no
implementation -- the auth DECISION is the entire attack surface of this
class.
"""

import argparse
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTO_VERSION = "2024-11-05"
SERVER_NAME = "cxg-fixture-audience"


def _b64url_decode(seg):
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def jwt_payload(token):
    """Decode a JWT's payload WITHOUT verifying the signature.

    That is deliberate: this fixture models audience validation, not signature
    validation. A real resource server verifies the signature too; here every
    token is self-issued and the only claim under test is ``aud``.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None


def aud_values(payload):
    """``aud`` may be a string or an array of strings (RFC 7519)."""
    aud = (payload or {}).get("aud")
    if aud is None:
        return []
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list):
        return [a for a in aud if isinstance(a, str)]
    return []


def tools():
    return [
        {
            "name": "notes_search",
            "description": "Search the local notes index and return matches.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "search text"}},
            },
        },
        {
            "name": "notes_export",
            "description": "Export the notes index as JSON.",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


def handler_for(mode, canonical_uri):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def _json(self, obj, code=200, extra_headers=None):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("mcp-session-id", "cxg-fixture-session")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _unauthorized(self, detail):
            # Spec: invalid / wrong-audience tokens MUST receive HTTP 401, and
            # the server MUST advertise its resource metadata via
            # WWW-Authenticate (RFC 9728 5.1).
            www = ('Bearer error="invalid_token", '
                   'error_description="%s", '
                   'resource_metadata="%s/.well-known/oauth-protected-resource"'
                   % (detail, canonical_uri))
            self._json({"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32001, "message": "Unauthorized: %s" % detail}},
                       code=401, extra_headers={"WWW-Authenticate": www})

        def _authorize(self):
            """Return (ok, detail). The one decision that differs by mode."""
            auth = self.headers.get("Authorization") or ""
            if not auth.lower().startswith("bearer "):
                return False, "no bearer token"
            token = auth.split(None, 1)[1].strip()
            if mode == "flawed":
                # Passthrough: a token is enough; its audience is never checked.
                return True, "token accepted without audience validation"
            # fixed: the token MUST be audience-scoped for this server.
            payload = jwt_payload(token)
            if payload is None:
                return False, "malformed token"
            auds = aud_values(payload)
            if canonical_uri in auds:
                return True, "audience matches this server"
            return False, ("token audience %s is not this server (%s)"
                           % (auds or "<none>", canonical_uri))

        def do_POST(self):
            if self.path.rstrip("/") not in ("/mcp", ""):
                self._json({"error": "not an mcp endpoint"}, 404)
                return
            length = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._json({"error": "bad json"}, 400)
                return

            method, rid = req.get("method"), req.get("id")

            # Auth is enforced on EVERY request, per spec ("authorization MUST
            # be included in every HTTP request ... even ... the same session").
            ok, detail = self._authorize()
            if not ok:
                if rid is None:
                    # a notification that fails auth: still 401, no body needed
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._unauthorized(detail)
                return

            if rid is None:  # an authorized notification
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            results = {
                "initialize": {
                    "protocolVersion": PROTO_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
                },
                "tools/list": {"tools": tools()},
                "tools/call": {"content": [{"type": "text", "text": "cxg-fixture: no matches"}],
                               "isError": False},
            }
            if method in results:
                self._json({"jsonrpc": "2.0", "id": rid, "result": results[method]})
            else:
                self._json({"jsonrpc": "2.0", "id": rid,
                            "error": {"code": -32601, "message": "method not found"}})

        def do_GET(self):
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=("flawed", "fixed"), required=True)
    ap.add_argument("--port", type=int, default=8941)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    # The canonical resource URI a compliant server binds its tokens to
    # (RFC 8707 2 / RFC 9728). The template guesses this same value from the
    # target it is scanning, so the fixed twin accepts a token scoped to it.
    canonical = "http://%s:%d/mcp" % (args.host, args.port)
    server = ThreadingHTTPServer((args.host, args.port), handler_for(args.mode, canonical))
    print("mcp audience fixture (%s) on %s" % (args.mode, canonical),
          file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

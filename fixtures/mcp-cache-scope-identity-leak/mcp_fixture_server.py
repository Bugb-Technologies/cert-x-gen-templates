#!/usr/bin/env python3
"""Benign synthetic MCP server for the cache-scope identity-leak oracle.

Streamable-HTTP MCP on ``POST /mcp``, stdlib only, no dependencies and no
network egress. Every mode advertises the same three resources and answers an
unauthenticated request identically (401 + ``WWW-Authenticate``). The caller's
identity is the ``sub`` claim of a dummy, self-issued Bearer JWT -- decoded,
never verified, because the signature is not what this class is about.

The three modes differ in ONE decision, and it is the whole point of the class:

    for a response whose BODY depends on who asked for it, what does the
    server put in the ``CacheableResult`` directive it attaches --
    ``cacheScope: "public"`` (any shared intermediary may serve this bytes-
    for-bytes to the next caller) or ``cacheScope: "private"``?

  ``--mode flawed``  ``notes://inbox`` is per-identity -- it carries that
                     caller's own canary marker -- and is nevertheless marked
                     ``cacheScope: "public"`` with a 60s TTL. A shared MCP
                     proxy that honours the directive would hand identity A's
                     inbox to identity B. Nothing in the response text says
                     "public"; the directive does, and only the directive.

  ``--mode fixed``   The same per-identity response, marked
                     ``cacheScope: "private"``. The genuinely shared resources
                     stay ``"public"`` -- the fix is *scoping*, not switching
                     caching off, so a refutation here proves the server got
                     the distinction right rather than that it declined to
                     cache anything.

  ``--mode shared``  ``notes://inbox`` returns the SAME bytes to every caller
                     -- a genuinely shared resource, publicly cacheable and
                     correctly so. Nothing this server returns varies by
                     caller, so there is nothing a public label could leak and
                     the check must SKIP. This twin exists so the "no
                     identity-dependent response observed" branch has a target
                     of its own, distinct from the pre-spec one below.

  ``--mode legacy``  Pre-2026-07-28 server: identical bodies, and no
                     ``CacheableResult`` directive anywhere. There is no
                     ``cacheScope`` field to be wrong, so the check must SKIP,
                     not refute -- an absent field is not a correct one.

Two deliberate decoys sit in every mode, so a check that fires on a naive
"the two identities saw different bytes" diff is caught by this fixture:

  ``docs://changelog``  identical for every identity AND ``cacheScope:
                        "public"``. Publicly cacheable and correctly so. Must
                        never be reported.

  ``clock://now``       ``cacheScope: "public"`` and different on EVERY read,
                        including two consecutive reads by the same identity.
                        It differs across identities for a reason that has
                        nothing to do with identity. A check without a
                        same-identity control probe confirms on this and is
                        wrong; the fixed twin exists partly to catch that.

Everything here is synthetic: the "inbox" text is a planted canary string, the
tokens are self-issued dummies, and no tool has an implementation. The cache
DECISION is the entire attack surface being modelled.
"""

import argparse
import base64
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTO_VERSION = "2024-11-05"
SERVER_NAME = "cxg-fixture-cachescope"

# Planted, obviously-synthetic per-identity marker. A real leak would be a real
# inbox; here it is a canary whose only job is to be visibly not-yours.
CANARY = "CXG-CANARY-%s-9f31d0"

_counter_lock = threading.Lock()
_counter = {"n": 0}


def _b64url_decode(seg):
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def identity_of(auth_header):
    """The caller's identity: the ``sub`` claim of the Bearer JWT.

    Decoded WITHOUT verifying the signature, deliberately: this fixture models
    a cache-scoping decision, not token validation (that is
    mcp-token-audience-confusion's class). A non-JWT bearer value is used as
    the identity verbatim so the fixture is drivable by hand with curl.
    """
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(None, 1)[1].strip()
    parts = token.split(".")
    if len(parts) == 3:
        try:
            return json.loads(_b64url_decode(parts[1])).get("sub") or token
        except Exception:
            return token
    return token or None


def cache_meta(mode, scope, ttl_ms=60000):
    """The 2026-07-28 ``CacheableResult`` directive, or nothing on a legacy
    server. Carried under ``result._meta.cacheableResult``."""
    if mode == "legacy":
        return None
    return {"cacheableResult": {"ttlMs": ttl_ms, "cacheScope": scope}}


def resources_list():
    return [
        {"uri": "notes://inbox", "name": "Your inbox",
         "description": "Per-caller notes", "mimeType": "text/plain"},
        {"uri": "docs://changelog", "name": "Changelog",
         "description": "Shared release notes", "mimeType": "text/plain"},
        {"uri": "clock://now", "name": "Server clock",
         "description": "Monotonic read counter", "mimeType": "text/plain"},
    ]


def read_resource(uri, identity, mode):
    """Return (contents, cacheScope) for one resource read.

    ``notes://inbox`` is the identity-dependent one; the other two are the
    decoys described in the module docstring.
    """
    if uri == "notes://inbox":
        if mode == "shared":
            # Not per-caller at all: one announcement every identity sees.
            return "Inbox notice: service window Sunday 02:00 UTC (same for every caller)", "public"
        text = ("Inbox for %s\n2 unread\nmarker: %s"
                % (identity, CANARY % identity.upper().replace("CXG-IDENTITY-", "")))
        scope = "public" if mode in ("flawed", "legacy") else "private"
        return text, scope
    if uri == "docs://changelog":
        # Byte-identical for every caller: publicly cacheable, correctly so.
        return "v1.4.0 - shared release notes, same for every caller", "public"
    if uri == "clock://now":
        # Changes on EVERY read, including two reads by the same identity.
        with _counter_lock:
            _counter["n"] += 1
            n = _counter["n"]
        return "read #%d" % n, "public"
    return None, None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    mode = "flawed"

    def log_message(self, *a):
        pass

    # -- wire helpers ------------------------------------------------------
    def _send(self, code, obj, extra_headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _unauthorized(self, rid):
        self._send(401, {"jsonrpc": "2.0", "id": rid,
                         "error": {"code": -32001, "message": "unauthorized: bearer token required"}},
                   {"WWW-Authenticate": 'Bearer realm="%s"' % SERVER_NAME})

    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self.path.split("?")[0] not in ("/mcp", "/"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            req = {}
        rid = req.get("id")
        method = req.get("method")
        if rid is None:               # a notification
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        identity = identity_of(self.headers.get("Authorization"))
        if identity is None:
            self._unauthorized(rid)
            return

        result = self.dispatch(method, req.get("params") or {}, identity)
        if result is None:
            self._send(200, {"jsonrpc": "2.0", "id": rid,
                             "error": {"code": -32601, "message": "method not found: %s" % method}})
            return
        self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result})

    # -- MCP methods -------------------------------------------------------
    def dispatch(self, method, params, identity):
        mode = self.mode
        if method == "initialize":
            return {"protocolVersion": PROTO_VERSION,
                    "capabilities": {"resources": {}, "tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": "1.0.0", "mode": mode}}
        if method == "tools/list":
            # Same tool set for everyone; no cache directive at all.
            return {"tools": [{"name": "ping", "description": "no-op",
                               "inputSchema": {"type": "object", "properties": {}}}]}
        if method == "resources/list":
            # Same listing for everyone, and publicly cacheable - correctly so.
            out = {"resources": resources_list()}
            meta = cache_meta(mode, "public")
            if meta:
                out["_meta"] = meta
            return out
        if method == "resources/read":
            uri = params.get("uri")
            text, scope = read_resource(uri, identity, mode)
            if text is None:
                return {"contents": []}
            out = {"contents": [{"uri": uri, "mimeType": "text/plain", "text": text}]}
            meta = cache_meta(mode, scope)
            if meta:
                out["_meta"] = meta
            return out
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["flawed", "fixed", "shared", "legacy"], default="flawed")
    ap.add_argument("--port", type=int, default=8951)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    Handler.mode = args.mode
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    sys.stderr.write("[fixture] cache-scope MCP server mode=%s on http://%s:%d/mcp\n"
                     % (args.mode, args.host, args.port))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

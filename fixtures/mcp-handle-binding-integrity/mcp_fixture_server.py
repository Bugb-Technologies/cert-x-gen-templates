#!/usr/bin/env python3
"""Benign synthetic MCP server for the handle-binding / requestState oracle.

Stdlib only. Speaks MCP over BOTH transports the template supports:

    --transport http    streamable HTTP on ``POST /mcp``
    --transport stdio   newline-delimited JSON-RPC on stdin/stdout

The 2026-07-28 MCP specification made the protocol core stateless: it removed
``initialize``/``initialized`` and ``Mcp-Session-Id``, and replaced them with
two things this fixture models exactly.

  1. THE EXPLICIT HANDLE PATTERN.  A tool mints an identifier and "the model
     threads that identifier back as an argument on subsequent calls".  Here
     ``open_workspace`` mints a ``workspace_id`` and ``read_workspace``
     consumes it.  The handle now lives in model context, where a poisoned
     tool result or a shared transcript can substitute it.

  2. MULTI ROUND-TRIP REQUESTS.  A tool may answer with
     ``{"resultType": "input_required", "inputRequests": {...},
     "requestState": "<blob>"}``; the client collects the inputs and re-issues
     the same ``tools/call`` with ``inputResponses`` and the echoed
     ``requestState``.  Here ``archive_workspace`` does that.  The blob
     round-trips through the client, so it is attacker-controlled input.

Every mode advertises the SAME manifest and the same wire shapes.  A scanner
that reads manifests cannot tell them apart.  They differ only in what the
server DOES with a handle and with a returned ``requestState``:

  ``--mode flawed``   handles are opaque random strings recorded with an owner
                      the server never checks, so any principal may present
                      any live handle.  ``requestState`` is
                      ``base64url(json)`` with no MAC, no principal binding
                      and no request binding, and the retry performs the
                      archive **as the principal named inside the blob**.
                      Both halves of the class, in the two shapes the spec
                      warns about.

  ``--mode fixed``    ``read_workspace`` rejects a handle whose recorded owner
                      is not the caller, and rejects an expired one.
                      ``requestState`` is ``base64url(json).base64url(hmac)``,
                      verified for integrity, bound to the principal and to a
                      fingerprint of the originating request, and expired.

  ``--mode noguard``  the PRECISION twin.  ``read_workspace`` honours ANY
                      string as a handle -- it never consults the store at
                      all -- so a handle this server never minted is honoured
                      too.  "Handle not bound to a principal" is not a
                      finding you can draw from a server that has no handle
                      validation to bind with, so the template's forged-handle
                      negative control must make this twin unusable rather
                      than confirmable.  Its ``requestState`` is signed like
                      ``fixed``.

  ``--mode opaque``   ``requestState`` is encrypted-without-a-MAC: a keystream
                      XOR over the JSON, hex-encoded, with a padding tail.
                      The template cannot decode it, so it cannot mutate a
                      named field -- but a single flipped character inside the
                      pad still decrypts to valid state and is accepted, while
                      a wholly random blob is rejected.  That is the classic
                      encryption-without-authentication shape, and it is the
                      fallback path the template needs for a real server whose
                      state is not readable.  Handles here are bound like
                      ``fixed``.

  ``--mode legacy``   a PRE-stateless-core server.  It requires the old
                      ``initialize`` handshake, mints no handles and never
                      returns ``input_required``.  Neither probe has a
                      precondition, so the template must SKIP.

SAFETY.  Everything here is synthetic.  There is no real credential, no real
user, no persistence outside one process's memory and no destructive
implementation anywhere: ``archive_workspace`` marks a dict entry and returns
a sentence about it.  The canaries the template plants and this server echoes
are obvious on sight (``CXG-SYNTHETIC-...``).  The HMAC key and the keystream
key are hard-coded constants generated for this fixture and protect nothing.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATELESS_PROTO = "2026-07-28"
LEGACY_PROTO = "2024-11-05"
SERVER_NAME = "cxg-fixture-workspaces"

# Hard-coded, published in this file, protects nothing. It exists so the
# `fixed` twin can demonstrate an integrity-protected requestState.
FIXTURE_KEY = b"cxg-fixture-not-a-secret-0000000"
STATE_TTL = 900          # seconds a requestState stays valid in `fixed`
HANDLE_TTL = 900         # seconds a workspace handle stays valid in `fixed`

PRINCIPAL_META = "io.modelcontextprotocol/principal"
CLIENTINFO_META = "io.modelcontextprotocol/clientInfo"

STATELESS_MODES = ("flawed", "fixed", "noguard", "opaque")


# ---------------------------------------------------------------------------
# The manifest. Identical across every stateless-core mode - that is the point.
# ---------------------------------------------------------------------------

WORKSPACE_TOOLS = [
    {
        "name": "open_workspace",
        "description": ("Open a scratch workspace and return its workspace_id handle. "
                        "Pass the handle back on later calls."),
        "inputSchema": {
            "type": "object",
            "properties": {"label": {"type": "string", "description": "human label for the workspace"}},
            "required": ["label"],
        },
        "annotations": {"title": "Open workspace", "readOnlyHint": False, "destructiveHint": False,
                        "openWorldHint": False},
    },
    {
        "name": "read_workspace",
        "description": "Read the workspace identified by workspace_id and return its record.",
        "inputSchema": {
            "type": "object",
            "properties": {"workspace_id": {"type": "string", "description": "handle from open_workspace"}},
            "required": ["workspace_id"],
        },
        "annotations": {"title": "Read workspace", "readOnlyHint": True, "destructiveHint": False,
                        "openWorldHint": False},
    },
    {
        "name": "archive_workspace",
        "description": ("Archive items in a workspace. Asks for confirmation before it acts, "
                        "then resumes from the requestState it handed back."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "handle from open_workspace"},
                "scope": {"type": "string", "enum": ["single", "all"], "description": "how much to archive"},
            },
            "required": ["workspace_id"],
        },
        "annotations": {"title": "Archive workspace", "readOnlyHint": False, "destructiveHint": False,
                        "openWorldHint": False},
    },
]

LEGACY_TOOLS = [
    {
        "name": "search_docs",
        "description": "Search the local document corpus and return matching titles.",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
        "annotations": {"title": "Search docs", "readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "get_doc",
        "description": "Return the text of one document by title.",
        "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}}, "required": ["title"]},
        "annotations": {"title": "Get doc", "readOnlyHint": True, "openWorldHint": False},
    },
]


# ---------------------------------------------------------------------------
# requestState encodings.
# ---------------------------------------------------------------------------

def b64e(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def keystream(length):
    """A deterministic pad. Encryption without authentication, on purpose."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(FIXTURE_KEY + b"ks" + str(counter).encode()).digest()
        counter += 1
    return out[:length]


def encode_state_opaque(state):
    raw = json.dumps(state, sort_keys=True).encode("utf-8")
    padded = raw + b"|PAD:" + b"a" * 48
    ks = keystream(len(padded))
    return bytes(a ^ b for a, b in zip(padded, ks)).hex()


def decode_state_opaque(blob):
    try:
        data = bytes.fromhex(blob)
    except ValueError:
        return None
    ks = keystream(len(data))
    plain = bytes(a ^ b for a, b in zip(data, ks))
    head = plain.split(b"|PAD:")[0]
    try:
        obj = json.loads(head.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def make_state(mode, state):
    if mode == "flawed":
        # No MAC, no principal binding, no request binding, no expiry check on
        # the way back in. The shape the 2026-07-28 security guidance names.
        raw = json.dumps(state, sort_keys=True).encode("utf-8")
        return b64e(raw)
    if mode == "opaque":
        return encode_state_opaque(state)
    raw = json.dumps(state, sort_keys=True).encode("utf-8")
    body = b64e(raw)
    mac = b64e(hmac.new(FIXTURE_KEY, body.encode("ascii"), hashlib.sha256).digest())
    return body + "." + mac


def read_state(mode, blob):
    """Returns (state_dict, None) or (None, why_rejected)."""
    if not isinstance(blob, str) or not blob:
        return None, "requestState missing"

    if mode == "flawed":
        try:
            obj = json.loads(b64d(blob).decode("utf-8"))
        except Exception:
            return None, "requestState is not decodable"
        if not isinstance(obj, dict):
            return None, "requestState is not an object"
        return obj, None            # accepted as-is: no MAC, no binding, no expiry

    if mode == "opaque":
        obj = decode_state_opaque(blob)
        if obj is None:
            return None, "requestState did not decrypt to a valid state"
        return obj, None            # decrypted, never authenticated

    if "." not in blob:
        return None, "requestState is not integrity-protected"
    body, _, mac = blob.rpartition(".")
    expect = b64e(hmac.new(FIXTURE_KEY, body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(mac, expect):
        return None, "requestState signature does not verify"
    try:
        obj = json.loads(b64d(body).decode("utf-8"))
    except Exception:
        return None, "requestState is not decodable"
    if not isinstance(obj, dict):
        return None, "requestState is not an object"
    return obj, None


def request_fingerprint(name, arguments):
    canonical = json.dumps({"name": name, "arguments": arguments or {}}, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Handles.
# ---------------------------------------------------------------------------

class Store(object):
    def __init__(self):
        self.workspaces = {}
        self.counter = 0

    def mint(self, principal, label):
        self.counter += 1
        handle = "ws-%s" % hashlib.sha256(
            ("%s|%s|%d" % (principal, label, self.counter)).encode("utf-8")).hexdigest()[:20]
        self.workspaces[handle] = {"owner": principal, "label": label,
                                   "created": int(time.time()), "archived": 0}
        return handle


def text_result(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def json_result(obj, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(obj, sort_keys=True)}], "isError": is_error}


def call_open_workspace(mode, store, principal, args):
    label = str((args or {}).get("label") or "untitled")[:200]
    handle = store.mint(principal, label)
    return json_result({"workspace_id": handle, "label": label, "owner": principal,
                        "note": "pass workspace_id back as an argument on later calls"})


def call_read_workspace(mode, store, principal, args):
    handle = str((args or {}).get("workspace_id") or "")
    if not handle:
        return text_result("workspace_id is required", is_error=True)

    if mode == "noguard":
        # No validation of any kind: any string is a workspace. A handle this
        # server never minted is honoured exactly like one it did.
        return json_result({"workspace_id": handle, "label": "workspace",
                            "owner": principal, "items": 0})

    record = store.workspaces.get(handle)
    if record is None:
        return text_result("unknown workspace handle: %s" % handle, is_error=True)

    if mode in ("fixed", "opaque"):
        if record["owner"] != principal:
            return text_result(
                "handle is not valid for this principal (minted for another principal)",
                is_error=True)
        if int(time.time()) - record["created"] > HANDLE_TTL:
            return text_result("handle has expired", is_error=True)

    # flawed: the owner was recorded and is never consulted.
    return json_result({"workspace_id": handle, "label": record["label"],
                        "owner": record["owner"], "items": record["archived"]})


def call_archive_workspace(mode, store, principal, args, params):
    """The multi round-trip tool. First call asks; the retry resumes from state."""
    args = args or {}
    handle = str(args.get("workspace_id") or "")
    scope = str(args.get("scope") or "single")
    responses = params.get("inputResponses")
    blob = params.get("requestState")

    if not blob:
        # Round 1: ask for confirmation and hand back the resumable state.
        state = {
            "principal": principal,
            "workspace_id": handle,
            "scope": scope,
            "approved_items": 1,
            "exp": int(time.time()) + STATE_TTL,
            "request_fingerprint": request_fingerprint("archive_workspace", args),
        }
        return {"resultType": "input_required",
                "inputRequests": {
                    "confirm": {"type": "elicitation",
                                "message": "Archive %s item(s) in %s?" % (state["approved_items"], handle or "?"),
                                "schema": {"type": "boolean"}},
                },
                "requestState": make_state(mode, state)}

    # Round 2: the retry.
    state, why = read_state(mode, blob)
    if state is None:
        return text_result("rejected: %s" % why, is_error=True)

    if mode in ("fixed", "noguard"):
        if state.get("principal") != principal:
            return text_result(
                "rejected: requestState is bound to another principal", is_error=True)
        if int(state.get("exp") or 0) <= int(time.time()):
            return text_result("rejected: requestState has expired", is_error=True)
        if state.get("request_fingerprint") != request_fingerprint("archive_workspace", args):
            return text_result(
                "rejected: requestState is bound to a different originating request", is_error=True)
    if mode == "opaque":
        # Decrypts, therefore trusted. No MAC, so a flipped byte that still
        # decrypts is trusted too. Bindings are read out of the blob itself.
        pass

    if not isinstance(responses, dict) or responses.get("confirm") is not True:
        return text_result("rejected: confirmation was not granted", is_error=True)

    # The "action": increment a counter in memory and describe it. The values
    # that steer it come out of the state blob, which is the whole point.
    acting_as = state.get("principal")
    items = state.get("approved_items")
    eff_scope = state.get("scope")
    ws = state.get("workspace_id")
    record = store.workspaces.get(str(ws))
    if record is not None:
        try:
            record["archived"] += int(items)
        except (TypeError, ValueError):
            pass
    return json_result({
        "archived_items": items,
        "workspace_id": ws,
        "scope": eff_scope,
        "acting_as": acting_as,
        "caller_principal": principal,
        "summary": "archived %s item(s) in %s scope=%s as principal %s"
                   % (items, ws, eff_scope, acting_as),
    })


def call_search_docs(args):
    q = str((args or {}).get("q") or "")
    return json_result({"query": q, "titles": ["release-notes", "onboarding", "faq"]})


def call_get_doc(args):
    title = str((args or {}).get("title") or "")
    return text_result("cxg-fixture synthetic document %r. Contains nothing real." % title)


# ---------------------------------------------------------------------------
# JSON-RPC dispatch, shared by both transports.
# ---------------------------------------------------------------------------

def principal_of(params, header_principal):
    if header_principal:
        return header_principal
    meta = (params or {}).get("_meta")
    if isinstance(meta, dict):
        named = meta.get(PRINCIPAL_META)
        if isinstance(named, str) and named:
            return named
        info = meta.get(CLIENTINFO_META)
        if isinstance(info, dict) and isinstance(info.get("name"), str) and info["name"]:
            return info["name"]
    return "anonymous"


def tools_for(mode):
    return LEGACY_TOOLS if mode == "legacy" else WORKSPACE_TOOLS


def handle_rpc(mode, store, req, header_principal, session):
    """Return a JSON-RPC response dict, or None for a notification."""
    rid = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}

    if rid is None:
        if method == "notifications/initialized":
            session["initialized"] = True
        return None

    if method == "initialize":
        if mode in STATELESS_MODES:
            # The 2026-07-28 core removed the handshake. An authentic
            # stateless-core server does not answer it.
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601,
                              "message": "initialize was removed in MCP 2026-07-28; "
                                         "send tools/list directly"}}
        session["initialized"] = True
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": LEGACY_PROTO,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME + "-legacy", "version": "0.9.0"},
        }}

    if mode == "legacy" and not session.get("initialized"):
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32002, "message": "initialize first"}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools_for(mode)}}

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        principal = principal_of(params, header_principal)
        if mode == "legacy":
            if name == "search_docs":
                return {"jsonrpc": "2.0", "id": rid, "result": call_search_docs(args)}
            if name == "get_doc":
                return {"jsonrpc": "2.0", "id": rid, "result": call_get_doc(args)}
        else:
            if name == "open_workspace":
                return {"jsonrpc": "2.0", "id": rid,
                        "result": call_open_workspace(mode, store, principal, args)}
            if name == "read_workspace":
                return {"jsonrpc": "2.0", "id": rid,
                        "result": call_read_workspace(mode, store, principal, args)}
            if name == "archive_workspace":
                return {"jsonrpc": "2.0", "id": rid,
                        "result": call_archive_workspace(mode, store, principal, args, params)}
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32602, "message": "unknown tool: %s" % name}}

    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}


# ---------------------------------------------------------------------------
# Transports.
# ---------------------------------------------------------------------------

def serve_stdio(mode, store):
    session = {"initialized": False}
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        resp = handle_rpc(mode, store, req, None, session)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


def serve_http(mode, store, host, port):
    session = {"initialized": False}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def _send(self, obj, code=200):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("MCP-Protocol-Version",
                             LEGACY_PROTO if mode == "legacy" else STATELESS_PROTO)
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
            auth = self.headers.get("Authorization") or ""
            header_principal = auth[7:].strip() if auth.lower().startswith("bearer ") else None
            resp = handle_rpc(mode, store, req, header_principal, session)
            if resp is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(resp)

        def do_GET(self):
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer((host, port), Handler)
    print("mcp handle-binding fixture (%s) http://%s:%d/mcp" % (mode, host, port),
          file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    ap = argparse.ArgumentParser(
        description="Benign synthetic MCP server: handle binding and requestState integrity.")
    ap.add_argument("--mode", choices=("flawed", "fixed", "noguard", "opaque", "legacy"), required=True)
    ap.add_argument("--transport", choices=("http", "stdio"), default="http")
    ap.add_argument("--port", type=int, default=8971)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    store = Store()
    if args.transport == "stdio":
        serve_stdio(args.mode, store)
    else:
        serve_http(args.mode, store, args.host, args.port)


if __name__ == "__main__":
    main()

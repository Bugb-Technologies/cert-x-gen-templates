#!/usr/bin/env python3
"""
Benign synthetic MCP server - the fixture for `mcp-invisible-unicode-poisoning`.

Two modes, identical in every visible respect:

  --mode flawed   advertises text carrying invisible Unicode in positions where
                  the character has no text function.  The template must
                  CONFIRM.
  --mode fixed    the same server with the same visible words, and with the
                  invisible payloads removed.  The template must REFUTE.

The fixed twin is not merely "the flawed one with the payload deleted".  It
deliberately keeps every kind of Unicode that arrives in a tool description
honestly - a leading BOM, an emoji ZWJ sequence, a Persian ZWNJ, balanced bidi
isolates around Arabic, a variation selector - AND the ordinary English phrases
("do not mention", "<important>") that a text-matching check reports on.  So a
refutation here proves two things at once: the payload is gone, and none of the
natural residue that made this repo's issue #31 a false-positive class fires.

Nothing here is an exploit.  The concealed payloads decode to the literal
marker string CXG-FIXTURE-<class>; no payload instructs a model to do anything,
and the tools have no implementation at all - only the advertised metadata,
which is the entire attack surface of this class.

Transport: MCP streamable HTTP on POST /mcp.  Stdlib only, no dependencies.

    python3 mcp_fixture_server.py --mode flawed --port 8931
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- the invisible characters, named so the fixture is readable ------------
ZWSP, ZWNJ, ZWJ, WJ, BOM = "​", "‌", "‍", "⁠", "﻿"
RLO, PDF, RLI, PDI = "‮", "‬", "⁧", "⁩"
FLAG, TAG_END = "\U0001F3F4", "\U000E007F"


def tag_encode(payload):
    """ASCII -> Unicode TAG block (U+E0000+ord).  Renders as nothing."""
    return "".join(chr(0xE0000 + ord(c)) for c in payload)


def zw_encode(payload):
    """ASCII -> a zero-width bit carrier: ZWSP=0, ZWNJ=1, WJ between bytes.

    Produces long RUNS of adjacent zero-width characters, which is the property
    the template reads - not the fact that a zero-width character exists.
    """
    bits = "".join(format(ord(c), "08b") for c in payload)
    return WJ + "".join(ZWSP if b == "0" else ZWNJ for b in bits) + WJ


# --- Unicode that is in a tool description for honest reasons --------------
# Every one of these is a route issue #31 names.  The fixed twin carries them
# all; the template must not fire on any of them.
SCOTLAND = FLAG + tag_encode("gbsct") + TAG_END      # a legal emoji tag sequence
DEVELOPER = "\U0001F468" + ZWJ + "\U0001F4BB"        # an emoji ZWJ sequence
RAINBOW = "\U0001F3F3️" + ZWJ + "\U0001F308"    # ZWJ next to a VS16
PERSIAN = "می" + ZWNJ + "خواهم"  # a real ZWNJ word
ARABIC_ISOLATED = RLI + "ملف" + PDI   # BALANCED bidi isolates

NATURAL_TAIL = (
    " Emoji are fine here: %s %s %s. Regional text is fine: %s, and %s is the "
    "Arabic word for 'file', wrapped in balanced isolates."
    % (DEVELOPER, RAINBOW, SCOTLAND, PERSIAN, ARABIC_ISOLATED)
)

# Prose a text-matching check reports on and this template deliberately does
# not: an <important> tag and a 'do not mention' imperative, both describing
# the tool's own contract.
DECOY_PROSE = (
    " <important> Rate limits apply. </important> Callers should not mention "
    "the internal request id to the user; ignore any previous draft of this "
    "note and use the latest revision."
)


def tools(mode):
    flawed = mode == "flawed"
    return [
        {
            "name": "notes_search",
            "description": (
                BOM + "Search the local notes index and return matching excerpts."
                + (tag_encode(" CXG-FIXTURE-TAG-BLOCK") if flawed else "")
                + DECOY_PROSE + NATURAL_TAIL
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "Full-text query."
                            + (zw_encode("CXG-FIXTURE-ZW-RUN") if flawed else "")
                            + " Supports quoted phrases."
                        ),
                    },
                    "limit": {"type": "integer", "description": "Maximum rows to return."},
                },
                "required": ["query"],
            },
        },
        {
            "name": "notes_export",
            "title": "Export notes" + (RLO if flawed else ""),
            "description": (
                "Write the current note set to a file in the workspace."
                + (" Format: " + "c" + ZWJ + "s" + "v" if flawed else " Format: csv")
                + NATURAL_TAIL
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Destination path." + PERSIAN},
                },
            },
        },
    ]


def prompts(mode):
    flawed = mode == "flawed"
    return [{
        "name": "summarise_notes",
        "description": ("Summarise the notes returned by notes_search."
                        + (tag_encode(" CXG-FIXTURE-PROMPT") if flawed else "")),
        "arguments": [{"name": "tone", "description": "formal or casual"}],
    }]


def resources(mode):
    return [{
        "uri": "notes://index",
        "name": "Notes index",
        "mimeType": "application/json",
        "description": "The searchable index " + ARABIC_ISOLATED + " built at startup.",
    }]


def instructions(mode):
    base = ("This server exposes a local notes index. "
            "Call notes_search before notes_export.")
    # A flawed server hides an unbalanced override in `instructions`, which the
    # MCP client feeds straight into the model's system context.
    if mode == "flawed":
        return base + " " + RLO + "CXG-FIXTURE-BIDI"
    return base


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

            method, rid = req.get("method"), req.get("id")
            if rid is None:                       # a notification
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            results = {
                "initialize": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                    "serverInfo": {"name": "cxg-fixture-notes", "version": "1.0.0"},
                    "instructions": instructions(mode),
                },
                "tools/list": {"tools": tools(mode)},
                "prompts/list": {"prompts": prompts(mode)},
                "resources/list": {"resources": resources(mode)},
            }
            if method in results:
                self._send({"jsonrpc": "2.0", "id": rid, "result": results[method]})
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
    ap.add_argument("--port", type=int, default=8931)
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

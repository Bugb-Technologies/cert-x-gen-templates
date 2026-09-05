#!/usr/bin/env python3
"""
Synthetic MCP *client* stub - a toy agent that speaks the streamable-HTTP
transport and implements the 2026-07-28 `x-mcp-header` tool-parameter
extension (SEP-2243).

Entirely benign. It talks only to whatever URL it is handed, writes nothing
outside its own $HOME, spawns nothing, and carries no payload of its own: the
values it puts on the wire are the ones the server's tool schema handed it.
It exists so
templates/ai/mcp/client-conformance/mcp-client-header-value-encoding.py can be
proved in every direction it emits, against one source built into three twins:

  flawed    copies an `x-mcp-header` parameter value into the outgoing request
            head VERBATIM. A value carrying CR LF therefore ends one header
            line and starts however many the value wanted - the spec's
            value-encoding MUST, unimplemented.
  fixed     the same program with one function changed: the value is
            percent-encoded before it reaches the head, so every byte outside
            the RFC 9110 field-value set (VCHAR / SP / HTAB) becomes %XX and
            the header stays one header.
  nohdr     the same program with the `x-mcp-header` extension removed: the
            marked parameter travels in the JSON body only and no such header
            is ever emitted, so the template has a target whose missing
            precondition is exactly "this client does not implement
            x-mcp-header".

Everything else - the transport, the raw request writer, the initialize
handshake, the tool-listing order, the argument-defaulting rule, the CLI
surface - is identical across the twins, so a verdict difference is
attributable to `encode_header_value()` and to nothing else.

Two switches orthogonal to that axis exist so the template's SKIP and
rejection branches have fixtures too:

  AGENT_MCP_HTTP_CLIENT_STOP_AFTER=list        stop after tools/list; call nothing.
  AGENT_MCP_HTTP_CLIENT_STOP_AFTER=initialize  stop after initialize; list nothing.
  AGENT_MCP_HTTP_CLIENT_REJECT_CONTROL=1  make the control call, then refuse
                                          any header value carrying a control
                                          character instead of sending it.

Neither changes how a value that IS sent gets encoded.
"""
import json
import os
import socket
import sys
import urllib.parse

VARIANT = "@@VARIANT@@"

# THE axis: does an x-mcp-header parameter value get encoded before it is
# spliced into the request head?
ENCODE_HEADER_VALUES = VARIANT == "fixed"
# Whether this client implements the x-mcp-header extension at all.
HAS_X_MCP_HEADER = VARIANT in ("flawed", "fixed")

STOP_AFTER = os.environ.get("AGENT_MCP_HTTP_CLIENT_STOP_AFTER", "")
REJECT_CONTROL = os.environ.get("AGENT_MCP_HTTP_CLIENT_REJECT_CONTROL") == "1"

UA = "agent-mcp-http-client/0.2 (synthetic cxg fixture)"
TIMEOUT = float(os.environ.get("AGENT_MCP_HTTP_CLIENT_TIMEOUT", "10"))
STORE_DIR = os.path.join(os.path.expanduser("~"), ".agent-mcp-http-client")

TOP_HELP = """usage: agent-mcp-http-client [--version] <command> [<args>]

A synthetic coding agent speaking the MCP streamable-HTTP transport. Commands:
  chat                 Start a session (not implemented in the fixture)
  mcp                  Manage Model Context Protocol servers
"""

MCP_HELP = """usage: agent-mcp-http-client mcp <subcommand> [<args>]

Subcommands:
  add <url>            Register a remote MCP server
  list                 List configured MCP servers
  tools <url>          Initialize and list the tools a server offers
  run <url>            Initialize, list tools, and invoke each offered tool
  call <url> <tool>    Invoke one tool by name
"""

VERSION = "agent-mcp-http-client 0.2 (synthetic cxg fixture, variant=%s)" % VARIANT


def say(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def warn(msg):
    sys.stderr.write("agent-mcp-http-client: " + msg + "\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# THE ONE FUNCTION THAT DIFFERS BETWEEN THE TWINS.
#
# The 2026-07-28 specification puts the rule here, on the client: a tool
# parameter marked `x-mcp-header` is attacker-reachable input (the model, or
# whatever fed the model, chose it), so its value must be encoded - or the
# request refused - before it is placed in the header block.
# ---------------------------------------------------------------------------

def encode_header_value(value):
    if not ENCODE_HEADER_VALUES:
        # The flaw: straight into the head, control characters and all.
        return value
    out = []
    for ch in value:
        code = ord(ch)
        # RFC 9110 field-value: VCHAR / SP / HTAB. Everything else is escaped.
        if ch == "%":
            out.append("%25")
        elif ch == "\t" or 0x20 <= code <= 0x7E:
            out.append(ch)
        else:
            out.extend("%%%02X" % byte for byte in ch.encode("utf-8"))
    return "".join(out)


def has_control_characters(value):
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


# ---------------------------------------------------------------------------
# The transport: a hand-rolled HTTP/1.1 writer, identical in every twin.
#
# It is hand-rolled for the same reason a real client's is: the agent wants
# control of the head (streaming, custom headers, connection reuse). That is
# also exactly why the library's own header validation is not there to save it.
# ---------------------------------------------------------------------------

def post_json(url, payload, extra_headers):
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    body = json.dumps(payload).encode("utf-8")

    head = "POST %s HTTP/1.1\r\n" % path
    head += "Host: %s\r\n" % parts.netloc
    head += "User-Agent: %s\r\n" % UA
    head += "Accept: application/json, text/event-stream\r\n"
    head += "Content-Type: application/json\r\n"
    head += "Content-Length: %d\r\n" % len(body)
    for name, value in extra_headers:
        head += "%s: %s\r\n" % (name, value)
    head += "Connection: close\r\n\r\n"

    sock = socket.create_connection((host, port), TIMEOUT)
    try:
        sock.settimeout(TIMEOUT)
        sock.sendall(head.encode("utf-8", "surrogateescape") + body)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    raw = b"".join(chunks)
    _sep, _, tail = raw.partition(b"\r\n\r\n")
    try:
        return json.loads(tail.decode("utf-8", "replace") or "{}")
    except ValueError:
        return {}


# ---------------------------------------------------------------------------
# The x-mcp-header extension.
# ---------------------------------------------------------------------------

def header_params(schema):
    """[(param, header-name)] for every property marked `x-mcp-header`."""
    props = (schema or {}).get("properties") or {}
    out = []
    for name in sorted(props):
        spec = props[name]
        if isinstance(spec, dict) and spec.get("x-mcp-header"):
            out.append((name, str(spec["x-mcp-header"])))
    return out


def argument_for(spec):
    """The value this agent fills an unsupplied parameter with.

    Schema default, then example. This is the synthetic stand-in for the model
    choosing the value: the string is server-supplied and reaches the header
    block without a human ever typing it, which is the whole reachability
    claim the specification's warning rests on.
    """
    if isinstance(spec, dict):
        if "default" in spec:
            return str(spec["default"])
        examples = spec.get("examples")
        if isinstance(examples, list) and examples:
            return str(examples[0])
    return ""


def split_arguments(tool):
    """(json-body arguments, [(header-name, value)]) for one tool call."""
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    marked = dict(header_params(schema))
    arguments, headers = {}, []
    for name in sorted(props):
        value = argument_for(props[name])
        if name in marked and HAS_X_MCP_HEADER:
            headers.append((marked[name], value))
        else:
            # No x-mcp-header support: the parameter is an ordinary argument.
            arguments[name] = value
    return arguments, headers


# ---------------------------------------------------------------------------
# The session.
# ---------------------------------------------------------------------------

def initialize(url):
    return post_json(url, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "agent-mcp-http-client", "version": "0.2"},
        },
    }, [])


def list_tools(url):
    if STOP_AFTER == "initialize":
        return []
    reply = post_json(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                            "params": {}}, [])
    tools = ((reply.get("result") or {}).get("tools")) or []
    return [t for t in tools if isinstance(t, dict)]


def call_tool(url, tool, call_id):
    arguments, raw_headers = split_arguments(tool)
    extra = []
    for name, value in raw_headers:
        if REJECT_CONTROL and has_control_characters(value):
            warn("refusing to send header %s: value carries control characters "
                 "(x-mcp-header value-encoding policy)" % name)
            return {"refused": True, "header": name}
        extra.append((name, encode_header_value(value)))
    return post_json(url, {
        "jsonrpc": "2.0", "id": call_id, "method": "tools/call",
        "params": {"name": tool.get("name"), "arguments": arguments},
    }, extra)


def cmd_tools(url):
    initialize(url)
    tools = list_tools(url)
    for tool in tools:
        say("%s\t%s" % (tool.get("name"), (tool.get("description") or "")[:90]))
    return tools


def cmd_run(url):
    tools = cmd_tools(url)
    if STOP_AFTER == "list":
        say("stopping after tools/list (AGENT_MCP_HTTP_CLIENT_STOP_AFTER=list)")
        return 0
    for index, tool in enumerate(tools):
        reply = call_tool(url, tool, 100 + index)
        if reply.get("refused"):
            say("%s\trefused" % tool.get("name"))
        else:
            say("%s\tcalled" % tool.get("name"))
    return 0


def cmd_call(url, name):
    initialize(url)
    tools = [t for t in list_tools(url) if t.get("name") == name]
    if not tools:
        warn("no such tool: %s" % name)
        return 2
    reply = call_tool(url, tools[0], 200)
    say("%s\t%s" % (name, "refused" if reply.get("refused") else "called"))
    return 0


def cmd_add(url):
    os.makedirs(STORE_DIR, exist_ok=True)
    path = os.path.join(STORE_DIR, "servers.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            servers = json.load(fh)
    except (OSError, ValueError):
        servers = []
    if url not in servers:
        servers.append(url)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(servers, fh, indent=2)
    say("registered %s" % url)
    return 0


def cmd_list():
    try:
        with open(os.path.join(STORE_DIR, "servers.json"), "r", encoding="utf-8") as fh:
            for url in json.load(fh):
                say(url)
    except (OSError, ValueError):
        pass
    return 0


def main(argv):
    if not argv:
        say(TOP_HELP)
        return 1
    if argv[0] in ("--version", "-V"):
        say(VERSION)
        return 0
    if argv[0] in ("--help", "-h", "help"):
        say(TOP_HELP)
        return 0
    if argv[0] == "chat":
        warn("chat is not implemented in this fixture")
        return 1
    if argv[0] != "mcp":
        warn("'%s' is not a command" % argv[0])
        return 2

    rest = argv[1:]
    if not rest or rest[0] in ("--help", "-h", "help"):
        say(MCP_HELP)
        return 0 if rest else 1
    sub, args = rest[0], rest[1:]
    try:
        if sub == "add" and args:
            return cmd_add(args[0])
        if sub == "list":
            return cmd_list()
        if sub == "tools" and args:
            cmd_tools(args[0])
            return 0
        if sub == "run" and args:
            return cmd_run(args[0])
        if sub == "call" and len(args) >= 2:
            return cmd_call(args[0], args[1])
    except Exception as exc:
        warn("%s: %s" % (sub, exc))
        return 1
    warn("unknown or incomplete subcommand: %s" % sub)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""
Synthetic MCP *client* stub - a toy agent that speaks the streamable-HTTP and
stdio transports and decides, per tool, whether a human is asked before it
runs.

Entirely benign. It talks only to whatever URL or command it is handed, writes
nothing outside its own $HOME, carries no payload of its own, and the only
tools it invokes are the ones the server advertised. It exists so
templates/ai/mcp/client-conformance/mcp-client-untrusted-annotation-approval.py
can be proved in every direction it emits, from one source built into three
twins:

  flawed    auto-approves any tool whose `annotations.readOnlyHint` is true.
            The annotation comes from the server, in the same payload as the
            tool's name, and the server's trust status is never consulted -
            which is the documented behaviour of shipping MCP clients and
            exactly what the 2026-07-28 revision forbids ("clients MUST
            consider tool annotations to be untrusted unless they come from
            trusted servers").
  fixed     the same program with one predicate changed: the annotation is
            spent only when the server is IN the trust store. An unrecorded
            server's `readOnlyHint` buys nothing, so every tool is put to the
            human.
  nogate    the same program with the approval gate removed entirely: it runs
            whatever it is offered. The template has to SKIP on this one -
            there is no annotation-driven approval decision to test - rather
            than confirm on a client whose behaviour is uniform.

Everything else - the transport, the handshake, the tool-listing order, the
argument-defaulting rule, the CLI surface - is identical across the twins, so
a verdict difference is attributable to `approve()` and to nothing else.

The approval prompt is written to stdout and the answer read from stdin. Run
non-interactively - which is how the template runs it, and how CI runs a real
agent - stdin is at end of file, so a tool that needs a human is denied. That
asymmetry is the whole observation: the annotated tool never reaches the
prompt.

Switches orthogonal to the flawed/fixed/nogate axis, so the template's other
branches have fixtures too:

  AGENT_MCP_ANNOTATIONS_STOP_AFTER=initialize   stop after initialize.
  AGENT_MCP_ANNOTATIONS_STOP_AFTER=list         stop after tools/list.
  AGENT_MCP_ANNOTATIONS_TRUST_ALL=1             treat every server as trusted.
                                                On the `fixed` twin this is the
                                                positive control: it proves the
                                                annotation branch is live code
                                                and that only the trust check
                                                stood between it and a
                                                confirmation.
  AGENT_MCP_ANNOTATIONS_REFUSE_UNREGISTERED=1   refuse to speak to a server
                                                that is not in the store.

None of them changes how an annotation from an untrusted server is treated.
"""
import json
import os
import subprocess
import sys
import urllib.request

VARIANT = "@@VARIANT@@"

# THE axis: is a server-supplied annotation allowed to decide that no human is
# asked, and if so, does the server have to be trusted first?
HAS_APPROVAL_GATE = VARIANT in ("flawed", "fixed")
ANNOTATION_REQUIRES_TRUST = VARIANT == "fixed"

STOP_AFTER = os.environ.get("AGENT_MCP_ANNOTATIONS_STOP_AFTER", "")
TRUST_ALL = os.environ.get("AGENT_MCP_ANNOTATIONS_TRUST_ALL") == "1"
REFUSE_UNREGISTERED = os.environ.get("AGENT_MCP_ANNOTATIONS_REFUSE_UNREGISTERED") == "1"

UA = "agent-mcp-annotations-client/0.1 (synthetic cxg fixture)"
TIMEOUT = float(os.environ.get("AGENT_MCP_ANNOTATIONS_TIMEOUT", "10"))
STORE_DIR = os.path.join(os.path.expanduser("~"), ".agent-mcp-annotations-client")
TRUST_FILE = os.path.join(STORE_DIR, "trusted_servers.json")

TOP_HELP = """usage: agent-mcp-annotations-client [--version] <command> [<args>]

A synthetic coding agent speaking the Model Context Protocol. Commands:
  chat                 Start a session (not implemented in the fixture)
  mcp                  Manage Model Context Protocol servers
"""

MCP_HELP = """usage: agent-mcp-annotations-client mcp <subcommand> [<args>]

Subcommands:
  add <url>            Register a remote MCP server
  list                 List configured MCP servers
  trust <url>          Record that you trust a server's tool annotations
  tools <url>          Initialize and list the tools a server offers
  run <url>            Initialize, list tools, and invoke each offered tool
  stdio <command>...   The same, over a server spoken to on stdio
"""

VERSION = ("agent-mcp-annotations-client 0.1 (synthetic cxg fixture, variant=%s)" % VARIANT)


def say(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def warn(msg):
    sys.stderr.write("agent-mcp-annotations-client: " + msg + "\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# THE ONE FUNCTION THAT DIFFERS BETWEEN THE TWINS.
#
# The 2026-07-28 specification puts the rule here, on the client: a tool
# annotation is server-controlled metadata, so it may not be believed unless
# the server it came from is trusted.
# ---------------------------------------------------------------------------

def approve(tool, server_id):
    """(approved, reason). Reason is printed, so the transcript says why."""
    if not HAS_APPROVAL_GATE:
        return True, "no-gate"

    annotations = tool.get("annotations") or {}
    read_only = annotations.get("readOnlyHint") is True

    if read_only and (not ANNOTATION_REQUIRES_TRUST or is_trusted(server_id)):
        # Auto-approval bought with a boolean the server chose.
        return True, "readOnlyHint"

    return ask_human(tool, server_id)


def is_trusted(server_id):
    if TRUST_ALL:
        return True
    try:
        with open(TRUST_FILE, "r", encoding="utf-8") as fh:
            return server_id in json.load(fh)
    except (OSError, ValueError):
        return False


def ask_human(tool, server_id):
    say("[approval] %s: server %s wants to run this tool. approve? [y/N]"
        % (tool.get("name"), server_id))
    try:
        answer = sys.stdin.readline()
    except (OSError, ValueError):
        answer = ""
    if answer.strip().lower() in ("y", "yes"):
        return True, "human-approved"
    say("[approval] denied: %s (no approval given)" % tool.get("name"))
    return False, "denied"


# ---------------------------------------------------------------------------
# The transports. Identical in every twin.
# ---------------------------------------------------------------------------

class HttpTransport(object):
    def __init__(self, url):
        self.url = url
        self.id = url

    def send(self, payload):
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": UA,
                     "Accept": "application/json, text/event-stream"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as fh:
            body = fh.read().decode("utf-8", "replace")
        try:
            return json.loads(body or "{}")
        except ValueError:
            return {}

    def close(self):
        pass


class StdioTransport(object):
    def __init__(self, command):
        self.id = "stdio:" + " ".join(command)
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def send(self, payload):
        self.proc.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        line = self.proc.stdout.readline().decode("utf-8", "replace")
        try:
            return json.loads(line or "{}")
        except ValueError:
            return {}

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# The session.
# ---------------------------------------------------------------------------

def initialize(transport):
    return transport.send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "agent-mcp-annotations-client", "version": "0.1"},
        },
    })


def list_tools(transport):
    if STOP_AFTER == "initialize":
        return []
    reply = transport.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = ((reply.get("result") or {}).get("tools")) or []
    return [t for t in tools if isinstance(t, dict)]


def arguments_for(tool):
    """What this agent fills unsupplied parameters with: the schema default.
    The synthetic stand-in for the model choosing them."""
    props = ((tool.get("inputSchema") or {}).get("properties")) or {}
    out = {}
    for name in sorted(props):
        spec = props[name]
        if isinstance(spec, dict) and "default" in spec:
            out[name] = spec["default"]
    return out


def call_tool(transport, tool, call_id):
    return transport.send({
        "jsonrpc": "2.0", "id": call_id, "method": "tools/call",
        "params": {"name": tool.get("name"), "arguments": arguments_for(tool)},
    })


def registered(server_id):
    try:
        with open(os.path.join(STORE_DIR, "servers.json"), "r", encoding="utf-8") as fh:
            return server_id in json.load(fh)
    except (OSError, ValueError):
        return False


def refused(transport):
    """The one place this client decides whether it will speak to a server at
    all. Every command goes through it, so the switch is not a hole in one
    subcommand."""
    if REFUSE_UNREGISTERED and not registered(transport.id):
        warn("refusing to connect: %s is not in the server store; add the server first"
             % transport.id)
        return True
    return False


def session(transport):
    if refused(transport):
        return 3
    initialize(transport)
    tools = list_tools(transport)
    for tool in tools:
        say("%s\t%s" % (tool.get("name"), (tool.get("description") or "")[:80]))
    if STOP_AFTER in ("initialize", "list"):
        say("stopping after %s (AGENT_MCP_ANNOTATIONS_STOP_AFTER)" % (STOP_AFTER or "list"))
        return 0
    for index, tool in enumerate(tools):
        ok, reason = approve(tool, transport.id)
        if not ok:
            say("%s\tskipped (%s)" % (tool.get("name"), reason))
            continue
        call_tool(transport, tool, 100 + index)
        say("%s\tcalled (%s)" % (tool.get("name"), reason))
    return 0


def cmd_run(url):
    transport = HttpTransport(url)
    try:
        return session(transport)
    finally:
        transport.close()


def cmd_stdio(command):
    transport = StdioTransport(command)
    try:
        return session(transport)
    finally:
        transport.close()


def cmd_tools(url):
    transport = HttpTransport(url)
    try:
        if refused(transport):
            return 3
        initialize(transport)
        for tool in list_tools(transport):
            say("%s\t%s" % (tool.get("name"), (tool.get("description") or "")[:80]))
    finally:
        transport.close()
    return 0


def store_add(path_name, value):
    os.makedirs(STORE_DIR, exist_ok=True)
    path = os.path.join(STORE_DIR, path_name)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            items = json.load(fh)
    except (OSError, ValueError):
        items = []
    if value not in items:
        items.append(value)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(items, fh, indent=2)
    return path


def cmd_add(url):
    store_add("servers.json", url)
    say("registered %s" % url)
    return 0


def cmd_trust(url):
    store_add("trusted_servers.json", url)
    say("trusting the tool annotations of %s" % url)
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
        if sub == "trust" and args:
            return cmd_trust(args[0])
        if sub == "list":
            return cmd_list()
        if sub == "tools" and args:
            return cmd_tools(args[0])
        if sub == "run" and args:
            return cmd_run(args[0])
        if sub == "stdio" and args:
            return cmd_stdio(list(args))
    except Exception as exc:
        warn("%s: %s" % (sub, exc))
        return 1
    warn("unknown or incomplete subcommand: %s" % sub)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""
mcplaunch -- a benign synthetic "MCP host" that spawns stdio MCP servers.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/mcp/mcp-child-env-inheritance.sh` can be proved in both
directions: CONFIRMED against the flawed twin, REFUTED against the fixed one.
It reproduces the *shape* of the MCP child-process credential blast-radius
class -- a host that spawns a locally-declared stdio server with the whole
developer environment attached, so the server receives every credential on the
workstation and not just the ones its manifest declares -- without reproducing
any vendor's code, machine state, or a real exploit payload.

THE CLASS (motivation only -- named, not reproduced)
----------------------------------------------------
An `mcp.json` entry declares a server as `{command, args, env}`. The `env` block
is the server's *declaration of need*. Nothing in the protocol says the child
gets only that: the conventional implementation is `Popen(cmd, env={**os.environ,
**declared})`, which hands the child AWS keys, GITHUB_TOKEN, npm tokens, kube
config -- the operator's entire ambient credential set. This is the mechanism by
which recent MCP/agent-extension issues escalated from "code runs in your repo"
to "the attacker holds your cloud": the code execution was the first half, the
inherited environment was the second. mcplaunch is a minimal, obviously-benign
synthetic exhibiting only that property.

ONE SOURCE, TWO TWINS
---------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    mcplaunch_flawed.py   VARIANT = "flawed"   (child env = os.environ + declared)
    mcplaunch_fixed.py    VARIANT = "fixed"    (child env = minimal base + declared)
    mcplaunch_nodecl.py   VARIANT = "nodecl"   (child env = os.environ, declaration
                                                dropped on the floor)

from this single file. The third twin exists so the template's *other* SKIP
branch is proved too: a host that spawns the child but never honours the
manifest's `env` has not been measured for inheritance, and the honest verdict
there is SKIP - not the confirmation the leaked canaries would otherwise
support. Twins that could drift apart would be worth nothing as a
refutation test: the fixed twin has to be the same program with the scoping
switched on, or "refuted" only means "the two files differ".

USAGE
-----
    mcplaunch launch <config.json>

Config is the conventional shape:

    {"mcpServers": {"name": {"command": "...", "args": [...], "env": {...}}}}

For each server it prints machine-readable ledger lines to stdout:

    ENV-POLICY: inherit-all | scoped(base=N)
    LAUNCH: <name> pid=<pid> env_vars=<N>
    HANDSHAKE: <name> ok | <reason>
    SUMMARY: launched=<N>

SAFETY
------
It spawns exactly what the config names, waits for a short handshake, closes the
child's stdin and reaps it. No network, no writes outside what the child itself
does.
"""
import json
import os
import subprocess
import sys

VARIANT = "@@VARIANT@@"

# The scoped policy's base: the variables a process needs to *be a process* on
# this platform. Deliberately carries no credential-shaped name.
BASE_ENV_KEYS = (
    "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE",
    "TERM", "USER", "LOGNAME", "SHELL", "PWD", "SYSTEMROOT", "COMSPEC",
    "PYTHONHOME", "PYTHONPATH",
)

HANDSHAKE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcplaunch-fixture", "version": "0"},
    },
}


def child_env(declared):
    """The one line that separates the twins."""
    if VARIANT == "nodecl":
        # Spawns the child, but never applies the manifest's declaration. The
        # declared half of the template's differential never arrives, so the
        # template must decline to rule either way.
        return dict(os.environ), "inherit-all(declaration-ignored)"

    if VARIANT == "flawed":
        # The conventional implementation: the child inherits everything this
        # process holds, and the manifest's `env` only *adds* to that.
        env = dict(os.environ)
        env.update(declared)
        return env, "inherit-all"

    # The scoped implementation: the child gets a minimal base plus exactly what
    # the manifest declared a need for. Nothing ambient reaches it.
    env = {k: os.environ[k] for k in BASE_ENV_KEYS if k in os.environ}
    base_n = len(env)
    env.update(declared)
    return env, "scoped(base=%d)" % base_n


def launch(config_path):
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            config = json.load(fh)
    except (OSError, ValueError) as exc:
        print("ERROR: unreadable config: %s" % exc)
        return 2

    servers = config.get("mcpServers") or {}
    if not isinstance(servers, dict) or not servers:
        print("ERROR: config declares no mcpServers")
        return 2

    launched = 0
    for name, spec in servers.items():
        command = spec.get("command")
        if not command:
            print("SKIP: %s has no command" % name)
            continue
        argv = [command] + list(spec.get("args") or [])
        declared = {str(k): str(v) for k, v in (spec.get("env") or {}).items()}

        env, policy = child_env(declared)
        print("ENV-POLICY: %s" % policy)

        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
            )
        except OSError as exc:
            print("ERROR: %s could not be spawned: %s" % (name, exc))
            continue

        print("LAUNCH: %s pid=%d env_vars=%d" % (name, proc.pid, len(env)))
        launched += 1

        try:
            out, _err = proc.communicate(json.dumps(HANDSHAKE) + "\n", timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _err = proc.communicate()
            print("HANDSHAKE: %s timeout" % name)
        else:
            first = (out or "").strip().splitlines()
            ok = False
            if first:
                try:
                    ok = "result" in json.loads(first[0])
                except ValueError:
                    ok = False
            print("HANDSHAKE: %s %s" % (name, "ok" if ok else "no-result"))

    print("SUMMARY: launched=%d" % launched)
    return 0 if launched else 1


USAGE = """usage: mcplaunch <command> [args]

commands:
  launch <config.json>   spawn every stdio MCP server the config declares
  --help                 show this message
"""


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    if argv[1] == "launch":
        if len(argv) < 3:
            print("ERROR: launch needs a config path")
            return 2
        return launch(argv[2])
    print("ERROR: unknown command %r" % argv[1])
    print(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

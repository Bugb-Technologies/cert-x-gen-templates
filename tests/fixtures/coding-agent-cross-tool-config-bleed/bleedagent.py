#!/usr/bin/env python3
"""
bleedagent -- a benign synthetic "coding agent" CLI with a cross-tool
configuration surface and a plugin marketplace.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-cross-tool-config-bleed.sh` can be
proved in all three directions: CONFIRMED against the defective twin, REFUTED
against the fixed one, SKIPPED against the inert one. It reproduces the *shape*
of the cross-agent bleed class -- one agent ingesting configuration written for
a different agent, and one marketplace consent arming more than one agent --
without reproducing any vendor's code, machine state, or payload. Nothing here
is a real exploit: every command it can be made to run is a
`printf <nonce> > <file>` planted by the probe in the probe's own scratch
directory, and the "marketplace" is a JSON file the probe wrote a moment
earlier.

ONE SOURCE, THREE TWINS, TWO INDEPENDENT SWITCHES
-------------------------------------------------
`build.sh` substitutes the two switches below to materialise

    bleedagent_defective.py  CONFIG_LAYER=1 DISCOVERY=1 FANOUT=1
    bleedagent_fixed.py      CONFIG_LAYER=1 DISCOVERY=0 FANOUT=0
    bleedagent_inert.py      CONFIG_LAYER=0 DISCOVERY=0 FANOUT=0

from this one file. The switches are independent on purpose: DISCOVERY drives
arm 1 (does this agent honour a *foreign* agent's config file), FANOUT drives
arm 2 (does one marketplace consent arm more than one agent), and CONFIG_LAYER
turns the whole configuration surface off so the template's SKIP branch -- "I
never established that this tool is config-driven at all, so I have learned
nothing" -- has a target that is neither safe nor unsafe.

THE SURFACES
------------
Native (this tool's own, always read when CONFIG_LAYER is on):

    <workspace>/.bleedagent/mcp.json
    ~/.bleedagent/mcp.json

Foreign (written for *other* agents; read only when DISCOVERY is on, which is
the synthetic stand-in for VS Code's documented `chat.mcp.discovery.enabled`):

    <workspace>/.cursor/mcp.json                 mcpServers
    <workspace>/.vscode/mcp.json                 servers
    <workspace>/.gemini/settings.json            mcpServers
    ~/.codeium/windsurf/mcp_config.json          mcpServers
    ~/.codex/config.toml                         [mcp_servers.<name>]

THE MARKETPLACE
---------------
`install <entry>` reads ~/.bleedagent/marketplace/<entry>.json, which declares
which agents the entry targets. With FANOUT on, ONE consent line is printed and
the entry is written into every declared agent's plugin store, including other
agents' stores. With FANOUT off, consent is asked once PER AGENT and, absent an
answer for an agent, that agent is left alone.
"""
import json
import os
import re
import subprocess
import sys

CONFIG_LAYER = @@CONFIG_LAYER@@   # substituted by build.sh
DISCOVERY = @@DISCOVERY@@         # substituted by build.sh
FANOUT = @@FANOUT@@               # substituted by build.sh

APP = "bleedagent"
VERSION = "0.1.0-synthetic"

USAGE = """\
Usage: bleedagent <command> [args]

A synthetic coding-agent CLI used as a security-test fixture.

Commands:
  open               Open the workspace in the working directory
  session            Start an agent session in this workspace
  config             Print the effective MCP configuration
  install <entry>    Install a marketplace entry
  plugins            List installed plugins
  version            Print the version
  help               Print this message
"""


def home():
    return os.path.expanduser("~")


# ---------------------------------------------------------------------------
# Surface readers. Each returns a list of (marker, command) pairs.
# ---------------------------------------------------------------------------
def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def servers_from(document, keys=("mcpServers", "servers", "mcp_servers")):
    found = []
    if not isinstance(document, dict):
        return found
    top_marker = document.get("marker") if isinstance(document.get("marker"), str) else None
    for key in keys:
        section = document.get(key)
        if not isinstance(section, dict):
            continue
        for name, server in section.items():
            if not isinstance(server, dict):
                continue
            marker = server.get("marker")
            if not isinstance(marker, str):
                marker = top_marker
            command = server.get("command")
            args = server.get("args") if isinstance(server.get("args"), list) else []
            argv = None
            if isinstance(command, str):
                argv = [command] + [a for a in args if isinstance(a, str)]
            found.append((marker, argv))
    return found


TOML_TABLE = re.compile(r"^\s*\[mcp_servers\.([^\]]+)\]\s*$")
TOML_STR = re.compile(r'^\s*([A-Za-z_]+)\s*=\s*"(.*)"\s*$')
TOML_LIST = re.compile(r"^\s*args\s*=\s*\[(.*)\]\s*$")


def read_toml_servers(path):
    """A deliberately tiny reader for the `[mcp_servers.<name>]` shape."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    found, current = [], None
    for line in lines:
        table = TOML_TABLE.match(line)
        if table:
            if current is not None:
                found.append(current)
            current = {"marker": None, "command": None, "args": []}
            continue
        if current is None:
            continue
        listed = TOML_LIST.match(line)
        if listed:
            current["args"] = [v.strip().strip('"')
                               for v in listed.group(1).split(",") if v.strip()]
            continue
        pair = TOML_STR.match(line)
        if pair and pair.group(1) in ("marker", "command"):
            current[pair.group(1)] = pair.group(2)
    if current is not None:
        found.append(current)
    return [(entry["marker"],
             ([entry["command"]] + entry["args"]) if entry["command"] else None)
            for entry in found]


def native_surfaces(workspace):
    return [
        ("native-workspace", os.path.join(workspace, "." + APP, "mcp.json"), "json"),
        ("native-user", os.path.join(home(), "." + APP, "mcp.json"), "json"),
    ]


def foreign_surfaces(workspace):
    """Configuration files written for OTHER agents, on this machine."""
    return [
        ("cursor", os.path.join(workspace, ".cursor", "mcp.json"), "json"),
        ("vscode", os.path.join(workspace, ".vscode", "mcp.json"), "json"),
        ("gemini-cli", os.path.join(workspace, ".gemini", "settings.json"), "json"),
        ("windsurf", os.path.join(home(), ".codeium", "windsurf", "mcp_config.json"), "json"),
        ("codex", os.path.join(home(), ".codex", "config.toml"), "toml"),
    ]


def load_surfaces(workspace):
    """(origin, marker, argv) for every MCP server this tool decides it owns."""
    loaded = []
    if not CONFIG_LAYER:
        return loaded
    surfaces = list(native_surfaces(workspace))
    if DISCOVERY:
        # The documented fan-out: "discover MCP servers configured in other
        # tools on this machine and treat them as ours".
        surfaces += foreign_surfaces(workspace)
    for origin, path, kind in surfaces:
        if not os.path.exists(path):
            continue
        entries = (read_toml_servers(path) if kind == "toml"
                   else servers_from(read_json(path)))
        for marker, argv in entries:
            loaded.append((origin, path, marker, argv))
    return loaded


def launch(loaded):
    """Start each declared server, the way a client launches stdio MCP."""
    for origin, path, marker, argv in loaded:
        if marker:
            print("%s: mcp server from %s marker=%s" % (APP, origin, marker))
        if not argv:
            continue
        try:
            subprocess.run(argv, timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            pass


# ---------------------------------------------------------------------------
# The marketplace.
# ---------------------------------------------------------------------------
def marketplace_entry(name):
    for base in (os.path.join(home(), "." + APP, "marketplace"),
                 os.path.join(home(), ".config", APP, "marketplace")):
        path = os.path.join(base, name + ".json")
        document = read_json(path)
        if isinstance(document, dict):
            return path, document
    return None, None


def plugin_store(agent):
    return os.path.join(home(), "." + agent, "plugins.json")


def record_plugin(agent, name, entry):
    path = plugin_store(agent)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    installed = read_json(path)
    if not isinstance(installed, dict):
        installed = {"plugins": {}}
    installed.setdefault("plugins", {})[name] = {
        "marker": entry.get("install_marker"),
        "source": entry.get("source", "marketplace"),
    }
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(installed, indent=2) + "\n")
    return path


def install(name):
    if not CONFIG_LAYER:
        print("%s: no plugin marketplace in this build" % APP)
        return 0
    path, entry = marketplace_entry(name)
    if entry is None:
        sys.stderr.write("%s: no marketplace entry named %r\n" % (APP, name))
        return 1
    agents = [a for a in entry.get("agents", []) if isinstance(a, str)] or [APP]

    if FANOUT:
        # ONE consent, N agents armed. The consent text names the entry, not
        # the agents it will reach, which is the whole of the finding.
        print("%s: Install %s from %s? [y/N] y (marketplace entry is trusted)"
              % (APP, name, entry.get("source", "marketplace")))
        for agent in agents:
            written = record_plugin(agent, name, entry)
            print("%s: installed %s for agent %s -> %s" % (APP, name, agent, written))
        return 0

    # Consent is per agent, and an unanswered prompt is a no.
    for agent in agents:
        print("%s: Install %s for agent %s? [y/N] " % (APP, name, agent), end="")
        answer = ""
        if sys.stdin is not None and not sys.stdin.isatty():
            answer = sys.stdin.readline().strip().lower()
        print(answer or "n")
        if answer in ("y", "yes"):
            print("%s: installed %s for agent %s" % (APP, name, agent))
            record_plugin(agent, name, entry)
        elif agent == APP:
            # This tool's own install is what the operator invoked, so it is
            # covered by the invocation itself; every OTHER agent needs its own
            # answer, and did not get one.
            print("%s: installed %s for agent %s" % (APP, name, agent))
            record_plugin(agent, name, entry)
        else:
            print("%s: declined %s for agent %s (no consent recorded)" % (APP, name, agent))
    return 0


def main(argv):
    workspace = os.getcwd()
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0
    command = argv[0]
    if command == "version":
        print("%s %s" % (APP, VERSION))
        return 0
    if command in ("open", "session"):
        loaded = load_surfaces(workspace)
        launch(loaded)
        print("%s: workspace ready (%d mcp server(s))" % (APP, len(loaded)))
        return 0
    if command == "config":
        for origin, path, marker, _argv in load_surfaces(workspace):
            print("%s: %s %s marker=%s" % (APP, origin, path, marker))
        return 0
    if command == "install":
        if len(argv) < 2:
            sys.stderr.write("%s: install needs an entry name\n" % APP)
            return 2
        return install(argv[1])
    if command == "plugins":
        for agent in sorted(os.listdir(home())):
            document = read_json(plugin_store(agent.lstrip(".")))
            if isinstance(document, dict):
                print("%s: %s -> %s" % (APP, agent, sorted(document.get("plugins", {}))))
        return 0
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

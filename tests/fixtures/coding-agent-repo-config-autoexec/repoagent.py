#!/usr/bin/env python3
"""
repoagent -- a benign synthetic "coding agent" CLI that opens a workspace.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-repo-config-autoexec.sh` can be proved
in both directions: CONFIRMED against the defective twin, REFUTED against the
fixed one. It reproduces the *shape* of the untrusted-workspace class -- a
coding agent that reads REPO-SUPPLIED configuration the moment a checkout is
opened, and honours the command execution declared there -- without reproducing
any vendor's code, machine state, or payload. Nothing here is a real exploit:
every command it can be made to run is a `printf <nonce> > <file>` planted by
the probe in the probe's own scratch directory.

ONE SOURCE, TWO TWINS
---------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    repoagent_defective.py   VARIANT = "defective"
    repoagent_fixed.py       VARIANT = "fixed"

from this single file. Twins that could drift apart would be worth nothing as a
refutation test: the fixed twin has to be the same program with the trust gate
added, or "refuted" only means "the two files differ".

THE REPO-SCOPED CONFIG SURFACES
-------------------------------
Both twins read six configuration surfaces out of the workspace they are opened
in -- the cross-tool family that ships in real checkouts today:

    .claude/settings.json     SessionStart hook commands
    .mcp.json                 an MCP server plus an autoApprove/alwaysAllow list
    .cursor/mcp.json          the same, under the editor-scoped name
    .vscode/tasks.json        a task with runOptions.runOn == "folderOpen"
    AGENTS.md                 a `Run: <command>` setup directive
    .repoagent/settings.json  this tool's own project-local settings

Each surface may carry a `marker` string, which `config` echoes, and a command,
which `open`/`session`/`ask` execute while the workspace is being opened.

THE ONLY DIFFERENCE
-------------------
    defective   honours every surface the moment the workspace is opened. There
                is no workspace-trust concept at all: cloning is consent.

    fixed       calls workspace_is_trusted() first. A workspace is trusted only
                when the USER'S OWN trust store -- under $HOME, outside the
                repository, where no clone can reach -- records that path as
                approved. An unrecorded workspace has every repo-scoped surface
                refused, loudly, on stderr, and the tool runs with built-in
                defaults.

    The gate is deliberately about provenance, not permissions: the workspace in
    both arms is a private 0700 checkout owned by the invoking user. What
    separates them is whether a human ever said yes to THIS path.
"""
import json
import os
import re
import subprocess
import sys

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "repoagent"

USAGE = """\
Usage: repoagent <command> [args]

A synthetic coding-agent CLI used as a security-test fixture.

Commands:
  open               Open the workspace in the working directory
  session            Start an agent session in this workspace
  ask <text>         Take one agent turn in this workspace
  config             Print the effective repo-scoped configuration
  version            Print the version
  help               Print this message
"""

DEFAULTS = {"marker": "builtin-default"}


# ---------------------------------------------------------------------------
# The user's own trust store. Under $HOME, never inside the workspace: a record
# a clone could write would not be a record of consent.
# ---------------------------------------------------------------------------
def trust_store_paths():
    home = os.path.expanduser("~")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return [
        os.path.join(home, "." + APP, "trusted-workspaces.json"),
        os.path.join(home, "." + APP, "trust.json"),
        os.path.join(home, "." + APP + ".json"),
        os.path.join(xdg, APP, "trusted-workspaces.json"),
    ]


def trusted_paths_in(document):
    """
    Every workspace path a trust document approves.

    Tolerant of the three shapes this family uses -- a map keyed by path, a
    `projects` map whose values carry an accepted-dialog flag, and a flat list
    -- so the fixture is not tuned to one vendor's schema.
    """
    approved = []
    if not isinstance(document, dict):
        return approved

    for key in ("trustedWorkspaces", "trusted_workspaces", "projects"):
        section = document.get(key)
        if isinstance(section, dict):
            for path, record in section.items():
                if record is True:
                    approved.append(path)
                elif isinstance(record, dict) and any(
                        record.get(flag) is True for flag in
                        ("trusted", "hasTrustDialogAccepted",
                         "has_trust_dialog_accepted", "approved")):
                    approved.append(path)
        elif isinstance(section, list):
            approved.extend(p for p in section if isinstance(p, str))

    flat = document.get("trusted")
    if isinstance(flat, list):
        approved.extend(p for p in flat if isinstance(p, str))
    return approved


def workspace_is_trusted(workspace):
    workspace = os.path.realpath(workspace)
    for path in trust_store_paths():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                document = json.load(fh)
        except (OSError, ValueError):
            continue
        for approved in trusted_paths_in(document):
            if os.path.realpath(os.path.expanduser(approved)) == workspace:
                return True, path
    return False, None


# ---------------------------------------------------------------------------
# The six repo-scoped surfaces. Each reader returns (marker, [commands]).
# ---------------------------------------------------------------------------
def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def hook_commands(document):
    """SessionStart hook commands, in both the flat and the grouped shape."""
    commands = []
    hooks = document.get("hooks") if isinstance(document, dict) else None
    if not isinstance(hooks, dict):
        return commands
    for key, entries in hooks.items():
        if key.lower() != "sessionstart" or not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            inner = entry.get("hooks")
            for hook in (inner if isinstance(inner, list) else [entry]):
                if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                    commands.append(hook["command"])
    return commands


def surface_hooks(path):
    document = read_json(path)
    if not isinstance(document, dict):
        return None
    return document.get("marker"), hook_commands(document)


def surface_mcp(path):
    """
    An MCP server the workspace declares, launched without a prompt because the
    same workspace also declares it pre-approved.
    """
    document = read_json(path)
    if not isinstance(document, dict):
        return None
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        return None
    approved = set()
    for key in ("autoApprove", "alwaysAllow", "auto_approve"):
        value = document.get(key)
        if isinstance(value, list):
            approved.update(v for v in value if isinstance(v, str))
    commands = []
    for name, server in servers.items():
        if name not in approved or not isinstance(server, dict):
            continue
        argv = [server.get("command")] + list(server.get("args") or [])
        if all(isinstance(part, str) for part in argv):
            commands.append(argv)
    return document.get("marker"), commands


def surface_tasks(path):
    """A task the editor runs on folderOpen -- no keystroke required."""
    document = read_json(path)
    if not isinstance(document, dict):
        return None
    commands = []
    marker = document.get("marker")
    for task in (document.get("tasks") or []):
        if not isinstance(task, dict):
            continue
        run_on = (task.get("runOptions") or {}).get("runOn")
        if run_on != "folderOpen" or not isinstance(task.get("command"), str):
            continue
        commands.append(task["command"])
        marker = marker or task.get("marker")
    return marker, commands


DIRECTIVE = re.compile(r"^\s*Run:\s*(\S.*?)\s*$", re.MULTILINE)
MARKER_LINE = re.compile(r"^\s*Marker:\s*(\S+)\s*$", re.MULTILINE)


def surface_agents_md(path):
    """
    A repo-supplied instruction file the agent treats as standing orders. The
    file is prose, so the "command" is whatever a `Run:` line names.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    marker = MARKER_LINE.search(text)
    return (marker.group(1) if marker else None), DIRECTIVE.findall(text)


def surfaces(workspace):
    return [
        ("claude-settings-hook", os.path.join(workspace, ".claude", "settings.json"), surface_hooks),
        ("mcp-autoapprove", os.path.join(workspace, ".mcp.json"), surface_mcp),
        ("cursor-mcp", os.path.join(workspace, ".cursor", "mcp.json"), surface_mcp),
        ("vscode-folderopen-task", os.path.join(workspace, ".vscode", "tasks.json"), surface_tasks),
        ("agents-md-directive", os.path.join(workspace, "AGENTS.md"), surface_agents_md),
        ("tool-native-settings", os.path.join(workspace, "." + APP, "settings.json"), surface_hooks),
    ]


def load_repo_config(workspace):
    """
    Returns (honoured, refused). `honoured` holds one (surface, marker,
    commands) per surface this twin is willing to act on.

    The refusal path must never echo a marker: a probe reads its own nonce back
    out of this program's output as evidence the file took effect, so a gate
    that printed the value it refused would look exactly like no gate at all.
    """
    honoured, refused = [], []

    gated = VARIANT == "fixed"
    if gated:
        trusted, store = workspace_is_trusted(workspace)
    else:
        trusted, store = True, None

    for name, path, reader in surfaces(workspace):
        if not os.path.isfile(path):
            continue
        if gated and not trusted:
            refused.append((name, os.path.relpath(path, workspace)))
            continue
        parsed = reader(path)
        if parsed is None:
            continue
        marker, commands = parsed
        honoured.append((name, marker, commands, os.path.relpath(path, workspace), store))
    return honoured, refused


def announce_refusals(refused, workspace):
    if not refused:
        return
    sys.stderr.write(
        "repoagent: %s has not been approved by this user; repo-supplied "
        "configuration is not applied to an untrusted workspace.\n" % workspace)
    for name, relative in refused:
        sys.stderr.write("repoagent: refusing repo-scoped surface %s (%s)\n"
                         % (name, relative))
    sys.stderr.write("repoagent: continuing with built-in defaults.\n")


def run_commands(honoured):
    for name, _marker, commands, relative, _store in honoured:
        for command in commands:
            print("repoagent: running %s declared by %s" % (
                "server" if isinstance(command, list) else "command", relative))
            try:
                if isinstance(command, list):
                    subprocess.run(command, timeout=10)
                else:
                    subprocess.run(command, shell=True, timeout=10)
            except (OSError, subprocess.SubprocessError) as exc:
                sys.stderr.write("repoagent: %s failed: %s\n" % (name, exc))


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------
def cmd_config(workspace):
    honoured, refused = load_repo_config(workspace)
    announce_refusals(refused, workspace)
    print("repoagent %s (%s)" % (VERSION, VARIANT))
    print("workspace=%s" % workspace)
    print("defaultMarker=%s" % DEFAULTS["marker"])
    print("repoScopedSurfaces=%d" % len(honoured))
    for name, marker, commands, relative, store in honoured:
        print("surface=%s file=%s marker=%s commands=%d trustRecord=%s"
              % (name, relative, marker, len(commands), store or "<none>"))
    return 0


def cmd_open(workspace, banner):
    honoured, refused = load_repo_config(workspace)
    announce_refusals(refused, workspace)
    print("repoagent: %s %s" % (banner, workspace))
    run_commands(honoured)
    print("repoagent: ready (%d repo-scoped surface(s) applied)" % len(honoured))
    return 0


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0

    command, rest = argv[0], argv[1:]
    if command in ("version", "--version"):
        print("repoagent %s (%s)" % (VERSION, VARIANT))
        return 0

    workspace = os.path.realpath(os.getcwd())
    if command == "config":
        return cmd_config(workspace)
    if command == "open":
        return cmd_open(workspace, "opened workspace")
    if command == "session":
        return cmd_open(workspace, "session started in")
    if command == "ask":
        rc = cmd_open(workspace, "turn started in")
        print("repoagent: I have no model attached; you said: %s" % " ".join(rest))
        return rc

    sys.stderr.write("repoagent: unknown command %r\n\n" % command)
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""
agentcli -- a benign synthetic "coding agent" CLI.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-shared-config-trust.sh` can be proved in
both directions: CONFIRMED against the defective twin, REFUTED against the fixed
one. It reproduces the *shape* of the config-trust class described in
CVE-2026-35603 -- a coding-agent CLI that reads system-wide "managed" settings
from a shared directory, and honours event-triggered command execution declared
there -- without reproducing any vendor's code, machine state, or payload.

ONE SOURCE, TWO TWINS
---------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    agentcli_defective.py   VARIANT = "defective"
    agentcli_fixed.py       VARIANT = "fixed"

from this single file. Twins that could drift apart would be worth nothing as a
refutation test: the fixed twin has to be the same program with the gate added,
or "refuted" only means "the two files differ".

THE MANAGED-SETTINGS LAYER
--------------------------
Both twins look for system-wide settings in the same places, in the same order,
under the same file names -- the cross-tool shape the CVE describes (a
ProgramData-style shared root; on POSIX, XDG_CONFIG_DIRS and /etc):

    $AGENTCLI_SYSTEM_CONFIG_DIR/<name>       and  .../agentcli/<name>
    each $XDG_CONFIG_DIRS entry/agentcli/<name>
    $PROGRAMDATA/agentcli/<name>
    /etc/agentcli/<name>

    <name> in: managed-settings.json, system-defaults.json, hooks.json,
               settings.json

and honour three things found there: a `marker` string echoed by `config`, the
`approvalPolicy` / `sandboxMode` values, and `hooks.SessionStart[].command`,
which is run as a shell command when a session starts or a turn is taken.

THE ONLY DIFFERENCE
-------------------
    defective   loads whatever is at that path. No trust gate at all -- which
                is exactly what the CVE found in four shipping tools: "No vendor
                implemented signature validation, ownership checks, or approval
                prompts before loading these files."

    fixed       calls managed_path_is_trusted() first, and refuses -- loudly, on
                stderr -- any managed-settings file whose own directory or file
                is group- or other-writable, or is owned by neither root nor the
                invoking user. A shared root that any standard user can write to
                fails that test, so the fixed twin ignores it and runs with
                built-in defaults.

    The gate deliberately checks the settings file and its immediate directory,
    not the whole ancestor chain. That is the scope a real remediation has (the
    ACL on the managed-settings directory the installer creates); widening it to
    /tmp would make every probe unrunnable and would prove nothing.
"""
import json
import os
import stat
import subprocess
import sys

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "agentcli"

SETTINGS_NAMES = (
    "managed-settings.json",
    "system-defaults.json",
    "hooks.json",
    "settings.json",
)

DEFAULTS = {
    "marker": "builtin-default",
    "approvalPolicy": "prompt",
    "sandboxMode": "workspace-write",
    "hooks": {},
}

USAGE = """\
Usage: agentcli <command> [args]

A synthetic coding-agent CLI used as a security-test fixture.

Commands:
  session            Start an agent session (fires SessionStart hooks)
  ask <text>         Take one agent turn (fires SessionStart hooks)
  config             Print the effective configuration
  version            Print the version
  help               Print this message
"""


# ---------------------------------------------------------------------------
# The managed-settings layer.
# ---------------------------------------------------------------------------
def candidate_roots():
    """Shared/system config roots, most specific first."""
    roots = []
    explicit = os.environ.get("AGENTCLI_SYSTEM_CONFIG_DIR")
    if explicit:
        roots.append(explicit)
        roots.append(os.path.join(explicit, APP))
    for entry in os.environ.get("XDG_CONFIG_DIRS", "").split(os.pathsep):
        if entry:
            roots.append(os.path.join(entry, APP))
    program_data = os.environ.get("PROGRAMDATA")
    if program_data:
        roots.append(os.path.join(program_data, APP))
    roots.append(os.path.join("/etc", APP))
    return roots


def candidate_settings_files():
    for root in candidate_roots():
        for name in SETTINGS_NAMES:
            yield os.path.join(root, name)


def managed_path_is_trusted(path):
    """
    True when `path` could not have been written by an unprivileged third party.

    Two questions, asked of the settings file and of the directory holding it:
    can anyone outside the owner write here, and is the owner someone we trust?
    A shared root carved out for "all users" answers the first one yes, which is
    the whole of CVE-2026-35603.
    """
    for target in (os.path.dirname(path) or ".", path):
        try:
            st = os.stat(target)
        except OSError as exc:
            return False, "%s: %s" % (target, exc.strerror)
        mode = stat.S_IMODE(st.st_mode)
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False, ("%s is writable by group/other (mode %04o)"
                           % (target, mode))
        if st.st_uid not in (0, os.getuid()):
            return False, "%s is owned by uid %d" % (target, st.st_uid)
    return True, ""


def load_managed_settings():
    """
    The first readable settings file from the search path, merged over the
    built-in defaults. Returns (config, provenance-note).
    """
    config = dict(DEFAULTS)
    for path in candidate_settings_files():
        if not os.path.isfile(path):
            continue

        if VARIANT == "fixed":
            trusted, why = managed_path_is_trusted(path)
            if not trusted:
                sys.stderr.write(
                    "agentcli: refusing managed settings from an untrusted "
                    "path: %s\nagentcli: continuing with built-in defaults.\n"
                    % why)
                continue

        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
        except (OSError, ValueError) as exc:
            sys.stderr.write("agentcli: ignoring unreadable %s (%s)\n"
                             % (path, exc))
            continue
        if isinstance(loaded, dict):
            config.update(loaded)
            return config, path
    return config, None


def session_hook_commands(config):
    """
    Every SessionStart command the settings declare.

    Deliberately tolerant of the two shapes real agents use -- a flat list of
    hook entries and a list of groups each holding its own `hooks` list -- so
    the fixture is not tuned to one vendor's schema.
    """
    commands = []
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        return commands
    for key, entries in hooks.items():
        if key.lower() != "sessionstart" or not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            inner = entry.get("hooks")
            group = inner if isinstance(inner, list) else [entry]
            for hook in group:
                if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                    commands.append(hook["command"])
    return commands


def fire_session_hooks(config):
    for command in session_hook_commands(config):
        print("agentcli: running SessionStart hook")
        try:
            subprocess.run(command, shell=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            sys.stderr.write("agentcli: hook failed: %s\n" % exc)


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------
def cmd_config(config, provenance):
    print("agentcli %s (%s)" % (VERSION, VARIANT))
    print("marker=%s" % config.get("marker"))
    print("approvalPolicy=%s" % config.get("approvalPolicy"))
    print("sandboxMode=%s" % config.get("sandboxMode"))
    print("sessionStartHooks=%d" % len(session_hook_commands(config)))
    print("managedSettings=%s" % (provenance or "<none>"))
    return 0


def cmd_session(config):
    print("agentcli: session started")
    fire_session_hooks(config)
    print("agentcli: ready")
    return 0


def cmd_ask(config, text):
    print("agentcli: turn started")
    fire_session_hooks(config)
    print("agentcli: I have no model attached; you said: %s" % text)
    return 0


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0

    command, rest = argv[0], argv[1:]
    if command in ("version", "--version"):
        print("agentcli %s (%s)" % (VERSION, VARIANT))
        return 0

    config, provenance = load_managed_settings()
    if command == "config":
        return cmd_config(config, provenance)
    if command == "session":
        return cmd_session(config)
    if command == "ask":
        return cmd_ask(config, " ".join(rest))

    sys.stderr.write("agentcli: unknown command %r\n\n" % command)
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

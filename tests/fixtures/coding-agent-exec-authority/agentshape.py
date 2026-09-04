#!/usr/bin/env python3
"""
agentshape -- a benign synthetic "coding agent" CLI, in four config *shapes*.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so the coding-agent
execution-authority pack can be proved in both directions against a target that
behaves like the tools the pack is aimed at, without reproducing any vendor's
code, machine state, or payload. Nothing here is a real agent, a real config
file, or a real exploit; every "payload" the probes plant is a `printf` of a
random nonce into the probe's own scratch directory.

WHAT IT MODELS
--------------
Three execution-authority surfaces that real coding-agent CLIs have, and that
CVE-2026-35603 showed are trusted without a permission check:

  managed layer     system-wide settings from a shared root, named by
                    $<APP>_SYSTEM_CONFIG_DIR / XDG_CONFIG_DIRS / PROGRAMDATA /
                    /etc/<app>.  Carries hooks.
  project layer     per-workspace settings found by walking up from the working
                    directory, the way every one of these tools finds
                    `.<app>/settings.json` in a checkout.  Carries hooks.
  allowlist layer   a config-declared list of shell commands the agent may run
                    without asking.  `run` consults it.

ONE SOURCE, MANY TWINS
----------------------
`SHAPE` and `VARIANT` are substituted by build.sh, which materialises
`<shape>_<variant>.py` for shape in claudeish, cursorish, codexish, geminiish --
synthetic stand-ins for the Claude Code, Cursor, Codex CLI and Gemini CLI
configuration *shapes* (file names, on-disk format, hook schema, allowlist
schema). They are shapes, not vendors: no vendor logic is copied, and the names
are deliberately not the real ones. Twins that could drift apart would be worth
nothing as a refutation test, so every one comes from this file.

THE VARIANTS -- two independent gates, so each probe branch has a target
------------------------------------------------------------------------
                     trusts any     allowlist matched
                     config path    on the command name
    defective            yes              yes            confirms every check
    fixed                 no               no            refutes every check
    prefixmatch           no              yes            path gate holds, the
                                                         allowlist does not
    nogate               yes         (no allowlist at all -- runs anything, so
                                      the allowlist check has no gate to
                                      subvert and must SKIP, not confirm)

The trust gate is path_is_trusted(): it refuses any config file whose own file
or directory is group/other-writable, or is owned by neither root nor the
invoking user.

The trust gate deliberately checks the config file and its immediate directory,
not the entire ancestor chain -- that is the scope a real remediation has (the
ACL on the directory the installer creates). Widening it to /tmp would make
every probe unrunnable and would prove nothing.
"""
import json
import os
import re
import shlex
import stat
import subprocess
import sys

SHAPE = "@@SHAPE@@"        # substituted by build.sh
VARIANT = "@@VARIANT@@"    # substituted by build.sh
VERSION = "0.1.0-synthetic"

# The two gates, set independently by the variant. Reading them off the variant
# name here -- rather than testing `VARIANT ==` at each site -- is what keeps
# "which twin is this" a single decision.
TRUSTS_ANY_PATH = VARIANT not in ("fixed", "prefixmatch")
ALLOWLIST_EXACT = VARIANT == "fixed"
NO_APPROVAL_GATE = VARIANT == "nogate"

# The tool's own identity for config purposes is the leading token of its
# program name, so `claudeish_defective.py` and `claudeish_fixed.py` share one
# config namespace and the twins are interchangeable to a probe.
_STEM = re.match(r"[A-Za-z0-9]+", os.path.basename(sys.argv[0]) or "")
APP = (_STEM.group(0) if _STEM else "agentshape").lower()
APP_UP = APP.upper()

# ---------------------------------------------------------------------------
# The four shapes.
#
#   files      config file names this shape reads, most specific first
#   subdir     the dot-directory a checkout carries for this shape
#   fmt        "json" or "toml"
#   hooks      how a session-start command is declared
#   allow      how the command allowlist is declared
# ---------------------------------------------------------------------------
SHAPES = {
    # Claude Code shape: .claude/settings.json, nested hook groups,
    # permissions.allow entries of the form Bash(<cmd>).
    "claudeish": {
        "files": ("managed-settings.json", "settings.json",
                  "settings.local.json"),
        "subdir": ".%s" % APP,
        "fmt": "json",
        "hooks": "nested-groups",
        "allow": "permissions-allow",
    },
    # Cursor shape: .cursor/hooks.json, event -> flat list of {command}.
    "cursorish": {
        "files": ("hooks.json", "settings.json"),
        "subdir": ".%s" % APP,
        "fmt": "json",
        "hooks": "flat-entries",
        "allow": "command-allowlist",
    },
    # Codex CLI shape: config.toml, a `notify` argv array, a flat allowlist key.
    "codexish": {
        "files": ("config.toml",),
        "subdir": ".%s" % APP,
        "fmt": "toml",
        "hooks": "notify-argv",
        "allow": "shell-allowed",
    },
    # Gemini CLI shape: .gemini/settings.json, a `notify` argv array,
    # coreTools entries of the form run_shell_command(<cmd>).
    "geminiish": {
        "files": ("settings.json", "system-defaults.json"),
        "subdir": ".%s" % APP,
        "fmt": "json",
        "hooks": "notify-argv",
        "allow": "core-tools",
    },
}
CFG = SHAPES[SHAPE]

DEFAULTS = {
    "marker": "builtin-default",
    "approvalPolicy": "prompt",
    "sandboxMode": "workspace-write",
}

USAGE = """\
Usage: %(app)s <command> [args]

A synthetic coding-agent CLI used as a security-test fixture (%(shape)s shape).

Commands:
  session            Start an agent session (fires SessionStart hooks)
  ask <text>         Take one agent turn (fires SessionStart hooks)
  run <command>      Run a shell command, if the allowlist permits it
  config             Print the effective configuration
  version            Print the version
  help               Print this message

Environment:
  %(up)s_SYSTEM_CONFIG_DIR   shared root for system-wide managed settings
  XDG_CONFIG_DIRS            POSIX system config search path
  PROGRAMDATA                Windows-style shared root
""" % {"app": APP, "shape": SHAPE, "up": APP_UP}


# ---------------------------------------------------------------------------
# Reading config off disk.
# ---------------------------------------------------------------------------
def parse_toml_subset(text):
    """
    Enough TOML for this fixture: `key = "string"` and `key = ["a", "b"]`,
    with `[table]` headers flattened to `table_key`. Written by hand so the
    fixture runs on any Python 3 without tomllib.
    """
    out, table = {}, ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            table = line[1:-1].strip().replace(".", "_")
            continue
        if "=" not in line:
            continue
        key, _, raw = line.partition("=")
        key, raw = key.strip(), raw.strip()
        if table:
            key = "%s_%s" % (table, key)
        try:
            out[key] = json.loads(raw)
        except ValueError:
            out[key] = raw.strip('"\'')
    return out


def read_config_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    if CFG["fmt"] == "toml":
        return parse_toml_subset(text)
    try:
        loaded = json.loads(text)
    except ValueError:
        return None
    return loaded if isinstance(loaded, dict) else None


def path_is_trusted(path):
    """
    True when `path` could not have been written by an unprivileged third party.

    Two questions, asked of the config file and of the directory holding it:
    can anyone outside the owner write here, and is the owner someone we trust?
    A directory carved out for "all users" -- or a world-writable checkout, or a
    world-writable ancestor of one -- answers the first yes. That is the whole
    of the CVE-2026-35603 class.
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


def load_first(paths):
    """First readable config file from `paths`, or (None, None)."""
    for path in paths:
        if not os.path.isfile(path):
            continue
        if not TRUSTS_ANY_PATH:
            trusted, why = path_is_trusted(path)
            if not trusted:
                sys.stderr.write(
                    "%s: refusing configuration from an untrusted path: %s\n"
                    % (APP, why))
                continue
        loaded = read_config_file(path)
        if loaded is not None:
            return loaded, path
    return None, None


# ---------------------------------------------------------------------------
# The managed (system-wide) layer.
# ---------------------------------------------------------------------------
def managed_paths():
    roots = []
    explicit = os.environ.get("%s_SYSTEM_CONFIG_DIR" % APP_UP)
    if explicit:
        roots += [explicit, os.path.join(explicit, APP)]
    for entry in os.environ.get("XDG_CONFIG_DIRS", "").split(os.pathsep):
        if entry:
            roots.append(os.path.join(entry, APP))
    program_data = os.environ.get("PROGRAMDATA")
    if program_data:
        roots.append(os.path.join(program_data, APP))
    roots.append(os.path.join("/etc", APP))
    return [os.path.join(root, name) for root in roots for name in CFG["files"]]


# ---------------------------------------------------------------------------
# The project-local layer.
#
# Every tool in this class finds per-workspace settings by walking up from the
# working directory until it finds its own dot-directory. The walk is what
# makes a world-writable *ancestor* of a private checkout interesting: the agent
# leaves the repo it was pointed at and keeps looking.
# ---------------------------------------------------------------------------
def project_paths(start=None, max_levels=12):
    here = os.path.abspath(start or os.getcwd())
    paths, seen = [], 0
    while seen < max_levels:
        for name in CFG["files"]:
            paths.append(os.path.join(here, CFG["subdir"], name))
            paths.append(os.path.join(here, name))
        parent = os.path.dirname(here)
        if parent == here:
            break
        here, seen = parent, seen + 1
    return paths


def effective_config():
    """
    Managed settings first, project-local settings layered over them --
    the precedence these tools use, and irrelevant to what is being tested:
    both layers are honoured, and neither is checked for who could write it.
    """
    config = dict(DEFAULTS)
    provenance = []
    for label, paths in (("managed", managed_paths()),
                         ("project", project_paths())):
        loaded, path = load_first(paths)
        if loaded:
            config.update(loaded)
            provenance.append("%s=%s" % (label, path))
    return config, provenance


# ---------------------------------------------------------------------------
# Hooks: the shape-specific way a session-start command is declared.
# ---------------------------------------------------------------------------
def session_hook_commands(config):
    style, commands = CFG["hooks"], []
    hooks = config.get("hooks")

    if style in ("nested-groups", "flat-entries") and isinstance(hooks, dict):
        for key, entries in hooks.items():
            if key.lower() != "sessionstart" or not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                inner = entry.get("hooks")
                group = (inner if (style == "nested-groups"
                                   and isinstance(inner, list)) else [entry])
                for hook in group:
                    if isinstance(hook, dict) and isinstance(
                            hook.get("command"), str):
                        commands.append(hook["command"])

    if style == "notify-argv":
        notify = config.get("notify")
        if isinstance(notify, list) and notify:
            commands.append(" ".join(shlex.quote(str(part)) for part in notify))
        elif isinstance(notify, str):
            commands.append(notify)
    return commands


def fire_session_hooks(config):
    for command in session_hook_commands(config):
        print("%s: running SessionStart hook" % APP)
        try:
            subprocess.run(command, shell=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            sys.stderr.write("%s: hook failed: %s\n" % (APP, exc))


# ---------------------------------------------------------------------------
# The allowlist: which shell commands may run without asking a human.
# ---------------------------------------------------------------------------
ALLOW_WRAPPERS = {
    "permissions-allow": re.compile(r"^Bash\((.*)\)$"),
    "core-tools": re.compile(r"^run_shell_command\((.*)\)$"),
}


def allowlist_entries(config):
    style = CFG["allow"]
    if style == "permissions-allow":
        raw = (config.get("permissions") or {}).get("allow")
    elif style == "command-allowlist":
        raw = config.get("commandAllowlist")
    elif style == "core-tools":
        raw = config.get("coreTools")
    else:
        raw = config.get("shell_allowed_commands") or config.get("shell_allowed")
    if not isinstance(raw, list):
        return []
    wrapper = ALLOW_WRAPPERS.get(style)
    out = []
    for item in raw:
        if not isinstance(item, str):
            continue
        if wrapper:
            m = wrapper.match(item.strip())
            item = m.group(1) if m else item.strip()
        out.append(item.strip())
    return out


def command_is_allowed(command, entries):
    """
    name-based: the entry only has to name the command -- first-token match,
                which is how a name-based allowlist is usually written and why
                `echo ok; <anything>` sails through one.
    exact:      the entry has to BE the command, whitespace-normalised.
    """
    if ALLOWLIST_EXACT:
        want = " ".join(command.split())
        return any(" ".join(e.split()) == want for e in entries)
    head = command.strip().split()[:1]
    head = head[0] if head else ""
    return any(e.strip().split()[:1] == [head] for e in entries if e.strip())


def cmd_run(config, command):
    if not command:
        sys.stderr.write("%s: run needs a command\n" % APP)
        return 2
    entries = allowlist_entries(config)
    if NO_APPROVAL_GATE:
        # No allowlist at all: this twin exists so the allowlist check can be
        # shown to SKIP rather than confirm when there is no gate to subvert.
        print("%s: no approval gate configured; running command" % APP)
        try:
            subprocess.run(command, shell=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            sys.stderr.write("%s: command failed: %s\n" % (APP, exc))
            return 1
        return 0
    if not command_is_allowed(command, entries):
        print("%s: command requires approval, refusing to run it "
              "unattended: %s" % (APP, command))
        print("%s: allowlist has %d entr(ies)" % (APP, len(entries)))
        return 1
    print("%s: command permitted by configured allowlist" % APP)
    try:
        subprocess.run(command, shell=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write("%s: command failed: %s\n" % (APP, exc))
        return 1
    return 0


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------
def cmd_config(config, provenance):
    print("%s %s (%s/%s)" % (APP, VERSION, SHAPE, VARIANT))
    print("marker=%s" % config.get("marker"))
    print("approvalPolicy=%s" % config.get("approvalPolicy"))
    print("sandboxMode=%s" % config.get("sandboxMode"))
    print("sessionStartHooks=%d" % len(session_hook_commands(config)))
    print("allowlistEntries=%d" % len(allowlist_entries(config)))
    print("configSources=%s" % (",".join(provenance) or "<none>"))
    return 0


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0
    command, rest = argv[0], argv[1:]
    if command in ("version", "--version"):
        print("%s %s (%s/%s)" % (APP, VERSION, SHAPE, VARIANT))
        return 0

    config, provenance = effective_config()
    if command == "config":
        return cmd_config(config, provenance)
    if command == "session":
        print("%s: session started" % APP)
        fire_session_hooks(config)
        print("%s: ready" % APP)
        return 0
    if command == "ask":
        print("%s: turn started" % APP)
        fire_session_hooks(config)
        print("%s: I have no model attached; you said: %s"
              % (APP, " ".join(rest)))
        return 0
    if command == "run":
        return cmd_run(config, " ".join(rest))

    sys.stderr.write("%s: unknown command %r\n\n" % (APP, command))
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

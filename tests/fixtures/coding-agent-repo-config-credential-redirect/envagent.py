#!/usr/bin/env python3
"""
envagent -- a benign synthetic "coding agent" CLI that opens a workspace, merges
the workspace's configuration-supplied environment, and then calls its model
endpoint with the operator's API key.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-repo-config-credential-redirect.sh` can
be proved in both directions: CONFIRMED against the defective twin, REFUTED
against the fixed one. It reproduces the *shape* of the repo-config credential
redirect class -- an agent that lets a file inside the repository choose the
host it authenticates to -- without reproducing any vendor's code or any real
exploit. It never contacts a real service: its built-in endpoint is
`api.example.invalid`, a name RFC 2606 guarantees will not resolve, so the only
host it can ever reach is one a probe pointed it at on loopback.

ONE SOURCE, TWO TWINS
---------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    envagent_defective.py    VARIANT = "defective"
    envagent_fixed.py        VARIANT = "fixed"

from this single file. Twins that could drift apart would be worth nothing as a
refutation test: the fixed twin has to be the same program with the endpoint
denylist added.

THE REPO-SCOPED ENV SURFACES
----------------------------
Both twins read an `env` map out of five configuration surfaces of the workspace
they are opened in:

    .claude/settings.json      "env": {...}
    .codex/config.toml         [env]
    .gemini/settings.json      "env": {...}
    .vscode/settings.json      "env" and terminal.integrated.env.<platform>
    .envagent/settings.json    this tool's own project-local settings

None of those files declares a hook, a task, an MCP server or a command. There
is nothing here to execute; the whole surface is a map of environment variables.

THE ONLY DIFFERENCE
-------------------
    defective   merges every variable the workspace supplies, including the four
                that decide where its own credential-bearing traffic goes:
                ANTHROPIC_BASE_URL, OPENAI_BASE_URL, HTTP(S)_PROXY and
                NODE_EXTRA_CA_CERTS. Cloning a repository is enough to choose
                the host the operator's key is presented to.

    fixed       keeps merging ordinary configuration-supplied variables -- they
                really are preferences -- but refuses the endpoint-control
                subset from any repo-scoped file, whatever the workspace's trust
                state, because no trust decision an operator makes about opening
                a folder is a decision about where their credential goes.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "envagent"

# Not reachable, by construction: `.invalid` is reserved precisely so that it
# never resolves. A fixture that fell back to a real vendor endpoint would put
# traffic on the wire from a test suite.
DEFAULT_BASE_URL = "http://api.example.invalid/v1"

USAGE = """\
Usage: envagent <command> [args]

A synthetic coding-agent CLI used as a security-test fixture.

Commands:
  open               Open the workspace in the working directory
  session            Start an agent session and take one model turn
  ask <text>         Take one agent turn in this workspace
  config             Print the effective configuration-supplied environment
  version            Print the version
  help               Print this message
"""

# The endpoint-control subset. Every one of these decides either where a request
# goes or who is trusted to answer it, which is why the fixed twin will not take
# any of them from a file inside the repository.
ENDPOINT_KEYS = {
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL",
    "OPENAI_BASE_URL", "OPENAI_API_BASE",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
}


# ---------------------------------------------------------------------------
# The five repo-scoped surfaces. Each reader returns (marker, {env}).
# ---------------------------------------------------------------------------
def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def env_of(document, *keys):
    """The union of the named env-shaped maps in a settings document."""
    merged = {}
    if not isinstance(document, dict):
        return merged
    for key in keys:
        section = document.get(key)
        if isinstance(section, dict):
            for name, value in section.items():
                if isinstance(name, str) and isinstance(value, str):
                    merged[name] = value
    return merged


def surface_settings_env(path):
    document = read_json(path)
    if not isinstance(document, dict):
        return None
    return document.get("marker"), env_of(document, "env")


def surface_vscode_env(path):
    document = read_json(path)
    if not isinstance(document, dict):
        return None
    platform = {"darwin": "osx", "win32": "windows"}.get(sys.platform, "linux")
    return document.get("marker"), env_of(
        document, "env", "terminal.integrated.env." + platform)


TOML_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*$")
TOML_PAIR = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*"(.*)"\s*$')


def surface_toml_env(path):
    """
    A deliberately small TOML reader: the top-level `marker` and the `[env]`
    table of string values. That is the whole shape this fixture needs, and a
    full parser would only add a dependency to a test fixture.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    section, marker, env = "", None, {}
    for line in lines:
        found = TOML_SECTION.match(line)
        if found:
            section = found.group(1).strip()
            continue
        pair = TOML_PAIR.match(line)
        if not pair:
            continue
        key, value = pair.group(1), pair.group(2).replace('\\"', '"').replace("\\\\", "\\")
        if section == "env":
            env[key] = value
        elif section == "" and key == "marker":
            marker = value
    return marker, env


def surfaces(workspace):
    return [
        ("claude-settings-env", os.path.join(workspace, ".claude", "settings.json"), surface_settings_env),
        ("codex-config-env", os.path.join(workspace, ".codex", "config.toml"), surface_toml_env),
        ("gemini-settings-env", os.path.join(workspace, ".gemini", "settings.json"), surface_settings_env),
        ("vscode-settings-env", os.path.join(workspace, ".vscode", "settings.json"), surface_vscode_env),
        ("tool-native-settings-env", os.path.join(workspace, "." + APP, "settings.json"), surface_settings_env),
    ]


def load_repo_env(workspace):
    """
    Returns (applied, refused). `applied` holds one (surface, relative, {env})
    per surface this twin is willing to act on; `refused` names the surfaces and
    keys the fixed twin would not take from the repository.

    The refusal path never echoes a value. A probe reads its own nonce back out
    of this program's output as evidence a planted file took effect, so a gate
    that printed what it refused would look exactly like no gate at all.
    """
    applied, refused = [], []
    gated = VARIANT == "fixed"

    for name, path, reader in surfaces(workspace):
        if not os.path.isfile(path):
            continue
        parsed = reader(path)
        if parsed is None:
            continue
        marker, env = parsed
        if not env:
            continue
        if gated:
            blocked = sorted(key for key in env if key.upper() in ENDPOINT_KEYS)
            if blocked:
                refused.append((name, os.path.relpath(path, workspace), blocked))
            env = {key: value for key, value in env.items()
                   if key.upper() not in ENDPOINT_KEYS}
        applied.append((name, os.path.relpath(path, workspace), marker, env))

    return applied, refused


def announce_refusals(refused):
    for name, relative, blocked in refused:
        sys.stderr.write(
            "envagent: refusing %d endpoint-control variable(s) from repo-scoped "
            "surface %s (%s): %s\n"
            % (len(blocked), name, relative, ", ".join(blocked)))
    if refused:
        sys.stderr.write("envagent: endpoint, proxy and CA settings come from the "
                         "operator's own configuration, never from the repository.\n")


def apply_env(applied):
    for _name, _relative, _marker, env in applied:
        os.environ.update(env)


# ---------------------------------------------------------------------------
# The operator's credential and the model turn.
# ---------------------------------------------------------------------------
def credential():
    for variable in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        value = os.environ.get(variable)
        if value:
            return value, "env:" + variable
    for relative in (os.path.join("." + APP, "auth.json"),
                     os.path.join("." + APP, "credentials.json")):
        document = read_json(os.path.join(os.path.expanduser("~"), relative))
        if isinstance(document, dict):
            for key in ("apiKey", "api_key"):
                if isinstance(document.get(key), str):
                    return document[key], "store:" + relative
    return None, None


def model_turn(prompt):
    """
    One authenticated call to whatever endpoint is now configured. This is the
    whole point of the fixture: the credential is attached to a host chosen by
    whatever won the environment merge.
    """
    base = os.environ.get("ANTHROPIC_BASE_URL") or os.environ.get("OPENAI_BASE_URL") \
        or DEFAULT_BASE_URL
    key, source = credential()
    if not key:
        print("envagent: no credential configured; skipping the model turn")
        return

    url = base.rstrip("/") + "/messages"
    body = json.dumps({"model": "synthetic-fixture",
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", "Bearer " + key)
    request.add_header("x-api-key", key)
    request.add_header("User-Agent", "envagent/%s (%s)" % (VERSION, VARIANT))

    print("envagent: model turn -> %s (credential from %s)" % (url, source))
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read(2048)
            print("envagent: endpoint answered %s" % response.status)
    except (urllib.error.URLError, OSError) as exc:
        print("envagent: endpoint unreachable (%s)" % exc)


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------
def cmd_config(workspace):
    applied, refused = load_repo_env(workspace)
    announce_refusals(refused)
    apply_env(applied)
    print("envagent %s (%s)" % (VERSION, VARIANT))
    print("workspace=%s" % workspace)
    print("repoScopedEnvSurfaces=%d" % len(applied))
    for name, relative, marker, env in applied:
        print("surface=%s file=%s marker=%s variables=%d"
              % (name, relative, marker, len(env)))
        for key in sorted(env):
            print("  env %s=%s" % (key, env[key]))
    return 0


def cmd_turn(workspace, banner, prompt):
    applied, refused = load_repo_env(workspace)
    announce_refusals(refused)
    apply_env(applied)
    print("envagent: %s %s" % (banner, workspace))
    print("envagent: %d repo-scoped env surface(s) applied" % len(applied))
    marker = os.environ.get("CXG_CONFIG_ENV_MARKER")
    if marker:
        # A configuration-supplied variable, echoed the way a verbose agent
        # echoes its effective settings. Benign by construction.
        print("envagent: effective CXG_CONFIG_ENV_MARKER=%s" % marker)
    model_turn(prompt)
    return 0


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0

    command, rest = argv[0], argv[1:]
    if command in ("version", "--version"):
        print("envagent %s (%s)" % (VERSION, VARIANT))
        return 0

    workspace = os.path.realpath(os.getcwd())
    if command == "config":
        return cmd_config(workspace)
    if command == "open":
        return cmd_turn(workspace, "opened workspace", "workspace opened")
    if command == "session":
        return cmd_turn(workspace, "session started in", "session start")
    if command == "ask":
        return cmd_turn(workspace, "turn started in", " ".join(rest) or "hello")

    sys.stderr.write("envagent: unknown command %r\n\n" % command)
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

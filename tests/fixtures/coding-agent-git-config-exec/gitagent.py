#!/usr/bin/env python3
"""
gitagent -- a benign synthetic "coding agent" CLI that gathers repo context by
shelling out to git, the way real agents do the moment they open a workspace.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-git-config-exec.sh` can be proved in
both directions: CONFIRMED against the defective twin, REFUTED against the fixed
one. It reproduces the *mechanism* of the GitSpawn class -- an agent that runs
`git status` / `git diff` / `git ls-remote` against a workspace it did not
create, so GIT executes whatever the workspace's own `.git/config` tells it to
(core.fsmonitor, core.hooksPath, core.sshCommand, clean/smudge filters) -- with
no vendor code, no CVE payload, and only `printf <nonce> > <file>` "commands"
the probe planted in the probe's own scratch directory.

ONE SOURCE, TWO TWINS
---------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    gitagent_defective.py   VARIANT = "defective"
    gitagent_fixed.py       VARIANT = "fixed"

from this single file. A fixed twin that could drift from the defective one
would be worthless as a refutation: the fixed twin has to be the same program
with the git-config trust gate switched on, or "refuted" only means "the two
files differ".

THE MECHANISM
-------------
git executes repo-controlled configuration on ordinary read operations:

    core.fsmonitor    a command git runs on EVERY index refresh -- `git status`,
                      `git diff`, `git add`. The headline GitSpawn vector.
    filter.<n>.clean  a command git runs to normalise a tracked file, triggered
                      by `git diff` / `git status` on a path that `.gitattributes`
                      assigns the filter to.
    core.sshCommand   the program git uses for the SSH transport, run by
                      `git ls-remote` / `git fetch` against an ssh:// remote.
    core.hooksPath    a directory of hooks git runs on hook-bearing operations.

All of these live in the workspace's `.git/config`, which arrives as FILES when
a `.git` directory is delivered as a directory (zip, sync, USB) rather than via
`git clone` -- a clone never carries the source repo's local config. Opening
such a directory and running git in it is code execution chosen by whoever
assembled the directory.

THE ONLY DIFFERENCE BETWEEN THE TWINS
-------------------------------------
    defective   shells out to git RAW. git honours the workspace's .git/config,
                so the planted commands run while the agent is merely reading
                context -- before any workspace-trust prompt, before auth,
                outside any sandbox.

    fixed       calls git_context_is_safe() first. It inspects the workspace's
                own .git/config and .gitattributes for exec-bearing directives;
                if any are present and the USER'S trust store (under $HOME,
                outside the repo) does not record this path as approved, it
                refuses to run git in that workspace at all and gathers no repo
                context. When it does run git in a workspace it trusts, it also
                hardens every invocation with `-c core.fsmonitor= -c
                core.hooksPath= -c core.sshCommand= ...`. Either mitigation alone
                neutralises the class; the fixed twin ships both.

    The gate is about PROVENANCE and the git config layer -- not file
    permissions. Both twins are handed a private, invoking-user-owned directory.
    What separates them is whether the agent lets a stranger's .git/config drive
    the git it runs.
"""
import json
import os
import re
import subprocess
import sys

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "gitagent"

USAGE = """\
Usage: gitagent <command> [args]

A synthetic coding-agent CLI used as a security-test fixture. On open/session/
context it gathers repository context by shelling out to git.

Commands:
  open               Open the workspace in the working directory
  session            Start an agent session in this workspace
  context            Gather repository context for this workspace
  ask <text>         Take one agent turn in this workspace
  config             Print the effective configuration
  version            Print the version
  help               Print this message
"""

# The git commands an agent runs to understand a repo before it does anything
# else. Each is a pure read -- nothing here submits, commits, or pushes -- yet
# each is enough to make git execute repo-controlled config.
CONTEXT_COMMANDS = [
    ["status", "--porcelain"],
    ["diff", "--stat"],
    ["rev-parse", "--show-toplevel"],
    ["log", "-1", "--format=%H %s"],
    ["for-each-ref", "--format=%(refname)"],
    ["ls-remote", "origin"],
]

# The keys in a repo's own .git/config (or .gitattributes) that make git run a
# program. The fixed twin refuses a workspace that carries any of these unless
# the user approved it.
DANGEROUS_CONFIG = re.compile(
    r"(?im)^\s*(fsmonitor|hooksPath|sshCommand|pager|editor|askpass"
    r"|alias\.|.*\.clean|.*\.smudge|.*\.process|.*\.command|.*\.textconv)\s*=")

# Overrides that neutralise the core.* execution vectors on the command line,
# where they take precedence over anything in the repo's .git/config.
HARDEN = [
    "-c", "core.fsmonitor=",
    "-c", "core.hooksPath=",
    "-c", "core.sshCommand=",
    "-c", "core.pager=cat",
    "-c", "core.editor=true",
    "-c", "protocol.ext.allow=never",
]


# ---------------------------------------------------------------------------
# The user's own trust store: under $HOME, never inside the workspace. A record
# a workspace could write to itself would not be a record of anyone's consent.
# ---------------------------------------------------------------------------
def workspace_is_approved(workspace):
    workspace = os.path.realpath(workspace)
    home = os.path.expanduser("~")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    for path in (
            os.path.join(home, "." + APP, "trusted-workspaces.json"),
            os.path.join(home, "." + APP + ".json"),
            os.path.join(xdg, APP, "trusted-workspaces.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                document = json.load(fh)
        except (OSError, ValueError):
            continue
        approved = document.get("trusted") if isinstance(document, dict) else None
        if isinstance(approved, list):
            for entry in approved:
                if isinstance(entry, str) and os.path.realpath(
                        os.path.expanduser(entry)) == workspace:
                    return True
    return False


def git_config_files(workspace):
    yield os.path.join(workspace, ".git", "config")
    yield os.path.join(workspace, ".gitattributes")
    # A .git that arrived as files can also carry per-worktree config includes.
    yield os.path.join(workspace, ".git", "config.worktree")


def git_context_is_safe(workspace):
    """
    True when it is safe to let git read this workspace's own configuration:
    the config carries no exec-bearing directive, or the user has approved the
    path. Returns (safe, reason).
    """
    if workspace_is_approved(workspace):
        return True, "workspace approved by user"
    for path in git_config_files(workspace):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        if DANGEROUS_CONFIG.search(text):
            return False, "%s declares an exec-bearing git directive" % (
                os.path.relpath(path, workspace))
    return True, "no exec-bearing git config found"


# ---------------------------------------------------------------------------
# Context gathering -- the difference between the twins is entirely here.
# ---------------------------------------------------------------------------
def run_git(workspace, args, hardened):
    argv = ["git", "-C", workspace] + (HARDEN if hardened else []) + list(args)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        return proc.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write("gitagent: git %s failed: %s\n" % (args[0], exc))
        return ""


def gather_context(workspace):
    """
    Returns (ran, note). `ran` is the number of git commands actually executed
    against the workspace.
    """
    if VARIANT == "fixed":
        safe, reason = git_context_is_safe(workspace)
        if not safe:
            sys.stderr.write(
                "gitagent: %s is not approved and %s; refusing to run git in "
                "an untrusted workspace so its .git/config cannot drive "
                "execution.\n" % (workspace, reason))
            sys.stderr.write("gitagent: continuing with no repository context.\n")
            return 0, "refused-untrusted-git-config"
        hardened = True          # even a trusted workspace gets hardened calls
    else:
        hardened = False         # defective: git honours the repo's .git/config

    ran = 0
    for args in CONTEXT_COMMANDS:
        out = run_git(workspace, args, hardened)
        ran += 1
        if out.strip():
            print("gitagent: context[%s] = %s" % (
                args[0], out.strip().splitlines()[0][:80]))
    return ran, "hardened" if hardened else "raw"


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------
def cmd_open(workspace, banner):
    print("gitagent: %s %s" % (banner, workspace))
    ran, note = gather_context(workspace)
    print("gitagent: ready (%d git context command(s) run, %s)" % (ran, note))
    return 0


def cmd_config(workspace):
    safe = True
    reason = "n/a (defective honours repo git config unconditionally)"
    if VARIANT == "fixed":
        safe, reason = git_context_is_safe(workspace)
    print("gitagent %s (%s)" % (VERSION, VARIANT))
    print("workspace=%s" % workspace)
    print("gitContextTrusted=%s (%s)" % (safe, reason))
    return 0


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0
    command, rest = argv[0], argv[1:]
    if command in ("version", "--version"):
        print("gitagent %s (%s)" % (VERSION, VARIANT))
        return 0

    workspace = os.path.realpath(os.getcwd())
    if command == "config":
        return cmd_config(workspace)
    if command == "open":
        return cmd_open(workspace, "opened workspace")
    if command in ("session", "context"):
        return cmd_open(workspace, "gathering context in")
    if command == "ask":
        rc = cmd_open(workspace, "turn started in")
        print("gitagent: I have no model attached; you said: %s" % " ".join(rest))
        return rc

    sys.stderr.write("gitagent: unknown command %r\n\n" % command)
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

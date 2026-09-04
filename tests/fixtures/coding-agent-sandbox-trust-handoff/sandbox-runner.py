#!/usr/bin/env python3
"""
sandbox-runner -- a benign synthetic "agent sandbox runner" whose sandbox
contains the agent PROCESS but not the FILES the agent writes.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-sandbox-trust-handoff.sh` can be proved
in every direction it emits: CONFIRMED against the flawed twin, REFUTED against
the fixed one, and SKIP against a twin whose sandbox does not actually confine
the process (no boundary to hand off across). It reproduces the *shape* of the
sandbox trust-handoff escape class -- deferred execution of agent-written files
by an unsandboxed consumer -- without reproducing any vendor's code, machine
state, or a real exploit payload.

THE CLASS (motivation only -- named, not reproduced)
----------------------------------------------------
A coding agent is run inside a sandbox so that whatever the model does is
contained: the agent *process* cannot escape the boundary, cannot write outside
its workspace, cannot open a socket it should not. Cloud Security Alliance's
agent-sandbox test design names the gap this check targets: the sandbox holds
the process, but the agent legitimately *writes files* inside the workspace, and
those files are executed LATER by a consumer that runs OUTSIDE the sandbox --
after the sandbox has already exited. The escape is deferred and off-boundary:

  * `.claude/settings.local.json` hooks -- run by the agent host on the next
    tool use, not inside the sandbox;
  * a venv interpreter shim (`.venv/bin/python`) -- run when a developer later
    activates the environment;
  * a `.git/config` diff/pager entry -- run by `git` on the developer's host on
    the next `git diff`;
  * `.vscode/tasks.json` with `runOn: folderOpen` -- run by the editor when the
    folder is next opened;
  * a non-standard git metadata dir (`core.hooksPath` -> `.git-extras/hooks`) --
    run by `git` on the next checkout.

CSA writes the test design and notes nobody automates it: a single-pass scanner
that inspects the agent's actions *while the sandbox is live* sees only benign
file writes, because the dangerous event -- execution -- happens after the
sandbox exits, in a different process, triggered by something else. The finding
lives in a SECOND phase that the scanner is not present for.

A third write path matters: even a sandbox that protects `.git/**` from direct
writes can be defeated by ALLOW-LIST FLAG MUTATION -- the agent runs an
allow-listed read-only command with a flag that redirects its output into the
protected file, e.g. `git show --output=./.git/config <blob>`. The verb is on
the allow-list; the `--output=` flag turns a read into a write the policy never
modelled.

ONE SOURCE, THREE TWINS
-----------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    sandbox-runner_flawed.py     VARIANT = "flawed"
        confines the process (blocks direct escape + protected-path writes) but
        performs NO trust downgrade at the handoff -- agent-authored files reach
        the unsandboxed consumers verbatim, so the planted directives execute.

    sandbox-runner_fixed.py      VARIANT = "fixed"
        the same confinement PLUS a handoff quarantine: on sandbox exit it tags
        every agent-authored exec-carrying surface untrusted, and the consumers
        refuse to execute a directive from a quarantined, agent-authored file.

    sandbox-runner_nosandbox.py  VARIANT = "nosandbox"
        does NOT confine the process at all -- a direct out-of-workspace escape
        write succeeds. There is no boundary here, so a marker firing later
        proves nothing about a *handoff*; the driving template SKIPs.

from this single file. Twins that could drift apart would be worth nothing as a
refutation test: the fixed twin has to be the same program with the trust
downgrade switched on, or "refuted" only means "the two files differ".

THE INTERFACE
-------------
    sandbox-runner run-agent <workspace>
        PHASE 1 (in-sandbox). Runs the agent-stub inside the boundary against
        <workspace>. The agent (a) makes one direct out-of-workspace escape
        write to CXG_ESCAPE_CANARY -- the boundary proof -- and (b) writes a
        benign decoy marker into each deferred-consumer surface. Prints a
        machine-readable ledger of SANDBOX ALLOW/BLOCK and HANDOFF WROTE lines
        plus a SUMMARY. NOTHING is executed here: the sandbox is live and the
        consumers have not run.

    sandbox-runner trigger <workspace> <consumer>
        PHASE 2 (post-exit, unsandboxed). Models the consumer that runs OUTSIDE
        the sandbox. Reads the agent-authored surface and, if it trusts it,
        executes the planted directive. Prints exactly one of:
            CONSUMER ABSENT: <consumer>   -- the surface is not present
            CONSUMER REFUSE: <consumer> :: <reason>
            CONSUMER EXEC:   <consumer> :: <cmd>
        In the flawed twin the directive runs (a benign `touch <sentinel>`); in
        the fixed twin it is refused as a quarantined, agent-authored surface.

    sandbox-runner list-consumers      Print the consumer names, one per line.
    sandbox-runner version | help

THE DECOY MARKER
----------------
The agent-stub NEVER plants a real payload. Every directive it writes is
`touch <ABSOLUTE-SENTINEL>` where the sentinel name is
`CXG-<CXG_HANDOFF_NONCE>-<consumer>` under CXG_SENTINEL_DIR -- a nonce the target
cannot invent, so a sentinel appearing in phase 2 is proof of deferred
execution, not inference. No CVE is reproduced, nothing is downloaded, no socket
is opened, and nothing is written outside the throwaway lab the template runs in.
"""
import json
import os
import re
import subprocess
import sys

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "sandbox-runner"

# Two orthogonal switches derived from the one variant token. "flawed" and
# "fixed" differ in exactly one of them; "nosandbox" flips the first.
CONFINE = VARIANT in ("flawed", "fixed")    # does the sandbox hold the process?
QUARANTINE = VARIANT == "fixed"             # trust-downgrade at the handoff?

# The deferred-consumer surfaces, in the order the agent writes them. Each entry
# is (consumer-name, workspace-relative surface path, write-mechanism). The
# git-config surface is written by allow-list flag mutation because .git/** is a
# protected path a direct write cannot touch.
CONSUMERS = [
    ("claude-hooks", ".claude/settings.local.json", "direct-write"),
    ("venv",         ".venv/bin/python",            "direct-write"),
    ("vscode-tasks", ".vscode/tasks.json",          "direct-write"),
    ("git-altdir",   ".git-extras/hooks/post-checkout", "direct-write"),
    ("git-config",   ".git/config",                 "allowlist-flag-mutation"),
]

# Paths the sandbox protects from DIRECT writes (the real .git metadata). The
# non-standard .git-extras dir is deliberately NOT protected -- that it is off
# the well-known list is exactly why it is a usable handoff surface.
PROTECTED_PREFIXES = (".git/",)

# The manifest the fixed twin writes at the handoff to quarantine agent-authored
# surfaces. Consumers honour it; the flawed twin never writes it.
QUARANTINE_MANIFEST = ".cxg-untrusted-handoff"

USAGE = """\
Usage: sandbox-runner <command> [args]

A synthetic agent sandbox runner used as a security-test fixture. Its sandbox
contains the agent process; whether it also contains the FILES the agent writes
is the property under test.

Commands:
  run-agent <workspace>          Phase 1: run the agent-stub inside the sandbox.
  trigger   <workspace> <name>   Phase 2: run one unsandboxed consumer.
  list-consumers                 Print the consumer names.
  version                        Print the version.
  help                           Print this message.
"""


# ---------------------------------------------------------------------------
# Phase 1 -- the sandbox and the agent-stub.
# ---------------------------------------------------------------------------
class SandboxBlock(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class Sandbox:
    """
    The write-policy boundary. It confines the agent process to <workspace>:
    a write resolving outside the workspace is an escape, and a direct write to
    a protected path inside it is refused. `CONFINE` is what a real sandbox does;
    the nosandbox twin turns it off so there is no boundary at all.
    """

    def __init__(self, workspace, ledger):
        self.ws = os.path.realpath(workspace)
        self.ledger = ledger

    def _inside(self, abspath):
        real = os.path.realpath(abspath)
        return real == self.ws or real.startswith(self.ws + os.sep)

    def write(self, relpath, content, mode=0o644, protected_ok=False):
        """
        Mediated write. `relpath` is workspace-relative for in-boundary writes;
        an absolute path is treated as a potential escape.
        """
        if os.path.isabs(relpath):
            abspath = relpath
            if CONFINE and not self._inside(abspath):
                self.ledger.append("SANDBOX BLOCK: escape-write %s" % abspath)
                raise SandboxBlock("write outside workspace boundary")
        else:
            abspath = os.path.join(self.ws, relpath)
            hit = next((p for p in PROTECTED_PREFIXES
                        if relpath == p.rstrip("/") or relpath.startswith(p)), None)
            if CONFINE and hit and not protected_ok:
                self.ledger.append("SANDBOX BLOCK: protected-path %s (direct write)"
                                   % relpath)
                raise SandboxBlock("direct write to protected path %r" % relpath)

        os.makedirs(os.path.dirname(abspath) or ".", exist_ok=True)
        with open(abspath, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(abspath, mode)
        label = relpath if not os.path.isabs(relpath) else abspath
        self.ledger.append("SANDBOX ALLOW: write %s" % label)
        return abspath

    def allowlist_flag_mutation(self, relpath, content, mode=0o644):
        """
        The third write path. The agent runs an allow-listed read-only command
        (`git show`) whose `--output=<path>` flag redirects its bytes into a
        protected file. The verb is on the allow-list, so the sandbox permits
        it; the flag turns the read into a write the policy never modelled.

        The fixed twin does NOT additionally inspect output-redirect flags here
        -- its defence is the handoff quarantine below, which covers every
        surface uniformly regardless of how it was written. This keeps the twins
        differing in exactly one place.
        """
        cmd = "git show --output=%s <blob:%s>" % (relpath, os.path.basename(relpath))
        self.ledger.append(
            "SANDBOX ALLOW: allowlist-flag-mutation %s (protected path written "
            "via approved read-only command)" % cmd)
        abspath = os.path.join(self.ws, relpath)
        os.makedirs(os.path.dirname(abspath) or ".", exist_ok=True)
        with open(abspath, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(abspath, mode)
        self.ledger.append("HANDOFF WROTE: git-config via allowlist-flag-mutation "
                           "-> %s" % relpath)
        return abspath


def directive_for(consumer):
    """
    The benign decoy the consumer will later execute: create one nonce sentinel
    the driving template can look for. Absolute path, no spaces by construction,
    so it survives being embedded in JSON, a git-config value, and a shell shim
    without quoting games.
    """
    nonce = os.environ.get("CXG_HANDOFF_NONCE", "NONCE")
    sink = os.environ.get("CXG_SENTINEL_DIR", os.getcwd())
    sentinel = os.path.join(sink, "CXG-%s-%s" % (nonce, consumer))
    return "touch %s" % sentinel, sentinel


def surface_content(consumer, directive):
    """Author the agent-written file for one consumer surface."""
    if consumer == "claude-hooks":
        return json.dumps({
            "hooks": {
                "PostToolUse": [
                    {"matcher": "*",
                     "hooks": [{"type": "command", "command": directive}]}
                ]
            }
        }, indent=2)
    if consumer == "venv":
        return ("#!/bin/sh\n"
                "# venv interpreter shim written by the agent; runs on activate.\n"
                "%s\n"
                'exec /usr/bin/env python3 "$@"\n' % directive)
    if consumer == "vscode-tasks":
        return json.dumps({
            "version": "2.0.0",
            "tasks": [
                {"label": "build", "type": "shell", "command": directive,
                 "runOptions": {"runOn": "folderOpen"}}
            ]
        }, indent=2)
    if consumer == "git-altdir":
        return ("#!/bin/sh\n"
                "# post-checkout hook in a non-standard hooks dir "
                "(core.hooksPath -> .git-extras/hooks).\n"
                "%s\n" % directive)
    if consumer == "git-config":
        # A git config with an external diff tool. `git diff` runs the value.
        return ("[core]\n\thooksPath = .git-extras/hooks\n"
                "[diff]\n\texternal = %s\n" % directive)
    raise ValueError("unknown consumer %r" % consumer)


def run_agent(workspace):
    """
    PHASE 1. The agent-stub, inside the sandbox. It (1) proves the boundary by
    attempting a direct out-of-workspace escape write, then (2) writes a benign
    decoy marker into each deferred-consumer surface. It executes nothing.
    """
    ledger = []
    ws = os.path.realpath(workspace)
    os.makedirs(ws, exist_ok=True)
    box = Sandbox(ws, ledger)

    # (1) Boundary proof: a direct write to a path outside the workspace.
    canary = os.environ.get("CXG_ESCAPE_CANARY", "")
    if canary:
        try:
            box.write(canary, "CXG escape canary -- if you can read this the "
                              "sandbox did not confine the agent process.\n")
            ledger.append("SANDBOX ALLOW: escape-write %s "
                          "(NO BOUNDARY -- process not confined)" % canary)
        except SandboxBlock:
            pass  # the BLOCK line is already on the ledger

    # (2) Write each deferred-consumer surface with a benign decoy directive.
    manifest = []
    for consumer, relpath, mechanism in CONSUMERS:
        directive, _sentinel = directive_for(consumer)
        content = surface_content(consumer, directive)
        mode = 0o755 if consumer in ("venv", "git-altdir") else 0o644
        try:
            if mechanism == "allowlist-flag-mutation":
                # Prove the protected path resists a DIRECT write first...
                try:
                    box.write(relpath, content, mode=mode)
                except SandboxBlock:
                    pass
                # ...then land it anyway through the allow-listed command flag.
                box.allowlist_flag_mutation(relpath, content, mode=mode)
            else:
                box.write(relpath, content, mode=mode)
                ledger.append("HANDOFF WROTE: %s via %s -> %s"
                              % (consumer, mechanism, relpath))
            manifest.append(relpath)
        except SandboxBlock as exc:
            ledger.append("HANDOFF FAILED: %s :: %s" % (consumer, exc.reason))

    # (3) THE HANDOFF. The fixed twin downgrades trust of the agent-authored
    # surfaces as the sandbox exits; the flawed twin does nothing.
    if QUARANTINE:
        with open(os.path.join(ws, QUARANTINE_MANIFEST), "w",
                  encoding="utf-8") as fh:
            fh.write("# agent-authored surfaces quarantined at sandbox handoff\n")
            for relpath in manifest:
                fh.write(relpath + "\n")
        ledger.append("HANDOFF QUARANTINE: %d agent-authored surface(s) tagged "
                      "untrusted at sandbox exit" % len(manifest))
    else:
        ledger.append("HANDOFF QUARANTINE: none (agent-authored surfaces handed "
                      "to consumers verbatim)")

    allow = sum(1 for line in ledger if line.startswith("SANDBOX ALLOW:"))
    block = sum(1 for line in ledger if line.startswith("SANDBOX BLOCK:"))
    wrote = sum(1 for line in ledger if line.startswith("HANDOFF WROTE:"))
    for line in ledger:
        print(line)
    print("SUMMARY: sandbox_allow=%d sandbox_block=%d surfaces_written=%d "
          "confine=%s quarantine=%s" % (allow, block, wrote,
                                        str(CONFINE).lower(),
                                        str(QUARANTINE).lower()))
    return 0


# ---------------------------------------------------------------------------
# Phase 2 -- the unsandboxed consumers.
# ---------------------------------------------------------------------------
def _read(ws, relpath):
    path = os.path.join(ws, relpath)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _quarantined(ws, relpath):
    """True when the handoff tagged this surface untrusted (fixed twin only)."""
    text = _read(ws, QUARANTINE_MANIFEST)
    if not text:
        return False
    listed = {ln.strip() for ln in text.splitlines()
              if ln.strip() and not ln.startswith("#")}
    return relpath in listed


def _extract_directive(consumer, text):
    """Pull the planted command back out of an agent-authored surface."""
    if consumer == "claude-hooks":
        data = json.loads(text)
        groups = data["hooks"]["PostToolUse"]
        return groups[0]["hooks"][0]["command"]
    if consumer == "vscode-tasks":
        data = json.loads(text)
        return data["tasks"][0]["command"]
    if consumer == "git-config":
        m = re.search(r"external\s*=\s*(.+)", text)
        if not m:
            raise ValueError("no diff.external in git config")
        return m.group(1).strip()
    # venv / git-altdir: the surface is itself an executable script.
    return None


def trigger(workspace, consumer):
    """
    PHASE 2. Model the consumer that runs OUTSIDE the sandbox. There is no
    Sandbox object here at all: this process is unconfined, exactly as `git`,
    the venv, the editor, or the agent host would be when they run on the
    developer's machine after the sandbox has exited.
    """
    ws = os.path.realpath(workspace)
    relpath = dict((c, p) for c, p, _m in CONSUMERS).get(consumer)
    if relpath is None:
        print("CONSUMER ABSENT: %s (unknown consumer)" % consumer)
        return 0

    text = _read(ws, relpath)
    if text is None:
        print("CONSUMER ABSENT: %s (surface %s not present)" % (consumer, relpath))
        return 0

    # The handoff trust check. A consumer that honours the quarantine refuses to
    # execute a directive from an agent-authored, untrusted surface.
    if _quarantined(ws, relpath):
        print("CONSUMER REFUSE: %s :: surface %s quarantined at sandbox handoff "
              "(agent-authored, untrusted)" % (consumer, relpath))
        return 0

    # Trusted (flawed twin): read the directive and run it, unsandboxed.
    surface = os.path.join(ws, relpath)
    if consumer in ("venv", "git-altdir"):
        cmd = surface  # the surface is itself the executable the consumer runs
        display = "exec %s" % relpath
    else:
        try:
            cmd = _extract_directive(consumer, text)
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            print("CONSUMER REFUSE: %s :: could not parse surface (%s)"
                  % (consumer, exc))
            return 0
        display = cmd

    print("CONSUMER EXEC: %s :: %s" % (consumer, display))
    try:
        subprocess.run(cmd, shell=True, cwd=ws, timeout=10)
    except Exception as exc:  # noqa: BLE001 -- report, never crash the fixture
        print("CONSUMER ERROR: %s :: %s" % (consumer, exc))
    return 0


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0
    if argv[0] in ("version", "--version"):
        print("%s %s (%s)" % (APP, VERSION, VARIANT))
        return 0
    if argv[0] == "list-consumers":
        for consumer, _p, _m in CONSUMERS:
            print(consumer)
        return 0
    if argv[0] == "run-agent":
        if len(argv) < 2:
            sys.stderr.write("%s: run-agent needs a workspace path\n" % APP)
            return 2
        return run_agent(argv[1])
    if argv[0] == "trigger":
        if len(argv) < 3:
            sys.stderr.write("%s: trigger needs <workspace> <consumer>\n" % APP)
            return 2
        return trigger(argv[1], argv[2])

    sys.stderr.write("%s: unknown command %r\n\n" % (APP, argv[0]))
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

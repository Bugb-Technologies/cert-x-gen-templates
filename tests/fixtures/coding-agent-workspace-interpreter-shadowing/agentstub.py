#!/usr/bin/env python3
"""
agentstub -- a benign synthetic "coding agent" CLI that runs an interpreter in
the workspace it is pointed at.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-workspace-interpreter-shadowing.sh` can
be proved in all three directions: CONFIRMED against the defective twin, REFUTED
against the fixed one, and (via a separate no-interpreter stub in the prove
script) SKIPPED. It reproduces the *shape* of the interpreter search-path
shadowing class -- a coding agent that runs `python3 -c` from the workspace
directory, so any module the workspace planted next to the code is imported in
place of the standard library -- without reproducing any vendor's code or a real
payload. Nothing here is an exploit: the "attack" is three benign look-alikes
planted by the probe, each of which only writes a nonce and re-exports the real
module.

ONE SOURCE, TWO TWINS
---------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    agentstub_defective.py   VARIANT = "defective"
    agentstub_fixed.py       VARIANT = "fixed"

from this single file. The fixed twin must be the same program with the one-flag
mitigation switched on, or "refuted" would only mean "the two files differ".

WHAT THE AGENT DOES
-------------------
On `run` / `check` / `session` / `open`, the agent runs a small, entirely benign
Python self-check in its current working directory -- the workspace it was
launched in. The snippet is the agent's OWN good-faith code: it imports a few
standard-library modules (json, struct, shutil) and, like countless real
agent chores, touches zipfile, whose own stdlib source does `import struct`.
No code from the workspace is read as input; no instruction from the workspace
is followed. The only thing the workspace contributes is its presence on the
module search path.

THE ONLY DIFFERENCE
-------------------
    defective   runs `python3 -c <snippet>` with the workspace as cwd and
                nothing removed from the module search path. CPython prepends ''
                (the cwd) to sys.path for -c, so a workspace struct.py shadows
                the standard library. Opening the workspace is consent.

    fixed       runs the same snippet with PYTHONSAFEPATH=1 in the environment
                -- the one-flag mitigation -- which drops the cwd/script dir from
                sys.path. The workspace can no longer answer an import. Same
                program, same snippet, workspace off the module path.
"""
import os
import subprocess
import sys

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"

USAGE = """\
Usage: agentstub <command> [args]

A synthetic coding-agent CLI used as a security-test fixture.

Commands:
  run                Run the agent's workspace self-check (python -c)
  check              Alias for run
  session            Start an agent session in this workspace
  open               Open the workspace
  version            Print the version
  help               Print this message
"""

# The agent's own benign code. It imports stdlib modules and exercises zipfile,
# whose stdlib source itself does `import struct`. Every one of these imports is
# resolved through sys.path; whether the workspace is on that path is the whole
# question. The snippet is deliberately trivial and side-effect-free beyond a
# line of stdout.
SELF_CHECK = r"""
import json, struct, shutil, io, zipfile, sys
doc = json.dumps({"agentstub": "self-check", "ok": True})
packed = struct.pack(">I", 0x43584720)          # exercises struct
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:            # zipfile -> stdlib import struct
    zf.writestr("hello.txt", "hi")
have_py = bool(shutil.which("python3"))          # exercises shutil
print("agentstub: workspace self-check ok (json/struct/shutil/zipfile;"
      " python3=%s)" % have_py)
"""


def run_self_check():
    """Run the benign self-check in the current working directory."""
    env = dict(os.environ)
    argv = [sys.executable if False else "python3", "-c", SELF_CHECK]

    if VARIANT == "fixed":
        # The one-flag mitigation: drop cwd / script dir from the module search
        # path so the workspace cannot answer an import. Same program otherwise.
        env["PYTHONSAFEPATH"] = "1"
    # defective: nothing removed; cwd ('') stays early on sys.path.

    completed = subprocess.run(argv, env=env)      # cwd is inherited = workspace
    return completed.returncode


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0
    cmd = argv[0]
    if cmd == "version":
        print("agentstub %s (variant=%s)" % (VERSION, VARIANT))
        return 0
    if cmd in ("run", "check", "session", "open"):
        return run_self_check()
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

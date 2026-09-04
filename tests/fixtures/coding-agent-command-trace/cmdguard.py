#!/usr/bin/env python3
"""
cmdguard -- a benign synthetic "coding-agent command gateway" with a per-command
validator.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-command-trace-composition.sh` can be
proved in both directions: CONFIRMED against the flawed twin, REFUTED against
the fixed one. It reproduces the *shape* of the agent command-trace
composition-bypass class -- a validator that approves each command in
isolation, but whose approvals COMPOSE across a session into a dangerous action
it never sees -- without reproducing any vendor's code, machine state, or a real
exploit payload.

THE CLASS (motivation only -- named, not reproduced)
----------------------------------------------------
Real coding agents guard tool/command execution with a *validator* that decides,
per command, whether it is safe to run. Two shipping failure modes motivate this
fixture:

  * the Cursor 9.8 / Claude Code single-quote-strip validator bug -- the
    validator NORMALISES a command (stripping quotes) before matching an
    allowlist, so what it checks is not what runs; and
  * "Benign in Isolation, Harmful in Composition" (SCR-Bench, Xie et al. 2026)
    -- each step is individually harmless, and only the *composition across a
    session* is dangerous.

cmdguard is a minimal, obviously-benign synthetic that exhibits the *property*
those bugs share: a per-item validator cannot see a data-flow that only exists
once several individually-approved statements are composed.

ONE SOURCE, TWO TWINS
---------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    cmdguard_flawed.py   VARIANT = "flawed"   (validates each statement alone)
    cmdguard_fixed.py    VARIANT = "fixed"    (also re-validates the RESOLVED,
                                               composed command at the exec sink)

from this single file. Twins that could drift apart would be worth nothing as a
refutation test: the fixed twin has to be the same program with the stateful
check added, or "refuted" only means "the two files differ".

THE TRACE LANGUAGE
------------------
`cmdguard run-trace <file>` reads a newline-separated *trace* of statements and
evaluates them in order, threading a session symbol table across statements.
Each statement is passed through `validate()` and, if allowed, applied:

    set  NAME TOKEN     bind NAME to a literal string fragment
    join NAME A B       bind NAME to value(A) + " " + value(B)
    show NAME           print value(NAME)              (read-only, never executes)
    run  NAME           EXECUTE value(NAME) as a shell command

For every statement it prints one machine-readable ledger line to stdout:

    LEDGER ALLOW: <statement>
    LEDGER BLOCK: <statement> :: <reason>

plus `EXEC:` / `SHOW ...=...` effect lines and a final `SUMMARY: allow=N block=M`.
Exit is 0 when every statement was allowed, 1 when any was blocked, 2 on usage
error. (The driving template reads its verdict from the ledger and from an
observable filesystem effect, never from the exit code alone.)

THE VALIDATOR, AND THE ONLY DIFFERENCE
--------------------------------------
Both twins share `looks_runnable()` -- the heuristic for "this string, if
executed, is a command invocation with an argument (or shell metacharacters),
rather than a bare token". Both twins apply it at the one place a per-item
validator naturally applies it: when a statement's *own literal* is a command.

    set  -- BLOCK if the literal being bound is itself command-shaped. A lone
            token ("touch", "hello", "CXG-marker") is a string, not a command,
            and is allowed -- a validator that blocked every string assignment
            would break the tool.
    join -- string concatenation of two already-approved names. Benign in both
            twins: joining two approved strings is a string operation.
    show -- read-only; allowed in both twins.
    run  -- executes value(NAME).
              flawed: ALLOW as long as NAME is a declared name. It trusts that a
                      *named* action was vetted when it was declared -- but
                      declaration only vetted the fragments, never the
                      composition. It never re-inspects what NAME now resolves
                      to. This is exactly the per-item blind spot the class is
                      about.
              fixed:  before executing, RESOLVE value(NAME) and re-validate it
                      with the same `looks_runnable()` check -- the stateful
                      step. `touch CXG-marker`, assembled across `set`/`set`/
                      `join`, is command-shaped at the exec sink, so the fixed
                      twin BLOCKS it. No per-line scan could: the verb `touch`
                      (line 1) and its argument (line 2) only meet the exec sink
                      (line 4) through the session's def-use chain.

SAFETY
------
cmdguard executes whatever a `run` statement resolves to -- that capability is
the vulnerability being demonstrated -- but the driving template only ever
composes a benign decoy marker (`touch <nonce>` inside its own throwaway lab).
No CVE is reproduced, nothing is downloaded, no socket is opened, and nothing is
written outside the directory the template runs cmdguard in. The quote-strip
normalisation and the exec sink are present because they are what makes the
class real, not because this fixture needs them to do anything destructive.
"""
import os
import re
import subprocess
import sys

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "cmdguard"

USAGE = """\
Usage: cmdguard <command> [args]

A synthetic coding-agent command gateway used as a security-test fixture.

Commands:
  run-trace <file>   Evaluate a newline-separated command trace, validating
                     and applying each statement in session order.
  version            Print the version
  help               Print this message

Trace statements:
  set  NAME TOKEN    Bind NAME to a literal string fragment
  join NAME A B      Bind NAME to value(A) + " " + value(B)
  show NAME          Print value(NAME)              (never executes)
  run  NAME          Execute value(NAME) as a shell command
"""

# Shell metacharacters that make a string more than a bare token.
_METACHARS = set(";|&$`()<>{}*?!\n")


def normalize(token):
    """
    Strip one layer of matching surrounding quotes.

    This is the quote-stripping "normalisation" step the Cursor/Claude-Code
    class is built on: the validator checks the *normalised* string, so a value
    that arrives quoted is judged as if the quotes were never there.
    """
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    return token


def looks_runnable(value):
    """
    True when `value`, taken as a command to execute, is an invocation with an
    argument or carries shell metacharacters -- as opposed to a single bare
    token whose execution is inert.

    A bare token ("touch", "hello") is not runnable-with-effect on its own; a
    verb followed by an argument ("touch CXG-marker") is. This is the property
    the validator must judge at the moment of execution -- which, for a composed
    value, is the only moment the whole command exists.
    """
    value = value.strip()
    if any(c in _METACHARS for c in value):
        return True
    # Two or more whitespace-separated tokens: a verb plus at least one argument.
    return bool(re.search(r"\S\s+\S", value))


class Blocked(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def evaluate(statements):
    """
    Run the trace. Returns (allow_count, block_count). Prints the ledger.

    The session symbol table `env` is what makes this stateful: the value a
    `run` executes was assembled by earlier `set`/`join` statements, and no
    statement can be judged in isolation without it.
    """
    env = {}
    allow = 0
    block = 0

    for raw in statements:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        verb = parts[0]
        rest = parts[1] if len(parts) > 1 else ""

        try:
            if verb == "set":
                nm = rest.split(None, 1)
                if len(nm) < 2:
                    raise Blocked("set needs NAME and TOKEN")
                name, token = nm[0], normalize(nm[1])
                if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                    raise Blocked("illegal name %r" % name)
                # A per-item defence both twins have: reject a literal that is
                # itself a command. A lone token is a string and is allowed.
                if looks_runnable(token):
                    raise Blocked("literal is command-shaped: %r" % token)
                env[name] = token

            elif verb == "join":
                p = rest.split()
                if len(p) != 3:
                    raise Blocked("join needs NAME A B")
                name, a, b = p
                if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                    raise Blocked("illegal name %r" % name)
                if a not in env or b not in env:
                    raise Blocked("join of undeclared name(s)")
                # Concatenating two already-approved strings. A string
                # operation -- benign in both twins.
                env[name] = env[a] + " " + env[b]

            elif verb == "show":
                name = rest.strip()
                if name not in env:
                    raise Blocked("show of undeclared name %r" % name)
                print("SHOW %s=%s" % (name, env[name]))

            elif verb == "run":
                name = rest.strip()
                if name not in env:
                    raise Blocked("run of undeclared name %r" % name)
                resolved = env[name]
                if VARIANT == "fixed":
                    # THE STATEFUL CHECK. Re-validate the RESOLVED command at the
                    # execution sink, using the composed session state. This is
                    # the whole difference between the twins.
                    if looks_runnable(resolved):
                        raise Blocked(
                            "resolved command is command-shaped: %r" % resolved)
                # flawed: NAME is declared, so run it -- no look at `resolved`.
                print("EXEC: %s" % resolved)
                subprocess.run(resolved, shell=True, timeout=5)

            else:
                raise Blocked("unknown statement %r" % verb)

        except Blocked as exc:
            print("LEDGER BLOCK: %s :: %s" % (line, exc.reason))
            block += 1
            continue

        print("LEDGER ALLOW: %s" % line)
        allow += 1

    print("SUMMARY: allow=%d block=%d" % (allow, block))
    return allow, block


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0
    if argv[0] in ("version", "--version"):
        print("cmdguard %s (%s)" % (VERSION, VARIANT))
        return 0
    if argv[0] == "run-trace":
        if len(argv) < 2:
            sys.stderr.write("cmdguard: run-trace needs a trace file\n")
            return 2
        path = argv[1]
        try:
            with open(path, "r", encoding="utf-8") as fh:
                statements = fh.read().splitlines()
        except OSError as exc:
            sys.stderr.write("cmdguard: cannot read %s (%s)\n" % (path, exc))
            return 2
        _, block = evaluate(statements)
        return 1 if block else 0

    sys.stderr.write("cmdguard: unknown command %r\n\n" % argv[0])
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

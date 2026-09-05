#!/usr/bin/env python3
"""
agent-host -- a benign synthetic "coding agent host" that ships a DENY SURFACE:
an operator writes a deny rule naming a file, in the host's strongest scope, and
from that moment reasons about that file as unreadable by the agent.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-deny-rule-reachability.sh` can be proved
in every direction it emits. It reproduces the *shape* of the class -- a deny
rule enforced at the wrong layer -- without reproducing any vendor's code,
machine state, or a real exploit payload. Every path it touches is one the
driving template created inside its own disposable lab and handed over in an
environment variable.

THE CLASS (named, not reproduced)
---------------------------------
Coding agents grew a deny surface: `permissions.deny`, managed/enterprise
settings, a sandbox `denyRead` list, a hook `if` condition. An operator writes
`Read(/etc/secrets/token)` and treats the file as gone.

The bug is *where the rule is enforced*. If the host matches the rule against
the rendered command string -- "does this command look like a read of that
path?" -- then the rule covers exactly the syntactic forms the matcher has been
taught, and nothing else. The set of forms that reach a file is not enumerable:
a redirect, a reader that takes options before its operand, an option VALUE
(`--ignore-revs-file=F`, `-fF`, `@F`), a tool operand, a `cd` compound with a
relative name, a symlink alias, a symlinked search path, a shell assignment
carrying a command substitution. Several of those contain the denied path as a
LITERAL and still slip past, because the matcher is anchored on a shape rather
than on the file.

One vendor shipped five patches to this class in two weeks and reverted one of
them. That is what an un-enumerable channel set looks like from the inside, and
it is the reason the check has to be behavioural: you cannot grep a matcher for
the form nobody thought of.

The second half is a check/use split. A path is validated and then RE-OPENED by
name to be read. Anything that can replace the name's target between those two
moments -- a symlink swapped in -- is read instead of the thing that was
checked. The fix is to open once and validate the open descriptor.

ONE SOURCE, NINE TWINS
----------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    agent-host_flawed.py    all three flaws on: the rule is matched against the
                            command string, the check/use split re-opens by
                            name, and a rule with trailing text is accepted and
                            silently never matches.
    agent-host_fixed.py     the same host, enforced correctly: every read
                            funnels through one file-open chokepoint that
                            compares the OPEN descriptor's identity against the
                            denied files, and the checked descriptor is the one
                            that is read.
    agent-host_syntaxonly.py    only the command-string matcher flaw.
    agent-host_toctouonly.py    only the check/use split.
    agent-host_inertrule.py     only the trailing-text rule that is accepted
                                and then never matches.
    agent-host_deadrule.py      rules are accepted and reported as parsed, and
                                the enforcement never consults them. Even the
                                literal direct read succeeds -- so nothing about
                                channel equivalence or the check/use split is
                                proved by this host, and the driving template
                                must say so rather than claim three findings.
    agent-host_nodeny.py        ships no deny surface at all -- there is no rule
                                here that could fail to hold.
    agent-host_rejects.py       refuses the rule, so the operator never got the
                                control they asked for.
    agent-host_deadchannels.py  cannot execute tool channels in this
                                environment, so no arm produces anything --
                                including the positive control. "Blocked" and
                                "broken" must not be confused.

from this single file. Twins that could drift apart would be worth nothing: the
enforcing twin has to be the same program with the switches flipped, or REFUTED
only means "two files differ".

THE INTERFACE
-------------
    agent-host capabilities
        DENY SURFACE SUPPORTED / DENY SCOPES / STRONGEST DENY SCOPE /
        RULE SYNTAX / CHANNELS

    agent-host rule-clear
    agent-host rule-add --scope <scope> '<rule>'
        RULE ACCEPTED: ... | RULE REJECTED: ...

    agent-host rules
    agent-host run-channel <workspace> <channel> --target deny|control
        Render the channel's command, apply this host's enforcement, execute the
        plan through the host's file layer, print a ledger and, when the read
        happened, the bytes.

    agent-host version | help

WHAT THE HOST IS HANDED (all of it created by the driving template)
-------------------------------------------------------------------
    CXG_DENY_TARGET      the canary the rule names.
    CXG_CONTROL_TARGET   a second file the rule does NOT name -- the positive
                         control, so a channel that produces nothing can be told
                         apart from a channel that was blocked.
    CXG_ALIAS_DENY / CXG_ALIAS_CONTROL   symlinks to those two.
    CXG_LINK_DIR         a symlink to the directory holding both.
    CXG_TOCTOU_PATH      a real, benign file the check/use arm validates.
    CXG_TOCTOU_READY     a rendezvous file. The check/use arm waits for it
                         between check and use, so the race is observed
                         deterministically instead of flakily. The window is
                         widened; the split it exposes is the real one.

There is no code path here that opens a file the driving template did not name.
"""
import hashlib
import json
import os
import re
import sys
import time

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "agent-host"

# ---------------------------------------------------------------------------
# Five independent switches derived from the one variant token, so that every
# verdict branch of the driving template has a twin that produces it.
# ---------------------------------------------------------------------------
HAS_DENY_SURFACE = VARIANT != "nodeny"
ACCEPTS_RULES = VARIANT != "rejects"
CHANNELS_WORK = VARIANT != "deadchannels"
# The flaw: enforcement reads the rendered command string instead of the file.
MATCH_COMMAND_STRING = VARIANT in ("flawed", "syntaxonly")
# The flaw: the validated path is re-opened by name to be read.
TOCTOU_REOPEN = VARIANT in ("flawed", "toctouonly")
# The flaw: a rule carrying anything after the closing paren is accepted and
# then stored without a path, so it matches nothing.
TRAILING_TEXT_INERT = VARIANT in ("flawed", "inertrule")
# The flaw: rules are accepted, reported as parsed, and never consulted.
DENY_ENFORCED = VARIANT != "deadrule"

SCOPES = ("managed", "user", "project")
STRONGEST_SCOPE = "managed"
CHANNELS = ("direct", "redirect", "reader", "optvalue", "shortopt", "atfile",
            "operand", "compound", "symlink", "searchpath", "assign", "toctou")
POLICY_REL = os.path.join(".agent-host", "policy.json")

# How long the check/use arm will wait for the rendezvous before giving up.
TOCTOU_WINDOW_SECS = float(os.environ.get("CXG_HOST_TOCTOU_WINDOW", "20"))

# The command-string matcher, in the state five patches leave it in: it knows a
# bare operand of a known reader, and it knows a redirect. Every other way of
# naming a file is a form it was never taught.
READERS = "cat|head|less|more|sed"


class Denied(Exception):
    pass


class Unreadable(Exception):
    pass


# ---------------------------------------------------------------------------
# The policy store. It lives under HOME, which the driving template redirects
# into its own lab, so no real settings file is read or written.
# ---------------------------------------------------------------------------
def policy_path():
    return os.path.join(os.path.expanduser("~"), POLICY_REL)


def load_policy():
    try:
        with open(policy_path()) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"rules": []}


def save_policy(policy):
    path = policy_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(policy, fh, indent=2)


RULE_RE = re.compile(r"^\s*Read\(\s*(?P<path>[^)]+?)\s*\)\s*(?P<trail>.*?)\s*$")


def parse_rule(raw):
    """`Read(<path>)`, optionally followed by trailing text. Returns
    (path, trailing) or (None, None) when the spelling is not a rule at all."""
    match = RULE_RE.match(raw)
    if not match:
        return None, None
    return match.group("path"), match.group("trail")


def rule_add(argv):
    scope = STRONGEST_SCOPE
    raw = None
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--scope" and index + 1 < len(argv):
            scope = argv[index + 1]
            index += 2
            continue
        if item.startswith("--scope="):
            scope = item.split("=", 1)[1]
            index += 1
            continue
        if raw is None:
            raw = item
        index += 1

    if not HAS_DENY_SURFACE:
        print("RULE REJECTED: this host ships no deny surface")
        return 0
    if raw is None:
        print("RULE REJECTED: no rule text supplied")
        return 0
    if not ACCEPTS_RULES:
        print("RULE REJECTED: this host does not accept externally supplied "
              "deny rules in scope %s" % scope)
        return 0
    if scope not in SCOPES:
        print("RULE REJECTED: unknown scope %s" % scope)
        return 0

    path, trail = parse_rule(raw)
    if path is None:
        print("RULE REJECTED: not a rule this host understands: %s" % raw)
        return 0

    stored = path
    parsed = "yes"
    if trail and TRAILING_TEXT_INERT:
        # Accepted, acknowledged, and then stored with no path at all. The
        # operator is told the rule is in force; it matches nothing.
        stored = None
        parsed = "no"

    policy = load_policy()
    policy.setdefault("rules", []).append(
        {"raw": raw, "scope": scope, "path": stored})
    save_policy(policy)
    print("RULE ACCEPTED: scope=%s raw=%s parsed=%s path=%s"
          % (scope, raw, parsed, stored if stored else "none"))
    return 0


def rule_clear():
    save_policy({"rules": []})
    print("RULES CLEARED")
    return 0


def active_rules():
    return load_policy().get("rules", [])


def denied_paths():
    return [rule["path"] for rule in active_rules() if rule.get("path")]


def denied_realpaths():
    return set(os.path.realpath(p) for p in denied_paths())


def denied_identities():
    """(st_dev, st_ino) of every denied file. Identity, not spelling: this is
    what an enforcement point that cannot be renamed around compares."""
    out = set()
    for path in denied_paths():
        try:
            st = os.stat(path)
        except OSError:
            continue
        out.add((st.st_dev, st.st_ino))
    return out


def rule_fingerprint():
    rules = active_rules()
    blob = "|".join("%s::%s" % (r.get("scope"), r.get("raw")) for r in rules)
    return "scope=%s rules=%d sha=%s" % (
        rules[0].get("scope") if rules else "none", len(rules),
        hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16])


# ---------------------------------------------------------------------------
# The file layer. EVERY read in this host goes through host_open. In the
# enforcing twins the deny check lives here and nowhere else, which is the whole
# point: one chokepoint that no spelling can route around.
# ---------------------------------------------------------------------------
def host_open(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise Unreadable("cannot open %s: %s" % (path, exc.strerror))
    if DENY_ENFORCED and not MATCH_COMMAND_STRING:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) in denied_identities():
            os.close(fd)
            raise Denied("deny rule covers the file this open resolved to")
    with os.fdopen(fd, "r", errors="replace") as fh:
        return fh.read()


def command_string_denied(command):
    """The flawed enforcement point: does the rendered command LOOK LIKE a read
    of a denied path? Two shapes are recognised, which is two more than the
    matcher started with and still not all of them."""
    for path in denied_paths():
        literal = re.escape(path)
        if re.match(r"^\s*(?:%s)\s+%s\s*$" % (READERS, literal), command):
            return path
        if re.match(r"^\s*(?:%s)\s*<\s*%s\s*$" % (READERS, literal), command):
            return path
    return None


# ---------------------------------------------------------------------------
# The channels. Each renders a command string (what the matcher sees) and a
# plan (what actually gets opened). Both come from one spec, so the fixture
# cannot cheat by showing the matcher a command it does not run.
# ---------------------------------------------------------------------------
def channel_spec(channel, target, alias, link_dir, toctou_path):
    directory, base = os.path.split(target)
    if channel == "direct":
        return "cat %s" % target, [target]
    if channel == "redirect":
        return "cat < %s" % target, [target]
    if channel == "reader":
        return "head -c 4096 %s" % target, [target]
    if channel == "optvalue":
        return "blamer --ignore-revs-file=%s" % target, [target]
    if channel == "shortopt":
        return "blamer -f%s" % target, [target]
    if channel == "atfile":
        return "blamer @%s" % target, [target]
    if channel == "operand":
        return "grep -h CXG %s" % target, [target]
    if channel == "compound":
        return "cd %s && cat %s" % (directory, base), [os.path.join(directory, base)]
    if channel == "symlink":
        return "cat %s" % alias, [alias]
    if channel == "searchpath":
        return ("cat %s" % os.path.join(link_dir, base),
                [os.path.join(link_dir, base)])
    if channel == "assign":
        return ("V=$(cat %s); printf '%%s\\n' \"$V\"" % target, [target])
    if channel == "toctou":
        return "cat %s" % toctou_path, [toctou_path]
    return None, []


def wait_for_rendezvous(emit):
    ready = os.environ.get("CXG_TOCTOU_READY", "")
    deadline = time.time() + TOCTOU_WINDOW_SECS
    emit("TOCTOU CHECK: passed")
    sys.stdout.flush()
    while time.time() < deadline:
        if ready and os.path.exists(ready):
            emit("TOCTOU WINDOW: closed by rendezvous")
            return
        time.sleep(0.02)
    emit("TOCTOU WINDOW: closed by timeout")


def run_toctou(path, emit):
    """Validate, then read. The only question is whether the thing that was
    validated is the thing that is read."""
    if TOCTOU_REOPEN:
        # Validate the NAME. The descriptor that is eventually read is opened
        # afterwards, from the same name -- which by then may point elsewhere.
        resolved = os.path.realpath(path)
        emit("TOCTOU VALIDATE: name=%s resolved=%s" % (path, resolved))
        if DENY_ENFORCED and not MATCH_COMMAND_STRING \
                and resolved in denied_realpaths():
            emit("TOCTOU CHECK: blocked")
            raise Denied("deny rule covers %s" % resolved)
        wait_for_rendezvous(emit)
        emit("TOCTOU USE: re-opening by name")
        return read_after_validation(path)
    # Validate the DESCRIPTOR, and read that same descriptor. Nothing that
    # happens to the name in between can change what is read.
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise Unreadable("cannot open %s: %s" % (path, exc.strerror))
    st = os.fstat(fd)
    emit("TOCTOU VALIDATE: descriptor dev=%d ino=%d" % (st.st_dev, st.st_ino))
    if DENY_ENFORCED and not MATCH_COMMAND_STRING \
            and (st.st_dev, st.st_ino) in denied_identities():
        os.close(fd)
        emit("TOCTOU CHECK: blocked")
        raise Denied("deny rule covers the validated descriptor")
    wait_for_rendezvous(emit)
    emit("TOCTOU USE: reading the validated descriptor")
    with os.fdopen(fd, "r", errors="replace") as fh:
        return fh.read()


def read_after_validation(path):
    """The `use` half of the check/use split, exactly as it is written in real
    code: the name was validated a moment ago, so the read trusts that verdict
    and does not re-derive it. Whatever the name resolves to NOW is what comes
    back."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        raise Unreadable("cannot open %s: %s" % (path, exc.strerror))


# ---------------------------------------------------------------------------
# run-channel
# ---------------------------------------------------------------------------
def run_channel(argv):
    workspace = None
    channel = None
    target_kind = "deny"
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--target" and index + 1 < len(argv):
            target_kind = argv[index + 1]
            index += 2
            continue
        if item.startswith("--target="):
            target_kind = item.split("=", 1)[1]
            index += 1
            continue
        if item in CHANNELS and channel is None:
            channel = item
        elif workspace is None:
            workspace = item
        index += 1

    if workspace is None or channel is None:
        print("usage: %s run-channel <workspace> <%s> [--target deny|control]"
              % (APP, "|".join(CHANNELS)), file=sys.stderr)
        return 2

    os.makedirs(workspace, exist_ok=True)
    artifacts = os.path.join(workspace, "artifacts")
    os.makedirs(artifacts, exist_ok=True)

    lines = []

    def emit(line):
        lines.append(line)
        print(line)

    emit("HOST: %s %s (synthetic fixture, variant=%s)" % (APP, VERSION, VARIANT))
    emit("DENY SURFACE SUPPORTED: %s" % ("yes" if HAS_DENY_SURFACE else "no"))
    emit("CHANNEL: %s" % channel)
    emit("TARGET KIND: %s" % target_kind)
    emit("RULE FINGERPRINT: %s" % rule_fingerprint())
    emit("ACTIVE RULES: %d" % len(active_rules()))

    if target_kind == "control":
        target = os.environ.get("CXG_CONTROL_TARGET", "")
        alias = os.environ.get("CXG_ALIAS_CONTROL", "")
    else:
        target = os.environ.get("CXG_DENY_TARGET", "")
        alias = os.environ.get("CXG_ALIAS_DENY", "")
    link_dir = os.environ.get("CXG_LINK_DIR", "")
    toctou_path = os.environ.get("CXG_TOCTOU_PATH", "")

    if not target:
        emit("READ: unavailable detail=no-target-path (nothing was handed to "
             "this host to read)")
        emit("SUMMARY: channel=%s target=%s read=not-performed"
             % (channel, target_kind))
        return 0

    command, operands = channel_spec(channel, target, alias, link_dir,
                                     toctou_path)
    if command is None:
        emit("READ: unavailable detail=unknown-channel")
        emit("SUMMARY: channel=%s target=%s read=not-performed"
             % (channel, target_kind))
        return 0
    emit("COMMAND: %s" % command)

    if not CHANNELS_WORK:
        emit("READ: unavailable detail=this host cannot execute tool channels "
             "in this environment")
        emit("SUMMARY: channel=%s target=%s read=not-performed"
             % (channel, target_kind))
        return 0

    # The flawed enforcement point sits HERE, before the plan is executed, and
    # sees only the rendered string.
    if DENY_ENFORCED and MATCH_COMMAND_STRING:
        hit = command_string_denied(command)
        if hit:
            emit("DENY DECISION: blocked by command-string match on %s" % hit)
            emit("SUMMARY: channel=%s target=%s read=blocked"
                 % (channel, target_kind))
            return 0
        emit("DENY DECISION: command does not match any deny rule")
    elif DENY_ENFORCED:
        emit("DENY DECISION: deferred to the file layer")
    else:
        emit("DENY DECISION: rules recorded, not consulted")

    try:
        if channel == "toctou":
            content = run_toctou(operands[0], emit)
        else:
            content = "".join(host_open(path) for path in operands)
    except Denied as exc:
        emit("DENY DECISION: blocked at the file layer (%s)" % exc)
        emit("SUMMARY: channel=%s target=%s read=blocked"
             % (channel, target_kind))
        return 0
    except Unreadable as exc:
        emit("READ: unavailable detail=%s" % exc)
        emit("SUMMARY: channel=%s target=%s read=not-performed"
             % (channel, target_kind))
        return 0

    artifact = os.path.join(artifacts, "%s-%s.txt" % (channel, target_kind))
    with open(artifact, "w") as fh:
        fh.write(content)
    emit("READ OUTPUT: %s" % content.strip())
    emit("ARTIFACT: %s" % artifact)
    emit("SUMMARY: channel=%s target=%s read=performed" % (channel, target_kind))
    return 0


def rules_cmd():
    for rule in active_rules():
        print("RULE: scope=%s raw=%s path=%s"
              % (rule.get("scope"), rule.get("raw"), rule.get("path") or "none"))
    print("ACTIVE RULES: %d" % len(active_rules()))
    print("RULE FINGERPRINT: %s" % rule_fingerprint())
    return 0


def capabilities():
    print("HOST: %s %s (synthetic fixture, variant=%s)" % (APP, VERSION, VARIANT))
    print("DENY SURFACE SUPPORTED: %s" % ("yes" if HAS_DENY_SURFACE else "no"))
    print("DENY SCOPES: %s" % (" ".join(SCOPES) if HAS_DENY_SURFACE else "none"))
    print("STRONGEST DENY SCOPE: %s"
          % (STRONGEST_SCOPE if HAS_DENY_SURFACE else "none"))
    print("RULE SYNTAX: Read(<absolute-path>)")
    print("CHANNELS: %s" % " ".join(CHANNELS))
    return 0


USAGE = """%s %s (synthetic fixture)

  %s capabilities                       print the deny surface
  %s rule-add --scope <scope> '<rule>'  install a deny rule
  %s rule-clear                         drop every installed rule
  %s rules                              list the installed rules
  %s run-channel <workspace> <channel> [--target deny|control]
  %s version | help

channels: %s
""" % (APP, VERSION, APP, APP, APP, APP, APP, APP, " ".join(CHANNELS))


def main(argv):
    if not argv:
        print(USAGE)
        return 0
    command, rest = argv[0], argv[1:]
    if command in ("capabilities", "caps", "--capabilities"):
        return capabilities()
    if command == "rule-add":
        return rule_add(rest)
    if command == "rule-clear":
        return rule_clear()
    if command == "rules":
        return rules_cmd()
    if command == "run-channel":
        return run_channel(rest)
    if command in ("version", "--version"):
        print("%s %s" % (APP, VERSION))
        return 0
    if command in ("help", "--help", "-h"):
        print(USAGE)
        return 0
    print("unknown command: %s" % command, file=sys.stderr)
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

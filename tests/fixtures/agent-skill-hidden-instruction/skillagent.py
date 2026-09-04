#!/usr/bin/env python3
"""
skillagent -- a benign synthetic "agent that loads skills from a directory".

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/agent-skill-hidden-instruction-trust.py` can be
proved in every direction it can emit: CONFIRMED against the flawed twin,
REFUTED against the fixed one, SKIP against a twin with no skill surface at
all. It reproduces the *shape* of the agent-extension hidden-instruction class
without reproducing any marketplace skill, any vendor's agent, or a real
payload.

THE CLASS (motivation only -- named, not reproduced)
----------------------------------------------------
Agent extensions -- Claude Code skills, Copilot/Cursor rule files, MCP server
instruction blobs -- are distributed as Markdown. A human reviews the *rendered*
document and approves it; the agent is handed the *source*. Those are not the
same document. Markdown has whole categories of content that render to nothing
or render collapsed:

  * Unicode TAG-block characters (U+E0000-U+E007F), which mirror ASCII
    one-for-one and paint zero pixels;
  * HTML comments, which every Markdown renderer drops; and
  * a collapsed `<details>` block, whose body is present in the DOM and absent
    from the page until someone clicks it.

Public work on this class (Snyk's "ToxicSkills" survey, Orca's and Reversec's
skill-registry audits) reads the Markdown and reports what it *finds*. The
property that actually matters is downstream of that: whether the agent, having
loaded such a skill, will ACT on the part the reviewer could not see -- with no
consent step between "loaded" and "executed". skillagent is the minimal
synthetic that either has that boundary or does not.

ONE SOURCE, THREE TWINS
-----------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    skillagent_flawed.py    VARIANT = "flawed"    honours the MODEL view
    skillagent_fixed.py     VARIANT = "fixed"     honours the APPROVAL view only
    skillagent_noskills.py  VARIANT = "noskills"  has no skills surface at all

from this single file. The switches are independent, not one flawed/fixed axis:
`SANITISE` decides which view of a skill is authoritative, and `SKILLS_ENABLED`
decides whether there is a skill-loading surface to speak of. That is what lets
one source reach all three of the driving template's verdicts.

THE TWO VIEWS, AND THE ONLY DIFFERENCE THAT MATTERS
---------------------------------------------------
    model_view(raw)     what a language model reads: TAG-block characters
                        decoded back to the ASCII they mirror, HTML comments
                        and collapsed <details> bodies intact. Nothing is
                        dropped, because nothing is dropped for a tokenizer.
    approval_view(raw)  what a human reviewing the rendered Markdown sees:
                        invisible formatting characters removed, HTML comments
                        removed, collapsed <details> bodies removed.

    flawed:   extracts directives from model_view() and runs them. Every
              directive in the file executes; the reviewer saw a subset.
    fixed:    extracts directives from approval_view(), PRINTS each one it is
              about to run (the consent boundary), and runs only those. A
              directive that exists only in the source never executes.
    noskills: ignores --skills-dir entirely; there is no skill surface here.

THE DIRECTIVE LANGUAGE
----------------------
A line of the form `RUN: <command>` inside a SKILL.md is an action the skill
asks the agent to take. `shlex.split` parses it and it is executed WITHOUT a
shell. This is the synthetic stand-in for a skill instructing an agent to use
its tools; the driving template only ever asks for `touch <nonce>` inside its
own throwaway lab, plus one loopback GET at a canary the template itself is
listening on.

SAFETY
------
skillagent executes what a skill tells it to -- that capability is the property
being demonstrated -- but every command the driving template composes is a
decoy: an empty sentinel file in a `mktemp -d` lab, and an HTTP GET to
127.0.0.1 on a port the template opened. No CVE is reproduced, no marketplace
skill is installed, no real agent is driven, and nothing leaves the loopback
interface.

    skillagent run --skills-dir <dir> --task "<a task>"
"""
import os
import re
import shlex
import subprocess
import sys

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "skillagent"

# The two independent switches. `build.sh` sets VARIANT; everything else here
# is derived, so the three twins cannot drift into being three programs.
SANITISE = (VARIANT == "fixed")          # approval view is authoritative
SKILLS_ENABLED = (VARIANT != "noskills")  # a skill-loading surface exists

DIRECTIVE = re.compile(r"^[ \t>*-]*RUN:[ \t]*(.+?)[ \t]*$", re.MULTILINE)
FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
COLLAPSED_DETAILS = re.compile(r"<details\b[^>]*>.*?</details>", re.DOTALL | re.IGNORECASE)
SUMMARY = re.compile(r"<summary\b[^>]*>(.*?)</summary>", re.DOTALL | re.IGNORECASE)

# Characters a renderer paints as nothing. The TAG block is handled separately
# because it is not merely invisible -- it decodes.
INVISIBLE = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,
             0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
TAG_LO, TAG_HI = 0xE0000, 0xE007F
TAG_ASCII_LO, TAG_ASCII_HI = 0xE0020, 0xE007E

USAGE = """\
Usage: skillagent <command> [options]

A synthetic skill-loading agent used as a security-test fixture.

Commands:
  run [--skills-dir DIR] [--task TEXT]   Load skills, then carry out TEXT
  version                                Print the version
  help                                   Print this message

Environment:
  AGENT_SKILLS_DIR   Skills directory, when --skills-dir is not given
"""


def decode_tags(text):
    """TAG-block characters mirror ASCII: U+E0041 is 'A'.

    A model reads them as the letters they mirror. Decoding here is what makes
    the flawed twin's `model_view` honest about what a model would see.
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if TAG_ASCII_LO <= cp <= TAG_ASCII_HI:
            out.append(chr(cp - 0xE0000))
        elif TAG_LO <= cp <= TAG_HI:
            pass                      # tag terminators and language tags: no glyph
        else:
            out.append(ch)
    return "".join(out)


def model_view(raw):
    """Everything the tokenizer sees, with the TAG block spelled out."""
    return decode_tags(raw)


def approval_view(raw):
    """What a human approving the rendered Markdown actually reads."""
    text = "".join(ch for ch in raw
                   if not (ord(ch) in INVISIBLE or TAG_LO <= ord(ch) <= TAG_HI))
    text = HTML_COMMENT.sub(" ", text)
    # A collapsed <details> renders as its summary line and nothing else until
    # someone clicks it; the body is in the DOM but not on the page.
    text = COLLAPSED_DETAILS.sub(
        lambda m: " ".join(SUMMARY.findall(m.group(0))), text)
    return text


def declared(raw, key, default="unset"):
    """Read one key out of the YAML-ish frontmatter, without a YAML parser."""
    block = FRONTMATTER.search(raw)
    if not block:
        return default
    for line in block.group(1).splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip() == key:
            return value.strip() or default
    return default


def load_skills(skills_dir):
    """(name, raw-text) for every <dir>/<skill>/SKILL.md, in a stable order."""
    skills = []
    try:
        entries = sorted(os.listdir(skills_dir))
    except OSError as exc:
        print("SKILLS ERROR: %s" % exc)
        return skills
    for entry in entries:
        manifest = os.path.join(skills_dir, entry, "SKILL.md")
        if os.path.isfile(manifest):
            with open(manifest, encoding="utf-8") as handle:
                skills.append((entry, handle.read()))
    return skills


def run(argv):
    skills_dir = os.environ.get("AGENT_SKILLS_DIR", "")
    task = ""
    rest = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("--skills-dir", "--skills"):
            if not SKILLS_ENABLED:
                # This twin has no skill surface: the flag is not part of its
                # interface, and it says so rather than silently ignoring it.
                print("%s: unknown option %s" % (APP, arg), file=sys.stderr)
                return 2
            skills_dir = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
            continue
        if arg == "--task":
            task = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
            continue
        if arg.startswith("--"):
            print("%s: unknown option %s" % (APP, arg), file=sys.stderr)
            return 2
        rest.append(arg)
        i += 1
    if not task and rest:
        task = " ".join(rest)

    print("AGENT %s %s variant=%s" % (APP, VERSION, VARIANT))

    executed = 0
    found = 0
    if SKILLS_ENABLED and skills_dir:
        for name, raw in load_skills(skills_dir):
            print("SKILL LOADED: %s (network=%s, source-bytes=%d)"
                  % (name, declared(raw, "network"), len(raw.encode("utf-8"))))
            view = approval_view(raw) if SANITISE else model_view(raw)
            directives = DIRECTIVE.findall(view)
            found += len(directives)
            for command in directives:
                if SANITISE:
                    # The consent boundary: everything about to run came out of
                    # the same view the reviewer read, and is named here first.
                    print("APPROVAL: %s will run: %s" % (name, command))
                executed += run_directive(name, command)
    elif SKILLS_ENABLED:
        print("SKILLS: none (no skills directory given)")
    else:
        print("SKILLS: unsupported by this build")

    print("TASK-DONE: %s" % (task or "<no task>"))
    print("SUMMARY: directives=%d executed=%d" % (found, executed))
    return 0


def run_directive(skill, command):
    """Execute one `RUN:` directive. No shell: the argv is what was written."""
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        print("EXEC SKIP: %s (unparseable directive: %s)" % (skill, exc))
        return 0
    if not argv:
        return 0
    try:
        proc = subprocess.run(argv, timeout=10,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rc = proc.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        print("EXEC FAIL: %s %s (%s)" % (skill, argv[0], exc))
        return 0
    # The command's own arguments are not echoed: a real agent collapses tool
    # output, and echoing them would hand the driving template its own nonce
    # back through a channel that proves nothing about execution.
    print("EXEC: %s %s (%d arg(s)) rc=%d" % (skill, argv[0], len(argv) - 1, rc))
    return 1


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("help", "-h", "--help"):
        print(USAGE)
        return 0
    if argv[0] in ("version", "--version"):
        print("%s %s (variant=%s)" % (APP, VERSION, VARIANT))
        return 0
    if argv[0] in ("run", "task", "agent"):
        return run(argv[1:])
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

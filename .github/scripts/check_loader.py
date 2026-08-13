#!/usr/bin/env python3
"""
Gate on what the ENGINE does with templates/, not on what a validator says.

`cxg template validate` and the engine's loader disagree about which templates
are valid, and the loader is the side that decides what actually runs at scan
time. A template the loader rejects is dead weight: the engine WARNs once and
carries on, so nothing about a scan's exit code or its results reveals that the
file never ran. That silence is what let four non-loading templates and five
collided ids sit in this repo unnoticed.

This script reads the log of

    cxg --disable-update-check -vv template list

and fails on the three signals that mean a template in this repo will not run:

  1. Any WARN line. The loader emits exactly one per template it could not
     parse, then continues.
  2. The count loaded from this repo's templates/ not matching the number of
     template files on disk. Belt to the WARN braces: it catches a file the
     loader skipped without warning at all.
  3. A "Deduplicated templates" line. Two templates claiming one @id: the
     engine keeps whichever the directory walk reached first and drops the
     rest, so a collided template never executes no matter how valid it is.

It also asserts that every OTHER template directory the loader consulted
contributed zero templates. cxg will download the published template set into
$HOME and merge it with this repo's tree; if that ever happens despite
--disable-update-check, counts 2 and 3 above would be measuring the wrong tree.

The file count comes from generate-index.py's own discover(), so CI and the
registry generator can never disagree about which files are templates.

Usage: check_loader.py <loader-log>   Exit 0 = clean, 1 = a template is dead.
"""
import importlib.util
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = REPO_ROOT / "templates"

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# A tracing line, e.g. "2026-08-13T09:51:57.042828Z  INFO ThreadId(01) mod: msg".
# Anchored so the 1600-odd lines of template table cxg also prints cannot be
# mistaken for loader output.
TRACING = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\S+Z\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s+.*?:\s+(.*)$")
LOADED = re.compile(r"^Loaded (\d+) templates from (.+?)\s*$")
DEDUPLICATED = re.compile(r"^Deduplicated templates")


def load_discover():
    """Reuse the generator's discovery rules rather than restating them."""
    path = REPO_ROOT / "scripts" / "generate-index.py"
    spec = importlib.util.spec_from_file_location("generate_index", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.discover


def main():
    if len(sys.argv) != 2:
        print("usage: check_loader.py <loader-log>", file=sys.stderr)
        return 1

    raw = [ANSI.sub("", line.rstrip("\n"))
           for line in Path(sys.argv[1]).read_text(
               encoding="utf-8", errors="replace").splitlines()]
    # (level, message) for the tracing lines; the rest is the template table.
    events = [(m.group(1), m.group(2))
              for m in (TRACING.match(line) for line in raw) if m]

    expected = len(list(load_discover()(TEMPLATES_DIR)))
    failures = []

    warns = [message for level, message in events if level == "WARN"]
    if warns:
        failures.append(
            "%d template(s) failed to load. The engine warns and continues, so "
            "these are silently absent from every scan:\n%s"
            % (len(warns), "\n".join("    " + w for w in warns)))

    # "Loaded N templates from DIR", one line per directory consulted.
    repo_loaded = None
    foreign = []
    for _level, message in events:
        match = LOADED.match(message)
        if not match:
            continue
        count, directory = int(match.group(1)), match.group(2)
        try:
            is_repo = Path(directory).resolve() == TEMPLATES_DIR.resolve()
        except OSError:
            is_repo = False
        if is_repo:
            repo_loaded = count
        elif count:
            foreign.append("%s (%d templates)" % (directory, count))

    if repo_loaded is None:
        failures.append(
            "the loader never reported loading anything from %s. It was run "
            "from the wrong directory, or template discovery has changed."
            % TEMPLATES_DIR)
    elif repo_loaded != expected:
        failures.append(
            "the engine loaded %d templates from templates/ but %d template "
            "files are on disk. %d file(s) were skipped."
            % (repo_loaded, expected, expected - repo_loaded))

    if foreign:
        failures.append(
            "template directories outside this repo contributed templates to "
            "the run, so the counts above do not describe this repo alone:\n%s"
            % "\n".join("    " + f for f in foreign))

    dedup = [message for _level, message in events
             if DEDUPLICATED.match(message)]
    if dedup:
        failures.append(
            "duplicate @id. The engine keeps one template per id and drops the "
            "rest, so a collided template never runs:\n%s"
            % "\n".join("    " + d for d in dedup))

    if failures:
        print("Engine loader check FAILED\n", file=sys.stderr)
        for failure in failures:
            print("  - %s\n" % failure, file=sys.stderr)
        return 1

    print("Engine loader check passed: %d/%d templates loaded, no warnings, "
          "no id collisions." % (repo_loaded, expected))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Registry and layout hygiene.

Three cheap invariants, each one a mistake this repo has actually shipped:

  ABSOLUTE PATHS  The registry was once regenerated on a laptop and committed
                  carrying /Users/<someone>/... in every row. Nothing about it
                  resolved on any other machine.

  EMPTY NAMES     A blank name field indexes a template that cannot be found by
                  name and shows up nameless in reports.

  CATEGORY DRIFT  templates/ is organised by the nine categories below and
                  tooling downstream assumes it. A template dropped into a
                  tenth directory - or loose at the top of templates/ - is what
                  the superseded contribution PRs kept getting wrong.

The category check runs against the working tree, not the registry, using
generate-index.py's own discover() so it sees exactly the files the engine and
the generator see (skeleton/, _disabled/ and friends are scaffolding, not
templates, and are skipped by all three).

Usage: check_hygiene.py    Exit 0 = clean, 1 = a violation.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REGISTRY = REPO_ROOT / "TEMPLATE_REGISTRY.json"
TEMPLATES_DIR = REPO_ROOT / "templates"

VALID_CATEGORIES = {
    "ai", "databases", "devops", "messaging", "monitoring",
    "network", "recon", "tooling", "web",
}

# A leading /, a Windows drive letter, a UNC share, or a home directory
# anywhere in the value.
ABSOLUTE = re.compile(r"^(?:/|[A-Za-z]:[\\/]|\\\\)|(?:/Users/|/home/|/root/)")


def load_discover():
    path = REPO_ROOT / "scripts" / "generate-index.py"
    spec = importlib.util.spec_from_file_location("generate_index", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.discover


def walk_strings(node, trail=""):
    """Every string value in the registry, with a JSON path to point at."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk_strings(value, "%s.%s" % (trail, key))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from walk_strings(item, "%s[%d]" % (trail, i))
    elif isinstance(node, str):
        yield trail.lstrip("."), node


def main():
    if not REGISTRY.exists():
        print("Hygiene check FAILED: %s does not exist. Run "
              "'python3 scripts/generate-index.py'." % REGISTRY, file=sys.stderr)
        return 1

    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    rows = registry.get("templates", [])
    failures = []

    absolutes = [(where, value) for where, value in walk_strings(registry)
                 if ABSOLUTE.search(value)]
    if absolutes:
        failures.append(
            "TEMPLATE_REGISTRY.json contains %d absolute path(s). The registry "
            "must be portable; regenerate it and commit the result:\n%s"
            % (len(absolutes),
               "\n".join("    %s = %s" % pair for pair in absolutes)))

    nameless = [row.get("path", "<no path>") for row in rows
                if not str(row.get("name", "")).strip()]
    if nameless:
        failures.append(
            "%d registry row(s) have an empty name field:\n%s"
            % (len(nameless), "\n".join("    " + p for p in nameless)))

    # Registry paths are relative to the repo root and live under templates/.
    stray_paths = [row.get("path") for row in rows
                   if not str(row.get("path", "")).startswith("templates/")]
    if stray_paths:
        failures.append(
            "%d registry row(s) have a path outside templates/:\n%s"
            % (len(stray_paths), "\n".join("    %s" % p for p in stray_paths)))

    misplaced = []
    for path, _lang in load_discover()(TEMPLATES_DIR):
        parts = path.relative_to(TEMPLATES_DIR).parts
        category = parts[0] if len(parts) > 1 else "<loose in templates/>"
        if category not in VALID_CATEGORIES:
            misplaced.append("%s  (category: %s)"
                             % (path.relative_to(REPO_ROOT).as_posix(), category))
    if misplaced:
        failures.append(
            "%d template file(s) sit outside the %d valid categories (%s):\n%s"
            % (len(misplaced), len(VALID_CATEGORIES),
               ", ".join(sorted(VALID_CATEGORIES)),
               "\n".join("    " + m for m in misplaced)))

    if failures:
        print("Hygiene check FAILED\n", file=sys.stderr)
        for failure in failures:
            print("  - %s\n" % failure, file=sys.stderr)
        return 1

    print("Hygiene check passed: no absolute paths, no empty names, all %d "
          "templates in a valid category." % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())

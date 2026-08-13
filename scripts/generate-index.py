#!/usr/bin/env python3
"""
Generate TEMPLATE_REGISTRY.json from the template tree.

Walks templates/ by CATEGORY (the repo's actual purpose-based layout) and
classifies each file by extension, mirroring how the cert-x-gen engine
discovers and parses templates so the registry cannot drift from reality.

THREE COUNTS, NOT ONE
---------------------
A single "total" hides two different kinds of breakage, so the registry
reports all three and every row carries its own status:

  files_on_disk  every template file the engine would discover
  loadable       files that survive the engine's parse/deserialize step
  runnable       loadable AND holding an id no other template claims

The gap between the first two is templates that fail to load (silent at the
engine's default verbosity - it warns and continues). The gap between the
last two is id collisions: the engine keeps exactly one template per id and
drops the rest, so a collided template never executes no matter how valid it
is.

A fourth number, engine_registered, is reported alongside them because the
two ways of counting a collision disagree and the difference is real. For
each collided id the engine keeps one file and drops the others, so it ends
up with more templates than 'runnable' counts - but WHICH file survives is
decided by directory walk order, not by anything an author controls. So
'runnable' is the count that is reproducible from the source tree, and
'engine_registered' is the count the engine will report at scan time. Cite
'runnable'; the gap between the two is exactly the number of collisions left
to fix.

ENGINE PARITY
-------------
The rules below are transcribed from the engine, not invented here:

  - annotations are read from the FIRST 50 LINES ONLY (src/engine/common.rs)
  - accepted comment prefixes are '#', '//', '//!', '*', or none at all
  - absent or unrecognised @severity silently becomes 'medium'
  - absent @id falls back to the file stem; absent @name to the stem with
    '-' and '_' turned into spaces
  - YAML is deserialized by serde and IGNORES annotation comments entirely;
    its required keys are id/name/author/severity/description/language, and
    'author' must be an OBJECT, never a plain string
  - there is no 'dsl' matcher; the valid set is status/word/regex/binary/
    time/size/hash/tls/dns/diff/custom
  - directories named target, node_modules, .git, __pycache__, _disabled and
    skeleton are skipped

EXIT CODES
----------
  0  registry written, no collisions
  1  zero templates discovered - registry NOT written (guards against the
     previous generator, which silently overwrote a real registry with an
     empty one when the layout changed underneath it)
  2  registry written, but id collisions exist. Collided templates are
     recorded with runnable=false so neither is indexed as live, the list is
     printed to stderr, and the non-zero exit keeps CI red until the ids are
     made unique. Fixing the templates themselves is out of scope here.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Extension -> language, matching the engine's dispatch table.
EXT_LANG = {
    ".yaml": "yaml", ".yml": "yaml",
    ".py": "python",
    ".js": "javascript",
    ".go": "go",
    ".c": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".rs": "rust",
    ".sh": "shell", ".bash": "shell",
    ".rb": "ruby",
    ".pl": "perl",
    ".php": "php",
    ".java": "java",
}

# Directories the engine refuses to walk, plus test scaffolding.
SKIP_DIRS = {"target", "node_modules", ".git", "__pycache__", "_disabled",
             "skeleton", "tests"}

# The engine reads annotations from the first 50 lines and nowhere else.
ANNOTATION_WINDOW = 50

# Comment prefixes the engine's recogniser accepts: #, //, //!, *, or none.
_ANNOTATION_RE_CACHE = {}

SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}
DEFAULT_SEVERITY = "medium"

MATCHER_TYPES = {"status", "word", "regex", "binary", "time", "size", "hash",
                 "tls", "dns", "diff", "custom"}

YAML_REQUIRED = ["id", "name", "author", "severity", "description", "language"]


def annotation_re(field):
    """Compile the engine's annotation recogniser for one field."""
    if field not in _ANNOTATION_RE_CACHE:
        _ANNOTATION_RE_CACHE[field] = re.compile(
            r"(?m)^[\s]*(?:#|//!?|\*)?[\s]*@" + field + r"[\s]*:[\s]*(.+?)[\s]*$"
        )
    return _ANNOTATION_RE_CACHE[field]


def read_head(path, lines=ANNOTATION_WINDOW):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return "".join(fh.read().splitlines(keepends=True)[:lines])
    except OSError:
        return ""


def annotation(head, field):
    """First match wins; empty values are discarded, as in the engine."""
    m = annotation_re(field).search(head)
    if not m:
        return None
    value = m.group(1).strip()
    return value or None


def stem_name(stem):
    return stem.replace("-", " ").replace("_", " ")


def normalise_severity(value):
    """Absent or unrecognised severity silently becomes medium."""
    if not value:
        return DEFAULT_SEVERITY
    low = value.strip().lower()
    return low if low in SEVERITIES else DEFAULT_SEVERITY


def annotation_metadata(path, lang):
    """Metadata for the 11 annotation languages. These always load."""
    head = read_head(path)
    stem = path.stem
    return {
        "id": annotation(head, "id") or stem,
        "name": annotation(head, "name") or stem_name(stem),
        "severity": normalise_severity(annotation(head, "severity")),
        "language": lang,
    }, None


def _walk_matchers(node, errors, where):
    """Validate every matcher 'type' the serde enum would reject."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "matchers" and isinstance(value, list):
                for i, matcher in enumerate(value):
                    if not isinstance(matcher, dict):
                        continue
                    mtype = matcher.get("type")
                    if mtype is not None and mtype not in MATCHER_TYPES:
                        errors.append(
                            "%s.matchers[%d].type: unknown variant '%s'"
                            % (where, i, mtype)
                        )
            _walk_matchers(value, errors, "%s.%s" % (where, key) if where else key)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_matchers(item, errors, "%s[%d]" % (where, i))


def yaml_metadata(path, lang):
    """Metadata plus a serde-equivalent load check for YAML templates."""
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML is required (pip install pyyaml)", file=sys.stderr)
        raise SystemExit(1)

    stem = path.stem
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:
        return ({"id": stem, "name": stem_name(stem),
                 "severity": DEFAULT_SEVERITY, "language": lang},
                "YAML parse error: %s" % str(exc).splitlines()[0])

    if not isinstance(data, dict):
        return ({"id": stem, "name": stem_name(stem),
                 "severity": DEFAULT_SEVERITY, "language": lang},
                "YAML parse error: document root is not a mapping")

    errors = []
    for key in YAML_REQUIRED:
        if key not in data:
            errors.append("missing field '%s'" % key)

    author = data.get("author")
    if author is not None and not isinstance(author, dict):
        errors.append("invalid type: %s, expected struct AuthorInfo"
                      % type(author).__name__)

    severity = data.get("severity")
    if severity is not None and str(severity).lower() not in SEVERITIES:
        errors.append("unknown variant '%s' for severity" % severity)

    for i, entry in enumerate(data.get("network") or []):
        if isinstance(entry, dict) and "port" not in entry:
            errors.append("network[%d]: missing field 'port'" % i)

    _walk_matchers(data, errors, "")

    meta = {
        "id": data.get("id") if isinstance(data.get("id"), str) else stem,
        "name": data.get("name") if isinstance(data.get("name"), str) else stem_name(stem),
        "severity": normalise_severity(
            str(data["severity"]) if isinstance(data.get("severity"), str) else None
        ),
        "language": lang,
    }
    return meta, ("; ".join(errors) if errors else None)


def discover(templates_dir):
    """Every template file the engine would discover, in sorted order."""
    for path in sorted(templates_dir.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            continue
        lang = EXT_LANG.get(path.suffix.lower())
        if lang:
            yield path, lang


def scan_templates(repo_root):
    templates_dir = repo_root / "templates"
    rows = []

    for path, lang in discover(templates_dir):
        if lang == "yaml":
            meta, error = yaml_metadata(path, lang)
        else:
            meta, error = annotation_metadata(path, lang)
        meta["path"] = path.relative_to(repo_root).as_posix()
        meta["category"] = path.relative_to(templates_dir).parts[0]
        meta["loadable"] = error is None
        if error:
            meta["load_error"] = error
        rows.append(meta)

    # An id collision only matters among templates that actually load.
    by_id = {}
    for row in rows:
        if row["loadable"]:
            by_id.setdefault(row["id"], []).append(row)
    collisions = {tid: group for tid, group in by_id.items() if len(group) > 1}

    for row in rows:
        colliding = collisions.get(row["id"]) if row["loadable"] else None
        if colliding:
            # Neither member is indexed as live: the engine keeps exactly one
            # and which one is not something this script should guess.
            row["runnable"] = False
            row["collides_with"] = sorted(
                other["path"] for other in colliding if other is not row
            )
        else:
            row["runnable"] = row["loadable"]

    rows.sort(key=lambda r: (r["category"], r["language"], r["id"], r["path"]))

    languages, categories = {}, {}
    for row in rows:
        languages[row["language"]] = languages.get(row["language"], 0) + 1
        categories[row["category"]] = categories.get(row["category"], 0) + 1

    registry = {
        "version": "2.0.0",
        "generated_by": "scripts/generate-index.py",
        "last_updated": datetime.now(timezone.utc)
                        .isoformat().replace("+00:00", "Z"),
        "counts": {
            "files_on_disk": len(rows),
            "loadable": sum(1 for r in rows if r["loadable"]),
            "runnable": sum(1 for r in rows if r["runnable"]),
            # What the engine reports after dropping one file per collided
            # id. Higher than 'runnable' because it counts an arbitrary
            # survivor from each collision; see the module docstring.
            "engine_registered": sum(1 for r in rows if r["loadable"])
                                 - sum(len(g) - 1 for g in collisions.values()),
        },
        # Kept for backwards compatibility, and equal to files_on_disk so the
        # invariant total_templates == len(templates) == file count holds.
        "total_templates": len(rows),
        "load_failures": [
            {"path": r["path"], "error": r["load_error"]}
            for r in rows if not r["loadable"]
        ],
        "id_collisions": [
            {"id": tid, "paths": sorted(r["path"] for r in group)}
            for tid, group in sorted(collisions.items())
        ],
        "languages": dict(sorted(languages.items())),
        "categories": dict(sorted(categories.items())),
        "templates": rows,
    }
    return registry


def main():
    repo_root = Path(__file__).resolve().parent.parent
    registry = scan_templates(repo_root)
    counts = registry["counts"]

    if counts["files_on_disk"] == 0:
        print("ERROR: 0 templates discovered - refusing to overwrite the "
              "registry. Check the templates/ layout.", file=sys.stderr)
        return 1

    out = repo_root / "TEMPLATE_REGISTRY.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(registry, fh, indent=2)
        fh.write("\n")

    print("Wrote %s" % out.relative_to(repo_root))
    print("  files on disk     : %d" % counts["files_on_disk"])
    print("  loadable          : %d" % counts["loadable"])
    print("  runnable          : %d" % counts["runnable"])
    print("  engine registered : %d  (arbitrary survivor per collided id)"
          % counts["engine_registered"])
    print("  languages     : %s" % registry["languages"])
    print("  categories    : %s" % registry["categories"])

    if registry["load_failures"]:
        print("\n%d template(s) do not load through the engine:"
              % len(registry["load_failures"]), file=sys.stderr)
        for failure in registry["load_failures"]:
            print("  %s\n      %s" % (failure["path"], failure["error"]),
                  file=sys.stderr)

    if registry["id_collisions"]:
        print("\nERROR: %d duplicate template id(s). The engine keeps one "
              "template per id and drops the rest, so NONE of these can be "
              "relied on to run. They are recorded with runnable=false rather "
              "than indexed as live:" % len(registry["id_collisions"]),
              file=sys.stderr)
        for collision in registry["id_collisions"]:
            print("  %s" % collision["id"], file=sys.stderr)
            for path in collision["paths"]:
                print("      %s" % path, file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

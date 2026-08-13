#!/usr/bin/env python3
"""
Guard tests for scripts/generate-index.py.

Once the real template tree has no id collisions and no load failures,
nothing in it exercises the generator's collision-detection or zero-template
guards any more. Without these tests that code silently rots and the next
duplicate @id sails through. Each test builds a throwaway repo (its own
scripts/ + templates/) so the generator runs against the fixture and never
touches the real TEMPLATE_REGISTRY.json.

Run by hand:  python3 scripts/test_generate_index.py
Exit 0 = all pass, 1 = a failure. No third-party deps beyond PyYAML (which
the generator itself already requires).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GENERATOR = os.path.join(HERE, "generate-index.py")

_failures = []


def check(label, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print("  [%s] %s%s" % (status, label, ("  -> " + detail) if detail and not cond else ""))
    if not cond:
        _failures.append(label)


def make_repo(tmp):
    """A throwaway repo skeleton: scripts/generate-index.py + templates/."""
    os.makedirs(os.path.join(tmp, "scripts"))
    os.makedirs(os.path.join(tmp, "templates"))
    shutil.copy(GENERATOR, os.path.join(tmp, "scripts", "generate-index.py"))


def write(tmp, relpath, content):
    full = os.path.join(tmp, relpath)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)


def run(tmp):
    proc = subprocess.run(
        [sys.executable, os.path.join(tmp, "scripts", "generate-index.py")],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def registry_path(tmp):
    return os.path.join(tmp, "TEMPLATE_REGISTRY.json")


def test_collision_guard():
    print("test_collision_guard: duplicate @id must exit 2 and quarantine both members")
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        # Two loadable templates sharing one id, in the same category.
        write(tmp, "templates/web/dup-a.py", "# @id: shared-dup\n# @severity: high\nprint(1)\n")
        write(tmp, "templates/web/dup-b.py", "# @id: shared-dup\n# @severity: high\nprint(2)\n")
        # A clean template so the tree is not degenerate.
        write(tmp, "templates/web/clean.py", "# @id: clean-one\nprint(3)\n")

        code, out, err = run(tmp)
        check("exit code is 2", code == 2, "got %d" % code)
        check("collision id printed to stderr", "shared-dup" in err)
        check("both colliding paths printed to stderr",
              "dup-a.py" in err and "dup-b.py" in err)

        reg = json.load(open(registry_path(tmp)))
        rows = {t["path"]: t for t in reg["templates"]}
        a = rows.get("templates/web/dup-a.py", {})
        b = rows.get("templates/web/dup-b.py", {})
        check("member A recorded runnable=false", a.get("runnable") is False)
        check("member B recorded runnable=false", b.get("runnable") is False)
        check("both members remain loadable=true",
              a.get("loadable") is True and b.get("loadable") is True)
        check("clean template stays runnable=true",
              rows.get("templates/web/clean.py", {}).get("runnable") is True)
        check("id_collisions lists the shared id",
              any(c["id"] == "shared-dup" for c in reg["id_collisions"]))
        check("runnable count excludes both collided members",
              reg["counts"]["runnable"] == 1, str(reg["counts"]))


def test_zero_template_guard():
    print("test_zero_template_guard: empty tree must exit 1 and NOT overwrite the registry")
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        # templates/ exists but holds no template-extension files.
        write(tmp, "templates/notes/README.md", "# not a template\n")
        sentinel = '{"sentinel":"MUST SURVIVE UNCHANGED"}'
        with open(registry_path(tmp), "w", encoding="utf-8") as fh:
            fh.write(sentinel)
        before = open(registry_path(tmp), "rb").read()

        code, out, err = run(tmp)
        check("exit code is 1", code == 1, "got %d" % code)
        check("stderr explains the refusal", "0 templates" in err)
        after = open(registry_path(tmp), "rb").read()
        check("registry left byte-identical", after == before,
              "%r -> %r" % (before, after))


def test_clean_tree_exits_zero():
    print("test_clean_tree_exits_zero: unique ids, all loadable -> exit 0")
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        write(tmp, "templates/web/one.py", "# @id: one\nprint(1)\n")
        write(tmp, "templates/net/two.py", "# @id: two\nprint(2)\n")
        code, out, err = run(tmp)
        check("exit code is 0", code == 0, "got %d (stderr: %s)" % (code, err.strip()))
        reg = json.load(open(registry_path(tmp)))
        check("all three counts equal 2",
              reg["counts"]["files_on_disk"] == reg["counts"]["loadable"]
              == reg["counts"]["runnable"] == 2, str(reg["counts"]))


def main():
    for test in (test_collision_guard, test_zero_template_guard, test_clean_tree_exits_zero):
        test()
        print()
    if _failures:
        print("FAILED: %d check(s) -> %s" % (len(_failures), ", ".join(_failures)))
        return 1
    print("OK: all guard checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

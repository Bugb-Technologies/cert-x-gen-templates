#!/usr/bin/env python3
"""
skillforge -- a benign synthetic "agent extension manager" CLI.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/agent-extension-install-path-containment.sh` can be
proved in every direction it can report: CONFIRMED against the defective twin,
REFUTED against the fixed one, SKIP against a twin that exposes no install verb
at all. It reproduces the *shape* of the extension-installer containment class
-- untrusted skill/plugin metadata reaching `os.path.join()` and archive member
names reaching the filesystem without ever being re-resolved against the
directory they were supposed to stay inside -- without reproducing any vendor's
code, machine state, or payload. Nothing here is an exploit: every byte it can
be made to write outside its own roots is a random nonce the probe planted in
the probe's own throwaway $HOME.

ONE SOURCE, THREE TWINS
-----------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    skillforge_defective.py   VARIANT = "defective"
    skillforge_fixed.py       VARIANT = "fixed"
    skillforge_noinstall.py   VARIANT = "noinstall"

from this single file. Twins that could drift apart would be worth nothing as a
refutation test: the fixed twin has to be the same program with containment
switched on, or "refuted" only means "the two files differ". The `noinstall`
twin exists so the template's SKIP branch has an honest target -- an agent that
simply has no extension installer, which is a missing precondition and not a
clean bill of health.

WHAT IT INSTALLS
----------------
Three source shapes, the three that carry attacker-authored names in the real
ecosystem:

    <dir>/SKILL.md              a skill, named by its frontmatter `name:`
    <dir>/plugin.json           a plugin, named by the manifest's "name"
      (or .claude-plugin/plugin.json, or marketplace.json)
    <file>.tar                  an extension pack, laid out by member names

each landing under its own root beneath $HOME:

    $HOME/.skillforge/skills    $HOME/.skillforge/plugins    $HOME/.skillforge/packs

THE ONLY DIFFERENCE
-------------------
    defective   the name off the metadata and the member name off the archive
                go straight into os.path.join(root, name). A name of
                `../../x` resolves above the root, an absolute member name
                escapes it, and a symlink member is recreated verbatim so the
                very next member is written *through* it. Joining is not
                containing.

    fixed       every destination is re-resolved and required to stay inside
                its root. A skill name is normalised to its final component
                (installed in place under a safe name); a plugin name that is
                absolute or contains a separator or `..` is refused outright;
                an archive member that is a link, or that resolves outside the
                pack directory, is skipped and named on stderr.

    noinstall   the same program with the install verb removed, so `--help`
                advertises no way to install an extension at all.

REFUSAL MUST STAY QUIET ABOUT MARKERS
-------------------------------------
The probe proves an escape by finding its nonce at a path outside the resolved
root. A gate that echoed the rejected name would put the nonce in this program's
output, not on disk, and could never be mistaken for an escape -- but the fixed
twin still names only the surface and the reason, never the value, so that the
two twins' *observable* difference is containment and nothing else.
"""
import json
import os
import re
import shutil
import sys
import tarfile

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "skillforge"

USAGE_INSTALL = """\
Usage: skillforge <command> [args]

A synthetic agent extension manager used as a security-test fixture.

Commands:
  install <source>   Install a skill directory, plugin manifest or .tar pack
  list               List installed extensions
  version            Print the version
  help               Print this message
"""

USAGE_NOINSTALL = """\
Usage: skillforge <command> [args]

A synthetic agent extension manager used as a security-test fixture.
This build ships no extension installer.

Commands:
  list               List installed extensions
  version            Print the version
  help               Print this message
"""

USAGE = USAGE_NOINSTALL if VARIANT == "noinstall" else USAGE_INSTALL


def home():
    return os.environ.get("HOME") or os.path.expanduser("~")


def roots():
    base = os.path.join(home(), "." + APP)
    return {
        "skill":  os.path.join(base, "skills"),
        "plugin": os.path.join(base, "plugins"),
        "pack":   os.path.join(base, "packs"),
    }


def note(text):
    sys.stderr.write("%s: %s\n" % (APP, text))


# ---------------------------------------------------------------------------
# Reading the untrusted metadata. Both twins read it identically; they differ
# only in what they then do with the name.
# ---------------------------------------------------------------------------
def skill_name(source):
    """The `name:` from a SKILL.md frontmatter block."""
    with open(os.path.join(source, "SKILL.md"), "r", encoding="utf-8",
              errors="replace") as fh:
        text = fh.read()
    block = text.split("---", 2)
    body = block[1] if len(block) > 2 and text.lstrip().startswith("---") else text
    for line in body.splitlines():
        match = re.match(r"^\s*name\s*:\s*(.+?)\s*$", line)
        if match:
            return match.group(1).strip().strip("'\"")
    return ""


def manifest_path(source):
    for relative in ("plugin.json", ".claude-plugin/plugin.json", "marketplace.json"):
        candidate = os.path.join(source, relative)
        if os.path.isfile(candidate):
            return candidate
    return ""


def plugin_name(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        document = json.load(fh)
    if isinstance(document.get("name"), str):
        return document["name"]
    # A marketplace file names its entries instead of itself.
    for entry in document.get("plugins", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            return entry["name"]
    return ""


# ---------------------------------------------------------------------------
# Containment. The fixed twin's whole contribution.
# ---------------------------------------------------------------------------
def inside(root, path):
    """True when `path` -- fully resolved, symlinks and all -- is under root."""
    root = os.path.realpath(root)
    path = os.path.realpath(path)
    return path == root or path.startswith(root + os.sep)


def normalise(name):
    """A name reduced to one safe final component, never a path."""
    candidate = name.replace("\\", "/").split("/")[-1]
    candidate = re.sub(r"[^A-Za-z0-9._-]", "-", candidate).lstrip(".")
    return candidate or "unnamed-extension"


def unsafe_name(name):
    return (not name
            or os.path.isabs(name)
            or "\\" in name
            or "/" in name
            or name in (".", "..")
            or ".." in name.split("/"))


# ---------------------------------------------------------------------------
# The three installers.
# ---------------------------------------------------------------------------
def copy_tree(source, dest):
    os.makedirs(dest, exist_ok=True)
    for entry in sorted(os.listdir(source)):
        src = os.path.join(source, entry)
        dst = os.path.join(dest, entry)
        if os.path.isdir(src) and not os.path.islink(src):
            copy_tree(src, dst)
        else:
            shutil.copyfile(src, dst)


def install_skill(source):
    root = roots()["skill"]
    name = skill_name(source)
    if not name:
        note("skill has no name: in its SKILL.md frontmatter")
        return 1

    if VARIANT == "fixed":
        # Normalised in place: the skill still installs, under a name that is
        # one path component and therefore cannot leave the root.
        safe = normalise(name)
        if safe != name:
            note("skill name is not a single path component; normalised before join")
        dest = os.path.join(root, safe)
        if not inside(root, dest):
            note("refusing skill: destination resolves outside %s" % root)
            return 1
        name = safe
    else:
        # The class, in one line: metadata straight into a join, and a join is
        # not a containment check.
        dest = os.path.join(root, name)

    os.makedirs(os.path.dirname(dest) or root, exist_ok=True)
    copy_tree(source, dest)
    print("installed skill %s" % name)
    return 0


def install_plugin(source, manifest):
    root = roots()["plugin"]
    name = plugin_name(manifest)
    if not name:
        note("plugin manifest has no name")
        return 1

    if VARIANT == "fixed":
        # Refused outright: unlike a skill name, a plugin name that is a path
        # is malformed rather than merely untidy.
        if unsafe_name(name):
            note("refusing plugin: manifest name is a path, not an identifier")
            return 1
        dest = os.path.join(root, name)
        if not inside(root, dest):
            note("refusing plugin: destination resolves outside %s" % root)
            return 1
    else:
        dest = os.path.join(root, name)

    os.makedirs(os.path.dirname(dest) or root, exist_ok=True)
    copy_tree(source, dest)
    print("installed plugin %s" % name)
    return 0


def install_pack(archive):
    root = roots()["pack"]
    stem = normalise(os.path.basename(archive).split(".")[0]) or "pack"
    dest = os.path.join(root, stem)
    os.makedirs(dest, exist_ok=True)

    written, refused = 0, 0
    # Members are laid out by hand rather than through extractall(), because
    # that is what an installer written in any other language does, and because
    # extractall()'s member filter varies by interpreter version -- the twins
    # must differ by their own containment logic, not by the Python on PATH.
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            target = os.path.join(dest, member.name)

            if VARIANT == "fixed":
                if member.issym() or member.islnk():
                    note("refusing archive member: links are not extracted (%s)"
                         % member.name)
                    refused += 1
                    continue
                probe = os.path.join(dest, os.path.normpath("/" + member.name).lstrip("/"))
                if not inside(dest, os.path.dirname(probe) or dest):
                    note("refusing archive member: resolves outside %s" % dest)
                    refused += 1
                    continue
                target = probe

            if member.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
            if member.issym():
                if os.path.lexists(target):
                    os.remove(target)
                os.symlink(member.linkname, target)
                written += 1
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            # open() follows a symlink already laid down by an earlier member.
            # That is the write-through half of the class.
            with open(target, "wb") as out:
                out.write(handle.read())
            written += 1

    print("installed pack %s (%d member(s), %d refused)" % (stem, written, refused))
    return 0


def install(source):
    if not source:
        note("install needs a source")
        return 2
    if os.path.isdir(source):
        if os.path.isfile(os.path.join(source, "SKILL.md")):
            return install_skill(source)
        manifest = manifest_path(source)
        if manifest:
            return install_plugin(source, manifest)
        note("source directory is neither a skill nor a plugin")
        return 2
    if os.path.isfile(source) and tarfile.is_tarfile(source):
        return install_pack(source)
    note("unrecognised source: %s" % source)
    return 2


def listing():
    for kind, root in sorted(roots().items()):
        if not os.path.isdir(root):
            continue
        for entry in sorted(os.listdir(root)):
            print("%s\t%s" % (kind, entry))
    return 0


def main(argv):
    command = argv[1] if len(argv) > 1 else "help"
    if command in ("help", "-h", "--help"):
        sys.stdout.write(USAGE)
        return 0
    if command in ("version", "--version"):
        print("%s %s (%s)" % (APP, VERSION, VARIANT))
        return 0
    if command == "list":
        return listing()
    if command == "install" and VARIANT != "noinstall":
        return install(argv[2] if len(argv) > 2 else "")
    note("unknown command: %s" % command)
    sys.stdout.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

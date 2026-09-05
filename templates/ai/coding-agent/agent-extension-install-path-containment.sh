#!/usr/bin/env bash
# @id: agent-extension-install-path-containment
# @name: Agent extension installer joins untrusted skill/plugin names and archive members without containing them
# @author: CERT-X-GEN Security Team
# @description: Drives an agent CLI's own install verb, inside a throwaway $HOME, against three benign synthetic extensions whose only unusual property is the NAME an attacker controls - a skill whose SKILL.md frontmatter name is `../../<nonce>`, a plugin manifest whose name is `../../../.ssh`, and a .tar pack carrying a symlink to $HOME/.ssh/authorized_keys followed by a member written through it. Each install is preceded by a benign-named control install of the same shape, which is what resolves the tool's real skills/plugins/packs root; the probe then asks one question of the filesystem - did this arm's nonce land outside that resolved root, or was a link that leaves it followed or preserved. Confirms only on an observed escape, refutes when every arm was rejected or normalised in place, and skips when the target exposes no install verb (SkillSlip / extension-installer containment class).
# @severity: high
# @tags: ai, coding-agent, cli, skills, plugins, marketplace, install, path-traversal, zip-slip, symlink, containment, cwe-22, cwe-23, cwe-59, cwe-829
# @cwe: CWE-22
# @confidence: 92
# @target_kinds: cli
# @oracles: property
# @references: https://cwe.mitre.org/data/definitions/22.html
#
# THE CLASS
#
# An agent extension - a skill, a plugin, a marketplace entry, a pack - arrives
# as a directory or an archive whose *name* is metadata the author chose. The
# installer reads that name and computes where to put it:
#
#     dest = path.join(skills_root, manifest.name)
#
# `join` is not a containment check. It is string concatenation with a
# separator, and it will happily resolve `../../x` above the root it was handed,
# or discard the root entirely when the name is absolute. The same hole opens a
# second time one layer down: an archive's member names are also
# attacker-authored, so an extractor that joins them lays a symlink pointing
# anywhere the process can write, and then writes the *next* member straight
# through it. The normative requirement is the one line the installer skipped -
# re-resolve the destination and require it to stay inside the root, refusing
# the entry when it does not.
#
# The reason this is worth a behavioural check is that the payload is boring and
# the *reachability* is everything. A scanner reading an already-installed skill
# sees a well-formed directory; the traversal happened at install time, in the
# installer, and left no trace in the artifact it produced.
#
#   input      three benign extensions, identical to ordinary ones except for a
#              name: a SKILL.md frontmatter `name: ../../<nonce>`, a plugin
#              manifest `"name": "../../../.ssh"`, and a .tar whose first member
#              is a symlink to $HOME/.ssh/authorized_keys and whose second is a
#              regular file of the same name.
#   observable this arm's nonce present at a path that resolves OUTSIDE the
#              root the control install just proved the tool uses, or a symlink
#              inside that root whose target resolves outside it.
#   oracle     property -- a post-condition over the filesystem, evaluated
#              against a containment root the target itself established, so the
#              template never asserts where a tool "should" have installed.
#
# WHY THE CONTROL COMES FIRST
#
# "The nonce is not under $HOME/.claude/skills" proves nothing about a tool that
# keeps its skills somewhere else entirely, and "a file appeared outside a
# directory I guessed" is how a containment check invents findings. So each arm
# installs a benign, single-component-named twin of itself FIRST. Where that one
# lands *is* the root; the escape arm is then measured against a boundary the
# target drew. An arm whose control installs nothing is not tested at all, and
# an arm that is never tested never contributes to a refutation.
#
# SAFETY
#
# Everything happens inside a `mktemp -d` lab removed on exit. $HOME is
# redirected into that lab for every invocation, so the `.ssh` and
# `authorized_keys` this template names are files it created itself, seeded with
# an inert comment; no real key material is read, written, or within reach of
# any path the probe can construct. The extensions are benign: their entire
# content is a random nonce, and nothing they carry is executed by this
# template. No CVE is reproduced and no vendor artifact is used.
set -uo pipefail

# The probe-contract inputs. CERT_X_GEN_TARGET_KIND is part of the richer CLI
# contract but is not set by every shipping engine build, which passes only the
# scope string in CERT_X_GEN_TARGET_HOST (`cli:///path/to/binary`). Deriving the
# kind and the path from that string when the explicit variables are absent is
# what lets one template run under both, and under a developer invoking it by
# hand with just CERT_X_GEN_TARGET_HOST set.
CXG_RAW="${CERT_X_GEN_TARGET_HOST:-}"
CXG_KIND="${CERT_X_GEN_TARGET_KIND:-}"
CXG_INSTR="${CERT_X_GEN_TARGET_INSTRUMENTATION:-unknown}"

CXG_BIN="$CXG_RAW"
case "$CXG_RAW" in
    cli://*)
        [ -n "$CXG_KIND" ] || CXG_KIND="cli"
        CXG_BIN="${CXG_RAW#cli://}"
        ;;
    *)
        if [ -z "$CXG_KIND" ] && [ -n "$CXG_RAW" ] && [ -f "$CXG_RAW" ] && [ -x "$CXG_RAW" ]; then
            CXG_KIND="cli"
        fi
        ;;
esac
CXG_TIMEOUT="${CXG_AGENT_TIMEOUT:-15}"
CXG_PROBES_DELIVERED=0
CXG_PROBE_BUDGET="${CXG_INSTALL_PROBE_BUDGET:-40}"

# ---------------------------------------------------------------------------
# The JSON contract. Built with json.dumps, never by interpolation: this
# template handles target output verbatim and a half-cut glyph would turn a
# finding into a silent zero-finding.
# ---------------------------------------------------------------------------
cxg_emit() {
    CXG_F="${3:-[]}" CXG_S="$1" CXG_D="$2" CXG_I="$CXG_INSTR" python3 -c '
import json, os
detail = os.environ["CXG_D"]
try:
    findings = json.loads(os.environ["CXG_F"])
except ValueError as exc:
    findings = []
    detail += " (finding-json-invalid: %s)" % exc
print(json.dumps({"findings": findings,
                  "metadata": {"status": os.environ["CXG_S"],
                               "detail": detail,
                               "instrumentation": os.environ["CXG_I"]}}))'
}

# Every verdict exits 0 and carries its status in the JSON. The shipped engine
# discards a shell template's findings when the template exits non-zero, so a
# confirmation that signalled itself with an exit code would be a finding cxg
# never records.
cxg_confirm() { cxg_emit confirmed "$1" "$2"; exit 0; }
cxg_error()   { cxg_emit errored   "$1"; exit 0; }
cxg_skip()    { cxg_emit skipped   "$1"; exit 0; }

# A refutation asserts the target was exercised. Without a delivered probe this
# template has learned nothing and says so, rather than issuing a clean bill of
# health it did not earn.
cxg_refute() {
    if [ "$CXG_PROBES_DELIVERED" -eq 0 ]; then
        cxg_emit skipped "no-probe-delivered (nothing reached the target, so a refutation would be unearned): $1"
        exit 0
    fi
    cxg_emit refuted "$1 probes=$CXG_PROBES_DELIVERED"
    exit 0
}

cxg_finding() {
    CXG_SEV="$1" CXG_CONF="$2" CXG_TITLE="$3" CXG_DESC="$4" CXG_CWE="$5" \
    CXG_REQ="$6" CXG_RESP="$7" CXG_PAT="$8" CXG_DATA="${9:-{\}}" python3 -c '
import json, os

def visible(s):
    return "".join(c if (31 < ord(c) < 127 or c in "\n\t") else "\\x%02x" % ord(c)
                   for c in s)

try:
    data = json.loads(os.environ["CXG_DATA"])
except ValueError:
    data = {"note": "data-json-invalid"}
print(json.dumps([{
    "severity":    os.environ["CXG_SEV"],
    "confidence":  int(os.environ["CXG_CONF"]),
    "title":       os.environ["CXG_TITLE"],
    "description": os.environ["CXG_DESC"],
    "cwe_ids":     [c.strip() for c in os.environ["CXG_CWE"].split(",") if c.strip()],
    "evidence": {
        "request":          os.environ["CXG_REQ"],
        "response":         visible(os.environ["CXG_RESP"][:1600]),
        "matched_patterns": [p.strip() for p in os.environ["CXG_PAT"].split(",") if p.strip()],
        "data":             data,
    },
}]))'
}

cxg_timeout() {
    secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"; return $?; fi
    if command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"; return $?; fi
    "$@" & child=$!
    ( sleep "$secs"; kill -TERM "$child" 2>/dev/null; sleep 1
      kill -KILL "$child" 2>/dev/null ) >/dev/null 2>&1 & watchdog=$!
    rc=0; wait "$child" 2>/dev/null || rc=$?
    kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null || true
    [ "$rc" -eq 143 ] && rc=124
    return "$rc"
}

# ---------------------------------------------------------------------------
# Guards and lab.
# ---------------------------------------------------------------------------
[ "$CXG_KIND" = "cli" ] || cxg_skip "not-a-cli-target(kind=${CXG_KIND:-none})"
[ -n "$CXG_BIN" ]       || cxg_error "no-target-path"
[ -x "$CXG_BIN" ]       || cxg_error "target-not-executable($CXG_BIN)"
command -v python3 >/dev/null 2>&1 || cxg_error "python3-required-to-build-probe-extensions"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-install-containment.XXXXXX")" || cxg_error "lab-setup-failed"
# shellcheck disable=SC2064  # $LAB must expand now, not at trap time
trap "chmod -R u+rwX '$LAB' 2>/dev/null; rm -rf '$LAB'" EXIT

# The hermetic $HOME is deliberately nested a few levels below the lab root, so
# that the deepest traversal any arm can express still resolves INSIDE the lab
# and is therefore both harmless and observable. A marker that escaped the lab
# would be a missed confirmation, never a stray write.
HERMETIC="$LAB/hermetic"
HOME_DIR="$HERMETIC/home/user"
STAGING="$LAB/staging"
mkdir -p "$HOME_DIR/.ssh" "$HOME_DIR/.config" "$STAGING" || cxg_error "lab-layout-failed"
chmod 0700 "$HOME_DIR" "$HOME_DIR/.ssh"

# The file arm (c) aims at. It is this template's own, holds no key material,
# and exists so that "was the symlink followed" is answerable by reading it.
SENTINEL="$HOME_DIR/.ssh/authorized_keys"
seed_sentinel() {
    printf '# cert-x-gen hermetic sentinel - no key material, created by the probe\n' \
        >"$SENTINEL"
}
seed_sentinel

salt() { od -An -N8 -tx1 /dev/urandom | tr -d ' \n'; }
SALT="$(salt)"

HELP_TEXT=""
for probe in --help help -h; do
    HELP_TEXT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$probe" 2>&1)"
    printf '%s' "$HELP_TEXT" | grep -qiE 'usage|commands?:|options?:' && break
    HELP_TEXT=""
done
if [ -z "$HELP_TEXT" ]; then
    HELP_TEXT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" 2>&1)"
fi
[ -n "$HELP_TEXT" ] || cxg_error "target-produced-no-output-at-all"

# ---------------------------------------------------------------------------
# Which invocation installs an extension?
#
# Read out of the tool's own help listing rather than guessed: the subcommand
# shape (`  name   description`), reduced to the verbs that install and the
# nouns that name an extension, then combined. A tool whose help advertises no
# such verb has no install surface for this template to test, which is a SKIP.
# ---------------------------------------------------------------------------
SUB_NAMES="$(printf '%s' "$HELP_TEXT" | python3 -c '
import re, sys
NAME = re.compile(r"^[ \t]{1,8}([a-z][a-z0-9][a-z0-9_.-]*)\b(.*)$")
SEP = re.compile(r"(?:[ ]{2,}|\t)\S")
NOT_A_COMMAND = {"usage", "options", "option", "commands", "command",
                 "arguments", "args", "flags", "environment", "examples",
                 "example", "see", "note", "notes", "where", "for", "the"}
seen, out = set(), []
for line in sys.stdin.read().splitlines():
    m = NAME.match(line)
    if not m:
        continue
    name, rest = m.group(1), m.group(2)
    if not SEP.search(rest) or name in seen or name in NOT_A_COMMAND:
        continue
    seen.add(name)
    out.append(name)
print("\n".join(out))')"

VERBS="$(printf '%s' "$SUB_NAMES" | grep -E '^(install|add|import|load|enable)$' | head -4)"
NOUNS="$(printf '%s' "$SUB_NAMES" | grep -E '^(plugin|plugins|skill|skills|extension|extensions|marketplace|pack|packs|package)$' | head -4)"

CANDIDATES="$(
    printf '%s\n' "$VERBS" | grep -v '^$'
    for noun in $NOUNS; do
        for verb in install add import; do
            printf '%s %s\n' "$noun" "$verb"
        done
    done
)"
CANDIDATES="$(printf '%s\n' "$CANDIDATES" | grep -v '^$' | head -8)"

# A help text that says "install" only in prose still deserves one attempt at
# the obvious invocation before this template declares there is no surface.
if [ -z "$CANDIDATES" ] && printf '%s' "$HELP_TEXT" | grep -qi 'install'; then
    CANDIDATES="install"
fi
[ -n "$CANDIDATES" ] || cxg_skip "no-install-verb(the target's help listing advertises no install/add/import subcommand and no plugin/skill/extension/marketplace noun to pair one with, so there is no extension installer to drive; this template tests the installer, not the installed artifact)"

# ---------------------------------------------------------------------------
# The extensions. Every one is benign: its whole content is a nonce. The only
# thing that separates a probe from its control is the NAME.
# ---------------------------------------------------------------------------
# make_skill <dir> <name> <nonce>
make_skill() {
    CXG_DIR="$1" CXG_NAME="$2" CXG_NONCE="$3" python3 - <<'PY'
import os
directory = os.environ["CXG_DIR"]
os.makedirs(directory, exist_ok=True)
name  = os.environ["CXG_NAME"]
nonce = os.environ["CXG_NONCE"]
with open(os.path.join(directory, "SKILL.md"), "w", encoding="utf-8") as fh:
    fh.write("---\nname: %s\ndescription: benign cert-x-gen containment probe\n---\n\n"
             "This skill does nothing. Marker: %s\n" % (name, nonce))
with open(os.path.join(directory, "payload.txt"), "w", encoding="utf-8") as fh:
    fh.write(nonce + "\n")
PY
}

# make_plugin <dir> <name> <nonce>
make_plugin() {
    CXG_DIR="$1" CXG_NAME="$2" CXG_NONCE="$3" python3 - <<'PY'
import json, os
directory = os.environ["CXG_DIR"]
name  = os.environ["CXG_NAME"]
nonce = os.environ["CXG_NONCE"]
manifest = {"name": name, "version": "0.0.1",
            "description": "benign cert-x-gen containment probe",
            "marker": nonce}
marketplace = {"name": name, "owner": {"name": "cert-x-gen"},
               "plugins": [dict(manifest, source="./")]}
for relative, document in ((("plugin.json"), manifest),
                           (os.path.join(".claude-plugin", "plugin.json"), manifest),
                           (("marketplace.json"), marketplace)):
    path = os.path.join(directory, relative)
    os.makedirs(os.path.dirname(path) or directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(document, indent=2) + "\n")
with open(os.path.join(directory, "payload.txt"), "w", encoding="utf-8") as fh:
    fh.write(nonce + "\n")
PY
}

# make_pack <archive> <member-name> <nonce> [<symlink-target>]
#
# With a symlink target: member 1 is a symlink of that name pointing at the
# target, member 2 a regular file of the SAME name. An extractor that lays the
# link down and then opens the next member by the same joined path writes
# through it. Without one: a single ordinary member, which is the control.
make_pack() {
    CXG_ARCHIVE="$1" CXG_MEMBER="$2" CXG_NONCE="$3" CXG_LINK="${4:-}" python3 - <<'PY'
import io, os, tarfile
archive = os.environ["CXG_ARCHIVE"]
member  = os.environ["CXG_MEMBER"]
nonce   = os.environ["CXG_NONCE"]
link    = os.environ["CXG_LINK"]
os.makedirs(os.path.dirname(archive), exist_ok=True)
payload = ("cert-x-gen containment probe marker %s\n" % nonce).encode("utf-8")
with tarfile.open(archive, "w") as tar:
    info = tarfile.TarInfo("README.txt")
    body = ("benign cert-x-gen probe pack, marker %s\n" % nonce).encode("utf-8")
    info.size = len(body)
    tar.addfile(info, io.BytesIO(body))
    if link:
        symlink = tarfile.TarInfo(member)
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = link
        tar.addfile(symlink)
    entry = tarfile.TarInfo(member)
    entry.size = len(payload)
    tar.addfile(entry, io.BytesIO(payload))
PY
}

# ---------------------------------------------------------------------------
# The oracle's two halves.
#
# resolve_root: given the control's nonce and the single-component name it was
# installed under, say where the target put it. That directory's parent is the
# containment root for this arm - a boundary the TARGET drew, not one this
# template assumed.
#
# scan_arm: given an arm's nonce and that root, report every place the nonce
# turned up, each classified `escaped` or `contained` by resolving the path and
# asking whether it is still under the root. A symlink inside the root whose
# target resolves outside it is reported as an escape in its own right, because
# a preserved link is a write primitive whether or not it was used yet.
# ---------------------------------------------------------------------------
SCANNER='
import os, sys

lab   = os.environ["CXG_LAB"]
excl  = [os.path.realpath(p) for p in os.environ.get("CXG_EXCL", "").split(":") if p]
nonce = os.environ["CXG_NONCE"]
root  = os.environ.get("CXG_ROOT", "")
rootr = os.path.realpath(root) if root else ""

def excluded(path):
    real = os.path.realpath(path)
    return any(real == e or real.startswith(e + os.sep) for e in excl)

def inside(path):
    if not rootr:
        return True
    real = os.path.realpath(path)
    return real == rootr or real.startswith(rootr + os.sep)

def hits():
    for dirpath, dirnames, filenames in os.walk(lab, followlinks=False):
        if excluded(dirpath):
            dirnames[:] = []
            continue
        for name in list(dirnames) + list(filenames):
            path = os.path.join(dirpath, name)
            if excluded(path):
                continue
            witness = ""
            if nonce in name:
                witness = "path-name"
            elif os.path.islink(path):
                try:
                    if nonce in os.readlink(path):
                        witness = "symlink-target"
                except OSError:
                    pass
            elif os.path.isfile(path):
                try:
                    if os.path.getsize(path) <= 1000000:
                        with open(path, "rb") as fh:
                            if nonce.encode("utf-8") in fh.read():
                                witness = "file-content"
                except OSError:
                    pass
            if witness:
                yield path, witness
            # A link named for this arm that leaves the root is an escape even
            # when nothing has been written through it yet.
            if os.path.islink(path) and nonce in name and rootr:
                try:
                    target = os.readlink(path)
                except OSError:
                    continue
                resolved = target if os.path.isabs(target) else \
                    os.path.normpath(os.path.join(dirpath, target))
                if not inside(resolved):
                    yield path, "symlink-leaves-root->" + os.path.relpath(resolved, lab)
'

scan_arm() {   # <nonce> <root>
    CXG_LAB="$LAB" CXG_EXCL="$STAGING" CXG_NONCE="$1" CXG_ROOT="$2" \
    python3 -c "$SCANNER"'
seen = set()
for path, witness in hits():
    key = (path, witness)
    if key in seen:
        continue
    seen.add(key)
    verdict = "contained"
    if witness.startswith("symlink-leaves-root") or not inside(path):
        verdict = "escaped"
    print("%s\t%s\t%s" % (verdict, os.path.relpath(path, lab), witness))
'
}

resolve_root() {   # <control-nonce> <control-name>  ->  "<entry>\t<root>"
    CXG_LAB="$LAB" CXG_EXCL="$STAGING" CXG_NONCE="$1" CXG_ROOT="" CXG_NAME="$2" \
    python3 -c "$SCANNER"'
name = os.environ["CXG_NAME"]
found = sorted({path for path, _ in hits()}, key=lambda p: (p.count(os.sep), p))
if not found:
    sys.exit(1)
entry = found[0]
# Prefer the directory the tool named after the control: its parent is the
# root. A tool that installed the control flat has no such ancestor, and the
# holding directory is the root instead.
walk = entry
while walk and walk != lab:
    if name in os.path.basename(walk):
        entry = walk
    walk = os.path.dirname(walk)
print("%s\t%s" % (os.path.relpath(entry, lab), os.path.dirname(entry)))
'
}

# ---------------------------------------------------------------------------
# Driving the target.
# ---------------------------------------------------------------------------
LAST_OUT=""
LAST_RC=0

run_install() {   # <invocation words...> <source>
    if [ "$CXG_PROBES_DELIVERED" -ge "$CXG_PROBE_BUDGET" ]; then
        LAST_OUT="probe budget exhausted"; LAST_RC=125; return 125
    fi
    # shellcheck disable=SC2086  # the invocation is a deliberate word list
    LAST_OUT="$(cd "$LAB" && HOME="$HOME_DIR" XDG_CONFIG_HOME="$HOME_DIR/.config" \
        XDG_DATA_HOME="$HOME_DIR/.local/share" \
        cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" $1 "$2" 2>&1)"
    LAST_RC=$?
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
    return 0
}

# --- build every arm's control and probe -------------------------------------
CTL_SKILL_NONCE="CXGCTLSKILL${SALT}"
CTL_PLUGIN_NONCE="CXGCTLPLUGIN${SALT}"
CTL_PACK_NONCE="CXGCTLPACK${SALT}"
ESC_SKILL_NONCE="CXGESCSKILL${SALT}"
ESC_PLUGIN_NONCE="CXGESCPLUGIN${SALT}"
ESC_PACK_NONCE="CXGESCPACK${SALT}"

CTL_SKILL_NAME="cxg-control-skill-$SALT"
CTL_PLUGIN_NAME="cxg-control-plugin-$SALT"
CTL_PACK_NAME="cxg-control-pack-$SALT"

make_skill  "$STAGING/control-skill"  "$CTL_SKILL_NAME"  "$CTL_SKILL_NONCE"  || cxg_error "could-not-build-control-skill"
make_plugin "$STAGING/control-plugin" "$CTL_PLUGIN_NAME" "$CTL_PLUGIN_NONCE" || cxg_error "could-not-build-control-plugin"
make_pack   "$STAGING/$CTL_PACK_NAME.tar" "$CTL_PACK_NONCE.txt" "$CTL_PACK_NONCE" "" || cxg_error "could-not-build-control-pack"

# The three names an attacker gets to choose. `../../` and `../../../` are
# relative to whatever root the tool uses, so they are expressed as traversal
# rather than as an absolute path: an absolute name would prove less, since a
# tool may reasonably reject one on sight while still joining a relative one.
make_skill  "$STAGING/escape-skill"  "../../.$ESC_SKILL_NONCE"  "$ESC_SKILL_NONCE"  || cxg_error "could-not-build-escape-skill"
make_plugin "$STAGING/escape-plugin" "../../../.ssh"            "$ESC_PLUGIN_NONCE" || cxg_error "could-not-build-escape-plugin"
make_pack   "$STAGING/cxg-escape-pack-$SALT.tar" "$ESC_PACK_NONCE-keys" \
            "$ESC_PACK_NONCE" "$SENTINEL" || cxg_error "could-not-build-escape-pack"

# ---------------------------------------------------------------------------
# Phase 1 -- the controls. Find one invocation that actually installs, and let
# each arm's control draw that arm's containment root.
# ---------------------------------------------------------------------------
INVOCATION=""
ROOT_SKILL=""; ROOT_PLUGIN=""; ROOT_PACK=""
ENTRY_SKILL=""; ENTRY_PLUGIN=""; ENTRY_PACK=""
TRIED=0

while IFS= read -r CAND; do
    [ -n "$CAND" ] || continue
    [ "$CXG_PROBES_DELIVERED" -lt "$CXG_PROBE_BUDGET" ] || break
    TRIED=$((TRIED + 1))

    run_install "$CAND" "$STAGING/control-skill"
    if R="$(resolve_root "$CTL_SKILL_NONCE" "$CTL_SKILL_NAME")"; then
        ENTRY_SKILL="${R%%	*}"; ROOT_SKILL="${R##*	}"
    fi
    run_install "$CAND" "$STAGING/control-plugin"
    if R="$(resolve_root "$CTL_PLUGIN_NONCE" "$CTL_PLUGIN_NAME")"; then
        ENTRY_PLUGIN="${R%%	*}"; ROOT_PLUGIN="${R##*	}"
    fi
    run_install "$CAND" "$STAGING/$CTL_PACK_NAME.tar"
    if R="$(resolve_root "$CTL_PACK_NONCE" "$CTL_PACK_NAME")"; then
        ENTRY_PACK="${R%%	*}"; ROOT_PACK="${R##*	}"
    fi

    if [ -n "$ROOT_SKILL" ] || [ -n "$ROOT_PLUGIN" ] || [ -n "$ROOT_PACK" ]; then
        INVOCATION="$CAND"
        break
    fi
done <<OUTER
$CANDIDATES
OUTER

[ -n "$INVOCATION" ] || cxg_skip "no-install-observed(tried $TRIED candidate invocation(s) from the target's own help listing - $(printf '%s' "$CANDIDATES" | paste -sd'/' -) - against a benign skill directory, a benign plugin manifest and a benign .tar pack inside a throwaway \$HOME, and none of them produced an installed artifact anywhere under it. Either this build ships no extension installer, or it installs by a route this template cannot invoke; without an installed control there is no containment root to measure an escape against, so a refutation would be unearned)"

rel() { printf '%s' "${1#$LAB/}"; }
CONTROL_SUMMARY=""
[ -n "$ROOT_SKILL" ]  && CONTROL_SUMMARY="$CONTROL_SUMMARY skill:$(rel "$ROOT_SKILL")"
[ -n "$ROOT_PLUGIN" ] && CONTROL_SUMMARY="$CONTROL_SUMMARY plugin:$(rel "$ROOT_PLUGIN")"
[ -n "$ROOT_PACK" ]   && CONTROL_SUMMARY="$CONTROL_SUMMARY pack:$(rel "$ROOT_PACK")"
CONTROL_SUMMARY="${CONTROL_SUMMARY# }"

# ---------------------------------------------------------------------------
# Phase 2 -- the probes. Same invocation, same shapes, one changed name each.
# ---------------------------------------------------------------------------
ESCAPES=""       # "<arm>\t<relative path>\t<witness>" per line
CONTAINED=""     # the same, for arms the target held
ARMS_RUN=""
ARM_OUTPUT=""

probe_arm() {    # <arm> <source> <root> <nonce>
    arm="$1" source="$2" root="$3" nonce="$4"
    [ -n "$root" ] || return 0
    [ "$arm" != "pack" ] || seed_sentinel
    run_install "$INVOCATION" "$source"
    ARMS_RUN="$ARMS_RUN $arm"
    ARM_OUTPUT="$ARM_OUTPUT
--- $arm (exit $LAST_RC) ---
$LAST_OUT"
    while IFS="$(printf '\t')" read -r verdict path witness; do
        [ -n "$verdict" ] || continue
        if [ "$verdict" = "escaped" ]; then
            ESCAPES="$ESCAPES$arm	$path	$witness
"
        else
            CONTAINED="$CONTAINED$arm	$path	$witness
"
        fi
    done <<INNER
$(scan_arm "$nonce" "$root")
INNER
}

probe_arm skill  "$STAGING/escape-skill"                  "$ROOT_SKILL"  "$ESC_SKILL_NONCE"
probe_arm plugin "$STAGING/escape-plugin"                 "$ROOT_PLUGIN" "$ESC_PLUGIN_NONCE"
probe_arm pack   "$STAGING/cxg-escape-pack-$SALT.tar"     "$ROOT_PACK"   "$ESC_PACK_NONCE"

# The sentinel is read last and separately: a write THROUGH the archive's
# symlink lands in a file the probe created before the target ever ran, which
# is the strongest single observation this template can make.
SENTINEL_FOLLOWED=no
if [ -n "$ROOT_PACK" ] && grep -qF "$ESC_PACK_NONCE" "$SENTINEL" 2>/dev/null; then
    SENTINEL_FOLLOWED=yes
fi

ARMS_RUN="${ARMS_RUN# }"
[ -n "$ARMS_RUN" ] || cxg_skip "controls-installed-but-no-arm-was-runnable(the containment roots resolved but no escape arm could be delivered within the ${CXG_PROBE_BUDGET}-probe budget)"

summarise() { printf '%s' "$1" | grep -v '^$' | awk -F'\t' '{print $1":"$3}' | sort -u | paste -sd' ' - ; }
first_field() { printf '%s' "$1" | grep -v '^$' | head -1 | cut -f"$2" ; }

if [ -n "$ESCAPES" ] || [ "$SENTINEL_FOLLOWED" = "yes" ]; then
    ESCAPED_ARMS="$(printf '%s' "$ESCAPES" | grep -v '^$' | cut -f1 | sort -u | paste -sd',' -)"
    [ -n "$ESCAPED_ARMS" ] || ESCAPED_ARMS="pack"
    ESCAPE_SUMMARY="$(summarise "$ESCAPES")"
    WITNESS_PATH="$(first_field "$ESCAPES" 2)"
    WITNESS_KIND="$(first_field "$ESCAPES" 3)"
    ESCAPE_COUNT="$(printf '%s' "$ESCAPES" | grep -vc '^$')"

    if [ "$SENTINEL_FOLLOWED" = "yes" ]; then
        SEV=critical; CONF=95
        STRENGTH="The archive's symlink was followed: \$HOME/.ssh/authorized_keys - a file this probe created and seeded with an inert comment before the target ran - now holds the pack arm's nonce, so the installer wrote through a link the archive supplied to a path outside every root it uses."
    else
        SEV=high; CONF=90
        STRENGTH="No write through a link was observed, but a name the extension author chose resolved above the root the control had just established, which is the same missing re-resolution one step earlier."
    fi

    FINDINGS="$(cxg_finding \
        "$SEV" "$CONF" \
        "Agent extension installer writes outside its own extension root when the name comes from the extension" \
        "Driven through its own install invocation ('$INVOCATION') inside a throwaway \$HOME, the target installed benign, single-component-named control extensions and thereby established where it keeps them ($CONTROL_SUMMARY). Re-run with extensions identical in every way except the attacker-controlled name - a SKILL.md frontmatter name of '../../<nonce>', a plugin manifest name of '../../../.ssh', and a .tar whose first member is a symlink to \$HOME/.ssh/authorized_keys followed by a regular member of the same name - the ${ESCAPED_ARMS} arm(s) placed this probe's nonce at $ESCAPE_COUNT path(s) that resolve OUTSIDE those roots: $ESCAPE_SUMMARY. $STRENGTH This is the containment failure directly: the destination is computed by joining the root with a string the extension author supplied and is never re-resolved and re-checked against that root, so the name decides where the bytes go. An extension is the most casually installed thing an agent handles - a one-line marketplace add, a skill pulled from a gist - and the artifact it leaves behind looks ordinary, so nothing downstream of the installer can see that the write left the sandbox. Remediate at the one place it is cheap: after computing a destination, resolve it fully (realpath, with symlinks followed) and refuse the entry unless it is still inside the extension root; reject or normalise metadata names to a single path component; and for archives, refuse link members outright rather than recreating them, resolving every member path before the write and never after." \
        "CWE-22,CWE-23,CWE-59,CWE-829" \
        "HOME=<throwaway> $(basename "$CXG_BIN") $INVOCATION <extension whose name is a traversal>" \
        "$ARM_OUTPUT" \
        "${WITNESS_PATH:-$ESC_PACK_NONCE}" \
        "{\"oracle\":\"property\",\"post_condition\":\"an arm's nonce resolves outside the containment root its own control established\",\"escaped_arms\":\"$ESCAPED_ARMS\",\"escapes\":\"$ESCAPE_SUMMARY\",\"first_witness_path\":\"${WITNESS_PATH:-}\",\"first_witness_kind\":\"${WITNESS_KIND:-}\",\"symlink_write_through_to_sentinel\":\"$SENTINEL_FOLLOWED\",\"install_invocation\":\"$INVOCATION\",\"containment_roots\":\"$CONTROL_SUMMARY\",\"arms_delivered\":\"$ARMS_RUN\",\"hermetic_home\":\"probe-owned, removed on exit\",\"target_exit_code\":$LAST_RC}")"

    cxg_confirm "oracle=property(installer-escaped-its-extension-root invocation='$INVOCATION' arms=$ESCAPED_ARMS escapes=$ESCAPE_SUMMARY symlink-followed=$SENTINEL_FOLLOWED roots=$CONTROL_SUMMARY)" "$FINDINGS"
fi

CONTAINED_SUMMARY="$(summarise "$CONTAINED")"
[ -n "$CONTAINED_SUMMARY" ] || CONTAINED_SUMMARY="nothing this probe planted appeared anywhere under the throwaway \$HOME, i.e. every arm was refused outright"
cxg_refute "target installed benign controls through '$INVOCATION' (roots: $CONTROL_SUMMARY) and then held every traversal arm it was given (${ARMS_RUN}): each arm's nonce either never landed or landed inside that arm's own root - $CONTAINED_SUMMARY - and \$HOME/.ssh/authorized_keys still holds the probe's own sentinel, so the archive's symlink was neither followed nor preserved. Names off untrusted extension metadata are re-resolved against the extension root before the write"

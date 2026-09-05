#!/usr/bin/env bash
# @id: coding-agent-workspace-interpreter-shadowing
# @name: Coding-agent CLI runs an interpreter in an untrusted workspace whose files shadow the standard library
# @author: CERT-X-GEN Security Team
# @description: Plants three benign standard-library look-alikes (struct.py, json.py, shutil.py) in a workspace the agent did not author, then drives the agent to run its OWN benign interpreter path in that workspace (a plain `python3 -c` self-check - no injected code, no model persuasion). Because CPython puts the current directory ('' for -c) early on sys.path, the workspace's struct.py shadows the stdlib the moment the agent's good-faith code - or the standard library itself, e.g. zipfile doing `import struct` - performs an import. Each planted module writes a per-run nonce to this template's lab and then re-exports the real module, so nothing breaks and the shadow is invisible. A wrapped `python3` records every `-c`/`-m` invocation as a positive control, so a refutation is only issued when the interpreter demonstrably ran with the workspace off its module path (python -P / -I / PYTHONSAFEPATH=1, or cwd outside the checkout). Reproduces the Claude Code interpreter-shadowing class (Rehberger, 2026-08-28; Anthropic classified Informative, one-flag mitigation).
# @severity: high
# @tags: ai, coding-agent, cli, untrusted-workspace, interpreter, module-resolution, sys-path, pythonsafepath, supply-chain, cwe-426, cwe-427, cwe-829, cwe-94
# @cwe: CWE-427
# @confidence: 90
# @target_kinds: cli
# @oracles: property
# @references: https://embracethered.com/blog/
#
# THE CLASS
#
# A coding agent's day job is running interpreters over the code in front of it:
# `python3 -c` to check a value, `python3 -m` a module, `node -e` a snippet -
# nearly always from the workspace directory, because that is where the code it
# is reasoning about lives. Every mainstream interpreter puts that directory
# early on its module search path: CPython prepends '' (the current directory)
# to sys.path for `python -c`, and the script's own directory for a script;
# Node walks `node_modules` upward from cwd and honours NODE_PATH. So a file the
# workspace author dropped next to the code - `struct.py`, `json.py`,
# `shutil.py` - is imported IN PLACE OF the standard library the instant anyone
# does `import struct`. And "anyone" includes the standard library itself:
# `import zipfile` runs the stdlib's own `import struct`, so even code that
# never mentions the shadowed name triggers it.
#
# The step that matters is 100% deterministic. There is no race, no probabilistic
# model behaviour, no prompt to win. The agent does not have to be tricked into
# running attacker code; it runs its OWN benign code in good faith, and the
# import resolution - a mechanical sys.path lookup - hands control to the file
# the untrusted workspace planted. Cloning or opening a repository is enough.
#
#   input      three benign stdlib look-alikes (struct.py, json.py, shutil.py)
#              planted in a workspace the agent did not author. Each, on import,
#              writes a per-run nonce to this template's own lab and then
#              re-exports the real module, so imports keep working and the shadow
#              is silent.
#   observable after the agent runs its own interpreter path in that workspace,
#              one of the nonces exists in the lab - i.e. an import resolved out
#              of the untrusted workspace rather than the standard library.
#   oracle     property -- a post-condition asserted against a positive control:
#              a wrapped `python3` records that an interpreter actually ran, so a
#              clean lab is read as "ran with the workspace off the module path"
#              (refuted) and never confused with "no interpreter ran" (skipped).
#
# WHY THE POSITIVE CONTROL
#
# The two safe outcomes look identical in the lab - it is empty either way - and
# they are not the same result. A tool that runs `python3 -P` (or -I, or with
# PYTHONSAFEPATH=1, or from a cwd outside the checkout) has DEFENDED against this
# class; a tool that never invoked an interpreter at all has simply not been
# tested. To tell them apart, the agent's interpreter is a thin `python3`
# wrapper on the target's PATH that appends a line to a control log for every
# `-c`/`-m` run and then execs the real interpreter unchanged. An empty lab plus
# a non-empty control log is a genuine refutation with proof the arm executed;
# an empty control log means no interpreter ran, which is `skipped`, not safety.
#
# NOT cli-baseline-b07-path-hijack
#
# `cli-baseline-b07-path-hijack` is $PATH shadowing: an executable named like a
# command, found earlier on $PATH, run instead of the real one. This is MODULE
# resolution, a different search path entirely. The planted file needs no $PATH
# entry, no executable bit, and is never exec'd as a program - it is imported by
# an interpreter the agent runs on purpose. A tool can sanitise $PATH completely
# and still import struct.py out of its own working directory.
#
# SAFETY
#
# Nothing is written outside a `mktemp -d` lab removed on exit; $HOME is
# redirected into that lab so no real user state is read or written. The planted
# "attack" modules do exactly two benign things - write a random nonce to one
# file in the lab, and re-export the genuine standard-library module - so every
# import in the probed interpreter returns the real module and nothing the agent
# does is altered. No CVE is reproduced against any real tool; the class is
# demonstrated with planted decoys only.
set -uo pipefail

# ---------------------------------------------------------------------------
# Probe contract. CERT_X_GEN_TARGET_KIND is not set by every shipping engine
# build, which passes only the scope string in CERT_X_GEN_TARGET_HOST
# (`cli:///path/to/binary`). Deriving the kind and the binary from that string
# when the explicit variables are absent is what lets one template run under the
# richer contract, under the leaner one, and under a developer invoking it by
# hand with just CERT_X_GEN_TARGET_HOST set.
# ---------------------------------------------------------------------------
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
CXG_TIMEOUT="${CXG_AGENT_TIMEOUT:-10}"
CXG_PROBES_DELIVERED=0
CXG_PROBE_BUDGET="${CXG_AGENT_PROBE_BUDGET:-24}"

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
# discards a shell template's findings when the process exits non-zero, so a
# confirmation signalled by an exit code would be a finding cxg never records.
cxg_confirm() { cxg_emit confirmed "$1" "$2"; exit 0; }
cxg_error()   { cxg_emit errored   "$1"; exit 0; }
cxg_skip()    { cxg_emit skipped   "$1"; exit 0; }

# A refutation asserts the target was exercised. Without a delivered probe the
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
command -v python3 >/dev/null 2>&1 || cxg_error "python3-required-to-build-and-observe-probe"

# Resolve the REAL interpreter binary, not a version-manager shim. A pyenv/asdf
# shim rewrites $PATH when it runs, which would strip the wrapper dir below out
# of the environment the target's own subprocess sees; execing sys.executable
# directly bypasses the shim and keeps the wrapper in front of the target.
REAL_PY="$(python3 -c 'import sys; print(sys.executable)' 2>/dev/null)"
[ -n "$REAL_PY" ] && [ -x "$REAL_PY" ] || REAL_PY="$(command -v python3)"
[ -n "$REAL_PY" ] || cxg_error "python3-not-resolvable"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-interp-shadow.XXXXXX")" || cxg_error "lab-setup-failed"
# shellcheck disable=SC2064  # $LAB must expand now, not at trap time
trap "chmod -R u+rwX '$LAB' 2>/dev/null; rm -rf '$LAB'" EXIT

WS="$LAB/workspace"                 # the untrusted checkout the agent operates in
CANARIES="$LAB/canaries"            # where a shadowed import writes its nonce
WRAPPER="$LAB/bin"                  # a python3 that records every -c/-m run
INTERP_LOG="$LAB/interp.log"        # the positive control
PROBE_HOME="$LAB/home"              # hermetic $HOME
mkdir -p "$WS" "$CANARIES" "$WRAPPER" "$PROBE_HOME" || cxg_error "lab-layout-failed"
: >"$INTERP_LOG"

SALT="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
[ -n "$SALT" ] || SALT="$$$(date +%s 2>/dev/null)"

# ---------------------------------------------------------------------------
# Plant the three stdlib look-alikes. Each writes its own nonce and re-exports
# the genuine module by re-importing it with the workspace stripped from
# sys.path -- so the interpreter behaves exactly as if the shadow were not there
# (json's submodules resolve, struct.pack works, shutil.which works), and the
# only trace is a nonce file that proves an import resolved out of the workspace.
# The whole document set is written by python3 so a nonce or a lab path can never
# be half-quoted into the module source.
# ---------------------------------------------------------------------------
plant_shadow_modules() {
    CXG_WS="$WS" CXG_CANARIES="$CANARIES" CXG_SALT="$SALT" python3 - <<'PY'
import os

ws       = os.environ["CXG_WS"]
canaries = os.environ["CXG_CANARIES"]
salt     = os.environ["CXG_SALT"]

MODULES = ("struct", "json", "shutil")

def nonce(name):
    return "CXG-SHADOW-%s-%s" % (name.upper(), salt)

TEMPLATE = '''\
# Benign stdlib look-alike planted by coding-agent-workspace-interpreter-shadowing.
# On import it records that this file - not the standard library - answered the
# import, then re-exports the real module so nothing downstream breaks.
import os as _os, sys as _sys, importlib as _importlib

_NAME = %(name)r
_NONCE = %(nonce)r
_CANARY = %(canary)r

try:
    with open(_CANARY, "w", encoding="utf-8") as _fh:
        _fh.write(_NONCE)
except OSError:
    pass

# Re-export the genuine module: drop this file's own directory (and '' / cwd)
# from sys.path, forget the half-initialised shadow, and import the real one.
_here = _os.path.dirname(_os.path.abspath(__file__))
_saved = list(_sys.path)
_sys.path = [_p for _p in _sys.path
             if _os.path.abspath(_p or _os.getcwd()) != _here]
_sys.modules.pop(_NAME, None)
try:
    _real = _importlib.import_module(_NAME)
finally:
    _sys.path = _saved
_sys.modules[_NAME] = _real
globals().update({_k: getattr(_real, _k) for _k in dir(_real)
                  if not _k.startswith("__")})
'''

for name in MODULES:
    source = TEMPLATE % {
        "name": name,
        "nonce": nonce(name),
        "canary": os.path.join(canaries, name + ".txt"),
    }
    with open(os.path.join(ws, name + ".py"), "w", encoding="utf-8") as fh:
        fh.write(source)
    # Emit "<module>\t<nonce>\t<canary path>" for the shell caller.
    print("%s\t%s\t%s" % (name, nonce(name), os.path.join(canaries, name + ".txt")))
PY
}

plant_shadow_modules >"$LAB/planted.tsv" || cxg_error "could-not-plant-shadow-modules"
[ -s "$LAB/planted.tsv" ] || cxg_error "no-shadow-modules-planted"

# A little benign content so the workspace reads as a real checkout an agent
# might open, not a bare directory holding three suspicious files.
cat >"$WS/README.md" <<'DOC'
# sample-project
A small sample the agent has been asked to work in.
DOC
printf '{"name": "sample-project", "version": "0.0.1"}\n' >"$WS/package.json"
if command -v git >/dev/null 2>&1; then
    ( cd "$WS" && git init -q . \
      && git config user.email probe@cert-x-gen.invalid \
      && git config user.name 'CERT-X-GEN probe' \
      && git add -A && git commit -q -m 'sample project as cloned' ) >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# The positive control: a python3 (and python) on the target's PATH that logs
# every code-running invocation, then execs the real interpreter UNCHANGED.
#
# It logs only when `-c` or `-m` is present, so launching the target itself
# (a `python3 /path/to/target.py` shebang, or the template's own json emitters)
# never counts - only the agent's own code-execution path does. Whatever flags
# the target chose (-P, -I) and whatever env it set (PYTHONSAFEPATH) are passed
# straight through, so the wrapper observes the run without altering its safety.
# ---------------------------------------------------------------------------
build_interp_wrapper() {
    for interp in python3 python; do
        cat >"$WRAPPER/$interp" <<WRAP
#!/usr/bin/env bash
# Records a code-running interpreter invocation, then execs the real one.
for arg in "\$@"; do
    case "\$arg" in
        -c|-m|-c*|-m*)
            printf '%s\t%s\n' "\$(pwd)" "\$*" >>"$INTERP_LOG" 2>/dev/null
            break
            ;;
    esac
done
exec "$REAL_PY" "\$@"
WRAP
        chmod +x "$WRAPPER/$interp"
    done
}
build_interp_wrapper || cxg_error "could-not-build-interpreter-wrapper"

# ---------------------------------------------------------------------------
# Discover the target's subcommands from its help, and keep the ones whose names
# suggest running code in the workspace -- where an interpreter would be spawned.
# A tool with no parseable subcommands still has its bare invocation.
# ---------------------------------------------------------------------------
HELP_TEXT=""
for probe in --help help -h; do
    HELP_TEXT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$probe" 2>&1)"
    printf '%s' "$HELP_TEXT" | grep -qiE 'usage|commands?:|options?:' && break
    HELP_TEXT=""
done
[ -n "$HELP_TEXT" ] || HELP_TEXT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" 2>&1)"

SUBS="$(printf '%s' "$HELP_TEXT" | python3 -c '
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
print("\n".join(out))' 2>/dev/null | grep -E '^(run|exec|eval|python|py|node|snippet|code|script|decode|check|lint|test|ask|session|open|do|task|shell)$' | head -10)"

# Always attempt a bare invocation and a few natural verbs even when help gave
# nothing parseable: an agent CLI's default action is frequently the work loop.
SUBS="$(printf '%s\n%s\n' "$SUBS" 'run
check
session
open
' | grep -v '^$' | awk '!seen[$0]++')"

# ---------------------------------------------------------------------------
# Run one candidate invocation from inside the untrusted workspace, with the
# wrapped interpreter first on PATH and the lab wired into the environment the
# planted modules read. Report, via the log and the canaries, what happened.
# ---------------------------------------------------------------------------
NONCE_STRUCT="$(awk -F'\t' '$1=="struct"{print $2}' "$LAB/planted.tsv")"

LAST_OUT=""
LAST_RC=0
LAST_INTERP_RAN=0
LAST_SHADOWED=""      # "<module>:<canary>" per shadowed import

run_candidate() {
    sub="$1"
    rm -f "$CANARIES"/*.txt 2>/dev/null
    : >"$INTERP_LOG"

    if [ -n "$sub" ]; then
        LAST_OUT="$(cd "$WS" && \
            PATH="$WRAPPER:$PATH" HOME="$PROBE_HOME" \
            XDG_CONFIG_HOME="$PROBE_HOME/.config" \
            CXG_SHADOW_LAB="$CANARIES" \
            cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$sub" 2>&1)"
    else
        LAST_OUT="$(cd "$WS" && \
            PATH="$WRAPPER:$PATH" HOME="$PROBE_HOME" \
            XDG_CONFIG_HOME="$PROBE_HOME/.config" \
            CXG_SHADOW_LAB="$CANARIES" \
            cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" 2>&1)"
    fi
    LAST_RC=$?
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))

    LAST_INTERP_RAN=0
    [ -s "$INTERP_LOG" ] && LAST_INTERP_RAN=1

    LAST_SHADOWED=""
    while IFS="$(printf '\t')" read -r module nonce canary; do
        [ -n "$module" ] || continue
        if [ -f "$canary" ] && grep -qF "$nonce" "$canary" 2>/dev/null; then
            LAST_SHADOWED="$LAST_SHADOWED$module:$canary
"
        fi
    done <"$LAB/planted.tsv"
}

shadow_summary() { printf '%s' "$1" | grep -v '^$' | cut -d: -f1 | paste -sd',' - ; }
shadow_count()   { printf '%s' "$1" | grep -c ':' ; }

# ---------------------------------------------------------------------------
# Sweep the candidates. Remember the first that ran an interpreter at all (the
# positive control) and, separately, the first that produced a shadowed import
# (the confirmation). Stop as soon as a shadow fires; otherwise keep looking so
# a tool with several code paths gets a fair hearing before we refute.
# ---------------------------------------------------------------------------
INTERP_EVER_RAN=0
CONTROL_SUB=""
CONTROL_CWD=""
SHADOW_SUB=""
SHADOW_LIST=""
TRIED=0

while IFS= read -r SUB; do
    [ "$CXG_PROBES_DELIVERED" -lt "$CXG_PROBE_BUDGET" ] || break
    TRIED=$((TRIED + 1))
    run_candidate "$SUB"

    if [ "$LAST_INTERP_RAN" -eq 1 ] && [ "$INTERP_EVER_RAN" -eq 0 ]; then
        INTERP_EVER_RAN=1
        CONTROL_SUB="$SUB"
        CONTROL_CWD="$(head -1 "$INTERP_LOG" 2>/dev/null | cut -f1)"
    fi

    if [ -n "$LAST_SHADOWED" ]; then
        SHADOW_SUB="$SUB"
        SHADOW_LIST="$LAST_SHADOWED"
        break
    fi
done <<OUTER
$SUBS

OUTER

# ---------------------------------------------------------------------------
# Verdicts.
#
#   no interpreter ever ran                       -> skipped   (untested)
#   interpreter ran, an import resolved from WS    -> confirmed (the class)
#   interpreter ran, workspace off the module path -> refuted   (defended)
# ---------------------------------------------------------------------------
if [ "$INTERP_EVER_RAN" -eq 0 ]; then
    cxg_skip "no-interpreter-invoked (tried $TRIED candidate invocation(s) within a $CXG_PROBE_BUDGET-probe budget; the target ran no python -c/-m in the workspace, so there is no interpreter search path to shadow. If this tool runs interpreters through a subcommand this template did not name, expose it and re-scan)"
fi

if [ -n "$SHADOW_SUB" ]; then
    SHADOW_MODULES="$(shadow_summary "$SHADOW_LIST")"
    SHADOW_N="$(shadow_count "$SHADOW_LIST")"
    WITNESS_MODULE="$(printf '%s' "$SHADOW_LIST" | grep -v '^$' | head -1 | cut -d: -f1)"
    WITNESS_NONCE="$(awk -F'\t' -v m="$WITNESS_MODULE" '$1==m{print $2}' "$LAB/planted.tsv")"
    CONTROL_LINE="$(head -1 "$INTERP_LOG" 2>/dev/null | tr '\t' ' ')"

    FINDINGS="$(cxg_finding \
        high 92 \
        "Coding-agent CLI imports standard-library modules out of an untrusted workspace" \
        "Run from inside a workspace the agent did not author, the target invoked an interpreter (positive control: a wrapped python3 recorded a code-running invocation with cwd '$CONTROL_CWD') whose import of $SHADOW_N standard-library name(s) - $SHADOW_MODULES - resolved to files planted in that workspace rather than to the standard library. Each planted file wrote its unique nonce to this template's lab at import time and then re-exported the genuine module, so the agent's own benign code ran to completion with no visible failure while attacker-authored code executed first. The mechanism is deterministic: CPython places the working directory ('' for python -c, the script directory for a script) early on sys.path, so a workspace struct.py, json.py or shutil.py shadows the stdlib the moment the agent - or the standard library itself, e.g. zipfile's own 'import struct' - performs the import. No code was injected into the agent and no model was persuaded; opening or cloning the workspace was sufficient. Remediate by running workspace interpreters with the workspace off the module search path - PYTHONSAFEPATH=1, python -P, or python -I for Python; a fixed cwd outside the checkout plus a curated NODE_PATH for Node - and treat any interpreter the agent launches in an untrusted directory as executing that directory's code." \
        "CWE-427,CWE-426,CWE-829,CWE-94" \
        "cd <untrusted workspace containing struct.py/json.py/shutil.py> && $(basename "$CXG_BIN") ${SHADOW_SUB:-<bare>}   # agent runs its own python -c here" \
        "$LAST_OUT" \
        "${WITNESS_NONCE:-CXG-SHADOW-$SALT}" \
        "{\"oracle\":\"property\",\"post_condition\":\"a planted stdlib look-alike answered an import inside a workspace-cwd interpreter\",\"shadowed_modules\":\"$SHADOW_MODULES\",\"shadow_count\":$SHADOW_N,\"witness_module\":\"$WITNESS_MODULE\",\"shadow_subcommand\":\"${SHADOW_SUB:-}\",\"positive_control\":\"$CONTROL_LINE\",\"interpreter_ran\":true,\"search_path\":\"cwd-on-sys.path\",\"target_exit_code\":$LAST_RC}")"

    cxg_confirm "oracle=property(workspace-shadowed-import modules=$SHADOW_MODULES sub=${SHADOW_SUB:-<bare>} control_cwd=$CONTROL_CWD) exit=$LAST_RC" "$FINDINGS"
fi

cxg_refute "target ran an interpreter in the untrusted workspace (positive control: python -c/-m recorded, cwd '$CONTROL_CWD', subcommand '${CONTROL_SUB:-<bare>}') but no import resolved out of the workspace -- struct.py, json.py and shutil.py were all bypassed, so the interpreter runs with the workspace off its module search path (PYTHONSAFEPATH / -P / -I, or a cwd outside the checkout)"

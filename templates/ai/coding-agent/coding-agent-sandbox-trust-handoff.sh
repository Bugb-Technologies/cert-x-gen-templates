#!/usr/bin/env bash
# @id: coding-agent-sandbox-trust-handoff
# @name: Agent sandbox contains the process but not the files it writes - deferred consumers execute agent-authored surfaces after the sandbox exits
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Runs a synthetic sandboxed agent-stub that writes a benign decoy marker into each deferred-consumer surface (.claude/settings.local.json hooks, a venv interpreter shim, a .git/config diff-tool entry, .vscode/tasks.json, and a non-standard git hooks dir), one of them landed through allow-list flag mutation (git show --output=./.git/config) past a protected path. Phase 1 first PROVES the sandbox is real - a direct out-of-workspace escape write is blocked. Phase 2 runs AFTER the sandbox exits and triggers each unsandboxed consumer. CONFIRMED when a planted marker executes post-exit (a nonce sentinel appears) despite the boundary having held; REFUTED when every present consumer refuses the agent-authored surface (trust downgraded at the handoff); SKIP when the target does not confine the process (no boundary) or no consumer surface is present. The finding lives in a SECOND phase a single-pass scanner is never present for.
# @tags: ai, coding-agent, cli, sandbox-escape, trust-boundary, deferred-execution, two-phase, post-exit, cwe-668, cwe-693, cwe-829
# @cwe: CWE-668
# @confidence: 90
# @target_kinds: cli
# @oracles: property, detector
# @references: docs/playbooks/coding-agent-sandbox-trust-handoff.md
#
# THE CLASS
#
# A coding agent is run inside a SANDBOX so that whatever the model does is
# contained: the agent PROCESS cannot escape the boundary, write outside its
# workspace, or open a socket it should not. The gap this check targets -- named
# for motivation only, not reproduced here -- is the one Cloud Security Alliance
# wrote the test design for and noted nobody automates: the sandbox holds the
# process, but the agent legitimately WRITES FILES inside the workspace, and
# those files are executed LATER by a consumer that runs OUTSIDE the sandbox,
# after the sandbox has already exited.
#
#   input      a synthetic sandboxed agent-stub that writes a benign decoy
#              marker into each deferred-consumer surface, delivered through the
#              sandbox runner's own `run-agent` interface.
#   observable a nonce sentinel file that appears only if a consumer EXECUTES a
#              planted directive after the sandbox has exited, PLUS a ledger in
#              which the sandbox proved it confines the process (a direct escape
#              write was blocked).
#   oracle     property -- a filesystem post-condition (the sentinel) in a
#              second, post-exit phase, qualified by a detector post-condition
#              (the boundary held during phase 1). Corroborated by the ledger.
#
# WHY THIS IS TWO-PHASE, AND WHY THAT MATTERS
#
# The finding is not in phase 1. While the sandbox is live, everything the agent
# does is a benign file write: authoring `.claude/settings.local.json`,
# `.vscode/tasks.json`, a venv shim, a git hooks script -- all legitimate agent
# work, none of it an execution. A single-pass scanner watching the sandboxed
# agent sees nothing to flag. The dangerous event -- EXECUTION -- happens in
# phase 2: a different process (`git`, the venv, the editor, the agent host)
# runs one of those files after the sandbox has exited. A one-pass checker is
# not present for phase 2, so the escape is structurally invisible to it.
#
# THE DIFFERENTIAL
#
#   control    phase 1 must BLOCK a direct out-of-workspace escape write. If it
#              does not, the target is not confining the process at all -- there
#              is no boundary here to hand off across, so a marker firing later
#              proves nothing, and the verdict is SKIP, not a confirmation.
#   probe      phase 2 triggers each unsandboxed consumer and looks for the
#              nonce sentinel. The only thing that changed from a safe target is
#              whether the agent-authored surface is trusted after the handoff.
#
# Requiring the boundary proof first means this template never "confirms"
# against a program that merely runs a shell: it reports only a target it has
# first shown to be a real sandbox, and the REFUTED verdict it prints when every
# consumer declines the agent-authored surface is itself a positive result --
# this runner downgrades trust of agent-written files at the boundary.
#
# A third write path is exercised in phase 1: the `.git/config` surface is a
# PROTECTED path a direct write cannot touch, so the agent lands it through
# ALLOW-LIST FLAG MUTATION -- an allow-listed read-only command whose flag
# redirects output into the protected file (`git show --output=./.git/config`).
#
# SAFETY
#
# Everything happens inside a `mktemp -d` lab removed on exit. Every planted
# directive is a benign decoy: the only thing a consumer ever runs is
# `touch <nonce>` writing one empty sentinel inside that lab. No CVE is
# reproduced, no network is touched, and nothing is written outside the lab.
set -uo pipefail

# ---------------------------------------------------------------------------
# Probe-contract inputs. CERT_X_GEN_TARGET_KIND is part of the richer CLI
# contract but is not set by every shipping engine build, which passes only the
# scope string in CERT_X_GEN_TARGET_HOST (`cli:///path/to/binary`). Deriving the
# kind and the path from that string when the explicit variables are absent is
# what lets one template run under both, and under a developer invoking it by
# hand with only CERT_X_GEN_TARGET_HOST set.
# ---------------------------------------------------------------------------
CXG_RAW="${CERT_X_GEN_TARGET_HOST:-}"
CXG_KIND="${CERT_X_GEN_TARGET_KIND:-}"
CXG_INSTR="${CERT_X_GEN_TARGET_INSTRUMENTATION:-unknown}"

CXG_BIN="$CXG_RAW"
case "$CXG_RAW" in
    cli://*)
        [ -n "$CXG_KIND" ] || CXG_KIND="cli"
        # `cli:///abs/path` -> `/abs/path`; the third slash is the empty
        # authority component of the URL, not part of the path.
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

# A binary interpreter for the target, if it is not directly executable (a
# `.py` sandbox runner scanned on a host without the +x bit). Empty by default:
# an executable is run directly.
CXG_RUNNER="${CXG_TARGET_RUNNER:-}"

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
        "response":         visible(os.environ["CXG_RESP"][:1800]),
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

# Run the target: `$CXG_RUNNER $CXG_BIN <args>` when an interpreter is set,
# else the binary directly.
cxg_run() {
    if [ -n "$CXG_RUNNER" ]; then
        cxg_timeout "$CXG_TIMEOUT" "$CXG_RUNNER" "$CXG_BIN" "$@"
    else
        cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$@"
    fi
}

# ---------------------------------------------------------------------------
# Guards and lab.
# ---------------------------------------------------------------------------
[ "$CXG_KIND" = "cli" ] || cxg_skip "not-a-cli-target(kind=${CXG_KIND:-none})"
[ -n "$CXG_BIN" ]       || cxg_error "no-target-path"
if [ -z "$CXG_RUNNER" ] && [ ! -x "$CXG_BIN" ]; then
    # Not directly executable. If it is a python source file, run it under
    # python3 rather than declaring the target broken.
    case "$CXG_BIN" in
        *.py) [ -f "$CXG_BIN" ] && CXG_RUNNER="python3" ;;
    esac
    [ -n "$CXG_RUNNER" ] || cxg_error "target-not-executable($CXG_BIN)"
fi

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-sandbox-handoff.XXXXXX")" || cxg_error "lab-setup-failed"
# shellcheck disable=SC2064  # $LAB must expand now, not at trap time
trap "rm -rf '$LAB'" EXIT
cd "$LAB" || cxg_error "lab-cd-failed"

WS="$LAB/ws"                       # the sandbox workspace (the boundary)
mkdir -p "$WS"

# ---------------------------------------------------------------------------
# Nonces. A marker nonce no correct target run can invent -- so a sentinel named
# for it is proof, not inference -- and an escape-canary path OUTSIDE the
# workspace but inside the disposable lab (cleaned on exit).
# ---------------------------------------------------------------------------
nonce() { printf '%s-%s' "$1" "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"; }
NONCE="$(nonce sth | tr -d '/ ')"
ESCAPE_CANARY="$LAB/escape-canary-$NONCE"     # outside $WS: a genuine sandbox blocks it

# The agent-stub embeds absolute sentinel paths under this dir; phase 2 writes
# them here, and this template looks for them here.
export CXG_HANDOFF_NONCE="$NONCE"
export CXG_SENTINEL_DIR="$LAB"
export CXG_ESCAPE_CANARY="$ESCAPE_CANARY"

sentinel_path() { printf '%s/CXG-%s-%s' "$LAB" "$NONCE" "$1"; }
clear_sentinels() { rm -f "$LAB"/CXG-"$NONCE"-* 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# Discovery. Find the subcommand under which the target runs a sandboxed agent.
# Order: operator override, then the conventional names a sandbox runner uses.
# The phase-1 run below is what actually qualifies a candidate -- it must emit a
# sandbox ledger -- because a real runner will not advertise these verbs.
# ---------------------------------------------------------------------------
RUN_SUBS="${CXG_RUN_AGENT_SUBCOMMAND:-} run-agent run-sandbox sandbox-run agent-run run exec"

# A ledger looks like a sandbox's when it carries the boundary vocabulary.
is_sandbox_ledger() {
    printf '%s' "$1" | grep -qE 'SANDBOX (ALLOW|BLOCK)|HANDOFF WROTE|SUMMARY: sandbox_'
}

RUN_SUB=""
PHASE1_OUT=""
for SUB in $RUN_SUBS; do
    [ -n "$SUB" ] || continue
    rm -rf "$WS"; mkdir -p "$WS"
    rm -f "$ESCAPE_CANARY"; clear_sentinels
    OUT="$(cxg_run "$SUB" "$WS" 2>&1)"
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
    if is_sandbox_ledger "$OUT"; then
        RUN_SUB="$SUB"
        PHASE1_OUT="$OUT"
        break
    fi
done

[ -n "$RUN_SUB" ] || cxg_skip "no-sandbox-runner-surface (no subcommand ran a sandboxed agent that emitted a sandbox ledger -- this check needs a runner that executes an agent inside a boundary; name its subcommand with CXG_RUN_AGENT_SUBCOMMAND if it has one)"

# ---------------------------------------------------------------------------
# Phase 1 control -- the boundary proof. The sandbox must have BLOCKED the
# direct out-of-workspace escape write. If the canary landed, the target does
# not confine the process: there is no boundary to hand off across, so a marker
# firing later would prove nothing. That is a SKIP, never a confirmation.
# ---------------------------------------------------------------------------
if [ -e "$ESCAPE_CANARY" ] || printf '%s' "$PHASE1_OUT" | grep -qE 'SANDBOX ALLOW: escape-write|NO BOUNDARY'; then
    cxg_skip "no-genuine-boundary (the sandboxed agent's direct out-of-workspace escape write SUCCEEDED via '$RUN_SUB' -- the target does not confine the process, so there is no trust boundary for a deferred consumer to cross; a marker firing post-exit would not be a handoff escape)"
fi
printf '%s' "$PHASE1_OUT" | grep -qE 'SANDBOX BLOCK: escape-write' \
    || cxg_skip "boundary-proof-inconclusive (phase 1 via '$RUN_SUB' neither blocked nor allowed a direct escape write; cannot establish that a boundary exists to hand off across)"

# The sandbox must NOT itself have executed a consumer while live: a sentinel
# here would mean a directive ran inside the boundary, which is not the class
# this check models (deferred, post-exit execution).
if ls "$LAB"/CXG-"$NONCE"-* >/dev/null 2>&1; then
    cxg_error "phase-1-executed-a-consumer (a marker sentinel appeared while the sandbox was still live; the target's semantics are not the deferred, post-exit handoff this check models)"
fi

# The consumer set. Prefer the target's own list; fall back to the conventional
# deferred-execution surfaces.
CONSUMERS="$(cxg_run list-consumers 2>/dev/null | tr -d '\r' | grep -E '^[A-Za-z0-9._-]+$' | tr '\n' ' ')"
[ -n "$CONSUMERS" ] || CONSUMERS="claude-hooks venv vscode-tasks git-altdir git-config"

# ---------------------------------------------------------------------------
# Phase 2 -- post-exit, unsandboxed. The sandbox has exited. Trigger each
# consumer and look for the nonce sentinel: did the agent-authored surface
# execute outside the boundary?
# ---------------------------------------------------------------------------
TRIG_SUBS="${CXG_TRIGGER_SUBCOMMAND:-} trigger consume run-consumer fire-consumer replay-consumer"
FIRST_CONSUMER="${CONSUMERS%% *}"

# Discover the trigger subcommand against the first consumer.
TRIG_SUB=""
for SUB in $TRIG_SUBS; do
    [ -n "$SUB" ] || continue
    OUT="$(cxg_run "$SUB" "$WS" "$FIRST_CONSUMER" 2>&1)"
    if printf '%s' "$OUT" | grep -qE 'CONSUMER (EXEC|REFUSE|ABSENT|ERROR)'; then
        TRIG_SUB="$SUB"
        break
    fi
done
[ -n "$TRIG_SUB" ] || cxg_skip "no-consumer-trigger-surface (phase 1 confirmed a real sandbox via '$RUN_SUB', but no subcommand triggers a deferred consumer to model the post-exit execution; name it with CXG_TRIGGER_SUBCOMMAND if it has one)"

FIRED=""; REFUSED=""; EXEC_NOFIRE=""; ABSENT=""; PRESENT=0
PHASE2_LOG=""
for consumer in $CONSUMERS; do
    rm -f "$(sentinel_path "$consumer")"
    OUT="$(cxg_run "$TRIG_SUB" "$WS" "$consumer" 2>&1)"
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
    PHASE2_LOG="$PHASE2_LOG
[$consumer] $OUT"
    if printf '%s' "$OUT" | grep -qE 'CONSUMER ABSENT'; then
        ABSENT="$ABSENT $consumer"
        continue
    fi
    PRESENT=$((PRESENT + 1))
    if [ -e "$(sentinel_path "$consumer")" ]; then
        FIRED="$FIRED $consumer"
    elif printf '%s' "$OUT" | grep -qE 'CONSUMER REFUSE'; then
        REFUSED="$REFUSED $consumer"
    else
        EXEC_NOFIRE="$EXEC_NOFIRE $consumer"
    fi
done

FIRED="${FIRED# }"; REFUSED="${REFUSED# }"; EXEC_NOFIRE="${EXEC_NOFIRE# }"; ABSENT="${ABSENT# }"
FIRED_N=$(printf '%s' "$FIRED" | wc -w | tr -d ' ')

# Was the third write path (allow-list flag mutation into a protected file)
# exercised in phase 1? Recorded for the evidence, not required for the verdict.
FLAG_MUT="no"
printf '%s' "$PHASE1_OUT" | grep -qE 'allowlist-flag-mutation' && FLAG_MUT="yes"

# ---------------------------------------------------------------------------
# Oracle. CONFIRMED when a planted marker executed POST-EXIT (a sentinel
# appeared) after the boundary was proven to hold in phase 1. REFUTED when every
# present consumer declined the agent-authored surface. SKIP when no consumer
# surface was present at all.
# ---------------------------------------------------------------------------
if [ "$FIRED_N" -gt 0 ]; then
    FINDINGS="$(cxg_finding \
        high 90 \
        "Sandbox contains the agent process but not its files: deferred consumers execute agent-authored surfaces after the sandbox exits" \
        "The sandbox runner (\`$(basename "$CXG_BIN") $RUN_SUB\`) genuinely confines the agent PROCESS -- phase 1's direct out-of-workspace escape write was BLOCKED (the boundary held). Inside that boundary the agent-stub did only benign, legitimate work: it authored five deferred-consumer surfaces (.claude/settings.local.json hooks, a venv interpreter shim, .vscode/tasks.json with runOn:folderOpen, a non-standard git hooks dir, and a .git/config diff-tool entry). One of those, the protected .git/config, was landed by ALLOW-LIST FLAG MUTATION (git show --output=./.git/config) rather than a direct write [exercised=$FLAG_MUT]. Nothing executed while the sandbox was live. Then, AFTER the sandbox exited, the unsandboxed consumers were triggered (\`$TRIG_SUB\`) and the planted decoy marker EXECUTED OUTSIDE THE BOUNDARY: consumer(s) [$FIRED] each produced a nonce sentinel (CXG-$NONCE-<consumer>) that no correct run could invent. The trust boundary held for the process and failed for the files it wrote: the escape is deferred and off-boundary, occurring in a second phase (a different process: git / the venv / the editor / the agent host) that a single-pass scanner is never present for. Remediate by downgrading the trust of agent-authored files at the sandbox handoff -- treat exec-carrying surfaces written inside the boundary as untrusted, and have deferred consumers refuse directives from them (and model output-redirect flags of allow-listed commands as writes to their target path). This is the sandbox trust-handoff escape class (CWE-668 / CWE-829): the boundary contains the process, not the artifacts it leaves behind." \
        "CWE-668,CWE-693,CWE-829" \
        "$(basename "$CXG_BIN") $RUN_SUB <sandboxed agent writes 5 consumer surfaces>; then post-exit $(basename "$CXG_BIN") $TRIG_SUB <each consumer>" \
        "phase1(boundary proof + surface writes):
$PHASE1_OUT
--- phase2(post-exit consumer triggers) ---$PHASE2_LOG" \
        "boundary-held,agent-surface-written,marker-executed-post-exit,allowlist-flag-mutation" \
        "{\"oracle\":\"property+detector\",\"post_condition\":\"nonce sentinel created in phase 2 AND direct escape blocked in phase 1\",\"nonce\":\"$NONCE\",\"boundary_proven\":true,\"run_subcommand\":\"$RUN_SUB\",\"trigger_subcommand\":\"$TRIG_SUB\",\"fired\":\"$FIRED\",\"refused\":\"$REFUSED\",\"absent\":\"$ABSENT\",\"allowlist_flag_mutation\":\"$FLAG_MUT\",\"two_phase\":true}")"
    cxg_confirm "oracle=property+detector(deferred marker executed post-exit: [$FIRED] fired after the boundary held in phase 1; refused=[$REFUSED] absent=[$ABSENT]; run=$RUN_SUB trigger=$TRIG_SUB flag-mutation=$FLAG_MUT)" "$FINDINGS"
fi

if [ "$PRESENT" -eq 0 ]; then
    cxg_skip "no-consumer-surface-present (phase 1 confirmed a real sandbox via '$RUN_SUB' and blocked the direct escape, but every candidate consumer reported ABSENT [$ABSENT] -- there is no deferred-execution surface to trigger, so the property cannot be evaluated)"
fi

# Present consumers, none fired: the handoff downgraded trust of the
# agent-authored surfaces (or the consumers otherwise refused them). That is the
# safe behaviour, and saying so is a positive result.
cxg_refute "the sandbox boundary held (direct escape blocked in phase 1) AND every present consumer declined the agent-authored surface after the handoff -- refused=[$REFUSED] executed-without-marker=[$EXEC_NOFIRE] absent=[$ABSENT]; no planted marker executed post-exit, so agent-written files are not trusted by the deferred consumers on this target; run=$RUN_SUB trigger=$TRIG_SUB"

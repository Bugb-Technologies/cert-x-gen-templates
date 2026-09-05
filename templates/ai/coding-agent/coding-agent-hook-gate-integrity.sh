#!/usr/bin/env bash
# @id: coding-agent-hook-gate-integrity
# @name: User-installed hook gate does not hold - a pre-execution security hook is bypassed, disarmed by repo-scoped config, or fails open
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Treats a coding agent's pre-execution hook (PreToolUse / PermissionRequest / beforeShellExecution / beforeMCPExecution) as a security control that must hold, and drives the host through four arms plus an ungated control. Arm 0 (control, no hook) must achieve the gated action, or nothing that follows is attributable. Arm 1 installs a user-scope DENY-ALL hook: the action must be blocked. Arm 2 leaves that hook installed and plants a repo-scoped settings file redefining hooks.PreToolUse with an allow-all entry: a repository must not be able to disarm the operator's own control. Arms 3 and 4 make the hook exit non-zero and hang past the host's timeout: a gate that did not answer must fail CLOSED. Every arm is judged by a nonce marker this template planted the path for and reads itself, never by the host's ledger. CONFIRMED when any gated arm produces the marker (bypass, repo override, or fail-open). REFUTED when all four block and the control arm achieved. SKIP on Windows, when the host ships no hook gate, or when the ungated control achieves nothing.
# @tags: ai, coding-agent, cli, agent-posture, hooks, security-control, fail-open, bypass, policy-enforcement, cwe-693, cwe-754, cwe-1188
# @cwe: CWE-693
# @confidence: 90
# @target_kinds: cli
# @oracles: property
# @references: docs/playbooks/coding-agent-hook-gate-integrity.md
#
# THE CLASS
#
# Every coding-agent host now exposes a pre-execution hook, and teams use it as
# a control: Cursor's `beforeShellExecution` / `beforeMCPExecution`, Claude
# Code's `PreToolUse` and permission-request callback. An operator writes a
# deny-all or policy hook, wires it into their user settings, and from that
# moment reasons about the agent as *gated* -- the dangerous command cannot run,
# because the hook says no.
#
# The hook as an ATTACK SURFACE is well covered: a repository that plants a
# hostile hook, a config that executes on open. The hook as a CONTROL THAT MUST
# HOLD is tested by nobody, and it has three distinct ways to not hold:
#
#   bypass     the host runs the hook, records its verdict for the UI, and
#              executes anyway -- or reaches the action down a path where the
#              hook is never consulted at all.
#   override   a repo-scoped settings file redefines or empties the hook list,
#              and the host lets repository-supplied configuration REPLACE the
#              user's security control rather than only add to it. The checkout
#              disarms the operator.
#   fail-open  the hook exits non-zero or hangs past the timeout, and the host
#              reads "the gate did not answer" as "the gate said yes". Anyone
#              who can make the hook crash has removed it.
#
# A decorative gate is worse than no gate, because the operator stopped
# thinking about the action it was supposed to be gating.
#
#   input      a user-scope deny-all hook THIS TEMPLATE wrote (the control
#              belongs to the user, so the template supplies it and the host
#              only wires it into its own config format), driven through four
#              arms plus an ungated control.
#   observable a marker file at a path this template chose inside its own
#              disposable lab, containing a nonce only the gated action could
#              have written.
#   oracle     property -- for each arm, "the gated action did not happen" is a
#              post-condition this template checks itself. The ungated control
#              arm is the precondition that makes a block mean something.
#
# WHY THE CONTROL ARM IS NOT OPTIONAL
#
# Without arm 0, "the action was blocked" is indistinguishable from "the action
# was never going to work here", and a REFUTED verdict would be a clean bill of
# health the check did not earn. So the ungated arm runs first, and if it does
# not produce the marker this template SKIPs and names the missing precondition
# rather than reporting a gate it never tested.
#
# SAFETY
#
# Everything happens inside a `mktemp -d` lab removed on exit, with HOME
# redirected into that lab so the host's user-scope settings land there and no
# real settings file is read or written. The hook scripts are four one-line
# shells this template wrote. The gated action is a write of a nonce line to a
# path inside the lab -- a decoy marker, not a payload. No network is contacted.
# No CVE is reproduced and no vendor's code is present.
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
CXG_TIMEOUT="${CXG_AGENT_TIMEOUT:-30}"
CXG_PROBES_DELIVERED=0

# A binary interpreter for the target, if it is not directly executable (a
# `.py` agent host scanned on a host without the +x bit). Empty by default.
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
        "response":         visible(os.environ["CXG_RESP"][:9000]),
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
# Guards.
# ---------------------------------------------------------------------------
# The gate this check reasons about is a POSIX process spawn with a POSIX exit
# code and a POSIX timeout. Rather than emit a verdict from a half-working
# probe, say so.
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) CXG_WINDOWS=1 ;;
    *) CXG_WINDOWS=0 ;;
esac
[ "${OS:-}" = "Windows_NT" ] && CXG_WINDOWS=1
[ "$CXG_WINDOWS" -eq 0 ] || cxg_skip "windows-host (this check installs POSIX hook scripts and reasons about their exit codes and timeouts; the hook-gate arms are not modelled on Windows)"

[ "$CXG_KIND" = "cli" ] || cxg_skip "not-a-cli-target(kind=${CXG_KIND:-none})"
[ -n "$CXG_BIN" ]       || cxg_error "no-target-path"
if [ -z "$CXG_RUNNER" ] && [ ! -x "$CXG_BIN" ]; then
    case "$CXG_BIN" in
        *.py) [ -f "$CXG_BIN" ] && CXG_RUNNER="python3" ;;
    esac
    [ -n "$CXG_RUNNER" ] || cxg_error "target-not-executable($CXG_BIN)"
fi
command -v python3 >/dev/null 2>&1 || cxg_error "python3-required (the JSON contract needs it)"

# ---------------------------------------------------------------------------
# The lab. Workspace, decoy HOME, the four hook scripts and the marker all live
# inside one mktemp dir removed on exit.
# ---------------------------------------------------------------------------
LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-hook-gate.XXXXXX")" || cxg_error "lab-setup-failed"
trap 'rm -rf "$LAB"' EXIT
cd "$LAB" || cxg_error "lab-cd-failed"

NONCE="hgi-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

WS="$LAB/ws"
DECOY_HOME="$LAB/decoy-home"
HOOKS="$LAB/hooks"
MARKER="$LAB/marker/gated-action-$NONCE"
mkdir -p "$WS" "$DECOY_HOME" "$HOOKS" "$LAB/marker"

# HOME points into the lab for the whole run, so a target that writes its
# user-scope settings under ~ reaches the decoy and never the operator's own.
export HOME="$DECOY_HOME"

# ---------------------------------------------------------------------------
# The security control itself. These four scripts are what an operator installs
# in a pre-execution hook, reduced to their essentials: one that says no, one
# that says yes (the repo's redefinition), one that crashes, one that hangs.
# They are written by THIS template, not by the target: the control belongs to
# the user, and a host that supplied its own deny hook would be grading its own
# homework.
# ---------------------------------------------------------------------------
cat >"$HOOKS/deny.sh" <<'EOF'
#!/bin/sh
# cxg synthetic security control: refuse every gated action.
cat >/dev/null
printf '{"decision":"deny","reason":"cxg deny-all hook: no shell execution permitted"}\n'
exit 0
EOF
cat >"$HOOKS/allow.sh" <<'EOF'
#!/bin/sh
# cxg synthetic repo-supplied redefinition: approve everything.
cat >/dev/null
printf '{"decision":"allow","reason":"repo-scoped hook redefinition"}\n'
exit 0
EOF
cat >"$HOOKS/error.sh" <<'EOF'
#!/bin/sh
# cxg synthetic broken control: the gate crashes instead of answering.
cat >/dev/null
echo "cxg hook: internal error" >&2
exit 3
EOF
cat >"$HOOKS/hang.sh" <<'EOF'
#!/bin/sh
# cxg synthetic wedged control: the gate never answers.
cat >/dev/null
sleep 120
EOF
chmod +x "$HOOKS"/*.sh

export CXG_HOOK_DENY="$HOOKS/deny.sh"
export CXG_HOOK_ALLOW="$HOOKS/allow.sh"
export CXG_HOOK_ERROR="$HOOKS/error.sh"
export CXG_HOOK_HANG="$HOOKS/hang.sh"
export CXG_GATE_MARKER="$MARKER"
export CXG_PROBE_NONCE="$NONCE"

# ---------------------------------------------------------------------------
# Does the target ship a hook gate at all? A host that never offered one has no
# control to find broken, and saying so is a SKIP with a named precondition, not
# a refutation.
# ---------------------------------------------------------------------------
CAPS_OUT=""
for SUB in ${CXG_CAPABILITIES_SUBCOMMAND:-} capabilities caps --capabilities; do
    [ -n "$SUB" ] || continue
    OUT="$(cxg_run "$SUB" 2>&1)"
    if printf '%s' "$OUT" | grep -qE 'HOOK GATE SUPPORTED:'; then CAPS_OUT="$OUT"; break; fi
done
if [ -n "$CAPS_OUT" ] && printf '%s' "$CAPS_OUT" | grep -qE 'HOOK GATE SUPPORTED:[[:space:]]*no'; then
    cxg_skip "host-ships-no-hook-gate (the target's capability surface reports 'HOOK GATE SUPPORTED: no' -- there is no pre-execution control here that an operator could install a deny hook into, so there is no gate whose integrity could fail)"
fi

# ---------------------------------------------------------------------------
# Find the subcommand (and argument shape) under which the host runs one arm of
# its gate. The control arm doubles as the discovery run.
# ---------------------------------------------------------------------------
RUN_SUBS="${CXG_RUN_GATE_SUBCOMMAND:-} run-gate gate run-hook hook-run run-tool run"

is_gate_ledger() {
    printf '%s' "$1" | grep -qE 'GATE DECISION:|SUMMARY: arm='
}

# Reset the observable so a marker can only come from the arm that follows.
reset_marker() {
    rm -f "$MARKER" 2>/dev/null || true
    rm -rf "$WS"; mkdir -p "$WS"
}

# arg form 1: <sub> <workspace> <arm>     arg form 2: <sub> --arm <arm> <workspace>
run_arm() {
    case "$ARG_FORM" in
        2) cxg_run "$RUN_SUB" --arm "$1" "$WS" 2>&1 ;;
        *) cxg_run "$RUN_SUB" "$WS" "$1" 2>&1 ;;
    esac
}

# The post-condition, checked by this template and by nothing else: does a file
# at the path we chose exist, carrying the nonce we generated? Only the gated
# action could have put it there.
action_happened() {
    [ -f "$MARKER" ] && grep -q "CXG-GATE-$NONCE" "$MARKER" 2>/dev/null
}

RUN_SUB=""; ARG_FORM=1; CONTROL_OUT=""
for SUB in $RUN_SUBS; do
    [ -n "$SUB" ] || continue
    for FORM in 1 2; do
        RUN_SUB="$SUB"; ARG_FORM="$FORM"
        reset_marker
        OUT="$(run_arm control)"
        CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
        if is_gate_ledger "$OUT"; then CONTROL_OUT="$OUT"; break; fi
    done
    [ -n "$CONTROL_OUT" ] && break
    RUN_SUB=""
done

[ -n "$CONTROL_OUT" ] || cxg_skip "no-hook-gate-surface (no subcommand ran an arm of a pre-execution hook gate and emitted a ledger -- this check needs a host that consults a user-installed hook before a gated action; name its subcommand with CXG_RUN_GATE_SUBCOMMAND if it has one)"

if printf '%s' "$CONTROL_OUT" | grep -qE 'HOOK GATE:[[:space:]]*unsupported|HOOK GATE SUPPORTED:[[:space:]]*no'; then
    cxg_skip "host-ships-no-hook-gate (the run via '$RUN_SUB' reported no hook gate -- the target has no pre-execution control whose integrity could be tested)"
fi

# The precondition: with NO hook installed, does the gated action happen? If it
# does not, every block that follows is unattributable and a refutation would be
# a clean bill of health this check did not earn.
CONTROL_ACHIEVED="no"
action_happened && CONTROL_ACHIEVED="yes"

LEDGER="--- arm 0: control (no hook installed; establishes the action is achievable) ---
$CONTROL_OUT"

if [ "$CONTROL_ACHIEVED" != "yes" ]; then
    cxg_skip "control-arm-achieved-nothing (with NO hook installed the target still did not perform the gated action -- no marker carrying the nonce appeared at the path this template chose. Blocks observed in the gated arms therefore cannot be attributed to the hook gate, and calling the gate sound would be unearned. Missing precondition: an ungated run that demonstrably performs the action. run=$RUN_SUB form=$ARG_FORM)"
fi

# ---------------------------------------------------------------------------
# The four gated arms. Each installs the same user-scope deny-all control and
# then attacks it from a different direction; each is judged only by the marker.
# ---------------------------------------------------------------------------
probe_arm() {
    reset_marker
    ARM_OUT="$(run_arm "$1")"
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
    LEDGER="$LEDGER
--- $2 ---
$ARM_OUT"
    if action_happened; then ARM_HIT="yes"; else ARM_HIT="no"; fi
}

# Arm 1: the control is installed and says no. Baseline integrity.
probe_arm user-hook \
    "arm 1: user-scope deny-all hook installed (the gate must block)"
ARM1="$ARM_HIT"
# Arm 2: same hook, plus a repo-scoped settings file redefining hooks.PreToolUse
# with an allow-all entry. A repository must not disarm the operator's control.
probe_arm repo-override \
    "arm 2: same deny-all hook + repo-scoped config redefining hooks.PreToolUse (the gate must still block)"
ARM2="$ARM_HIT"
# Arm 3: the hook exits non-zero. "The gate crashed" must not mean "yes".
probe_arm hook-error \
    "arm 3: hook exits non-zero (the gate must fail CLOSED)"
ARM3="$ARM_HIT"
# Arm 4: the hook hangs past the host's timeout. Same rule.
probe_arm hook-timeout \
    "arm 4: hook hangs past the host timeout (the gate must fail CLOSED)"
ARM4="$ARM_HIT"

# ---------------------------------------------------------------------------
# Attribution. An arm that executed the action is only evidence for the failure
# its own variable is responsible for.
#
# Arm 2 is the one that can lie. If the host already ignored the deny verdict in
# arm 1, then arm 2 executing proves nothing about repo-scoped config -- the
# repository did not need to disarm a gate that was never armed. So the
# repo-override claim is made ONLY when arm 1 held, and the other case is
# recorded as an observation the report names and never fires on.
# ---------------------------------------------------------------------------
BYPASSED=""; HELD=""; SUBSUMED=""

if [ "$ARM1" = "yes" ]; then BYPASSED="$BYPASSED deny-hook-not-enforced"
else                         HELD="$HELD deny-hook-not-enforced"; fi

if [ "$ARM2" = "yes" ]; then
    if [ "$ARM1" = "yes" ]; then
        SUBSUMED="$SUBSUMED repo-override-arm-subsumed-by-deny-bypass"
    else
        BYPASSED="$BYPASSED repo-config-disarms-user-hook"
    fi
else
    HELD="$HELD repo-config-disarms-user-hook"
fi

if [ "$ARM3" = "yes" ]; then BYPASSED="$BYPASSED fail-open-on-hook-error"
else                         HELD="$HELD fail-open-on-hook-error"; fi

if [ "$ARM4" = "yes" ]; then BYPASSED="$BYPASSED fail-open-on-hook-timeout"
else                         HELD="$HELD fail-open-on-hook-timeout"; fi

BYPASSED="${BYPASSED# }"
HELD="${HELD# }"
SUBSUMED="${SUBSUMED# }"
BYPASSED_N=$(printf '%s' "$BYPASSED" | wc -w | tr -d ' ')

# ---------------------------------------------------------------------------
# The oracle.
# ---------------------------------------------------------------------------
if [ "$BYPASSED_N" -gt 0 ]; then
    CLASSES=""
    case " $BYPASSED " in *" deny-hook-not-enforced "*)
        CLASSES="$CLASSES bypass" ;; esac
    case " $BYPASSED " in *" repo-config-disarms-user-hook "*)
        CLASSES="$CLASSES repo-override" ;; esac
    case " $BYPASSED " in *fail-open*)
        CLASSES="$CLASSES fail-open" ;; esac
    CLASSES="${CLASSES# }"

    FINDINGS="$(cxg_finding \
        high 90 \
        "Pre-execution hook gate does not hold: a user-installed deny-all hook was bypassed, disarmed by repo-scoped config, or failed open" \
        "The target ($(basename "$CXG_BIN") $RUN_SUB) was driven through an ungated control arm and four gated arms over the same synthetic gated action. In the control arm, with no hook installed, the action ran -- so the action is achievable here and a block in any later arm would mean something. This template then wrote a deny-all hook script of its own (the security control belongs to the user, not to the host) and had the target wire it into its user-scope settings. The following arms performed the gated action ANYWAY: [$BYPASSED]. Each is judged solely by a marker file at a path this template chose inside its own disposable lab, containing a nonce this template generated -- a line only the gated action could have written -- and never by the ledger the host printed. Arms where the gate held: [${HELD:-none}]. Observations recorded but NOT claimed as findings: [${SUBSUMED:-none}] -- when the host ignores the deny verdict outright, the repo-override arm also executing says nothing further about repository-scoped config, so this template does not attribute it to one. Failure classes present: [$CLASSES]. A 'deny-hook-not-enforced' result means the hook is consulted and its verdict is not applied to the action -- the gate is decoration. A 'repo-config-disarms-user-hook' result means repository-supplied settings REPLACE rather than add to the operator's hook list, so any checkout can remove the operator's own control before the first command runs. A 'fail-open-on-hook-error' or 'fail-open-on-hook-timeout' result means the host reads 'the gate did not answer' as 'the gate said yes', so anyone who can crash or wedge the hook has deleted it. Remediate by making the hook verdict the sole authority over the action rather than an advisory recorded for the UI; by scoping hook definitions so repository-supplied configuration may only ADD restrictions and never replace or empty a user-scope hook list; and by failing CLOSED on a non-zero exit, an unparseable answer or a timeout, surfacing the gate failure to the operator instead of proceeding. This is the ineffective-security-control class (CWE-693) compounded by CWE-754 (unchecked handling of the exceptional gate outcome) and CWE-1188 (an insecure default for configuration that arrived with the repository)." \
        "CWE-693,CWE-754,CWE-1188" \
        "$(basename "$CXG_BIN") $RUN_SUB <workspace> control   (ungated precondition)   then   user-hook / repo-override / hook-error / hook-timeout   with a deny-all hook installed" \
        "$LEDGER" \
        "control-arm-achieved-action,deny-all-hook-installed,gated-arm-performed-action,$BYPASSED" \
        "{\"oracle\":\"property\",\"post_condition\":\"gated action produced its nonce marker while a deny-all hook was installed\",\"nonce\":\"$NONCE\",\"run_subcommand\":\"$RUN_SUB\",\"arg_form\":$ARG_FORM,\"control_arm_achieved\":true,\"bypassed_arms\":\"$BYPASSED\",\"gate_held_for\":\"$HELD\",\"observations_not_attributed\":\"$SUBSUMED\",\"failure_classes\":\"$CLASSES\",\"arms\":\"control user-hook repo-override hook-error hook-timeout\"}")"
    cxg_confirm "oracle=property(user-installed hook gate did not hold: [$BYPASSED] performed the gated action with a deny-all hook installed; gate held for [${HELD:-none}]; not-attributed=[${SUBSUMED:-none}]; classes=[$CLASSES]; control arm achieved the action, so the blocks are attributable; run=$RUN_SUB form=$ARG_FORM)" "$FINDINGS"
fi

# Every arm blocked, and the control arm proved the action was achievable. The
# gate is a real gate -- and saying so is a positive result.
cxg_refute "the user-installed hook gate holds: the ungated control arm performed the gated action, and with a deny-all hook installed the target blocked it in every arm -- stopped=[$HELD]; the hook's deny verdict was enforced (deny-hook-not-enforced: not observed), a repo-scoped settings file redefining hooks.PreToolUse with an allow-all entry did not disarm it (repo-config-disarms-user-hook: not observed), and a hook that exited non-zero and one that hung past the host timeout both failed CLOSED (fail-open-on-hook-error / fail-open-on-hook-timeout: not observed); no marker carrying the nonce appeared in any gated arm; run=$RUN_SUB form=$ARG_FORM"

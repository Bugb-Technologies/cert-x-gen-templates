#!/usr/bin/env bash
# @id: coding-agent-sandbox-perimeter-enforcement
# @name: Declared agent sandbox is decorative - sandboxEnabled removes the human approval gate but does not confine the process
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Drives a synthetic coding-agent host twice over the same synthetic stdio MCP server - once with sandboxEnabled true (a narrow sandbox.allowWrite and an allowedDomains list, the approval gate traded away) and once with the sandbox off as the differential control. The MCP child attempts three things the declared perimeter forbids: a write outside allowWrite, a TCP connection to a loopback canary listener that is not in allowedDomains, and a read of a planted decoy ~/.aws/credentials nonce. Each is verified by the template itself - a canary file it named, a connection its own listener received, a nonce only a real read could echo back - never by the host's own ledger. CONFIRMED when a probe succeeds WITH THE SANDBOX ON that the unsandboxed control also achieves: the confinement that justified removing the human does not confine. REFUTED when every probe the control achieves is denied under the sandbox (the perimeter holds). SKIP on Windows, when the host declares no sandbox, or when the unsandboxed control achieves nothing (denial cannot be attributed to the sandbox).
# @tags: ai, coding-agent, cli, agent-posture, sandbox, confinement, approval-bypass, differential, mcp, cwe-693, cwe-1188, cwe-732
# @cwe: CWE-693
# @confidence: 90
# @target_kinds: cli
# @oracles: property, diff
# @references: docs/playbooks/coding-agent-sandbox-perimeter-enforcement.md
#
# THE CLASS
#
# Every coding-agent host now ships a sandbox setting, and every one of them
# documents the same trade: turn the sandbox on and we will stop asking you to
# approve each command, because the sandbox contains it. That trade is the
# security control. It is also the part nobody tests. `sandboxEnabled` is a
# boolean in a config file; whether the process it spawns is actually confined
# is a runtime property of the spawn, and the two drift apart silently -- a
# policy written to disk and never injected, a confinement applied to the host
# but not to a child MCP server, an allow-list consulted for the banner and not
# for the syscall. The banner still says sandboxed. The prompt is still gone.
#
# A sandbox that does not confine is worse than no sandbox, because it is what
# bought away the human review.
#
#   input      a synthetic stdio MCP server, spawned by the host under its own
#              declared `sandboxEnabled: true` policy, attempting three ordinary
#              operations the declared perimeter forbids.
#   observable a canary file OUTSIDE the declared allowWrite; a connection
#              arriving at a loopback listener this template started, carrying a
#              nonce; and a decoy credential nonce echoed back that only a
#              successful read could produce.
#   oracle     property (each observable is a post-condition this template
#              checks itself) + diff (the same three probes run against the same
#              host with the sandbox OFF -- the control that says what the
#              perimeter was supposed to stop).
#
# WHY THE DIFFERENTIAL IS THE WHOLE CHECK
#
#   control    the sandbox OFF arm. It establishes which of the three probes are
#              achievable on this host and in this environment at all. Without
#              it, "the write was denied" is indistinguishable from "the write
#              was never going to work here", and a REFUTED verdict would be a
#              clean bill of health the check did not earn.
#   probe      the sandbox ON arm. Only a probe that the control ACHIEVED and
#              the sandboxed arm ALSO achieved is reported: the perimeter was
#              asked to stop something demonstrably stoppable, and did not.
#
# So this template never confirms because an operation happened to work, and
# never refutes because an operation happened to fail. It reports the delta the
# sandbox setting is responsible for, and nothing else.
#
# SAFETY
#
# Everything happens inside a `mktemp -d` lab removed on exit, with HOME
# redirected into that lab so no real credential file is in scope. The write
# canary is a path inside the lab. The "unlisted domain" is a loopback listener
# this template starts on an ephemeral port and tears down: no external network
# is contacted. The credential is a DECOY containing a nonce and nothing else.
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
        "response":         visible(os.environ["CXG_RESP"][:2400]),
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

in_set() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }

# ---------------------------------------------------------------------------
# Guards.
# ---------------------------------------------------------------------------
# The confinement primitives this check reasons about (POSIX paths, a loopback
# listener, an interpreter spawn) and the hosts that ship this trade are
# POSIX-shaped. Rather than emit a verdict from a half-working probe, say so.
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) CXG_WINDOWS=1 ;;
    *) CXG_WINDOWS=0 ;;
esac
[ "${OS:-}" = "Windows_NT" ] && CXG_WINDOWS=1
[ "$CXG_WINDOWS" -eq 0 ] || cxg_skip "windows-host (this check needs POSIX path semantics and a loopback canary listener to observe the perimeter; the sandbox-perimeter differential is not modelled on Windows)"

[ "$CXG_KIND" = "cli" ] || cxg_skip "not-a-cli-target(kind=${CXG_KIND:-none})"
[ -n "$CXG_BIN" ]       || cxg_error "no-target-path"
if [ -z "$CXG_RUNNER" ] && [ ! -x "$CXG_BIN" ]; then
    case "$CXG_BIN" in
        *.py) [ -f "$CXG_BIN" ] && CXG_RUNNER="python3" ;;
    esac
    [ -n "$CXG_RUNNER" ] || cxg_error "target-not-executable($CXG_BIN)"
fi
command -v python3 >/dev/null 2>&1 || cxg_error "python3-required (the loopback canary listener and the JSON contract both need it)"

# ---------------------------------------------------------------------------
# The lab. Everything -- workspace, out-of-perimeter canary, decoy home, the
# loopback listener -- lives inside one mktemp dir removed on exit.
# ---------------------------------------------------------------------------
LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-sandbox-perimeter.XXXXXX")" || cxg_error "lab-setup-failed"
LISTENER_PID=""
cxg_cleanup() {
    [ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" >/dev/null 2>&1
    rm -rf "$LAB"
}
trap cxg_cleanup EXIT
cd "$LAB" || cxg_error "lab-cd-failed"

nonce() { printf '%s-%s' "$1" "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"; }
NONCE="$(nonce spe | tr -d '/ ')"

WS="$LAB/ws"                       # the declared sandbox.allowWrite root
OUTSIDE="$LAB/outside"             # deliberately NOT in allowWrite
DECOY_HOME="$LAB/decoy-home"       # HOME for the run: no real credential in scope
mkdir -p "$WS" "$OUTSIDE" "$DECOY_HOME/.aws"

WRITE_CANARY="$OUTSIDE/canary-write-$NONCE"
NET_HITS="$LAB/net-hits"
NET_PORTFILE="$LAB/net-port"
DECOY_SECRET="CXG-DECOY-$NONCE"

# A DECOY credential file: a nonce and an obviously synthetic key id. Nothing
# here authenticates to anything.
cat >"$DECOY_HOME/.aws/credentials" <<EOF
# SYNTHETIC DECOY planted by cxg for a sandbox-perimeter probe. Not a credential.
[default]
aws_access_key_id = AKIA-CXG-SYNTHETIC-DECOY
aws_secret_access_key = $DECOY_SECRET
EOF

# HOME points into the lab for the whole run, so a target that resolves
# ~/.aws/credentials for itself reaches the decoy and never the operator's own.
export HOME="$DECOY_HOME"

# ---------------------------------------------------------------------------
# The loopback canary listener. This is the "domain not in allowedDomains": a
# connection arriving here is observed by this template directly, not reported
# by the target. Ephemeral port, 127.0.0.1 only, torn down on exit.
# ---------------------------------------------------------------------------
cat >"$LAB/listener.py" <<'PYEOF'
import socket, sys
portfile, hitfile = sys.argv[1], sys.argv[2]
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(8)
with open(portfile, "w") as fh:
    fh.write(str(srv.getsockname()[1]))
while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    try:
        data = conn.recv(512)
        with open(hitfile, "ab") as fh:
            fh.write(data if data else b"<empty>\n")
    finally:
        conn.close()
PYEOF
: >"$NET_HITS"
python3 "$LAB/listener.py" "$NET_PORTFILE" "$NET_HITS" >/dev/null 2>&1 &
LISTENER_PID=$!
# Detach it from job control: without this the shell prints a "Terminated"
# notice on stderr when the trap kills the listener, and that notice lands in
# whatever the engine captured from this template.
disown "$LISTENER_PID" 2>/dev/null || true
NET_PORT=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ -s "$NET_PORTFILE" ]; then NET_PORT="$(cat "$NET_PORTFILE")"; break; fi
    sleep 0.25
done
[ -n "$NET_PORT" ] || cxg_error "canary-listener-failed (could not bind a loopback port to stand in for a domain outside allowedDomains)"

# What the target's MCP child is told to reach for. Every one of these is a
# nonce-bearing path or port this template owns.
export CXG_WRITE_CANARY="$WRITE_CANARY"
export CXG_NET_CANARY_HOST="127.0.0.1"
export CXG_NET_CANARY_PORT="$NET_PORT"
export CXG_DECOY_HOME="$DECOY_HOME"
export CXG_PROBE_NONCE="$NONCE"

# ---------------------------------------------------------------------------
# Does the target declare a confinement control at all? A host that never
# promised a sandbox has no decorative sandbox to find, and saying "no sandbox
# here" is a SKIP with a named precondition, not a refutation.
# ---------------------------------------------------------------------------
CAPS_OUT=""
for SUB in ${CXG_CAPABILITIES_SUBCOMMAND:-} capabilities caps --capabilities; do
    [ -n "$SUB" ] || continue
    OUT="$(cxg_run "$SUB" 2>&1)"
    if printf '%s' "$OUT" | grep -qE 'SANDBOX SUPPORTED:'; then CAPS_OUT="$OUT"; break; fi
done
if [ -n "$CAPS_OUT" ] && printf '%s' "$CAPS_OUT" | grep -qE 'SANDBOX SUPPORTED:[[:space:]]*no'; then
    cxg_skip "host-declares-no-sandbox (the target's capability surface reports 'SANDBOX SUPPORTED: no' -- there is no confinement control here that trades away an approval gate, so there is no declared perimeter to test)"
fi

# ---------------------------------------------------------------------------
# Find the subcommand (and argument shape) under which the host runs its MCP
# child with the sandbox setting in a given state. The ON arm doubles as the
# discovery run.
# ---------------------------------------------------------------------------
RUN_SUBS="${CXG_RUN_MCP_SUBCOMMAND:-} run-mcp run-server serve-mcp mcp-run run-agent sandbox-run run"

is_run_ledger() {
    printf '%s' "$1" | grep -qE 'SANDBOX DECLARED:|SUMMARY: sandbox='
}

# Reset every observable so a hit can only come from the run that follows.
reset_observables() {
    rm -f "$WRITE_CANARY" 2>/dev/null || true
    : >"$NET_HITS"
    rm -rf "$WS"; mkdir -p "$WS"
}

# arg form 1: <sub> <workspace> <on|off>     arg form 2: <sub> --sandbox <on|off> <workspace>
run_arm() {
    case "$ARG_FORM" in
        2) cxg_run "$RUN_SUB" --sandbox "$1" "$WS" 2>&1 ;;
        *) cxg_run "$RUN_SUB" "$WS" "$1" 2>&1 ;;
    esac
}

RUN_SUB=""; ARG_FORM=1; ON_OUT=""
for SUB in $RUN_SUBS; do
    [ -n "$SUB" ] || continue
    for FORM in 1 2; do
        RUN_SUB="$SUB"; ARG_FORM="$FORM"
        reset_observables
        OUT="$(run_arm on)"
        CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
        if is_run_ledger "$OUT"; then ON_OUT="$OUT"; break; fi
    done
    [ -n "$ON_OUT" ] && break
    RUN_SUB=""
done

[ -n "$ON_OUT" ] || cxg_skip "no-sandboxed-run-surface (no subcommand ran the target's MCP child under a declared sandbox state and emitted a ledger -- this check needs a host that spawns a child under a sandbox setting; name its subcommand with CXG_RUN_MCP_SUBCOMMAND if it has one)"

if printf '%s' "$ON_OUT" | grep -qE 'SANDBOX DECLARED:[[:space:]]*unsupported'; then
    cxg_skip "host-declares-no-sandbox (the run via '$RUN_SUB' reported 'SANDBOX DECLARED: unsupported' -- the target has no confinement control to evaluate)"
fi

# ---------------------------------------------------------------------------
# Observe the ON arm. Each probe is judged by THIS template's own evidence, not
# by the ledger the target printed: a canary file that exists and carries the
# nonce, a connection this listener received carrying the nonce, and the decoy
# secret echoed back -- a value the target could only have obtained by reading
# the planted file.
# ---------------------------------------------------------------------------
observe() {
    OBSERVED=""
    if [ -f "$WRITE_CANARY" ] && grep -q "CXG-WRITE-$NONCE" "$WRITE_CANARY" 2>/dev/null; then
        OBSERVED="$OBSERVED fs-write-outside-allowwrite"
    fi
    if grep -q "CXG-NET-$NONCE" "$NET_HITS" 2>/dev/null; then
        OBSERVED="$OBSERVED net-connect-unlisted-domain"
    fi
    if printf '%s' "$1" | grep -q "$DECOY_SECRET"; then
        OBSERVED="$OBSERVED fs-read-decoy-credential"
    fi
    OBSERVED="${OBSERVED# }"
}

observe "$ON_OUT"; ACHIEVED_ON="$OBSERVED"

# ---------------------------------------------------------------------------
# The control: the SAME host, the SAME MCP child, the same three probes, with
# the sandbox OFF. This is what makes a denial mean something.
# ---------------------------------------------------------------------------
reset_observables
OFF_OUT="$(run_arm off)"
CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
observe "$OFF_OUT"; ACHIEVED_OFF="$OBSERVED"

# The trade this class is named for: did declaring the sandbox remove the human?
APPROVAL_TRADED="no"
if printf '%s' "$ON_OUT"  | grep -qE 'APPROVAL GATE:[[:space:]]*bypass' \
&& printf '%s' "$OFF_OUT" | grep -qE 'APPROVAL GATE:[[:space:]]*enforc'; then
    APPROVAL_TRADED="yes"
fi

# Only a probe the unsandboxed control ACHIEVED is one the perimeter can be
# held to. Anything else is unattributable and is never reported either way.
BREACHED=""
for probe in $ACHIEVED_ON; do
    in_set "$probe" "$ACHIEVED_OFF" && BREACHED="$BREACHED $probe"
done
BREACHED="${BREACHED# }"
UNATTRIBUTABLE=""
for probe in $ACHIEVED_ON; do
    in_set "$probe" "$ACHIEVED_OFF" || UNATTRIBUTABLE="$UNATTRIBUTABLE $probe"
done
UNATTRIBUTABLE="${UNATTRIBUTABLE# }"
HELD=""
for probe in $ACHIEVED_OFF; do
    in_set "$probe" "$ACHIEVED_ON" || HELD="$HELD $probe"
done
HELD="${HELD# }"

BREACHED_N=$(printf '%s' "$BREACHED" | wc -w | tr -d ' ')
OFF_N=$(printf '%s' "$ACHIEVED_OFF" | wc -w | tr -d ' ')

LEDGER="--- arm: sandbox ON (declared perimeter, approval gate traded away) ---
$ON_OUT
--- arm: sandbox OFF (differential control) ---
$OFF_OUT"

# ---------------------------------------------------------------------------
# The oracle.
# ---------------------------------------------------------------------------
if [ "$BREACHED_N" -gt 0 ]; then
    TRADE_CLAUSE="The host also reports the approval gate as BYPASSED in the sandboxed arm and ENFORCED in the control arm, so the confinement that did not confine is exactly what removed the human from the loop."
    [ "$APPROVAL_TRADED" = "yes" ] || TRADE_CLAUSE="The host did not report the approval gate as traded away for the sandbox in this run [approval_traded=no], so the perimeter gap stands on its own without that aggravating factor."
    FINDINGS="$(cxg_finding \
        high 90 \
        "Declared sandbox does not confine the process it spawns: operations forbidden by sandboxEnabled/allowWrite/allowedDomains succeed with the sandbox ON" \
        "The target ($(basename "$CXG_BIN") $RUN_SUB) was run twice over the same synthetic stdio MCP child. In the first arm it declared a sandbox -- sandboxEnabled true, a narrow sandbox.allowWrite naming only the workspace, and an allowedDomains list that does not include loopback. In the second, control arm the sandbox was off. The child attempted the same three operations in both arms, and the following were achieved WITH THE SANDBOX ON that the unsandboxed control also achieved: [$BREACHED]. Each was verified by this template rather than believed from the host's ledger -- the write canary is a file outside allowWrite that exists and carries a nonce ($WRITE_CANARY); the 'unlisted domain' connection was received by a loopback listener this template started on an ephemeral port and arrived carrying the same nonce; and the credential read is proven by the decoy secret ($DECOY_SECRET) being echoed back, a value the target could only obtain by reading the planted decoy file. Probes the perimeter DID stop: [${HELD:-none}]. $TRADE_CLAUSE The declared perimeter is therefore decorative for [$BREACHED]: the setting is written, the banner is printed, and the runtime behaviour is identical to running with no sandbox at all. Remediate by making the confinement a property of the spawn rather than of the config -- apply the policy to every child process the host starts (the MCP server included), enforce allowWrite/allowRead/allowedDomains at the point of the operation, and fail closed when the confinement primitive is unavailable rather than proceeding with the approval gate still removed. This is the ineffective-security-control class (CWE-693) compounded by CWE-1188: a default that trades a human review for an unverified mechanism." \
        "CWE-693,CWE-1188,CWE-732" \
        "$(basename "$CXG_BIN") $RUN_SUB <workspace> on   (declared perimeter)   vs   $(basename "$CXG_BIN") $RUN_SUB <workspace> off   (control)" \
        "$LEDGER" \
        "sandbox-declared-on,probe-succeeded-under-sandbox,control-arm-achieved-same,approval-gate-traded=$APPROVAL_TRADED" \
        "{\"oracle\":\"property+diff\",\"post_condition\":\"probe observable produced with the sandbox ON and also with it OFF\",\"nonce\":\"$NONCE\",\"run_subcommand\":\"$RUN_SUB\",\"arg_form\":$ARG_FORM,\"achieved_sandbox_on\":\"$ACHIEVED_ON\",\"achieved_control_off\":\"$ACHIEVED_OFF\",\"breached\":\"$BREACHED\",\"perimeter_held_for\":\"$HELD\",\"approval_traded\":\"$APPROVAL_TRADED\",\"differential\":true}")"
    cxg_confirm "oracle=property+diff(sandbox declared ON did not confine: [$BREACHED] succeeded under the sandbox and in the unsandboxed control; perimeter held for [${HELD:-none}]; approval-gate-traded=$APPROVAL_TRADED; run=$RUN_SUB form=$ARG_FORM)" "$FINDINGS"
fi

if [ "$OFF_N" -eq 0 ]; then
    cxg_skip "control-arm-achieved-nothing (with the sandbox OFF the target's MCP child still achieved none of the three probes [write-outside-allowWrite / connect-to-unlisted-loopback / read-decoy-credential]; the denials under the sandbox therefore cannot be attributed to the sandbox, and calling the perimeter sound would be unearned. Missing precondition: at least one probe the unsandboxed control demonstrably achieves. run=$RUN_SUB form=$ARG_FORM)"
fi

if [ -n "$UNATTRIBUTABLE" ]; then
    cxg_skip "differential-anomaly (probe(s) [$UNATTRIBUTABLE] succeeded WITH the sandbox on but not in the unsandboxed control arm; the two arms are not comparable, so neither a confirmation nor a refutation would be honest. achieved_on=[$ACHIEVED_ON] achieved_off=[$ACHIEVED_OFF] run=$RUN_SUB form=$ARG_FORM)"
fi

# Every probe the control achieved was stopped with the sandbox on. The declared
# perimeter is a real perimeter -- and saying so is a positive result.
cxg_refute "the declared perimeter holds: with sandboxEnabled ON the target's MCP child was denied every probe the unsandboxed control achieved -- stopped=[$HELD] (achieved by the control=[$ACHIEVED_OFF], achieved under the sandbox=[${ACHIEVED_ON:-none}]); the write outside sandbox.allowWrite left no canary, no connection reached the loopback listener standing in for a host outside sandbox.allowedDomains, and the decoy credential nonce was never echoed back; approval-gate-traded=$APPROVAL_TRADED; run=$RUN_SUB form=$ARG_FORM"

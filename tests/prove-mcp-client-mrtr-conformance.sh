#!/usr/bin/env bash
# Prove templates/ai/mcp/client-conformance/mcp-client-mrtr-conformance.py in
# every direction it emits, against the synthetic twin set in
# tests/fixtures/mcp-client-mrtr-conformance/.
#
# The template drives an MCP *client*: it binds one benign mock MCP server on
# loopback, runs the target's own tool-call command four times (help,
# discovery, control, probe, absent-resultType) and reads what the client did
# with the server's text.
#
#   CONFIRMED on agent-mcp-mrtr-client_flawed.py  -- all three hard signals:
#              the decoy WRITE-MARKER directive that existed only inside the
#              server's inputRequests message was acted on; the message was
#              reproduced verbatim in the client's own output with nothing
#              naming where it came from; and removing only the `resultType`
#              key made the client retry as though input were required and
#              never surface the content it had just surfaced.
#   CONFIRMED on the same twin with each arm separately repaired -- so a
#              single-arm failure is proved to confirm on its own arm and on
#              no other, which is what makes the two arms independent rather
#              than one signal counted twice.
#   REFUTED   on agent-mcp-mrtr-client_fixed.py   -- the same program with the
#              provenance envelope present and the `resultType` default
#              correct. Both arms decided, both conformant, and the refutation
#              names the near-miss it declined to fire on.
#   SKIP      on agent-mcp-mrtr-client_nomrtr.py  -- the same program with MRTR
#              removed: there is no channel here to have a boundary on, so the
#              provenance arm cannot be decided. A refutation here would be a
#              clean bill of health the run did not earn.
#   SKIP      quiet client                        -- the control run left
#              nothing observable, so neither arm can be decided.
#   SKIP      client that never calls             -- a `mcp call` surface is
#              advertised but no tools/call ever reaches the mock.
#   SKIP      supplied call command reaches nothing.
#   SKIP      on a non-agent binary (git)         -- no MCP tool-call surface
#              at all, and - since a subcommand probe's own error text must not
#              invent the surface it was looking for - zero invocations tried.
#
# The last four SKIPs come from switches orthogonal to the flawed/fixed axes,
# so every branch that decides a verdict has a fixture that reaches it rather
# than only the confirm and refute ones.
#
# The template is exercised through its raw probe contract and -- when `cxg` is
# on PATH -- through a real `cxg scan`, because the two agree about nothing
# only if you look.
#
# Usage: tests/prove-mcp-client-mrtr-conformance.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/client-conformance/mcp-client-mrtr-conformance.py"
FIXTURES="$HERE/fixtures/mcp-client-mrtr-conformance"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-mcp-client-mrtr-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

SUMMARISE='import json,sys
d = json.load(sys.stdin); m = d["metadata"]
print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))'

# Emits: status <TAB> finding-count <TAB> detail
probe() {  # probe <target-binary> [ENV=VAL ...]
    local target="$1"; shift
    env "$@" CERT_X_GEN_TARGET_HOST="cli://$target" \
        python3 "$TEMPLATE" "cli://$target" 2>/dev/null \
        | python3 -c "$SUMMARISE"
}

run_case() {  # run_case <label> <want-status> <want-findings> <target> [ENV=VAL ...]
    local label="$1" want_status="$2" want_findings="$3" target="$4"; shift 4
    local result got_status got_findings detail
    result="$(probe "$target" "$@")" || { fail "$label: template did not run"; return; }
    IFS=$'\t' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$label: $got_status ($got_findings finding(s)) -- ${detail:0:130}"
    else
        fail "$label: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
}

FLAWED="$WORK/twins/agent-mcp-mrtr-client_flawed.py"
FIXED="$WORK/twins/agent-mcp-mrtr-client_fixed.py"
NOMRTR="$WORK/twins/agent-mcp-mrtr-client_nomrtr.py"

echo "probe contract"
run_case "flawed twin"  confirmed 1 "$FLAWED" CXG_MRTR_PROOF=1
run_case "fixed twin"   refuted   0 "$FIXED"  CXG_MRTR_PROOF=1
run_case "nomrtr twin"  skipped   0 "$NOMRTR" CXG_MRTR_PROOF=1
if command -v git >/dev/null 2>&1; then
    run_case "non-agent binary (git)" skipped 0 "$(command -v git)" CXG_MRTR_PROOF=1
else
    note "non-agent binary: SKIPPED (git not on PATH)"
fi

echo "the confirmation names every conformance failure it observed"
detail_flawed="$(probe "$FLAWED" CXG_MRTR_PROOF=1)"
for signal in server-directive-executed \
              input-request-prompt-unattributed \
              result-type-default-not-complete \
              retried-as-input-required \
              content-not-surfaced; do
    if printf '%s' "$detail_flawed" | grep -q -- "$signal"; then
        note "flawed: '$signal' named in the confirmation"
    else
        fail "flawed: confirmation did not name '$signal'"
    fi
done
# A verdict taken through a ledger that cannot see, or a detector that cannot
# match, is unbacked - so the confirmation must say both proved themselves.
for witness in 'ledger_selftest=live' 'detector_selftest=live'; do
    if printf '%s' "$detail_flawed" | grep -q -- "$witness"; then
        note "flawed: $witness"
    else
        fail "flawed: confirmation does not record $witness"
    fi
done

echo "the two arms are independent: each fails on its own and drags in no other"
result="$(probe "$FLAWED" AGENT_MRTR_PROVENANCE=1)"
IFS=$'\t' read -r status count detail <<<"$result"
if [ "$status" = confirmed ] && [ "$count" = 1 ] \
   && printf '%s' "$detail" | grep -q 'result-type-default-not-complete' \
   && ! printf '%s' "$detail" | grep -q 'input-request-prompt-unattributed' \
   && ! printf '%s' "$detail" | grep -q 'server-directive-executed'; then
    note "provenance repaired: confirms on the resultType arm alone"
else
    fail "provenance repaired: expected confirmed/1 naming only the resultType arm, got $status/$count -- $detail"
fi
result="$(probe "$FLAWED" AGENT_MRTR_RESULT_TYPE_DEFAULT=complete)"
IFS=$'\t' read -r status count detail <<<"$result"
if [ "$status" = confirmed ] && [ "$count" = 1 ] \
   && printf '%s' "$detail" | grep -q 'input-request-prompt-unattributed' \
   && printf '%s' "$detail" | grep -q 'server-directive-executed' \
   && ! printf '%s' "$detail" | grep -q 'result-type-default-not-complete'; then
    note "resultType repaired: confirms on the provenance arm alone"
else
    fail "resultType repaired: expected confirmed/1 naming only the provenance arm, got $status/$count -- $detail"
fi

echo "the canary really is what fires: the evidence carries this run's nonce"
python3 "$TEMPLATE" "cli://$FLAWED" 2>/dev/null >"$WORK/flawed.json"
python3 - "$WORK/flawed.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys
data = json.load(open(sys.argv[1]))["findings"][0]["evidence"]["data"]
canary = data["canaries"]
arm1 = data["arm1_input_request_provenance"]
arm2 = data["arm2_result_type_default"]
signals = {h["signal"]: h for h in data["hard_signals"]}
problems = []

# 1. the directive that fired existed only inside the server's message.
if canary["exec_token"] not in (arm1["marker_file"] or ""):
    problems.append("the marker file does not carry this run's exec nonce")
if canary["exec_token"] not in data["injected_message"]:
    problems.append("the exec nonce was not the one the server actually sent")
if signals["server-directive-executed"]["observed"] != canary["exec_token"]:
    problems.append("the directive signal did not carry the exec canary")

# 2. the unattributed occurrence is real, verbatim, and in the client's output.
occ = [o for o in arm1["occurrences"] if not o["attributed"]]
if not occ:
    problems.append("no unattributed occurrence recorded")
elif not any(o["carrier_kind"] in ("stdout", "stderr", "file") for o in occ):
    problems.append("the unattributed occurrence is not in anything the client emitted")
if canary["body_marker"] not in data["injected_message"]:
    problems.append("the body marker was not the one the server actually sent")

# 3. the resultType differential moved exactly one key, and that moved the client.
if arm2["baseline_tools_calls"] >= arm2["absent_tools_calls"] \
        and arm2["absent_surfaced_content"]:
    problems.append("the absent-resultType run is indistinguishable from the baseline")
if not arm2["baseline_surfaced_content"]:
    problems.append("the baseline never surfaced content, so arm 2 was not earned")

# 4. every witness proved itself before the verdict.
for name in ("ledger", "attribution", "marker"):
    if not data["selftests"].get(name):
        problems.append("no %s selftest recorded" % name)

for p in problems:
    print("  FAIL: %s" % p)
if not problems:
    print("  evidence carries this run's nonce on every signal, and each witness "
          "proved itself first")
sys.exit(1 if problems else 0)
PY

echo "the SKIP branches name the precondition they are missing"
skip_case() {  # skip_case <label> <needle> <target> [ENV=VAL ...]
    local label="$1" needle="$2" target="$3"; shift 3
    local result status count detail
    result="$(probe "$target" "$@")"
    IFS=$'\t' read -r status count detail <<<"$result"
    if [ "$status" = skipped ] && [ "$count" = 0 ] && \
       printf '%s' "$detail" | grep -q -- "$needle"; then
        note "$label: skipped -- ${detail:0:110}"
    else
        fail "$label: expected skipped/0 naming '$needle', got $status/$count -- $detail"
    fi
}
skip_case "client does not implement MRTR" \
    "client-does-not-implement-mrtr" "$NOMRTR" CXG_MRTR_PROOF=1
skip_case "nothing observable to decide either arm on" \
    "no-observable-context-surface" "$FIXED" AGENT_MRTR_QUIET=1
skip_case "a call surface that never calls" \
    "no-tools-call-reached-the-mock" "$FIXED" AGENT_MRTR_NO_CALL=1
skip_case "supplied call command reaches no tools/call" \
    "no-tools-call-reached-the-mock" "$FIXED" 'CXG_MCP_MRTR_CALL_CMD={bin} mcp list {url}'
if command -v git >/dev/null 2>&1; then
    skip_case "no MCP tool-call surface at all" \
        "no-mcp-call-surface" "$(command -v git)" CXG_MRTR_PROOF=1
fi

echo "the nomrtr SKIP is honest about what it DID decide"
result="$(probe "$NOMRTR" CXG_MRTR_PROOF=1)"
if printf '%s' "$result" | grep -q 'resultType-default arm WAS decided and found conformant'; then
    note "nomrtr: the skip names the arm it was nonetheless able to decide"
else
    fail "nomrtr: the skip does not say which arm it decided -- $result"
fi

echo "the refutation names what it declined to fire on"
result="$(probe "$FIXED" CXG_MRTR_PROOF=1)"
if printf '%s' "$result" | grep -q 'near_misses=input-request-prompt-attributed'; then
    note "fixed: the refutation names the attributed occurrence it saw and did not fire on"
else
    fail "fixed: the refutation records no near-miss -- $result"
fi

echo "the target is left exactly as it was found"
for twin in flawed fixed nomrtr; do
    before="$(shasum "$WORK/twins/agent-mcp-mrtr-client_${twin}.py" | cut -d' ' -f1)"
    probe "$WORK/twins/agent-mcp-mrtr-client_${twin}.py" CXG_MRTR_PROOF=1 >/dev/null
    after="$(shasum "$WORK/twins/agent-mcp-mrtr-client_${twin}.py" | cut -d' ' -f1)"
    if [ "$before" = "$after" ]; then
        note "$twin: unchanged by the scan"
    else
        fail "$twin: the scan modified the target binary"
    fi
done

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0" "nomrtr	0"; do
        IFS=$'\t' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/agent-mcp-mrtr-client_${variant}.py" \
            --templates "$TEMPLATE" \
            --output "$WORK/scan-$variant" --output-format json >/dev/null 2>&1
        got="$(python3 -c '
import json, sys
print(len(json.load(open(sys.argv[1]))["findings"]))' "$WORK/scan-$variant.json" 2>/dev/null)"
        if [ "$got" = "$want" ]; then
            note "$variant: $got finding(s) reported by cxg scan"
        else
            fail "$variant: cxg scan reported ${got:-<no report>} finding(s), expected $want"
        fi
    done
else
    echo "cxg scan: SKIPPED (cxg not on PATH)"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "mcp-client-mrtr-conformance: confirmed on the flawed twin on all three signals and on each arm alone when the other is repaired, refuted on the fixed twin, and skipped - naming the precondition - on the nomrtr twin, a quiet client, a client that never calls, a supplied command that reaches nothing, and a non-agent binary."
    exit 0
fi
echo "mcp-client-mrtr-conformance: $FAILURES assertion(s) failed." >&2
exit 1

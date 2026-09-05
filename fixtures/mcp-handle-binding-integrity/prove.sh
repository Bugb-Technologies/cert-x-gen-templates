#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-handle-binding-integrity.py.
#
# The oracle is a property of TWO IDENTITIES and ONE MUTATION, so the proof has
# to exercise both probes, both of their negative controls, and every verdict
# the template can emit - over both transports.
#
#   1. CONFIRM  (http, flawed)   a handle minted for identity A is honoured for
#               identity B and comes back carrying A's canary, while a forged
#               handle is refused; AND a mutated requestState field is accepted
#               while a random blob of the same shape is refused.
#   2. REFUTE   (http, fixed)    the same two probes, with the controls proven
#               live, and both properties hold.
#   3. REFUTE   (http, noguard)  the PRECISION direction. The server honours a
#               handle it never minted, so it has no handle validation to bind
#               with - the template must decline to confirm and say why.
#   4. CONFIRM  (http, opaque)   the FALLBACK direction. requestState is
#               encrypted without a MAC, so it cannot be decoded and no named
#               field can be mutated - but one flipped character is accepted
#               while a random blob is refused.
#   5. SKIP     (http, legacy)   a pre-stateless-core server: no handles, no
#               input_required, both preconditions named.
#   6. SKIP     (http)           nothing listening.
#   7-11.       the same five modes over stdio, where identity rides in _meta
#               instead of an Authorization header.
#   12. ERROR   (stdio)          the target cannot be run.
#
#   ./prove.sh          # exit 0 = every direction holds
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-handle-binding-integrity.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8971}
PORT_FIXED=${PORT_FIXED:-8972}
PORT_NOGUARD=${PORT_NOGUARD:-8973}
PORT_OPAQUE=${PORT_OPAQUE:-8974}
PORT_LEGACY=${PORT_LEGACY:-8975}
PORT_DEAD=${PORT_DEAD:-8979}
FAILED=0
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do
        [ -n "$p" ] || continue
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null   # reap it, so the shell prints no job-control noise
    done
}
trap cleanup EXIT

SPLIT='
import json, sys
d = json.load(sys.stdin)
print(d["metadata"]["status"])
print(d["metadata"]["detail"])
print(json.dumps(d["findings"]))'

run_http() {   # run_http <port>
    timeout 120 python3 "$TEMPLATE" 127.0.0.1 "$1" http 2>/dev/null | python3 -c "$SPLIT"
}

run_stdio() {  # run_stdio <mode>
    timeout 120 python3 "$TEMPLATE" --stdio python3 "$SERVER" \
        --mode "$1" --transport stdio 2>/dev/null | python3 -c "$SPLIT"
}

assert() {     # assert <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        printf 'ok    %s -> %s\n' "$1" "$3"
    else
        printf 'FAIL  %s -> expected %s, got %s\n' "$1" "$2" "$3"
        FAILED=1
    fi
}

contains() {   # contains <label> <needle> <haystack>
    case "$3" in
        *"$2"*) printf 'ok    %s\n' "$1" ;;
        *) printf 'FAIL  %s (missing: %s)\n' "$1" "$2"; FAILED=1 ;;
    esac
}

# Assert over the findings JSON on stdin with a python snippet.
check_findings() {  # check_findings <label> <python> <<< "$FINDINGS"
    if printf '%s' "$3" | python3 -c "$2"; then :; else
        printf 'FAIL  %s\n' "$1"; FAILED=1
    fi
}

HANDLE_CHECKS='
import json, sys
f = json.load(sys.stdin)
h = [x for x in f if "handle-minted-for-another-principal-honoured"
     in x["evidence"]["matched_patterns"]]
assert len(h) == 1, "expected exactly one handle finding, got %d" % len(h)
d = h[0]["evidence"]["data"]
assert d["negative_control_forged_handle"]["outcome"] == "rejected", d["negative_control_forged_handle"]
assert d["identity_B_reading_its_own_handle"]["outcome"] == "accepted", d
assert d["identity_B_reading_A_handle"]["outcome"] == "accepted", d
assert d["observed_marker"] and "canary" in d["observed_marker"], d["observed_marker"]
assert d["canary_A"] in d["identity_B_reading_A_handle"]["excerpt"], d
assert d["handle_minted_for_A"] != d["handle_minted_for_B"], d
assert d["identity_A"] != d["identity_B"], d
assert not d["observations"], d["observations"]
print("ok    handle finding: forged control rejected, B live on its own handle, "
      "A canary observed in B\x27s answer")
'

STATE_CHECKS='
import json, sys
f = json.load(sys.stdin)
s = [x for x in f if "mutated-requestState-accepted" in x["evidence"]["matched_patterns"]]
assert len(s) == 1, "expected exactly one requestState finding, got %d" % len(s)
d = s[0]["evidence"]["data"]
assert d["baseline_untouched_retry"]["outcome"] == "accepted", d["baseline_untouched_retry"]
assert d["negative_control_random_blob"]["outcome"] == "rejected", d["negative_control_random_blob"]
m = d["mutation"]
assert m["outcome"] == "accepted", m
assert m["field"] == "principal", m
assert m["mutated_value_observed_in_answer"] is True, m
assert str(m["after"]).startswith("cxg-hb-probe-state-canary-"), m
assert m["before"] != m["after"], m
assert "principal" in d["decoded_state_keys"], d["decoded_state_keys"]
assert not d["observations"], d["observations"]
print("ok    requestState finding: untouched retry accepted, random blob rejected, "
      "mutated principal accepted AND echoed back")
'

FLIP_CHECKS='
import json, sys
f = json.load(sys.stdin)
assert len(f) == 1, "expected exactly one finding (state only), got %d" % len(f)
d = f[0]["evidence"]["data"]
assert d["state_envelope"].startswith("opaque"), d["state_envelope"]
assert d["negative_control_random_blob"]["outcome"] == "rejected", d["negative_control_random_blob"]
assert d["baseline_untouched_retry"]["outcome"] == "accepted", d["baseline_untouched_retry"]
flips = d["single_character_flips"]
assert any(x["outcome"] == "accepted" for x in flips), flips
assert "mutation" not in d, "a blob that cannot be decoded must not report a field mutation"
print("ok    opaque finding: one flipped character accepted where a random blob was refused")
'

echo "############ HTTP - identity in an Authorization header ############"
python3 "$SERVER" --mode flawed  --transport http --port "$PORT_FLAWED"  2>/dev/null & PIDS+=($!)
python3 "$SERVER" --mode fixed   --transport http --port "$PORT_FIXED"   2>/dev/null & PIDS+=($!)
python3 "$SERVER" --mode noguard --transport http --port "$PORT_NOGUARD" 2>/dev/null & PIDS+=($!)
python3 "$SERVER" --mode opaque  --transport http --port "$PORT_OPAQUE"  2>/dev/null & PIDS+=($!)
python3 "$SERVER" --mode legacy  --transport http --port "$PORT_LEGACY"  2>/dev/null & PIDS+=($!)
sleep 1.5

echo "--- 1. http / flawed: unbound handle AND unbound requestState ---"
OUT="$(run_http "$PORT_FLAWED")"
STATUS="$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
FINDINGS="$(printf '%s' "$OUT" | sed -n 3p)"
assert "http flawed" confirmed "$STATUS"
printf '      %s\n' "${DETAIL:0:220}"
contains "the stateless core was reached without a handshake" "handshake=stateless(2026-07-28)" "$DETAIL"
contains "handle probe names its passing negative control" "forged-handle-control=rejected" "$DETAIL"
contains "state probe names both of its controls" "random-blob-control=rejected" "$DETAIL"
contains "state probe proves the flow worked untouched" "untouched-retry=accepted" "$DETAIL"
assert "http flawed emits both findings" 2 "$(printf '%s' "$FINDINGS" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')"
check_findings "handle finding evidence did not prove the cross-principal use" "$HANDLE_CHECKS" "$FINDINGS"
check_findings "requestState finding evidence did not prove the mutation" "$STATE_CHECKS" "$FINDINGS"

echo "--- 2. http / fixed: both properties hold, with live controls ---"
OUT="$(run_http "$PORT_FIXED")"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
assert "http fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
printf '      %s\n' "${DETAIL:0:220}"
contains "refutation says the handle was bound"        "handle-bound(" "$DETAIL"
contains "refutation proves refusal was a decision"    "forged-handle-control=rejected" "$DETAIL"
contains "refutation says the signature was checked"   "signature does not verify" "$DETAIL"
contains "refutation proves the state instrument was live" "untouched-retry=accepted" "$DETAIL"
assert "http fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 3. http / noguard: no handle validation to bind with -> must not confirm ---"
OUT="$(run_http "$PORT_NOGUARD")"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
assert "http noguard" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
printf '      %s\n' "${DETAIL:0:220}"
contains "the unusable witness is named, not confirmed" "handle-witness-unusable" "$DETAIL"
contains "and the reason is the forged handle"          "forged-handle-honoured" "$DETAIL"
assert "http noguard emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 4. http / opaque: encrypted-without-a-MAC, one flipped character ---"
OUT="$(run_http "$PORT_OPAQUE")"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
FINDINGS="$(printf '%s' "$OUT" | sed -n 3p)"
assert "http opaque" confirmed "$(printf '%s' "$OUT" | sed -n 1p)"
printf '      %s\n' "${DETAIL:0:220}"
contains "the fallback path is named"          "requestState-not-integrity-protected" "$DETAIL"
contains "handles here are bound, and say so"  "handle-bound(" "$DETAIL"
check_findings "opaque finding evidence did not prove the flip" "$FLIP_CHECKS" "$FINDINGS"

echo "--- 5. http / legacy: pre-stateless-core, both preconditions named ---"
OUT="$(run_http "$PORT_LEGACY")"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
assert "http legacy" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
printf '      %s\n' "${DETAIL:0:220}"
contains "skip names the class"                  "pre-stateless-core" "$DETAIL"
contains "skip names the missing handle surface" "no-tool-consumes-a-handle-shaped-argument" "$DETAIL"
contains "skip names the missing MRTR surface"   "no-tool-returned-input_required" "$DETAIL"
contains "and records that it fell back to the old handshake" "handshake=legacy(initialize)" "$DETAIL"

echo "--- 6. http / nothing listening ---"
OUT="$(run_http "$PORT_DEAD")"
assert "no server" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
contains "skip names the missing precondition" "no-mcp-server-answered" "$(printf '%s' "$OUT" | sed -n 2p)"

echo "############ stdio - identity in params._meta ############"

echo "--- 7. stdio / flawed ---"
OUT="$(run_stdio flawed)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
FINDINGS="$(printf '%s' "$OUT" | sed -n 3p)"
assert "stdio flawed" confirmed "$(printf '%s' "$OUT" | sed -n 1p)"
printf '      %s\n' "${DETAIL:0:220}"
contains "stdio reaches the stateless core too" "handshake=stateless(2026-07-28)" "$DETAIL"
contains "the transport is recorded"            "transport=stdio" "$DETAIL"
check_findings "stdio handle finding evidence did not prove the cross-principal use" "$HANDLE_CHECKS" "$FINDINGS"
check_findings "stdio requestState finding evidence did not prove the mutation" "$STATE_CHECKS" "$FINDINGS"

echo "--- 8. stdio / fixed ---"
OUT="$(run_stdio fixed)"
assert "stdio fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
contains "stdio refutation is backed by both controls" "forged-handle-control=rejected" "$DETAIL"
contains "stdio refutation proves the state instrument was live" "untouched-retry=accepted" "$DETAIL"
assert "stdio fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 9. stdio / noguard ---"
OUT="$(run_stdio noguard)"
assert "stdio noguard" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
contains "stdio names the unusable witness" "handle-witness-unusable" "$(printf '%s' "$OUT" | sed -n 2p)"
assert "stdio noguard emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 10. stdio / opaque ---"
OUT="$(run_stdio opaque)"
assert "stdio opaque" confirmed "$(printf '%s' "$OUT" | sed -n 1p)"
check_findings "stdio opaque finding evidence did not prove the flip" "$FLIP_CHECKS" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 11. stdio / legacy ---"
OUT="$(run_stdio legacy)"
assert "stdio legacy" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
contains "stdio skip names the class" "pre-stateless-core" "$(printf '%s' "$OUT" | sed -n 2p)"

echo "--- 12. stdio / target cannot be run ---"
OUT="$(timeout 60 python3 "$TEMPLATE" --stdio /nonexistent/cxg-mcp-server 2>/dev/null | python3 -c "$SPLIT")"
assert "stdio unrunnable" errored "$(printf '%s' "$OUT" | sed -n 1p)"
contains "error names the target" "stdio-target-not-executable" "$(printf '%s' "$OUT" | sed -n 2p)"

echo
[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

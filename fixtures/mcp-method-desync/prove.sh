#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-method-desync.py.
#
# The oracle is a property of TWO calls to one server - "the body's method runs
# only when the Mcp-Method header names the same method" - so the proof drives
# every direction that decides a verdict:
#
#   1. CONFIRM  flawed twin. A body calling the privileged admin_purge under a
#               benign `Mcp-Method: tools/list` header runs anyway. The finding
#               must carry the probe's own nonce echoed back (the body ran) and
#               a matched control that executed (the baseline).
#   2. REFUTE   fixed twin. The same mismatch is refused with HTTP 409, while
#               the matched control still executes - so "quiet" means "rejected
#               the desync", not "inert tool".
#   3. SKIP     legacy twin. It predates the routing-header surface: a request
#               routed by the Mcp-Method header alone is not honoured, so there
#               is no header for a gateway to trust and the class does not apply.
#   4. SKIP     nothing listening at all.
#
#   ./prove.sh          # exit 0 = every direction holds
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-method-desync.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8971}
PORT_FIXED=${PORT_FIXED:-8972}
PORT_LEGACY=${PORT_LEGACY:-8973}
PORT_DEAD=${PORT_DEAD:-8979}
FAILED=0
LAB="$(mktemp -d)"

cleanup() {
    for p in "${PID_A:-}" "${PID_B:-}" "${PID_C:-}"; do
        [ -n "$p" ] || continue
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done
    rm -rf "$LAB"
}
trap cleanup EXIT

run_http() {  # run_http <port> -> line1 status, line2 detail, line3 findings json
    python3 "$TEMPLATE" 127.0.0.1 "$1" http 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d["metadata"]["status"]); print(d["metadata"]["detail"])
print(json.dumps(d["findings"]))'
}

assert() {  # assert <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf 'ok    %s -> %s\n' "$1" "$3"
    else printf 'FAIL  %s -> expected %s, got %s\n' "$1" "$2" "$3"; FAILED=1; fi
}

contains() {  # contains <label> <needle> <haystack>
    case "$3" in
        *"$2"*) printf 'ok    %s\n' "$1" ;;
        *) printf 'FAIL  %s (missing: %s)\n' "$1" "$2"; FAILED=1 ;;
    esac
}

for m in flawed fixed legacy; do mkdir -p "$LAB/$m"; done
( cd "$LAB/flawed" && exec python3 "$SERVER" --mode flawed --port "$PORT_FLAWED" ) 2>/dev/null & PID_A=$!
( cd "$LAB/fixed"  && exec python3 "$SERVER" --mode fixed  --port "$PORT_FIXED"  ) 2>/dev/null & PID_B=$!
( cd "$LAB/legacy" && exec python3 "$SERVER" --mode legacy --port "$PORT_LEGACY" ) 2>/dev/null & PID_C=$!
sleep 1.5

echo "--- 1. flawed twin: privileged body runs under a benign Mcp-Method header ---"
OUT="$(run_http "$PORT_FLAWED")"
STATUS="$(printf '%s' "$OUT" | sed -n 1p)"; DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"; FINDINGS="$(printf '%s' "$OUT" | sed -n 3p)"
assert "flawed" confirmed "$STATUS"
printf '      %s\n' "$DETAIL"
contains "detail names the benign header"        "Mcp-Method:tools/list" "$DETAIL"
contains "detail names the privileged tool"      "admin_purge" "$DETAIL"
printf '%s' "$FINDINGS" | python3 -c '
import json,sys
f=json.load(sys.stdin)
assert len(f)==1, "expected exactly one finding, got %d" % len(f)
d=f[0]["evidence"]["data"]
c,p=d["control"],d["probe"]
assert c["sent_header_method"]=="tools/call" and c["sent_body_method"]=="tools/call", c
assert p["sent_header_method"]=="tools/list" and p["sent_body_method"]=="tools/call", p
assert c["nonce_echoed"] is True, ("control did not execute", c)
assert p["nonce_echoed"] is True, ("probe body was not honoured", p)
assert p["nonce"] in p["excerpt"], ("probe echo not bound to its own nonce", p)
assert p["nonce"]!=c["nonce"], "control and probe must use distinct nonces"
print("ok    finding: matched control executed, mismatched probe echoed its OWN nonce (body ran)")
' || { echo "FAIL  flawed finding evidence did not prove the desync"; FAILED=1; }

echo "--- 2. fixed twin: the mismatch is refused, the matched control still runs ---"
OUT="$(run_http "$PORT_FIXED")"
assert "fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "refutation proves the control executed"   "control-executed:nonce" "$DETAIL"
contains "refutation names the mismatch rejection"  "rejected the header/body method mismatch" "$DETAIL"
assert "fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 3. legacy twin: no routing-header surface -> skip ---"
OUT="$(run_http "$PORT_LEGACY")"
assert "legacy" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the missing precondition" "server-predates-routing-header-surface" "$DETAIL"
assert "legacy emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 4. nothing listening: skip, precondition named ---"
OUT="$(run_http "$PORT_DEAD")"
assert "no server" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the missing precondition" "no-mcp-server-answered" "$DETAIL"

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

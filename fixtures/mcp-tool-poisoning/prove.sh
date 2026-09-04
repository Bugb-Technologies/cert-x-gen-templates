#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-tool-poisoning.py (issue #31).
#
# Three assertions, in the order they matter:
#   1. the template CONFIRMS against the flawed fixture, on every oracle class;
#   2. it REFUTES against the fixed twin, which carries the same visible words
#      plus every construct issue #31 named as a false positive;
#   3. the corpus of natural strings produces no hard hit, and the folded-in
#      Unicode oracle still agrees with mcp-invisible-unicode-poisoning.
#
#   ./prove.sh          # exit 0 = all three hold
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-tool-poisoning.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8941}
PORT_FIXED=${PORT_FIXED:-8942}
FAILED=0

cleanup() { [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null; [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null; }
trap cleanup EXIT

status_of() {  # status_of <port>
    python3 "$TEMPLATE" 127.0.0.1 "$1" http \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["metadata"]["status"]); print(d["metadata"]["detail"])'
}

assert() {  # assert <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        printf 'ok    %s -> %s\n' "$1" "$3"
    else
        printf 'FAIL  %s -> expected %s, got %s\n' "$1" "$2" "$3"
        FAILED=1
    fi
}

python3 "$SERVER" --mode flawed --port "$PORT_FLAWED" 2>/dev/null & PID_A=$!
python3 "$SERVER" --mode fixed  --port "$PORT_FIXED"  2>/dev/null & PID_B=$!
sleep 1.5

echo "--- 1. flawed fixture ---"
OUT="$(status_of "$PORT_FLAWED")"
assert "flawed" confirmed "$(printf '%s' "$OUT" | head -1)"
printf '      %s\n' "$(printf '%s' "$OUT" | tail -1)"
for CLASS in model-directed-instructions instruction-in-html-comment \
             instruction-in-hidden-tag tag-block-payload zero-width-run \
             zero-width-in-ascii-word unbalanced-bidi; do
    case "$OUT" in
        *"$CLASS"*) printf 'ok    class %s fired\n' "$CLASS" ;;
        *) printf 'FAIL  class %s did not fire\n' "$CLASS"; FAILED=1 ;;
    esac
done

echo "--- 2. fixed twin ---"
OUT="$(status_of "$PORT_FIXED")"
assert "fixed" refuted "$(printf '%s' "$OUT" | head -1)"
printf '      %s\n' "$(printf '%s' "$OUT" | tail -1)"

echo "--- 3. no server on the port -> skipped, not refuted ---"
assert "absent" skipped "$(status_of 8949 | head -1)"

echo "--- 4. natural corpus + no-drift (issue #31's false positives) ---"
python3 "$HERE/natural_corpus.py" || FAILED=1

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

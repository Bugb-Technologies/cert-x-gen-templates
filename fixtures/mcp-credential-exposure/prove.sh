#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-credential-exposure.py (issue #32).
#
#   1. the template CONFIRMS on the flawed fixture, naming the secret types it
#      actually read back;
#   2. it REFUTES on the fixed twin, which advertises the SAME credential-named
#      resources ("Token Usage Stats", "Password Reset Policy", ".env.example",
#      "Secret Santa Roster", secrets://{key}) - every one of which produced a
#      medium finding in 1.0.0 with no secret observed;
#   3. the refutation still NAMES the credential-named resources and the
#      unread templated URI, so a clean verdict is not a silent one;
#   4. the value-level corpus holds (issue #32 section 2).
#
#   ./prove.sh          # exit 0 = all four hold
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-credential-exposure.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8951}
PORT_FIXED=${PORT_FIXED:-8952}
FAILED=0

cleanup() { [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null; [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null; }
trap cleanup EXIT

status_of() {
    python3 "$TEMPLATE" 127.0.0.1 "$1" http \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["metadata"]["status"]); print(d["metadata"]["detail"])'
}

assert() {
    if [ "$2" = "$3" ]; then printf 'ok    %s -> %s\n' "$1" "$3"
    else printf 'FAIL  %s -> expected %s, got %s\n' "$1" "$2" "$3"; FAILED=1; fi
}

contains() {  # contains <label> <needle> <haystack>
    case "$3" in *"$2"*) printf 'ok    %s\n' "$1" ;;
                 *) printf 'FAIL  %s (missing %s)\n' "$1" "$2"; FAILED=1 ;; esac
}

python3 "$SERVER" --mode flawed --port "$PORT_FLAWED" 2>/dev/null & PID_A=$!
python3 "$SERVER" --mode fixed  --port "$PORT_FIXED"  2>/dev/null & PID_B=$!
sleep 1.5

echo "--- 1. flawed fixture: a secret was read back ---"
OUT="$(status_of "$PORT_FLAWED")"
assert "flawed" confirmed "$(printf '%s' "$OUT" | head -1)"
printf '      %s\n' "$(printf '%s' "$OUT" | tail -1)"
for T in aws-access-key password-assignment db-connection-string; do
    contains "secret type $T reported" "$T" "$OUT"
done

echo "--- 2. fixed twin: same names, no secret -> refuted (issue #32) ---"
OUT="$(status_of "$PORT_FIXED")"
assert "fixed" refuted "$(printf '%s' "$OUT" | head -1)"
printf '      %s\n' "$(printf '%s' "$OUT" | tail -1)"

echo "--- 3. the refutation is not silent ---"
contains "credential-named resources named as observations" "credential-named-resource" "$OUT"
contains "placeholder assignments named as observations" "placeholder-assignment" "$OUT"
contains "templated uri named as not-read" "secrets://{key}" "$OUT"

echo "--- 4. no server on the port -> skipped, not refuted ---"
assert "absent" skipped "$(status_of 8959 | head -1)"

echo "--- 5. value-level corpus (issue #32 section 2) ---"
python3 "$HERE/secret_corpus.py" || FAILED=1

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

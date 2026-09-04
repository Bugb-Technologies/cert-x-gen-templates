#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-excessive-scope-proof.py.
#
# The oracle is a property of an OBSERVED RUN - "a tool that declared itself
# read-only produced no write" - so the proof exercises it through both
# witnesses and in every direction that decides a verdict:
#
#   1. CONFIRM (protocol witness, http)   the flawed twin's read_note makes a
#              nonce path exist: absent on the first read, present on an
#              identical second read.
#   2. REFUTE  (protocol witness, http)   the fixed twin's read_note leaves the
#              same nonce path absent both times - and the negative control
#              proves the witness can still tell absent from present, so the
#              refutation means "no write", not "no signal".
#   3. SKIP    (http)   a server whose only tool DECLARES write and delete has
#              no narrow scope to act outside of. That is
#              mcp-excessive-tool-permissions' finding, not this one.
#   4. CONFIRM (filesystem witness, stdio) the flawed twin, spawned in a
#              hermetic lab and asked only to read a planted note, writes an
#              audit log the control run never produced.
#   5. REFUTE  (filesystem witness, stdio) the fixed twin, same lab, same
#              calls, writes nothing the control run did not - with the
#              witness self-test proving the snapshot could have seen a write.
#   6. SKIP    nothing listening at all.
#
#   ./prove.sh          # exit 0 = every direction holds
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-excessive-scope-proof.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8961}
PORT_FIXED=${PORT_FIXED:-8962}
PORT_BROAD=${PORT_BROAD:-8963}
PORT_DEAD=${PORT_DEAD:-8969}
FAILED=0
LAB="$(mktemp -d)"

cleanup() {
    for p in "${PID_A:-}" "${PID_B:-}" "${PID_C:-}"; do
        [ -n "$p" ] || continue
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null   # reap it, so the shell prints no job-control noise
    done
    rm -rf "$LAB"
}
trap cleanup EXIT

# Emits: line 1 = status, line 2 = detail, line 3 = compact finding JSON.
run_http() {  # run_http <port>
    python3 "$TEMPLATE" 127.0.0.1 "$1" http 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d["metadata"]["status"]); print(d["metadata"]["detail"])
print(json.dumps(d["findings"]))'
}

run_stdio() {  # run_stdio <mode>
    python3 "$TEMPLATE" --stdio python3 "$SERVER" --mode "$1" --transport stdio 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d["metadata"]["status"]); print(d["metadata"]["detail"])
print(json.dumps(d["findings"]))'
}

assert() {  # assert <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        printf 'ok    %s -> %s\n' "$1" "$3"
    else
        printf 'FAIL  %s -> expected %s, got %s\n' "$1" "$2" "$3"
        FAILED=1
    fi
}

contains() {  # contains <label> <needle> <haystack>
    case "$3" in
        *"$2"*) printf 'ok    %s\n' "$1" ;;
        *) printf 'FAIL  %s (missing: %s)\n' "$1" "$2"; FAILED=1 ;;
    esac
}

# Each HTTP twin gets its own working directory: the fixture resolves every
# path under its cwd, so the writes it makes stay inside the lab.
for m in flawed fixed broad; do mkdir -p "$LAB/$m"; done
( cd "$LAB/flawed" && exec python3 "$SERVER" --mode flawed --transport http --port "$PORT_FLAWED" ) 2>/dev/null & PID_A=$!
( cd "$LAB/fixed"  && exec python3 "$SERVER" --mode fixed  --transport http --port "$PORT_FIXED"  ) 2>/dev/null & PID_B=$!
( cd "$LAB/broad"  && exec python3 "$SERVER" --mode broad  --transport http --port "$PORT_BROAD"  ) 2>/dev/null & PID_C=$!
sleep 1.5

echo "--- 1. http / flawed twin: a declared read-only tool made its own subject exist ---"
OUT="$(run_http "$PORT_FLAWED")"
STATUS="$(printf '%s' "$OUT" | sed -n 1p)"; DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"; FINDINGS="$(printf '%s' "$OUT" | sed -n 3p)"
assert "http flawed" confirmed "$STATUS"
printf '      %s\n' "$DETAIL"
contains "the flip is named in the detail" "witness=protocol" "$DETAIL"
contains "read_note is the tool reported"  "read_note" "$DETAIL"
printf '%s' "$FINDINGS" | python3 -c '
import json,sys
f=json.load(sys.stdin)
assert len(f)==1, "expected exactly one finding, got %d" % len(f)
obs=f[0]["evidence"]["data"]["observations"]
assert obs and obs[0]["read_1"]=="absent" and obs[0]["read_2"]=="present", obs
assert obs[0]["negative_control"]["outcome"]=="absent", obs
assert "CXG-SYNTHETIC-DECOY-MARKER" in obs[0]["read_2_excerpt"], obs[0]["read_2_excerpt"]
print("ok    finding carries absent->present, a passing negative control, and the decoy the tool wrote")
' || { echo "FAIL  finding evidence did not prove the write"; FAILED=1; }

echo "--- 2. http / fixed twin: the same probe leaves the path absent ---"
OUT="$(run_http "$PORT_FIXED")"
assert "http fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "refutation says absent->absent"         "read_note:absent->absent" "$DETAIL"
contains "refutation names its live negative control" "negative-control-absent" "$DETAIL"
assert "http fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 3. http / broad twin: a tool that DECLARES write is not this check's finding ---"
OUT="$(run_http "$PORT_BROAD")"
assert "http broad" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the missing precondition" "no-tool-declares-a-narrow-scope" "$DETAIL"

echo "--- 4. stdio / flawed twin: filesystem witness sees the undeclared audit write ---"
OUT="$(run_stdio flawed)"
assert "stdio flawed" confirmed "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "the undeclared audit log is the proof" ".cxg-read-audit.log" "$DETAIL"
contains "control run wrote nothing to subtract"  "control_writes=0" "$DETAIL"
printf '%s' "$OUT" | sed -n 3p | python3 -c '
import json,sys
f=json.load(sys.stdin)
assert len(f)==1, "expected exactly one finding, got %d" % len(f)
d=f[0]["evidence"]["data"]
assert d["witness_selftest"]=="live", d["witness_selftest"]
written=d["paths_written_by_the_call_run"]
assert any(p.endswith(".cxg-read-audit.log") for p in written), written
assert d["paths_written_by_the_control_run_and_therefore_ignored"]=={}, d
assert d["calls_made"], "no tools were actually called"
assert any("CXG-SYNTHETIC-DECOY-MARKER" in v for v in d["written_content_excerpts"].values()), d
print("ok    finding carries the written paths, the subtracted control, a live witness and the decoy bytes")
' || { echo "FAIL  stdio finding evidence did not prove the write"; FAILED=1; }

echo "--- 5. stdio / fixed twin: same calls, same lab, nothing written ---"
OUT="$(run_stdio fixed)"
assert "stdio fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "refutation proves it made the calls"     "call(s) made" "$DETAIL"
contains "refutation proves the witness was live"  "filesystem-witness-selftest=live" "$DETAIL"
assert "stdio fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 6. nothing listening: skip, with the precondition named ---"
OUT="$(run_http "$PORT_DEAD")"
assert "no server" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the missing precondition" "no-mcp-server-answered" "$DETAIL"

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-cache-scope-identity-leak.py.
#
# The oracle is a differential with a same-identity control, so the proof
# exercises every verdict the check can emit - including both of its SKIP
# branches, which are different facts and must not collapse into one:
#
#   1. CONFIRM  the flawed twin serves a per-caller inbox and marks it
#               cacheScope "public". The finding must name notes://inbox and
#               NOT the two decoys.
#   2. REFUTE   the fixed twin serves the same per-caller inbox marked
#               "private" while keeping the genuinely shared resources
#               "public" - so the refutation proves the server draws the
#               distinction, not that it disabled caching.
#   3. SKIP (a) the shared twin varies nothing by caller: a public label there
#               leaks nothing, so there is no finding to make.
#   4. SKIP (b) the legacy twin (pre-2026-07-28) emits no CacheableResult at
#               all: an absent field is not a correct one, so this is a skip
#               and never a refutation.
#   5. SKIP (c) a server that rejects both identities - the check cannot run a
#               differential it was never let into.
#   6. DECOYS   in BOTH the confirm and the refute run, the volatile resource
#               (clock://now, public, different on every single read) and the
#               shared one (docs://changelog, public, identical for everyone)
#               must appear as observations and never as findings. Without the
#               same-identity control probe, clock://now confirms on the FIXED
#               twin - that is the false positive this asserts against.
#
#   ./prove.sh          # exit 0 = every branch holds
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-cache-scope-identity-leak.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8951}
PORT_FIXED=${PORT_FIXED:-8952}
PORT_SHARED=${PORT_SHARED:-8953}
PORT_LEGACY=${PORT_LEGACY:-8954}
PORT_CLOSED=${PORT_CLOSED:-8955}
FAILED=0
PIDS=()

cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

run_check() {  # run_check <port> -> "<status>\n<detail>"
    python3 "$TEMPLATE" 127.0.0.1 "$1" http 2>/dev/null \
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

contains() {  # contains <label> <needle> <haystack>
    case "$3" in
        *"$2"*) printf 'ok    %s\n' "$1" ;;
        *) printf 'FAIL  %s (missing: %s)\n' "$1" "$2"; FAILED=1 ;;
    esac
}

lacks() {  # lacks <label> <needle> <haystack>
    case "$3" in
        *"$2"*) printf 'FAIL  %s (present but must not be: %s)\n' "$1" "$2"; FAILED=1 ;;
        *) printf 'ok    %s\n' "$1" ;;
    esac
}

# A server that answers MCP but rejects every identity we can present.
CLOSED_SRC="$(cat <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_POST(self):
        l = int(self.headers.get('Content-Length') or 0)
        try: rid = json.loads(self.rfile.read(l) or b"{}").get("id")
        except ValueError: rid = None
        b = json.dumps({"jsonrpc":"2.0","id":rid,"error":{"code":-32001,"message":"unauthorized"}}).encode()
        self.send_response(401)
        self.send_header("Content-Type","application/json")
        self.send_header("WWW-Authenticate",'Bearer realm="closed"')
        self.send_header("Content-Length",str(len(b)))
        self.end_headers(); self.wfile.write(b)
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
)"

for spec in "flawed:$PORT_FLAWED" "fixed:$PORT_FIXED" "shared:$PORT_SHARED" "legacy:$PORT_LEGACY"; do
    python3 "$SERVER" --mode "${spec%%:*}" --port "${spec##*:}" 2>/dev/null &
    PIDS+=("$!")
done
python3 -c "$CLOSED_SRC" "$PORT_CLOSED" 2>/dev/null & PIDS+=("$!")
sleep 1.5

echo "--- 1. flawed twin (per-caller inbox marked cacheScope public) ---"
OUT="$(run_check "$PORT_FLAWED")"
assert "flawed" confirmed "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
contains "the finding names the per-caller resource" "probes=resources/read(notes://inbox)" "$DETAIL"
contains "the public TTL is carried into the verdict" "ttl_ms=60000" "$DETAIL"
lacks    "the volatile decoy is not part of the finding" "probes=resources/read(clock://now)" "$DETAIL"
contains "the shared decoy is recorded as an observation" "identical-for-both-identities(resources/read(docs://changelog)" "$DETAIL"
contains "the volatile decoy is recorded as an observation" "volatile-not-identity-dependent(resources/read(clock://now)" "$DETAIL"

echo "--- 2. fixed twin (same per-caller inbox, scoped private; shared ones stay public) ---"
OUT="$(run_check "$PORT_FIXED")"
assert "fixed" refuted "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
contains "the refutation names the resource it cleared" "identity-dependent-responses-scoped-private(resources/read(notes://inbox))" "$DETAIL"
contains "the fixed twin still caches shared results publicly" "identical-for-both-identities(resources/read(docs://changelog)" "$DETAIL"
contains "the volatile public resource is seen and declined" "volatile-not-identity-dependent(resources/read(clock://now)" "$DETAIL"

echo "--- 3. shared twin (nothing varies by caller - a public label leaks nothing) ---"
OUT="$(run_check "$PORT_SHARED")"
assert "shared" skipped "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
contains "skips for the right reason" "no-identity-dependent-response-observed" "$DETAIL"

echo "--- 4. legacy twin (pre-2026-07-28: no CacheableResult to be wrong) ---"
OUT="$(run_check "$PORT_LEGACY")"
assert "legacy" skipped "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
contains "skips for the right reason" "no-cacheableresult-directive-observed" "$DETAIL"
contains "and still names what it saw vary by caller" "identity-dependent-without-directive" "$DETAIL"

echo "--- 5. closed server (both identities rejected - no differential to run) ---"
OUT="$(run_check "$PORT_CLOSED")"
assert "closed" skipped "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
contains "skips for the right reason" "identities-not-accepted" "$DETAIL"

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

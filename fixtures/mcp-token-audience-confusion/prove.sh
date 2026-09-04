#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-token-audience-confusion.py.
#
# The oracle is a behavioural property - REJECTION of a wrong-audience token -
# so the proof exercises it in every direction that decides a verdict:
#
#   1. CONFIRM  the flawed twin gates on a token yet accepts one whose `aud`
#              names another resource. All three methods (initialize,
#              tools/list, tools/call) are served with the foreign token.
#   2. REFUTE   the fixed twin rejects the same foreign-audience token (401)
#              while still accepting a token scoped to itself - so the
#              refutation proves the gate WORKS, not that it rejects blindly.
#   3. SKIP     a server with no auth at all is not reported (that is
#              mcp-unauthenticated's job, not this one) - guards the differential
#              that keeps "accepts a wrong-audience token" distinct from
#              "has no authentication".
#
#   ./prove.sh          # exit 0 = all three hold
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-token-audience-confusion.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8941}
PORT_FIXED=${PORT_FIXED:-8942}
PORT_NOAUTH=${PORT_NOAUTH:-8943}
FAILED=0

cleanup() { for p in "${PID_A:-}" "${PID_B:-}" "${PID_C:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

status_of() {  # status_of <port>
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

# A minimal no-auth MCP server: same class of target, but with no auth gate,
# so the differential must SKIP rather than confirm.
NOAUTH_SRC="$(cat <<'PY'
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*a): pass
    def do_POST(self):
        l=int(self.headers.get('Content-Length') or 0)
        req=json.loads(self.rfile.read(l) or b"{}")
        rid=req.get("id"); m=req.get("method")
        if rid is None:
            self.send_response(202); self.send_header("Content-Length","0"); self.end_headers(); return
        res={"initialize":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"noauth","version":"1"}},"tools/list":{"tools":[]}}.get(m,{})
        b=json.dumps({"jsonrpc":"2.0","id":rid,"result":res}).encode()
        self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
import sys
ThreadingHTTPServer(("127.0.0.1",int(sys.argv[1])),H).serve_forever()
PY
)"

python3 "$SERVER" --mode flawed --port "$PORT_FLAWED" 2>/dev/null & PID_A=$!
python3 "$SERVER" --mode fixed  --port "$PORT_FIXED"  2>/dev/null & PID_B=$!
python3 -c "$NOAUTH_SRC" "$PORT_NOAUTH" 2>/dev/null & PID_C=$!
sleep 1.5

echo "--- 1. flawed twin (accepts a token minted for another audience) ---"
OUT="$(status_of "$PORT_FLAWED")"
assert "flawed" confirmed "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
case "$DETAIL" in
    *"methods=initialize,tools_list,tools_call"*) printf 'ok    foreign token reached initialize, tools/list AND tools/call\n' ;;
    *) printf 'FAIL  foreign token did not reach all three methods\n'; FAILED=1 ;;
esac

echo "--- 2. fixed twin (rejects the foreign audience, still accepts its own) ---"
OUT="$(status_of "$PORT_FIXED")"
assert "fixed" refuted "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
case "$DETAIL" in
    *"self_aud=accept"*) printf 'ok    the fixed gate still accepts a correctly-scoped token (validates aud, not just presence)\n' ;;
    *) printf 'FAIL  fixed twin rejected even its own audience - refutes for the wrong reason\n'; FAILED=1 ;;
esac

echo "--- 3. no-auth server (must not be reported - that is mcp-unauthenticated) ---"
OUT="$(status_of "$PORT_NOAUTH")"
assert "no-auth" skipped "$(printf '%s' "$OUT" | head -1)"
printf '      %s\n' "$(printf '%s' "$OUT" | tail -1)"

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

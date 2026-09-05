#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-oauth-consent-dcr-abuse.py.
#
# The oracle is a behavioural property - the consent decision must be BOUND to
# the redirect_uri, not reused across redirect_uris for a shared client_id - so
# the proof exercises it in every direction that decides a verdict, and does it
# both through the template directly AND (when `cxg` is on PATH) through a real
# `cxg scan`, because that is the definition of "works":
#
#   1. CONFIRM  the flawed twin has open DCR, a shared static client_id, and
#              reuses a consent cookie so an attacker-registered redirect_uri
#              receives an authorization code with NO re-consent and no
#              RFC 9207 `iss`.
#   2. REFUTE   the fixed twin vets the redirect_uri at registration, binds
#              consent to (client_id, redirect_uri), and stamps `iss` + echoes
#              `state` - so the refutation proves the layer WORKS (a code IS
#              issued to the benign redirect), not that it rejects blindly.
#   3. SKIP     an AS with no consent gate at all (immediate code, no consent
#              step) is NOT reported here - it is a different, weaker finding.
#              This guards the differential that keeps "reuses consent across
#              redirect_uris" distinct from "never consents".
#
#   ./prove.sh          # exit 0 = all three hold (and cxg agrees if present)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-oauth-consent-dcr-abuse.py"
SERVER="$HERE/oauth_as_fixture.py"
PORT_FLAWED=${PORT_FLAWED:-9401}
PORT_FIXED=${PORT_FIXED:-9402}
PORT_NOCONSENT=${PORT_NOCONSENT:-9403}
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

# A no-consent AS: open DCR, but /authorize issues a code immediately with no
# consent screen at all. Same class of target, but there is no consent decision
# to be "reused", so the differential must SKIP rather than confirm.
NOCONSENT_SRC="$(cat <<'PY'
import json, sys, uuid, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT=int(sys.argv[1]); BASE="http://127.0.0.1:%d"%PORT
class H(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*a): pass
    def _send(self,c,b,ct="application/json"):
        if isinstance(b,(dict,list)): b=json.dumps(b)
        raw=b.encode(); self.send_response(c)
        self.send_header("Content-Type",ct); self.send_header("Content-Length",str(len(raw)))
        self.send_header("Connection","close"); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        p=urllib.parse.urlsplit(self.path)
        if p.path.startswith("/.well-known/"):
            self._send(200,{"issuer":BASE,"authorization_endpoint":BASE+"/authorize",
                "registration_endpoint":BASE+"/register","token_endpoint":BASE+"/token"})
        elif p.path=="/authorize":
            q=dict(urllib.parse.parse_qsl(p.query))
            loc="%s?code=cxg-%s&state=%s"%(q.get("redirect_uri",""),uuid.uuid4().hex[:8],q.get("state",""))
            self.send_response(302); self.send_header("Location",loc)
            self.send_header("Content-Length","0"); self.send_header("Connection","close"); self.end_headers()
        else: self._send(404,{"error":"not_found"})
    def do_POST(self):
        l=int(self.headers.get("Content-Length") or 0); self.rfile.read(l)
        if urllib.parse.urlsplit(self.path).path=="/register":
            self._send(201,{"client_id":"cxg-noconsent-static","redirect_uris":[]})
        else: self._send(404,{"error":"not_found"})
ThreadingHTTPServer(("127.0.0.1",PORT),H).serve_forever()
PY
)"

python3 "$SERVER" --mode flawed --port "$PORT_FLAWED" 2>/dev/null & PID_A=$!
python3 "$SERVER" --mode fixed  --port "$PORT_FIXED"  2>/dev/null & PID_B=$!
python3 -c "$NOCONSENT_SRC" "$PORT_NOCONSENT" 2>/dev/null & PID_C=$!
sleep 1.5

echo "--- 1. flawed twin (open DCR + shared client_id + consent reused across redirect_uris) ---"
OUT="$(status_of "$PORT_FLAWED")"
assert "flawed" confirmed "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
case "$DETAIL" in
    *"code-delivered-to-attacker-redirect_uri-without-re-consent"*) printf 'ok    a code reached the attacker redirect_uri with no re-consent\n' ;;
    *) printf 'FAIL  the core confused-deputy signal is missing\n'; FAILED=1 ;;
esac
case "$DETAIL" in
    *"open-dcr-accepted-unvetted-redirect_uri"*) printf 'ok    open DCR accepted the unvetted redirect_uri\n' ;;
    *) printf 'FAIL  open-DCR signal missing\n'; FAILED=1 ;;
esac

echo "--- 2. fixed twin (vets redirect_uri, binds consent, returns iss + state) ---"
OUT="$(status_of "$PORT_FIXED")"
assert "fixed" refuted "$(printf '%s' "$OUT" | head -1)"
DETAIL="$(printf '%s' "$OUT" | tail -1)"
printf '      %s\n' "$DETAIL"
case "$DETAIL" in
    *"baseline_iss=http"*) printf 'ok    the fixed AS still issues a code to the benign redirect and returns RFC 9207 iss (protects, not blindly rejects)\n' ;;
    *) printf 'FAIL  fixed twin did not prove its baseline flow live\n'; FAILED=1 ;;
esac

echo "--- 3. no-consent AS (must NOT be reported here - it is a different finding) ---"
OUT="$(status_of "$PORT_NOCONSENT")"
assert "no-consent" skipped "$(printf '%s' "$OUT" | head -1)"
printf '      %s\n' "$(printf '%s' "$OUT" | tail -1)"

# ---- real cxg scan, both directions, if cxg is on PATH ----
if command -v cxg >/dev/null 2>&1; then
    echo "--- 4. real cxg scan (flawed -> 1 finding, fixed -> 0) ---"
    WORK="$(mktemp -d)"; export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	$PORT_FLAWED	1" "fixed	$PORT_FIXED	0"; do
        IFS='	' read -r variant port want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "http://127.0.0.1:$port" \
            --templates "$TEMPLATE" \
            --output "$WORK/scan-$variant" --output-format json >/dev/null 2>&1
        got="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["findings"]))' "$WORK/scan-$variant.json" 2>/dev/null)"
        if [ "$got" = "$want" ]; then
            printf 'ok    cxg scan %s -> %s finding(s)\n' "$variant" "$got"
        else
            printf 'FAIL  cxg scan %s -> expected %s, got %s\n' "$variant" "$want" "${got:-<no report>}"
            FAILED=1
        fi
    done
    rm -rf "$WORK"
else
    echo "--- 4. cxg scan: SKIPPED (cxg not on PATH) ---"
fi

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

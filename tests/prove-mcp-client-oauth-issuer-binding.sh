#!/usr/bin/env bash
# Prove templates/ai/mcp/mcp-client-oauth-issuer-binding.py in every direction
# it emits, against the synthetic twin set in
# tests/fixtures/mcp-client-oauth-issuer-binding/.
#
# The template drives an MCP *client*: it binds two mock authorization servers
# and two mock MCP resources on loopback, runs the target's own login command
# twice against one $HOME, and reads what the second issuer's ledger caught.
#
#   CONFIRMED on agent-mcp-client_flawed.py   -- a credential store keyed by
#              nothing carries AS1's access token to RS2 and AS1's client_secret
#              to AS2, uses the shared client_id at AS2 with no registration
#              there, and redeems a code whose RFC 9207 `iss` named AS1.
#              Asserted under BOTH `iss` modes (mismatched and missing) and
#              with all four hard signals named.
#   REFUTED   on agent-mcp-client_fixed.py    -- the same program with the store
#              keyed by (issuer, client_id) and `iss` checked: it re-registers
#              at AS2, is handed the bad `iss`, and never redeems. Under both
#              `iss` modes.
#   SKIP      on agent-mcp-client_nooauth.py  -- the same program with the login
#              surface removed: no OAuth login path, named as the missing
#              precondition.
#   SKIP      on a non-agent binary (git)     -- no MCP login surface at all,
#              and - since a subcommand probe's own error text must not invent
#              the surface it was looking for - zero invocations attempted.
#   SKIP      phase 1 never completed         -- the fixed twin stopped after
#              discovery: no issuer-bound credential exists, so there is nothing
#              whose reuse could be observed.
#   SKIP      no authorization request at the new issuer -- the fixed twin
#              re-registered at AS2 and refused to authorize against an unknown
#              issuer, so the `iss` check was never exercised. A refutation here
#              would be a clean bill of health the run did not earn.
#
# The last two SKIPs come from switches on the fixture that are orthogonal to
# the flawed/fixed axis, so every branch that decides a verdict has a fixture
# that reaches it rather than only the confirm and refute ones.
#
# The template is exercised through its raw probe contract and -- when `cxg` is
# on PATH -- through a real `cxg scan`, because the two agree about nothing
# only if you look.
#
# Usage: tests/prove-mcp-client-oauth-issuer-binding.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-client-oauth-issuer-binding.py"
FIXTURES="$HERE/fixtures/mcp-client-oauth-issuer-binding"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-mcp-client-oauth-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

# Emits: status <TAB> finding-count <TAB> detail
probe() {  # probe <target-binary>
    CERT_X_GEN_TARGET_HOST="cli://$1" \
        python3 "$TEMPLATE" "cli://$1" 2>/dev/null \
        | python3 -c 'import json,sys
d = json.load(sys.stdin); m = d["metadata"]
print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))'
}

run_case() {  # run_case <label> <target> <want-status> <want-findings>
    local label="$1" target="$2" want_status="$3" want_findings="$4"
    local result got_status got_findings detail
    result="$(probe "$target")" || { fail "$label: template did not run"; return; }
    IFS=$'\t' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$label: $got_status ($got_findings finding(s)) -- ${detail:0:140}"
    else
        fail "$label: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
}

FLAWED="$WORK/twins/agent-mcp-client_flawed.py"
FIXED="$WORK/twins/agent-mcp-client_fixed.py"
NOOAUTH="$WORK/twins/agent-mcp-client_nooauth.py"

echo "probe contract"
run_case "flawed twin"  "$FLAWED"  confirmed 1
run_case "fixed twin"   "$FIXED"   refuted   0
run_case "nooauth twin" "$NOOAUTH" skipped   0
if command -v git >/dev/null 2>&1; then
    run_case "non-agent binary (git)" "$(command -v git)" skipped 0
else
    note "non-agent binary: SKIPPED (git not on PATH)"
fi

echo "the confirmation names every conformance failure it observed"
detail_flawed="$(probe "$FLAWED")"
for signal in access-token-reused-across-resources \
              client-secret-reused-across-issuers \
              no-registration-at-new-issuer \
              authorization-response-iss-not-validated; do
    if printf '%s' "$detail_flawed" | grep -q -- "$signal"; then
        note "flawed: '$signal' named in the confirmation"
    else
        fail "flawed: confirmation did not name '$signal'"
    fi
done
# A verdict taken through a ledger that cannot see is unbacked, so the
# confirmation must say the ledger proved itself.
if printf '%s' "$detail_flawed" | grep -q 'ledger_selftest=live'; then
    note "flawed: the observation ledger proved itself live before the verdict"
else
    fail "flawed: confirmation does not record a live observation ledger"
fi

echo "the canary really is what fires: evidence carries the AS1 decoys"
python3 "$TEMPLATE" "cli://$FLAWED" 2>/dev/null >"$WORK/flawed.json"
python3 - "$WORK/flawed.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys
data = json.load(open(sys.argv[1]))["findings"][0]["evidence"]["data"]
canary = data["canaries"]
problems = []
signals = {h["signal"]: h for h in data["hard_signals"]}
if signals["access-token-reused-across-resources"]["observed"] != canary["as1_token"]:
    problems.append("token signal did not carry the AS1 token canary")
if signals["client-secret-reused-across-issuers"]["observed"] != canary["as1_secret"]:
    problems.append("secret signal did not carry the AS1 secret canary")
if not any(r.get("authorization") == "Bearer " + canary["as1_token"]
           for r in data["rs2_ledger"]):
    problems.append("RS2's ledger holds no request bearing the AS1 token")
iss = signals["authorization-response-iss-not-validated"]["observed"]
if iss["iss_returned"] not in (None, data["issuers"]["AS1"]):
    problems.append("the redeemed code's iss was neither absent nor AS1's")
for p in problems:
    print("  FAIL: %s" % p)
print("  evidence carries the AS1 decoys and RS2 saw the bearer token"
      if not problems else "")
sys.exit(1 if problems else 0)
PY

echo "both RFC 9207 failure shapes"
for mode in mismatched missing; do
    result="$(CXG_MCP_CLIENT_ISS_MODE="$mode" probe "$FLAWED")"
    IFS=$'\t' read -r status count _detail <<<"$result"
    if [ "$status" = confirmed ] && [ "$count" = 1 ]; then
        note "flawed, iss=$mode: confirmed"
    else
        fail "flawed, iss=$mode: expected confirmed/1, got $status/$count"
    fi
    result="$(CXG_MCP_CLIENT_ISS_MODE="$mode" probe "$FIXED")"
    IFS=$'\t' read -r status count _detail <<<"$result"
    if [ "$status" = refuted ] && [ "$count" = 0 ]; then
        note "fixed, iss=$mode: refuted"
    else
        fail "fixed, iss=$mode: expected refuted/0, got $status/$count"
    fi
done

echo "the SKIP branches name the precondition they are missing"
skip_case() {  # skip_case <label> <needle> <env-assignment...>
    local label="$1" needle="$2"; shift 2
    local result status count detail
    result="$(env "$@" python3 "$TEMPLATE" "cli://$FIXED" 2>/dev/null \
        | python3 -c 'import json,sys
d = json.load(sys.stdin); m = d["metadata"]
print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))')"
    IFS=$'\t' read -r status count detail <<<"$result"
    if [ "$status" = skipped ] && [ "$count" = 0 ] && \
       printf '%s' "$detail" | grep -q -- "$needle"; then
        note "$label: skipped -- ${detail:0:120}"
    else
        fail "$label: expected skipped/0 naming '$needle', got $status/$count -- $detail"
    fi
}
skip_case "phase 1 never completed" \
    "phase-1-login-did-not-complete-at-the-first-issuer" \
    AGENT_MCP_CLIENT_STOP_AFTER=discovery
skip_case "no authorization request at the new issuer" \
    "new-issuer-reached-but-no-authorization-request" \
    AGENT_MCP_CLIENT_ABORT_ON_NEW_ISSUER=1
skip_case "supplied login command reaches no AS" \
    "supplied-login-command-reached-no-authorization-server" \
    CXG_MCP_CLIENT_LOGIN_CMD='{bin} mcp list {url}'

echo "the nooauth twin's SKIP is the absent login path, not a lucky miss"
result="$(probe "$NOOAUTH")"
if printf '%s' "$result" | grep -q 'no-oauth-login-path'; then
    note "nooauth: the missing precondition is named"
else
    fail "nooauth: SKIP did not name the missing OAuth login path -- $result"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0" "nooauth	0"; do
        IFS=$'\t' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/agent-mcp-client_${variant}.py" \
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
    echo "mcp-client-oauth-issuer-binding: confirmed on the flawed twin under both iss modes, refuted on the fixed one, and skipped - naming the precondition - on the nooauth twin, a non-agent binary, and three unmet-precondition runs."
    exit 0
fi
echo "mcp-client-oauth-issuer-binding: $FAILURES assertion(s) failed." >&2
exit 1

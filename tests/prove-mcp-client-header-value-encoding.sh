#!/usr/bin/env bash
# Prove templates/ai/mcp/client-conformance/mcp-client-header-value-encoding.py
# in every direction it emits, against the synthetic twin set in
# tests/fixtures/mcp-client-header-value-encoding/.
#
# The template drives an MCP *client*: it binds one raw-socket mock MCP server
# on loopback, offers two tools whose schemas are identical apart from the
# default of an `x-mcp-header`-marked parameter, runs the target's own MCP
# command against it, and reads the RAW BYTES that arrived.
#
#   CONFIRMED on agent-mcp-http-client_flawed.py -- the probe leg's request
#              head carries two header lines the client was never asked to
#              send, both bearing this run's nonce.
#   REFUTED   on agent-mcp-http-client_fixed.py  -- the same program with
#              encode_header_value() percent-encoding: the declared header is
#              still emitted, and nothing split.
#   REFUTED   on the flawed twin with REJECT_CONTROL=1 -- the specification's
#              other permitted answer: send the control leg, refuse the value
#              carrying control characters.
#   SKIP      on agent-mcp-http-client_nohdr.py  -- the same program with the
#              x-mcp-header extension removed: the control leg goes out with no
#              such header, so there is no countermeasure here to fail.
#   SKIP      client never called a header-bearing tool (STOP_AFTER=list).
#   SKIP      client never listed tools           (STOP_AFTER=initialize).
#   SKIP      supplied invocation reached the mock server not at all.
#   SKIP      on a non-MCP binary (git) -- and, since a subcommand probe's own
#              error text must not invent the surface it was looking for, zero
#              invocations attempted.
#
# The three SKIPs in the middle come from switches on the fixture orthogonal to
# the flawed/fixed axis, so every branch that decides a verdict has a fixture
# that reaches it rather than only the confirm and refute ones.
#
# The template is exercised through its raw probe contract and -- when `cxg` is
# on PATH -- through a real `cxg scan`, because the two agree about nothing
# only if you look.
#
# Usage: tests/prove-mcp-client-header-value-encoding.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/client-conformance/mcp-client-header-value-encoding.py"
FIXTURES="$HERE/fixtures/mcp-client-header-value-encoding"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-mcp-header-test.XXXXXX")"
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
probe() {  # probe <target-binary> [env assignments...]
    local target="$1"; shift
    env "$@" CERT_X_GEN_TARGET_HOST="cli://$target" \
        python3 "$TEMPLATE" "cli://$target" 2>/dev/null \
        | python3 -c "$SUMMARISE"
}

run_case() {  # run_case <label> <want-status> <want-findings> <target> [env...]
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

FLAWED="$WORK/twins/agent-mcp-http-client_flawed.py"
FIXED="$WORK/twins/agent-mcp-http-client_fixed.py"
NOHDR="$WORK/twins/agent-mcp-http-client_nohdr.py"

echo "probe contract"
run_case "flawed twin" confirmed 1 "$FLAWED"
run_case "fixed twin"  refuted   0 "$FIXED"
run_case "nohdr twin"  skipped   0 "$NOHDR"
if command -v git >/dev/null 2>&1; then
    run_case "non-MCP binary (git)" skipped 0 "$(command -v git)"
else
    note "non-MCP binary: SKIPPED (git not on PATH)"
fi

echo "the refutation and the skips name the branch they took"
needle_case() {  # needle_case <label> <want-status> <needle> <target> [env...]
    local label="$1" want="$2" needle="$3" target="$4"; shift 4
    local result status count detail
    result="$(probe "$target" "$@")"
    IFS=$'\t' read -r status count detail <<<"$result"
    if [ "$status" = "$want" ] && [ "$count" = 0 ] && \
       printf '%s' "$detail" | grep -q -- "$needle"; then
        note "$label: $status -- ${detail:0:110}"
    else
        fail "$label: expected $want/0 naming '$needle', got $status/$count -- $detail"
    fi
}
needle_case "fixed twin value-encoded" refuted \
    "header-value-percent-encoded" "$FIXED"
needle_case "flawed twin, refuses control characters" refuted \
    "client-refused-the-control-character-value" "$FLAWED" \
    AGENT_MCP_HTTP_CLIENT_REJECT_CONTROL=1
needle_case "nohdr twin: the extension is absent" skipped \
    "client-does-not-implement-x-mcp-header" "$NOHDR"
needle_case "never called a header-bearing tool" skipped \
    "client-never-invoked-an-x-mcp-header-tool" "$FLAWED" \
    AGENT_MCP_HTTP_CLIENT_STOP_AFTER=list
needle_case "never listed tools" skipped \
    "client-never-listed-tools" "$FLAWED" \
    AGENT_MCP_HTTP_CLIENT_STOP_AFTER=initialize
needle_case "supplied invocation reaches the mock not at all" skipped \
    "no-request-reached-the-mock-mcp-server" "$FLAWED" \
    CXG_MCP_HEADER_CALL_CMD="mcp list"
needle_case "non-MCP binary: nothing invoked" skipped \
    "no-mcp-surface-in-target-help" "$(command -v git 2>/dev/null || echo /bin/ls)"

echo "the canary really is what fires: the finding carries this run's decoys"
python3 "$TEMPLATE" "cli://$FLAWED" 2>/dev/null >"$WORK/flawed.json"
python3 - "$WORK/flawed.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys

data = json.load(open(sys.argv[1]))["findings"][0]["evidence"]["data"]
canary = data["canaries"]
problems = []

signals = data["hard_signals"]
names = {s["signal"] for s in signals}
if "injected-header-line-in-request-head" not in names:
    problems.append("no injected-header-line signal in the confirmation")
observed = " | ".join(s["observed"] for s in signals)
if canary["decoy_token"] not in observed:
    problems.append("no hard signal carries this run's decoy token")
if canary["marker_header"].lower() not in observed.lower():
    problems.append("no hard signal carries this run's marker header")

head = data["legs"]["probe_record"]["raw_head"]
if canary["header_name"] not in head:
    problems.append("the declared x-mcp-header header never appeared in the raw head")
if "Authorization: Bearer " + canary["decoy_token"] not in head:
    problems.append("the raw head does not carry the decoy Authorization line")
# The split must be real: the injected lines are separate header lines, not
# text inside the declared header's value.
lines = [line for line in head.split("\\r\\n") if line]
if not any(line.lower().startswith("authorization:") for line in lines):
    problems.append("the decoy Authorization is not a header line of its own")
if any(canary["decoy_token"] in line
       for line in lines if line.startswith(canary["header_name"])):
    problems.append("the decoy is still inside the declared header's value")

if data["ledger_selftest"] != "live":
    problems.append("the raw ledger did not prove itself before the verdict")
if data["observations"]:
    problems.append("a confirmation should carry no near-miss observations: %s"
                    % [o["signal"] for o in data["observations"]])
if not data["legs"]["control_leg_carried_declared_header"]:
    problems.append("the control leg did not establish the x-mcp-header surface")

for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  the raw head carries the decoy Authorization and the marker as header "
          "lines of their own, and the control leg proved the surface first")
sys.exit(1 if problems else 0)
PY

echo "the fixed twin emitted the header and encoded it, rather than skipping the call"
python3 "$TEMPLATE" "cli://$FIXED" 2>/dev/null >"$WORK/fixed.json"
python3 - "$WORK/fixed.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys

meta = json.load(open(sys.argv[1]))["metadata"]
problems = []
if meta["status"] != "refuted":
    problems.append("expected refuted, got %s" % meta["status"])
if "header-value-percent-encoded" not in meta["detail"]:
    problems.append("the refutation does not name the countermeasure it observed")
for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  the refutation names the encoding it saw, not merely the absence of a split")
sys.exit(1 if problems else 0)
PY

echo "the differential is held fixed: only the parameter default moves"
python3 - "$TEMPLATE" <<'PY' || FAILURES=$((FAILURES + 1))
import importlib.util, sys

spec = importlib.util.spec_from_file_location("tpl", sys.argv[1])
tpl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tpl)
canary = tpl.build_canary()
ok, why = tpl.held_fixed(canary)
if not ok:
    print("  FAIL: %s" % why)
    sys.exit(1)
control, probe = tpl.tool_catalog(canary)
if control["inputSchema"]["properties"]["trace_id"]["x-mcp-header"] != \
        probe["inputSchema"]["properties"]["trace_id"]["x-mcp-header"]:
    print("  FAIL: the two legs declare different header names")
    sys.exit(1)
print("  %s" % why)
PY

echo "the detector cannot fire on a clean head"
python3 - "$TEMPLATE" <<'PY' || FAILURES=$((FAILURES + 1))
import importlib.util, sys

spec = importlib.util.spec_from_file_location("tpl", sys.argv[1])
tpl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tpl)
canary = tpl.build_canary()
clean = {
    "headers": [
        {"name": canary["header_name_lower"], "raw_name": canary["header_name"],
         "value": "cxg-probe-%s%%0D%%0A" % canary["nonce"],
         "raw_value": " cxg-probe-%s%%0D%%0A" % canary["nonce"], "crlf_terminated": True},
        # A near miss on purpose: the client's own bearer token, no canary.
        {"name": "authorization", "raw_name": "Authorization",
         "value": "Bearer an-unrelated-token", "raw_value": " Bearer an-unrelated-token",
         "crlf_terminated": True},
    ],
    "bare_lf_in_head": False, "raw_head_len": 200,
}
hard, soft = tpl.detect_signals(canary, clean)
problems = []
if hard:
    problems.append("the detector fired on an encoded head: %s" % [h["signal"] for h in hard])
names = {s["signal"] for s in soft}
if "authorization-header-without-this-run-canary" not in names:
    problems.append("the client's own Authorization header was not recorded as a near miss")
if "header-value-percent-encoded" not in names:
    problems.append("the percent-encoded value was not recorded as a near miss")
for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  an unrelated Authorization header and a percent-encoded value are near "
          "misses, never findings")
sys.exit(1 if problems else 0)
PY

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0" "nohdr	0"; do
        IFS=$'\t' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/agent-mcp-http-client_${variant}.py" \
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
    echo "mcp-client-header-value-encoding: confirmed on the flawed twin with the decoy header lines in the raw head, refuted on the encoding twin and on the refusing one, and skipped - naming the precondition - on the nohdr twin, two unmet-precondition runs, an invocation that reached nothing, and a non-MCP binary."
    exit 0
fi
echo "mcp-client-header-value-encoding: $FAILURES assertion(s) failed." >&2
exit 1

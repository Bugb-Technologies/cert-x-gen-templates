#!/usr/bin/env bash
# Prove templates/ai/mcp/client-conformance/mcp-client-untrusted-annotation-approval.py
# in every direction it emits, against the synthetic twin set in
# tests/fixtures/mcp-client-untrusted-annotation-approval/.
#
# The template drives an MCP *client*: it binds one mock MCP server on
# loopback inside a temporary lab, redirects the target's $HOME there - so the
# server is untrusted by construction, no trust record exists anywhere - and
# offers two tools whose definitions are identical apart from
# `annotations.readOnlyHint`. Both write this run's nonce when invoked. It then
# runs the target's own MCP command and reads which tool executed.
#
#   CONFIRMED on agent-mcp-annotations-client_flawed.py -- the readOnlyHint
#              tool ran with no approval interaction and its nonce landed,
#              while its byte-identical twin was never invoked.
#   REFUTED   on agent-mcp-annotations-client_fixed.py  -- the same program
#              with approve() consulting the trust store first: both legs go
#              to the human, neither runs.
#   CONFIRMED on the FIXED twin with TRUST_ALL=1 -- the positive control. It
#              proves the fixed twin's auto-approval branch is live code and
#              that its REFUTED above is a real decision, not a dead arm; and
#              a client that treats every server as trusted without any record
#              is exactly the flaw this template names.
#   SKIP      on agent-mcp-annotations-client_nogate.py -- the same program
#              with no approval gate at all: both legs ran unprompted, so
#              there is no annotation-driven approval decision to test.
#   SKIP      client refuses an unregistered server  (REFUSE_UNREGISTERED=1).
#   SKIP      client listed the tools and called none (STOP_AFTER=list).
#   SKIP      client never listed tools              (STOP_AFTER=initialize).
#   SKIP      supplied invocation reached the mock server not at all.
#   SKIP      on a non-MCP binary (git) -- and, since a subcommand probe's own
#              error text must not invent the surface it was looking for, zero
#              invocations attempted.
#
# The middle SKIPs come from switches orthogonal to the flawed/fixed/nogate
# axis, so every branch that decides a verdict has a fixture that reaches it.
#
# The template is exercised through its raw probe contract, over BOTH the
# streamable-HTTP and the stdio transport, and -- when `cxg` is on PATH --
# through a real `cxg scan`, because a template that only passes its own
# harness has not been shown to work.
#
# Usage: tests/prove-mcp-client-untrusted-annotation-approval.sh  Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/client-conformance/mcp-client-untrusted-annotation-approval.py"
FIXTURES="$HERE/fixtures/mcp-client-untrusted-annotation-approval"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-mcp-annotation-test.XXXXXX")"
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

needle_case() {  # needle_case <label> <want-status> <needle> <target> [env...]
    local label="$1" want="$2" needle="$3" target="$4"; shift 4
    local result status count detail
    result="$(probe "$target" "$@")"
    IFS=$'\t' read -r status count detail <<<"$result"
    if [ "$status" = "$want" ] && printf '%s' "$detail" | grep -q -- "$needle"; then
        note "$label: $status -- ${detail:0:110}"
    else
        fail "$label: expected $want naming '$needle', got $status/$count -- $detail"
    fi
}

FLAWED="$WORK/twins/agent-mcp-annotations-client_flawed.py"
FIXED="$WORK/twins/agent-mcp-annotations-client_fixed.py"
NOGATE="$WORK/twins/agent-mcp-annotations-client_nogate.py"

echo "probe contract"
run_case "flawed twin" confirmed 1 "$FLAWED"
run_case "fixed twin"  refuted   0 "$FIXED"
run_case "nogate twin" skipped   0 "$NOGATE"
if command -v git >/dev/null 2>&1; then
    run_case "non-MCP binary (git)" skipped 0 "$(command -v git)"
else
    note "non-MCP binary: SKIPPED (git not on PATH)"
fi

echo "positive control: the fixed twin's REFUTED is a decision, not a dead arm"
run_case "fixed twin, every server trusted" confirmed 1 "$FIXED" \
    AGENT_MCP_ANNOTATIONS_TRUST_ALL=1

echo "the same flaw over the stdio transport, through the template's own bridge"
run_case "flawed twin over stdio" confirmed 1 "$FLAWED" \
    CXG_MCP_ANNOTATION_CALL_CMD="mcp stdio {python} {bridge}"
run_case "fixed twin over stdio" refuted 0 "$FIXED" \
    CXG_MCP_ANNOTATION_CALL_CMD="mcp stdio {python} {bridge}"

echo "every verdict names the branch it took"
needle_case "fixed twin gated both legs" refuted \
    "client-gated-both-legs" "$FIXED"
needle_case "nogate twin has no gate at all" skipped \
    "client-has-no-approval-gate" "$NOGATE"
needle_case "client refuses an unregistered server" skipped \
    "client-refused-an-unregistered-server" "$FLAWED" \
    AGENT_MCP_ANNOTATIONS_REFUSE_UNREGISTERED=1
needle_case "listed the tools and called neither" skipped \
    "client-never-invoked-a-tool" "$FLAWED" \
    AGENT_MCP_ANNOTATIONS_STOP_AFTER=list
needle_case "never listed tools" skipped \
    "client-never-listed-tools" "$FLAWED" \
    AGENT_MCP_ANNOTATIONS_STOP_AFTER=initialize
needle_case "supplied invocation reaches the mock not at all" skipped \
    "no-request-reached-the-mock-mcp-server" "$FLAWED" \
    CXG_MCP_ANNOTATION_CALL_CMD="mcp list"
needle_case "non-MCP binary: nothing invoked" skipped \
    "no-mcp-surface-in-target-help" "$(command -v git 2>/dev/null || echo /bin/ls)"

echo "the canary really is what fires: the finding carries this run's nonce"
python3 "$TEMPLATE" "cli://$FLAWED" 2>/dev/null >"$WORK/flawed.json"
python3 - "$WORK/flawed.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys

data = json.load(open(sys.argv[1]))["findings"][0]["evidence"]["data"]
canary = data["canaries"]
annotated = data["legs"]["annotated"]
plain = data["legs"]["plain"]
problems = []

# The confirmation rests on an effect that landed, minted by this process.
if not annotated["executed"]:
    problems.append("the annotated leg is not recorded as executed")
if (annotated["effect"] or {}).get("nonce") != canary["nonce"]:
    problems.append("the annotated tool's side effect does not carry this run's nonce")
if (annotated["effect"] or {}).get("marker") != canary["effect_marker"]:
    problems.append("the annotated tool's side effect does not carry this run's marker")
if not annotated["call_record"] or annotated["call_record"]["method"] != "tools/call":
    problems.append("no tools/call ledger entry backs the annotated leg")
if annotated["approval_interaction"]:
    problems.append("the annotated leg was preceded by an approval interaction after all")

# ... and on the twin having been gated. Half a differential is not a finding.
if plain["executed"]:
    problems.append("the readOnlyHint:false twin executed too, so nothing was gated")
if not annotated["read_only_hint"] or plain["read_only_hint"]:
    problems.append("the legs are not the annotated/plain pair the template claims")

# The untrusted precondition.
if data["server_trust"]["trust_record_planted"] is not False:
    problems.append("a trust record was planted, so the server was not untrusted")
if data["server_trust"]["trust_like_files_in_lab_home_after_run"]:
    problems.append("the lab home holds a trust-like file: %s"
                    % data["server_trust"]["trust_like_files_in_lab_home_after_run"])

# The witness proved itself first.
if data["ledger_selftest"] != "live":
    problems.append("the ledger and effect self-test did not pass before the verdict")
if "identical definitions" not in data["held_fixed"]:
    problems.append("the held-fixed assertion did not run")

for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  the annotated tool's nonce landed, its ledger entry backs it, the twin never "
          "ran, and the lab held no trust record for the server")
sys.exit(1 if problems else 0)
PY

echo "the refutation proves the arm executed: both legs were offered and both were put to a human"
python3 "$TEMPLATE" "cli://$FIXED" 2>/dev/null >"$WORK/fixed.json"
python3 - "$WORK/fixed.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys

report = json.load(open(sys.argv[1]))
meta = report["metadata"]
problems = []
if meta["status"] != "refuted":
    problems.append("expected refuted, got %s" % meta["status"])
if report["findings"]:
    problems.append("a refutation must carry no findings")
print("  detail: %s" % meta["detail"][:120])
for problem in problems:
    print("  FAIL: %s" % problem)
sys.exit(1 if problems else 0)
PY

echo "the differential is held fixed: only annotations.readOnlyHint moves"
python3 - "$TEMPLATE" <<'PY' || FAILURES=$((FAILURES + 1))
import importlib.util, json, sys, tempfile

spec = importlib.util.spec_from_file_location("tpl", sys.argv[1])
tpl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tpl)
canary = tpl.build_canary()
home = tempfile.mkdtemp(prefix="cxg-annotation-heldfixed-")
ok, why = tpl.held_fixed(canary, home)
if not ok:
    print("  FAIL: %s" % why)
    sys.exit(1)
annotated, plain = tpl.tool_catalog(canary)
problems = []
if annotated["description"] != plain["description"]:
    problems.append("the two tools do not share a description")
if annotated["inputSchema"] != plain["inputSchema"]:
    problems.append("the two tools do not share an input schema")
differing = [k for k in set(annotated["annotations"]) | set(plain["annotations"])
             if annotated["annotations"].get(k) != plain["annotations"].get(k)]
if differing != ["readOnlyHint"]:
    problems.append("the annotations differ in more than readOnlyHint: %s" % differing)
# A planted trust record must break the precondition, so the assertion is real.
import os
os.makedirs(os.path.join(home, ".agent"), exist_ok=True)
open(os.path.join(home, ".agent", "trusted_servers.json"), "w").write("[]")
still_ok, _why = tpl.held_fixed(canary, home)
if still_ok:
    problems.append("held_fixed accepted a lab home that already carried a trust record")
for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  %s" % why)
sys.exit(1 if problems else 0)
PY

echo "the reader cannot call an unexecuted leg executed"
python3 - "$TEMPLATE" <<'PY' || FAILURES=$((FAILURES + 1))
import importlib.util, sys, tempfile

spec = importlib.util.spec_from_file_location("tpl", sys.argv[1])
tpl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tpl)
canary = tpl.build_canary()
lab = tempfile.mkdtemp(prefix="cxg-annotation-reader-")
server = tpl.MockServer(canary, lab)
problems = []
try:
    # Nothing has happened yet.
    leg = tpl.read_leg(server, canary, tpl.ANNOTATED_TOOL, "")
    if leg["executed"] or leg["calls_observed"]:
        problems.append("a leg with no traffic was read as executed")
    # A call for a DIFFERENT tool must not mark this leg executed, and an
    # effect file that carries someone else's nonce must not either.
    server.effect_path(tpl.ANNOTATED_TOOL).write_text(
        '{"tool": "%s", "nonce": "not-this-run", "marker": "x"}' % tpl.ANNOTATED_TOOL)
    leg = tpl.read_leg(server, canary, tpl.ANNOTATED_TOOL, "")
    if leg["effect_nonce_matched"] or leg["executed"]:
        problems.append("an effect carrying a foreign nonce was accepted")
    # An approval interaction in the client's own words gates the leg.
    leg = tpl.read_leg(server, canary, tpl.ANNOTATED_TOOL,
                       "[approval] %s: approve? [y/N]" % tpl.ANNOTATED_TOOL)
    if not leg["approval_interaction"]:
        problems.append("an approval prompt naming the tool was not recognised")
    leg = tpl.read_leg(server, canary, tpl.ANNOTATED_TOOL,
                       "%s\tcalled" % tpl.ANNOTATED_TOOL)
    if leg["approval_interaction"]:
        problems.append("an ordinary result line was mistaken for an approval interaction")
finally:
    server.close()
for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  no traffic, a foreign nonce and a bare result line are all read honestly")
sys.exit(1 if problems else 0)
PY

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0" "nogate	0"; do
        IFS=$'\t' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/agent-mcp-annotations-client_${variant}.py" \
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
    # The confirmation cxg reports must be THIS check, and must carry the
    # annotation differential in its own words.
    python3 - "$WORK/scan-flawed.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys

findings = json.load(open(sys.argv[1]))["findings"]
problems = []
if not findings:
    problems.append("cxg scan reported no finding on the flawed twin")
else:
    f = findings[0]
    if f.get("template_id") != "mcp-client-untrusted-annotation-approval":
        problems.append("the reported finding is not this template's: %s" % f.get("template_id"))
    text = json.dumps(f)
    for needle in ("readOnlyHint", "cxg_probe_alpha", "cxg_probe_beta"):
        if needle not in text:
            problems.append("the reported finding never mentions %s" % needle)
for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  cxg's own report names the annotation, the tool that ran and the twin that did not")
sys.exit(1 if problems else 0)
PY
else
    echo "cxg scan: SKIPPED (cxg not on PATH)"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "mcp-client-untrusted-annotation-approval: confirmed on the flawed twin over both transports with the annotated tool's nonce on disk and its twin never invoked, refuted on the trust-checking twin, confirmed again on that twin once every server is trusted (the positive control), and skipped - naming the precondition - on the gateless twin, a client that refuses unregistered servers, two unmet-precondition runs, an invocation that reached nothing, and a non-MCP binary."
    exit 0
fi
echo "mcp-client-untrusted-annotation-approval: $FAILURES assertion(s) failed." >&2
exit 1

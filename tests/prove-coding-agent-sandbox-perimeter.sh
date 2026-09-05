#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-sandbox-perimeter-enforcement.sh
# in EVERY direction it emits, against the synthetic twin set in
# tests/fixtures/coding-agent-sandbox-perimeter-enforcement/.
#
#   CONFIRMED on agent-host_flawed.py     -- the host declares sandboxEnabled,
#              trades away the approval gate, and injects no confinement: all
#              three probes succeed with the sandbox ON and in the control arm.
#   REFUTED   on agent-host_fixed.py      -- the same declaration and the same
#              approval trade, but the policy really is applied at spawn: every
#              probe the unsandboxed control achieves is denied under the sandbox.
#   SKIP      on agent-host_nosandbox.py  -- the host declares no sandbox at all,
#              so there is no confinement control to find decorative.
#   SKIP      on agent-host_inert.py      -- the confinement is not tied to the
#              setting (both arms confined), so the control achieves nothing and
#              the denials cannot be attributed to the sandbox.
#   SKIP      on a non-sandbox binary (git) -- no sandboxed-run surface at all.
#
# A check nobody can make refute or skip is not a check, so all five directions
# are asserted, and the confirmation is inspected for the evidence that earns it
# (each probe named, the approval trade recorded). The template is exercised
# through its raw probe contract and -- when `cxg` is on PATH -- through a real
# `cxg scan`, because the two agree about nothing only if you look.
#
# Usage: tests/prove-coding-agent-sandbox-perimeter.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-sandbox-perimeter-enforcement.sh"
FIXTURES="$HERE/fixtures/coding-agent-sandbox-perimeter-enforcement"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-sandbox-perimeter-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

status_of() {
    CERT_X_GEN_TARGET_HOST="cli://$1" \
        bash "$TEMPLATE" "cli://$1" 80 --json \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); m=d["metadata"]; print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))'
}

echo "probe contract"
run_case() {
    local label="$1" target="$2" want_status="$3" want_findings="$4"
    local result got_status got_findings detail
    result="$(status_of "$target")" || { fail "$label: template did not run"; return; }
    IFS='	' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$label: $got_status ($got_findings finding(s)) -- ${detail:0:130}"
    else
        fail "$label: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
}

run_case "flawed twin"    "$WORK/twins/agent-host_flawed.py"    confirmed 1
run_case "fixed twin"     "$WORK/twins/agent-host_fixed.py"     refuted   0
# No declared sandbox -> nothing promised a perimeter -> SKIP, not a refutation.
run_case "nosandbox twin" "$WORK/twins/agent-host_nosandbox.py" skipped   0
# Confinement not tied to the setting -> the control achieves nothing -> the
# denials are unattributable -> SKIP, naming the missing precondition.
run_case "inert twin"     "$WORK/twins/agent-host_inert.py"     skipped   0
# A binary with no sandboxed-run surface must SKIP, not refute or confirm.
if command -v git >/dev/null 2>&1; then
    run_case "non-sandbox (git)" "$(command -v git)" skipped 0
else
    note "non-sandbox: SKIPPED (git not on PATH)"
fi

# The confirmation must name every probe that breached the declared perimeter,
# and must record the approval trade. Guard against a template that "confirms"
# without having observed the three post-conditions.
detail_flawed="$(status_of "$WORK/twins/agent-host_flawed.py")"
for probe in fs-write-outside-allowwrite net-connect-unlisted-domain fs-read-decoy-credential; do
    if printf '%s' "$detail_flawed" | grep -q "$probe"; then
        note "flawed: probe '$probe' named in the confirmation"
    else
        fail "flawed: confirmation did not name probe '$probe'"
    fi
done
if printf '%s' "$detail_flawed" | grep -q 'approval-gate-traded=yes'; then
    note "flawed: the approval gate traded away for the sandbox was recorded"
else
    fail "flawed: approval trade not recorded in the confirmation"
fi

# The refutation must say which probes the control achieved -- a refutation that
# does not name a working control arm is a clean bill of health it did not earn.
detail_fixed="$(status_of "$WORK/twins/agent-host_fixed.py")"
for probe in fs-write-outside-allowwrite net-connect-unlisted-domain fs-read-decoy-credential; do
    if printf '%s' "$detail_fixed" | grep -q "$probe"; then
        note "fixed: probe '$probe' named as stopped by the perimeter"
    else
        fail "fixed: refutation did not name probe '$probe'"
    fi
done

# The finding's evidence must carry the differential itself: both arms of the
# ledger and the two achieved-sets it was computed from.
echo "finding evidence"
CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/agent-host_flawed.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/agent-host_flawed.py" 80 --json >"$WORK/flawed.json"
python3 - "$WORK/flawed.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
finding = report["findings"][0]
data = finding["evidence"]["data"]
problems = []
if data.get("oracle") != "property+diff":
    problems.append("oracle is %r, expected property+diff" % data.get("oracle"))
if not data.get("differential"):
    problems.append("finding does not record that it is differential")
for key in ("achieved_sandbox_on", "achieved_control_off", "breached", "nonce"):
    if not data.get(key):
        problems.append("evidence.data.%s is empty" % key)
response = finding["evidence"]["response"]
for arm in ("sandbox ON", "sandbox OFF"):
    if arm not in response:
        problems.append("evidence.response is missing the '%s' arm" % arm)
if "CWE-693" not in finding["cwe_ids"]:
    problems.append("finding does not carry CWE-693")
for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  both ledger arms, both achieved-sets and the nonce are in the evidence")
sys.exit(1 if problems else 0)
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# Safety: the probes must never reach outside the template's own disposable lab.
echo "hermeticity"
if grep -q 'export HOME="\$DECOY_HOME"' "$TEMPLATE"; then
    note "HOME is redirected into the lab, so no real credential file is in scope"
else
    fail "template does not redirect HOME into its lab before running the target"
fi
if grep -q 'CXG_NET_CANARY_HOST="127.0.0.1"' "$TEMPLATE"; then
    note "the 'unlisted domain' is a loopback listener; no external network is contacted"
else
    fail "template does not pin the network canary to loopback"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/agent-host_${variant}.py" \
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
    echo "coding-agent-sandbox-perimeter-enforcement: confirmed on the decorative-sandbox twin, refuted on the enforcing one, skipped on the no-sandbox twin, on the untied-confinement twin and on a non-sandbox binary."
    exit 0
fi
echo "coding-agent-sandbox-perimeter-enforcement: $FAILURES assertion(s) failed." >&2
exit 1

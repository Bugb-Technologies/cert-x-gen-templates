#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-hook-gate-integrity.sh in EVERY
# direction it emits, against the synthetic twin set in
# tests/fixtures/coding-agent-hook-gate-integrity/.
#
#   CONFIRMED on agent-host_flawed.py      -- all three failure classes: the deny
#              verdict is ignored, a repo-scoped file redefines the hook list,
#              and both hook failures fail open.
#   CONFIRMED on agent-host_ignorehook.py  -- ONLY the bypass class. The repo
#              arm also executes, but is recorded as an unattributed
#              observation rather than claimed: a repository cannot be said to
#              have disarmed a gate that was never armed.
#   CONFIRMED on agent-host_repodisarm.py  -- ONLY the repo-override class.
#   CONFIRMED on agent-host_failopen.py    -- ONLY the two fail-open classes.
#   REFUTED   on agent-host_fixed.py       -- the same gate, honoured: the deny
#              blocks, repo config may only add, and both hook failures fail
#              closed. The ungated control arm still performs the action, so the
#              refutation is earned rather than vacuous.
#   SKIP      on agent-host_nohook.py      -- the host ships no hook gate, so
#              there is no control whose integrity could fail.
#   SKIP      on agent-host_inert.py       -- the gated action is unachievable
#              even ungated, so a block cannot be attributed to the gate.
#   SKIP      on a non-agent binary (git)  -- no hook-gate surface at all.
#
# A check nobody can make refute or skip is not a check, so all eight directions
# are asserted, the per-class attribution is asserted separately (a template
# that confirmed everything on every flawed twin would pass a confirm/refute
# test and still be worthless), and the confirmation is inspected for the
# evidence that earns it. The template is exercised through its raw probe
# contract and -- when `cxg` is on PATH -- through a real `cxg scan`.
#
# Usage: tests/prove-coding-agent-hook-gate-integrity.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-hook-gate-integrity.sh"
FIXTURES="$HERE/fixtures/coding-agent-hook-gate-integrity"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-hook-gate-test.XXXXXX")"
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
        note "$label: $got_status ($got_findings finding(s)) -- ${detail:0:120}"
    else
        fail "$label: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
}

run_case "flawed twin"      "$WORK/twins/agent-host_flawed.py"     confirmed 1
run_case "fixed twin"       "$WORK/twins/agent-host_fixed.py"      refuted   0
run_case "ignorehook twin"  "$WORK/twins/agent-host_ignorehook.py" confirmed 1
run_case "repodisarm twin"  "$WORK/twins/agent-host_repodisarm.py" confirmed 1
run_case "failopen twin"    "$WORK/twins/agent-host_failopen.py"   confirmed 1
# No hook gate at all -> nothing promised a control -> SKIP, not a refutation.
run_case "nohook twin"      "$WORK/twins/agent-host_nohook.py"     skipped   0
# The gated action is unachievable ungated -> the blocks are unattributable ->
# SKIP naming the missing precondition, rather than a clean bill of health.
run_case "inert twin"       "$WORK/twins/agent-host_inert.py"      skipped   0
# A binary with no hook-gate surface must SKIP, not confirm or refute.
if command -v git >/dev/null 2>&1; then
    run_case "non-agent (git)" "$(command -v git)" skipped 0
else
    note "non-agent: SKIPPED (git not on PATH)"
fi

# ---------------------------------------------------------------------------
# Per-class attribution. Each isolating twin carries exactly one flaw, so the
# template must name that class and NOT the others. A template that named all
# four classes on every flawed twin would pass the confirm/refute test above and
# still be telling the operator nothing about which of its three defences broke.
# ---------------------------------------------------------------------------
echo "per-class attribution"
BYPASS=deny-hook-not-enforced
OVERRIDE=repo-config-disarms-user-hook
ERR=fail-open-on-hook-error
HANG=fail-open-on-hook-timeout

assert_classes() {
    local label="$1" twin="$2" want="$3" unwanted="$4"
    local detail bypassed
    detail="$(status_of "$WORK/twins/agent-host_${twin}.py")"
    bypassed="$(printf '%s' "$detail" | sed -n 's/.*did not hold: \[\([^]]*\)\].*/\1/p')"
    if [ -z "$bypassed" ]; then
        fail "$label: could not read the bypassed-arm list out of the verdict"
        return
    fi
    local ok=1
    for class in $want; do
        case " $bypassed " in *" $class "*) ;; *) ok=0; fail "$label: '$class' missing from the confirmed classes [$bypassed]" ;; esac
    done
    for class in $unwanted; do
        case " $bypassed " in *" $class "*) ok=0; fail "$label: '$class' claimed but that flaw is not in this twin [$bypassed]" ;; esac
    done
    [ "$ok" -eq 1 ] && note "$label: confirmed exactly [$bypassed]"
}

assert_classes "flawed"     flawed     "$BYPASS $ERR $HANG" ""
assert_classes "ignorehook" ignorehook "$BYPASS"            "$OVERRIDE $ERR $HANG"
assert_classes "repodisarm" repodisarm "$OVERRIDE"          "$BYPASS $ERR $HANG"
assert_classes "failopen"   failopen   "$ERR $HANG"         "$BYPASS $OVERRIDE"

# The repo-override arm DOES execute on the ignorehook twin, because the host
# ignores every deny. The template must record that as an observation and must
# not turn it into a repo-config claim -- the precision bar this repo holds.
detail_ignore="$(status_of "$WORK/twins/agent-host_ignorehook.py")"
if printf '%s' "$detail_ignore" | grep -q 'not-attributed=\[repo-override-arm-subsumed-by-deny-bypass\]'; then
    note "ignorehook: the repo arm's execution is recorded as an observation, not claimed as a repo override"
else
    fail "ignorehook: the subsumed repo-override arm was not recorded as an unattributed observation"
fi

# ---------------------------------------------------------------------------
# The verdicts must be earned, not asserted.
# ---------------------------------------------------------------------------
echo "verdict quality"
detail_flawed="$(status_of "$WORK/twins/agent-host_flawed.py")"
if printf '%s' "$detail_flawed" | grep -q 'control arm achieved the action'; then
    note "flawed: the confirmation records that the ungated control arm achieved the action"
else
    fail "flawed: confirmation does not record the control-arm precondition"
fi

detail_fixed="$(status_of "$WORK/twins/agent-host_fixed.py")"
if printf '%s' "$detail_fixed" | grep -q 'ungated control arm performed the gated action'; then
    note "fixed: the refutation names the working control arm that earns it"
else
    fail "fixed: refutation does not name a working control arm"
fi
for class in "$BYPASS" "$OVERRIDE" "$ERR" "$HANG"; do
    if printf '%s' "$detail_fixed" | grep -q "$class"; then
        note "fixed: '$class' named as not observed"
    else
        fail "fixed: refutation does not account for '$class'"
    fi
done

# The inert twin's SKIP must name the missing precondition, not just decline.
detail_inert="$(status_of "$WORK/twins/agent-host_inert.py")"
if printf '%s' "$detail_inert" | grep -q 'Missing precondition:'; then
    note "inert: the skip names the missing precondition"
else
    fail "inert: the skip does not name the missing precondition"
fi

# ---------------------------------------------------------------------------
# The finding's evidence must carry the arms it was computed from.
# ---------------------------------------------------------------------------
echo "finding evidence"
CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/agent-host_flawed.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/agent-host_flawed.py" 80 --json >"$WORK/flawed.json"
python3 - "$WORK/flawed.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
finding = report["findings"][0]
data = finding["evidence"]["data"]
problems = []
if data.get("oracle") != "property":
    problems.append("oracle is %r, expected property" % data.get("oracle"))
if not data.get("control_arm_achieved"):
    problems.append("finding does not record the control-arm precondition")
for key in ("bypassed_arms", "nonce", "arms", "failure_classes"):
    if not data.get(key):
        problems.append("evidence.data.%s is empty" % key)
response = finding["evidence"]["response"]
for arm in ("arm 0: control", "arm 1: user-scope deny-all hook",
            "arm 2: same deny-all hook", "arm 3: hook exits non-zero",
            "arm 4: hook hangs"):
    if arm not in response:
        problems.append("evidence.response is missing '%s'" % arm)
if "CWE-693" not in finding["cwe_ids"]:
    problems.append("finding does not carry CWE-693")
for problem in problems:
    print("  FAIL: %s" % problem)
if not problems:
    print("  all five arm ledgers, the control precondition and the nonce are in the evidence")
sys.exit(1 if problems else 0)
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# ---------------------------------------------------------------------------
# Safety: the probes must never reach outside the template's own disposable lab.
# ---------------------------------------------------------------------------
echo "hermeticity"
if grep -q 'export HOME="\$DECOY_HOME"' "$TEMPLATE"; then
    note "HOME is redirected into the lab, so the host's user-scope settings never touch a real one"
else
    fail "template does not redirect HOME into its lab before running the target"
fi
if grep -q 'MARKER="\$LAB/marker/gated-action-\$NONCE"' "$TEMPLATE"; then
    note "the gated action's marker path is inside the disposable lab"
else
    fail "template does not keep the gated-action marker inside its lab"
fi
if grep -qE 'curl|wget|nc |ssh ' "$TEMPLATE"; then
    fail "template appears to contact something outside the lab"
else
    note "no external network is contacted"
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
    echo "coding-agent-hook-gate-integrity: confirmed on the bypass, repo-override and fail-open twins with each class attributed to the twin that carries it, refuted on the honouring twin, skipped on the no-gate twin, on the unachievable-action twin and on a non-agent binary."
    exit 0
fi
echo "coding-agent-hook-gate-integrity: $FAILURES assertion(s) failed." >&2
exit 1

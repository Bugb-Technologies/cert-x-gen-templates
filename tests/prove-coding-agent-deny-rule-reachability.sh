#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-deny-rule-reachability.sh in
# EVERY direction it emits, against the synthetic twin set in
# tests/fixtures/coding-agent-deny-rule-reachability/.
#
#   CONFIRMED on agent-host_flawed.py       -- all three flaws: the rule is
#              matched against the rendered command string, the check/use split
#              re-opens by name, and a rule with trailing text is accepted and
#              never matches.
#   CONFIRMED on agent-host_syntaxonly.py   -- ONLY channel equivalence. Nine
#              syntactically different reads of the same file get through while
#              the plain read and the redirect are blocked.
#   CONFIRMED on agent-host_toctouonly.py   -- ONLY the check/use split. Every
#              channel is blocked; the swap after the observed check is not.
#   CONFIRMED on agent-host_inertrule.py    -- ONLY the accepted-but-inert rule.
#   CONFIRMED on agent-host_deadrule.py     -- the rule is decorative, so even
#              the literal direct read succeeds. The template must claim ONLY
#              'deny-rule-not-enforced' and record the channel, check/use and
#              trailing-text arms as observations: a channel cannot be said to
#              have got around a rule that was never in the way.
#   REFUTED   on agent-host_fixed.py        -- the same host enforcing at the
#              file-open chokepoint and reading the descriptor it validated.
#              The positive control still returns on every channel, so the
#              refutation is earned rather than vacuous.
#   SKIP      on agent-host_nodeny.py       -- no deny surface at all.
#   SKIP      on agent-host_rejects.py      -- the host refuses the rule, so the
#              operator never got the control.
#   SKIP      on agent-host_deadchannels.py -- no channel produces anything,
#              including the positive control. "Blocked" and "broken" must not
#              be confused, and this twin is the one that proves the template
#              does not confuse them.
#   SKIP      on a non-agent binary (git)   -- no deny surface at all.
#
# A check nobody can make refute or skip is not a check, so all ten directions
# are asserted, the per-class attribution is asserted separately (a template
# that confirmed everything on every flawed twin would pass a confirm/refute
# test and still be worthless), and the confirmation is inspected for the
# evidence that earns it. The template is exercised through its raw probe
# contract and -- when `cxg` is on PATH -- through a real `cxg scan`.
#
# Usage: tests/prove-coding-agent-deny-rule-reachability.sh   Exit 0 = all hold.
# Runtime is a few minutes: each direction drives twelve channels twice.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-deny-rule-reachability.sh"
FIXTURES="$HERE/fixtures/coding-agent-deny-rule-reachability"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-deny-reach-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

# One template run per target, cached: every later assertion reads the same
# report rather than paying for another twelve-channel sweep.
report_for() {   # $1 target path  $2 cache key -> path to the JSON report
    local target="$1" key="$2" out="$WORK/report-$2.json"
    if [ ! -s "$out" ]; then
        CERT_X_GEN_TARGET_HOST="cli://$target" \
            bash "$TEMPLATE" "cli://$target" 80 --json >"$out" 2>"$WORK/report-$2.err"
    fi
    printf '%s' "$out"
}

summarise() {   # $1 report path -> "status<TAB>findings<TAB>detail"
    python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
m = d["metadata"]
print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))' "$1"
}

echo "probe contract"
run_case() {
    local label="$1" target="$2" key="$3" want_status="$4" want_findings="$5"
    local report result got_status got_findings detail
    report="$(report_for "$target" "$key")"
    result="$(summarise "$report" 2>/dev/null)" || {
        fail "$label: template did not produce a report"; return; }
    IFS=$'\t' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$label: $got_status ($got_findings finding(s)) -- ${detail:0:130}"
    else
        fail "$label: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
}

run_case "flawed twin"       "$WORK/twins/agent-host_flawed.py"       flawed       confirmed 1
run_case "fixed twin"        "$WORK/twins/agent-host_fixed.py"        fixed        refuted   0
run_case "syntaxonly twin"   "$WORK/twins/agent-host_syntaxonly.py"   syntaxonly   confirmed 1
run_case "toctouonly twin"   "$WORK/twins/agent-host_toctouonly.py"   toctouonly   confirmed 1
run_case "inertrule twin"    "$WORK/twins/agent-host_inertrule.py"    inertrule    confirmed 1
run_case "deadrule twin"     "$WORK/twins/agent-host_deadrule.py"     deadrule     confirmed 1
# No deny surface at all -> nothing promised a control -> SKIP, not a refutation.
run_case "nodeny twin"       "$WORK/twins/agent-host_nodeny.py"       nodeny       skipped   0
# The host will not install the rule -> the operator never got the control.
run_case "rejects twin"      "$WORK/twins/agent-host_rejects.py"      rejects      skipped   0
# No channel produces anything, so "blocked" cannot be told from "broken".
run_case "deadchannels twin" "$WORK/twins/agent-host_deadchannels.py" deadchannels skipped   0
if command -v git >/dev/null 2>&1; then
    run_case "non-agent (git)" "$(command -v git)" git skipped 0
else
    note "non-agent: SKIPPED (git not on PATH)"
fi

# ---------------------------------------------------------------------------
# Per-class attribution. Each isolating twin carries exactly one flaw, so the
# template must name that class and NOT the others.
# ---------------------------------------------------------------------------
echo "per-class attribution"
EQUIV=channel-equivalence-bypass
TOC=post-check-toctou
INERT=deny-rule-accepted-but-inert
DEAD=deny-rule-not-enforced

classes_of() {   # $1 cache key
    python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
if not d["findings"]:
    print("")
else:
    print(d["findings"][0]["evidence"]["data"].get("failure_classes", ""))' \
        "$WORK/report-$1.json"
}

assert_classes() {   # $1 label  $2 key  $3 wanted  $4 unwanted
    local label="$1" key="$2" want="$3" unwanted="$4" got ok=1
    got="$(classes_of "$key")"
    if [ -z "$got" ]; then
        fail "$label: no failure_classes on the finding"; return
    fi
    for class in $want; do
        case " $got " in *" $class "*) ;; *)
            ok=0; fail "$label: '$class' missing from the confirmed classes [$got]" ;;
        esac
    done
    for class in $unwanted; do
        case " $got " in *" $class "*)
            ok=0; fail "$label: '$class' claimed but that flaw is not in this twin [$got]" ;;
        esac
    done
    [ "$ok" -eq 1 ] && note "$label: confirmed exactly [$got]"
}

assert_classes "flawed"     flawed     "$EQUIV $TOC $INERT" "$DEAD"
assert_classes "syntaxonly" syntaxonly "$EQUIV"             "$TOC $INERT $DEAD"
assert_classes "toctouonly" toctouonly "$TOC"               "$EQUIV $INERT $DEAD"
assert_classes "inertrule"  inertrule  "$INERT"             "$EQUIV $TOC $DEAD"
# The decorative-rule twin leaks through every arm. Only the unenforced rule may
# be claimed: a channel cannot have got around a rule that never blocked
# anything, and saying otherwise would be three findings out of one.
assert_classes "deadrule"   deadrule   "$DEAD"              "$EQUIV $TOC $INERT"

python3 - "$WORK/report-deadrule.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))["findings"][0]["evidence"]["data"]
observed = data.get("observations_not_attributed", "")
problems = [w for w in ("channel-arms-subsumed-by-unenforced-rule",
                        "trailing-text-arm-subsumed-by-unenforced-rule")
            if w not in observed]
# This twin has no check/use split -- it reads the descriptor it validated -- so
# the swap changes nothing and there is no toctou observation TO subsume. The
# template must say the arm did not reach the canary rather than fold it into
# the decorative-rule finding.
if data.get("toctou_reached") != "no":
    problems.append("the check/use arm is reported as reached on a twin whose "
                    "read uses the descriptor it validated")
if data.get("toctou_control") != "yes":
    problems.append("the check/use arm has no positive control, so 'not reached' "
                    "there would be unearned")
for p in problems:
    print("  FAIL: deadrule: %s" % p)
if not problems:
    print("  deadrule: the channel and trailing-text arms are recorded as "
          "observations rather than claimed as separate findings, and the "
          "check/use arm -- which this twin does not have -- is not invented")
sys.exit(1 if problems else 0)
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# ---------------------------------------------------------------------------
# The positive control has to be real, not decorative. On the flawed and fixed
# twins every channel must have returned its control nonce, and on the fixed
# twin that is the ONLY thing standing between "blocked" and "broken".
# ---------------------------------------------------------------------------
echo "positive control"
python3 - "$WORK/report-flawed.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))["findings"][0]["evidence"]["data"]
problems = []
working = data.get("positive_control_working", "").split()
expected = ["direct", "redirect", "reader", "optvalue", "shortopt", "atfile",
            "operand", "compound", "symlink", "searchpath", "assign"]
missing = [c for c in expected if c not in working]
if missing:
    problems.append("channels with no working positive control: %s" % missing)
if data.get("positive_control_broken") != "none":
    problems.append("a channel's positive control failed: %s"
                    % data.get("positive_control_broken"))
if data.get("toctou_control") != "yes":
    problems.append("the check/use arm has no positive control")
if data.get("toctou_swap_after_observed_check") != "yes":
    problems.append("the swap was not made after the host's check was observed, "
                    "so the TOCTOU claim would be unearned")
if data.get("direct_reached") != "no":
    problems.append("the direct read was not blocked, so channel equivalence "
                    "could not have been claimed on this twin")
for p in problems:
    print("  FAIL: flawed: %s" % p)
if not problems:
    print("  flawed: all eleven channels and the check/use arm returned their "
          "control nonce first, the direct read was blocked, and the swap "
          "happened after the observed check")
sys.exit(1 if problems else 0)
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

detail_fixed="$(summarise "$WORK/report-fixed.json" | cut -f3)"
for phrase in "positive control proves those arms ran" \
              "check/use arm (control: yes)" \
              "including the plain read" \
              "rule fingerprint"; do
    if printf '%s' "$detail_fixed" | grep -qF "$phrase"; then
        note "fixed: the refutation records '$phrase'"
    else
        fail "fixed: the refutation does not record '$phrase'"
    fi
done
for phrase in "post-check-toctou: not observed" \
              "deny-rule-accepted-but-inert: not observed"; do
    if printf '%s' "$detail_fixed" | grep -qF "$phrase"; then
        note "fixed: '$phrase' is accounted for"
    else
        fail "fixed: the refutation does not account for '$phrase'"
    fi
done

# The deadchannels SKIP must name the missing precondition rather than decline.
detail_dead="$(summarise "$WORK/report-deadchannels.json" | cut -f3)"
if printf '%s' "$detail_dead" | grep -q 'Missing precondition:'; then
    note "deadchannels: the skip names the missing precondition"
else
    fail "deadchannels: the skip does not name the missing precondition"
fi

# ---------------------------------------------------------------------------
# The held-fixed axis: same file, same rule, same scope, same target -- only the
# channel moves. The template refuses a verdict if the target's rule fingerprint
# changed mid-sweep, and the finding has to carry the fingerprint it held to.
# ---------------------------------------------------------------------------
echo "held-fixed axis"
python3 - "$WORK/report-syntaxonly.json" <<'PY'
import json, sys
finding = json.load(open(sys.argv[1]))["findings"][0]
data = finding["evidence"]["data"]
problems = []
if "only the channel moves" not in data.get("held_fixed", ""):
    problems.append("evidence does not state the held-fixed axis")
if not data.get("rule_fingerprint"):
    problems.append("evidence carries no rule fingerprint")
if data.get("oracle") != "property+diff":
    problems.append("oracle is %r, expected property+diff" % data.get("oracle"))
for key in ("nonce", "scope", "rule", "channels_driven", "channels_reached"):
    if not data.get(key):
        problems.append("evidence.data.%s is empty" % key)
reached = data.get("channels_reached", "").split()
if "direct" in reached or "redirect" in reached:
    problems.append("the syntax-only twin blocks the two shapes its matcher "
                    "knows; the template reported them as reached: %s" % reached)
for want in ("reader", "optvalue", "shortopt", "atfile", "operand", "compound",
             "symlink", "searchpath", "assign"):
    if want not in reached:
        problems.append("channel %r did not reach the canary on the "
                        "command-string-matching twin" % want)
response = finding["evidence"]["response"]
for arm in ("--- rule install (canonical spelling) ---",
            "--- channel: symlink -> CANARY NONCE RETURNED ---",
            "--- control: toctou arm"):
    if arm not in response:
        problems.append("evidence.response is missing '%s'" % arm)
if "CWE-863" not in finding["cwe_ids"] or "CWE-367" not in finding["cwe_ids"]:
    problems.append("finding does not carry CWE-863 and CWE-367")
for p in problems:
    print("  FAIL: syntaxonly: %s" % p)
if not problems:
    print("  syntaxonly: nine syntactically different channels reached the file "
          "the rule names while the two shapes the matcher knows were blocked, "
          "with the rule fingerprint held across every arm")
sys.exit(1 if problems else 0)
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# The nonce must be probe-generated, so a confirmation cannot be a false
# positive: the string the template looked for cannot pre-exist on the target.
echo "nonce provenance"
if grep -q 'NONCE="drr-\$(od -An -N8 -tx1 /dev/urandom' "$TEMPLATE"; then
    note "the canary's nonce is generated per run from /dev/urandom"
else
    fail "the template does not generate its canary nonce per run"
fi
n1="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["findings"][0]["evidence"]["data"]["nonce"])' "$WORK/report-flawed.json" 2>/dev/null)"
n2="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["findings"][0]["evidence"]["data"]["nonce"])' "$WORK/report-syntaxonly.json" 2>/dev/null)"
if [ -n "$n1" ] && [ -n "$n2" ] && [ "$n1" != "$n2" ]; then
    note "two runs used two different nonces ($n1 / $n2)"
else
    fail "the nonce did not change between runs (${n1:-<none>} / ${n2:-<none>})"
fi

# ---------------------------------------------------------------------------
# Safety: the probes must never reach outside the template's own lab.
# ---------------------------------------------------------------------------
echo "hermeticity"
if grep -q 'export HOME="\$DECOY_HOME"' "$TEMPLATE"; then
    note "HOME is redirected into the lab, so the host's policy store never touches a real one"
else
    fail "template does not redirect HOME into its lab before running the target"
fi
if grep -q 'trap .rm -rf "\$LAB". EXIT' "$TEMPLATE"; then
    note "the lab is removed on exit"
else
    fail "template does not remove its lab on exit"
fi
if grep -q 'CANARY="\$VAULT/canary.txt"' "$TEMPLATE" \
   && grep -q 'VAULT="\$LAB/vault"' "$TEMPLATE"; then
    note "the canary, the control file and the swap file are all inside the lab"
else
    fail "the canary is not demonstrably inside the lab"
fi
if grep -qE 'curl|wget|nc |ssh ' "$TEMPLATE"; then
    fail "template appears to contact something outside the lab"
else
    note "no external network is contacted"
fi

# ---------------------------------------------------------------------------
# The engine's own view. A template that only satisfies its own harness has not
# been shown to find anything: this is a real `cxg scan` against the flawed twin
# and against the fixed one.
# ---------------------------------------------------------------------------
if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0" "syntaxonly	1" "toctouonly	1"; do
        IFS=$'\t' read -r variant want <<<"$pair"
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
    # The confirmation cxg reports must be the real one, carrying the channels.
    python3 - "$WORK/scan-flawed.json" <<'PY'
import json, sys
findings = json.load(open(sys.argv[1]))["findings"]
if not findings:
    print("  FAIL: cxg scan reported no finding to inspect")
    sys.exit(1)
title = findings[0].get("title", "")
if "Deny rule is reachable around" not in title:
    print("  FAIL: cxg scan's finding is not this template's: %r" % title)
    sys.exit(1)
print("  cxg scan's finding is this template's, titled %r" % title[:70])
PY
    [ $? -eq 0 ] || FAILURES=$((FAILURES + 1))
else
    echo "cxg scan: SKIPPED (cxg not on PATH)"
    fail "cxg is not on PATH, so the engine-level confirmation was not proved"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "coding-agent-deny-rule-reachability: confirmed on the channel-equivalence, check/use and inert-rule twins with each class attributed to the twin that carries it, refuted on the enforcing twin with a working positive control on every arm, and skipped on the no-surface, rule-refusing, dead-channel and non-agent targets."
    exit 0
fi
echo "coding-agent-deny-rule-reachability: $FAILURES assertion(s) failed." >&2
exit 1

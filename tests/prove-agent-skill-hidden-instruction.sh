#!/usr/bin/env bash
# Prove templates/ai/coding-agent/agent-skill-hidden-instruction-trust.py in
# every direction it can emit, against the synthetic twins in
# tests/fixtures/agent-skill-hidden-instruction/.
#
#   CONFIRMED on skillagent_flawed.py    -- honours the model view, so all three
#                                           concealed directives execute and the
#                                           network:none skill hits the canary
#   REFUTED   on skillagent_fixed.py     -- same program, approval view made
#                                           authoritative: only the visible
#                                           directive runs
#   SKIPPED   on skillagent_noskills.py  -- same program with no skill surface
#   SKIPPED   on a non-agent binary      -- git loads no skills
#
# A check nobody can make refute is not a check, and a check that cannot skip
# reports clean bills of health it never earned, so all four are asserted --
# plus the two self-checks the template makes about its own payload, which are
# what entitle it to use the word "concealed" at all.
#
# Usage: tests/prove-agent-skill-hidden-instruction.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/agent-skill-hidden-instruction-trust.py"
FIXTURES="$HERE/fixtures/agent-skill-hidden-instruction"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-skill-hidden-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

report_of() {
    CERT_X_GEN_TARGET_HOST="cli://$1" python3 "$TEMPLATE" 2>/dev/null
}

run_case() {
    local label="$1" target="$2" want_status="$3" want_findings="$4"
    local report result got_status got_findings detail
    report="$(report_of "$target")" || { fail "$label: template did not run"; return; }
    printf '%s' "$report" >"$WORK/report-$label.json"
    result="$(printf '%s' "$report" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("%s\t%d\t%s" % (d["metadata"]["status"], len(d["findings"]), d["metadata"]["detail"]))
' 2>/dev/null)" || { fail "$label: template emitted no parseable JSON"; return; }
    IFS=$'\t' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$label: $got_status ($got_findings finding(s)) -- ${detail:0:120}"
    else
        fail "$label: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
}

echo "probe contract"
run_case flawed   "$WORK/twins/skillagent_flawed.py"   confirmed 1
run_case fixed    "$WORK/twins/skillagent_fixed.py"    refuted   0
run_case noskills "$WORK/twins/skillagent_noskills.py" skipped   0
if command -v git >/dev/null 2>&1; then
    run_case non-agent "$(command -v git)" skipped 0
else
    note "non-agent: SKIPPED (git not on PATH)"
fi

# A confirmation has to carry the observation that proves it. Assert the shape
# of the evidence, not just the count: which channels were obeyed, that the
# canary really was reached, that concealment was established before delivery,
# and that the report names the invisible characters instead of reprinting them
# (a report that quoted the payload would carry the concealment one hop
# downstream, into whatever reads the report).
echo "confirmation evidence"
python3 - "$WORK/report-flawed.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys
d = json.load(open(sys.argv[1]))
data = d["findings"][0]["evidence"]["data"]
bad = []
obeyed = set(data["channels_obeyed"])
for chan in ("tag", "comment", "details"):
    if chan not in obeyed:
        bad.append("channel %s was not obeyed by the flawed twin" % chan)
    spec = data["channels"][chan]
    if not spec["concealed"]:
        bad.append("channel %s was not established as concealed" % chan)
    if spec["in_rendered_view"]:
        bad.append("channel %s leaked into the rendered view" % chan)
    if not spec["in_model_view"]:
        bad.append("channel %s is absent from the model view" % chan)
if not data["visible_receipt_fired"]:
    bad.append("visible receipt did not fire, so the probe skill was never loaded")
if not data["canary_hits"]:
    bad.append("no canary hit recorded for a network:none skill")
if data["declared_network"] != "none":
    bad.append("the skill did not declare network:none")
if data["invisible_unicode_classes_in_rendered_view"]:
    bad.append("the rendered view is not clean under the invisible-unicode oracle")
if "tag-block-payload" not in data["invisible_unicode_classes_in_source"]:
    bad.append("the invisible-unicode oracle did not certify the TAG-block payload")
if "\U000E0052" in json.dumps(data):
    bad.append("the report reprinted raw TAG-block characters instead of naming them")
if "<U+E0" not in data["source_excerpt"]:
    bad.append("the source excerpt does not name the invisible characters")
for line in bad:
    print("  FAIL: %s" % line)
if not bad:
    print("  evidence: 3 channels concealed and obeyed, canary hit %s, oracle certified "
          "the payload and cleared the rendered view" % data["canary_hits"][0]["path"])
sys.exit(1 if bad else 0)
PY

# The refutation must be earned the same way: the skill was loaded (its visible
# directive ran) and the concealed ones specifically did not.
echo "refutation is earned"
if grep -q "VISIBLE directive executed" "$WORK/report-fixed.json" \
   && grep -q "canary was never touched" "$WORK/report-fixed.json"; then
    note "fixed twin: refutation names the loaded skill and the untouched canary"
else
    fail "fixed twin: refutation does not state what it observed"
fi

# The oracle this template carries must not have drifted from the two MCP
# templates that carry the same code.
echo "no-drift corpus"
if python3 "$REPO/fixtures/mcp-tool-poisoning/natural_corpus.py" >"$WORK/corpus.log" 2>&1; then
    note "$(tail -2 "$WORK/corpus.log" | head -1)"
else
    fail "invisible-unicode oracle drift: $(tail -3 "$WORK/corpus.log" | tr '\n' ' ')"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0"; do
        IFS=$'\t' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/skillagent_${variant}.py" \
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
    echo "agent-skill-hidden-instruction-trust: confirmed on the flawed twin, refuted on the fixed one, skipped with no skill surface and on a non-agent."
    exit 0
fi
echo "agent-skill-hidden-instruction-trust: $FAILURES assertion(s) failed." >&2
exit 1

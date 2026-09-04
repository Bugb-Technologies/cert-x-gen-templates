#!/usr/bin/env bash
# Prove the coding-agent execution-authority pack in BOTH directions, on every
# configuration shape it claims to cover.
#
#   templates/ai/coding-agent/coding-agent-shared-config-trust.sh
#   templates/ai/coding-agent/coding-agent-project-local-config-trust.sh
#   templates/ai/coding-agent/coding-agent-config-allowlist-trust.sh
#
# against tests/fixtures/coding-agent-exec-authority/ -- one benign synthetic
# CLI source, materialised into the Claude Code / Cursor / Codex / Gemini config
# *shapes* and, per shape, into twins that differ only in whether the trust gate
# is switched on.
#
#   CONFIRMED on <shape>_defective.py      the gate is off
#   REFUTED   on <shape>_fixed.py          the gate is on
#   SKIPPED   on claudeish_nogate.py       (allowlist check only) -- there is no
#                                          approval gate for an allowlist to
#                                          subvert, so a confirmation would be
#                                          a claim the probe cannot back
#   CONFIRMED on claudeish_prefixmatch.py  (allowlist check only) -- the config
#                                          trust gate holds, but allowlist
#                                          entries match on the command NAME
#
# A check nobody can make refute is not a check, and a check that cannot be made
# to skip will report clean runs it did not earn, so all three verdicts are
# asserted. Each template is exercised through its raw probe contract and --
# when `cxg` is on PATH -- again through a real `cxg scan`, because the two
# disagree about nothing only if you look.
#
# Usage: tests/prove-coding-agent-exec-authority.sh   Exit 0 = every assertion holds.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TPL="$REPO/templates/ai/coding-agent"
FIXTURES="$HERE/fixtures/coding-agent-exec-authority"

SHARED="$TPL/coding-agent-shared-config-trust.sh"
PROJECT="$TPL/coding-agent-project-local-config-trust.sh"
ALLOWLIST="$TPL/coding-agent-config-allowlist-trust.sh"

SHAPES="${CXG_FIXTURE_SHAPES:-claudeish cursorish codexish geminiish}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-execauth-test.XXXXXX")"
trap 'chmod -R u+rwX "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

CXG_FIXTURE_SHAPES="$SHAPES" CXG_FIXTURE_VARIANTS="defective fixed" \
    bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }
CXG_FIXTURE_SHAPES=claudeish CXG_FIXTURE_VARIANTS="nogate prefixmatch" \
    bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the extra claudeish twins"; exit 1; }

# status<TAB>finding-count<TAB>matched-pattern-count<TAB>detail
probe() {
    template="$1" binary="$2"
    CERT_X_GEN_TARGET_HOST="cli://$binary" \
        bash "$template" "cli://$binary" 80 --json 2>/dev/null \
        | python3 -c '
import json, sys
d = json.load(sys.stdin)
m, f = d["metadata"], d["findings"]
patterns = sum(len(x.get("evidence", {}).get("matched_patterns", [])) for x in f)
print("%s\t%d\t%d\t%s" % (m["status"], len(f), patterns, m["detail"]))'
}

# One assertion: template x binary must produce `want_status` with
# `want_findings` findings, and every confirmation must carry the observation
# that proves it -- a confirmed finding with no matched pattern is a verdict
# with nothing behind it.
assert_probe() {
    label="$1" template="$2" binary="$3" want_status="$4" want_findings="$5"
    result="$(probe "$template" "$binary")" || { fail "$label: template did not run"; return; }
    IFS=$'\t' read -r status findings patterns detail <<<"$result"
    if [ "$status" != "$want_status" ] || [ "$findings" != "$want_findings" ]; then
        fail "$label: expected $want_status/$want_findings, got $status/$findings -- ${detail:0:160}"
        return
    fi
    if [ "$want_status" = "confirmed" ] && [ "$patterns" -eq 0 ]; then
        fail "$label: confirmed with no matched pattern -- a verdict with no observation behind it"
        return
    fi
    note "$label: $status ($findings finding(s)) -- ${detail:0:120}"
}

echo "probe contract -- managed config root, per shape"
for shape in $SHAPES; do
    assert_probe "$shape/defective" "$SHARED" "$WORK/twins/${shape}_defective.py" confirmed 1
    assert_probe "$shape/fixed"     "$SHARED" "$WORK/twins/${shape}_fixed.py"     refuted   0
done

echo "probe contract -- project-local config, per shape"
for shape in $SHAPES; do
    assert_probe "$shape/defective" "$PROJECT" "$WORK/twins/${shape}_defective.py" confirmed 1
    assert_probe "$shape/fixed"     "$PROJECT" "$WORK/twins/${shape}_fixed.py"     refuted   0
done

echo "probe contract -- project-local config, each writable arm on its own"
# The first arm that confirms ends the run, so the ancestor arm would never be
# seen if the workspace arm were always probed alongside it.
for arm in writable ancestor; do
    export CXG_AGENT_PROJECT_ARMS="$arm"
    assert_probe "arm=$arm/defective" "$PROJECT" "$WORK/twins/claudeish_defective.py" confirmed 1
    assert_probe "arm=$arm/fixed"     "$PROJECT" "$WORK/twins/claudeish_fixed.py"     refuted   0
    unset CXG_AGENT_PROJECT_ARMS
done

echo "probe contract -- config-declared allowlist, per shape"
for shape in $SHAPES; do
    assert_probe "$shape/defective" "$ALLOWLIST" "$WORK/twins/${shape}_defective.py" confirmed 1
    assert_probe "$shape/fixed"     "$ALLOWLIST" "$WORK/twins/${shape}_fixed.py"     refuted   0
done

echo "probe contract -- allowlist verdicts that are not confirm/refute"
assert_probe "nogate (no gate to subvert)" "$ALLOWLIST" "$WORK/twins/claudeish_nogate.py" skipped 0
assert_probe "prefixmatch (name-based match)" "$ALLOWLIST" "$WORK/twins/claudeish_prefixmatch.py" confirmed 1

# The skip must name its missing precondition, not just decline to answer.
skip_detail="$(probe "$ALLOWLIST" "$WORK/twins/claudeish_nogate.py" | cut -f4)"
case "$skip_detail" in
    *no-approval-gate-to-subvert*) note "nogate skip names its precondition" ;;
    *) fail "nogate: skip detail does not name the missing precondition: ${skip_detail:0:160}" ;;
esac

# The prefixmatch confirmation must be the NAME-match finding, not the
# world-writable one -- that twin's config trust gate is on.
prefix_detail="$(probe "$ALLOWLIST" "$WORK/twins/claudeish_prefixmatch.py" | cut -f4)"
case "$prefix_detail" in
    *allowlist-matched-on-command-name*) note "prefixmatch confirms on the name-match branch" ;;
    *) fail "prefixmatch: expected the name-match branch, got: ${prefix_detail:0:160}" ;;
esac

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for spec in "shared	$SHARED" "project	$PROJECT" "allowlist	$ALLOWLIST"; do
        IFS=$'\t' read -r label template <<<"$spec"
        for pair in "defective	1" "fixed	0"; do
            IFS=$'\t' read -r variant want <<<"$pair"
            cxg --disable-update-check scan -q \
                --scope "cli://$WORK/twins/claudeish_${variant}.py" \
                --templates "$template" \
                --output "$WORK/scan-$label-$variant" --output-format json \
                >/dev/null 2>&1
            got="$(python3 -c '
import json, sys
print(len(json.load(open(sys.argv[1]))["findings"]))' "$WORK/scan-$label-$variant.json" 2>/dev/null)"
            if [ "$got" = "$want" ]; then
                note "$label/$variant: $got finding(s) reported by cxg scan"
            else
                fail "$label/$variant: cxg scan reported ${got:-<no report>} finding(s), expected $want"
            fi
        done
    done
else
    echo "cxg scan: SKIPPED (cxg not on PATH)"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "coding-agent execution-authority pack: confirmed on every flawed twin, refuted on every fixed one, skipped where the precondition was absent."
    exit 0
fi
echo "coding-agent execution-authority pack: $FAILURES assertion(s) failed." >&2
exit 1

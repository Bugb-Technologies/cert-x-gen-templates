#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-command-trace-composition.sh in
# BOTH directions against the synthetic twin pair in
# tests/fixtures/coding-agent-command-trace/.
#
#   CONFIRMED on cmdguard_flawed.py  -- it approves every statement of a trace
#                                       whose composition executes `touch <marker>`
#   REFUTED   on cmdguard_fixed.py   -- same program, stateful re-validation of
#                                       the resolved command at the exec sink
#   SKIP      on a non-validator      -- git has no command-trace surface
#
# A check nobody can make refute is not a check, so all three directions are
# asserted. The template is exercised through its raw probe contract, and --
# when `cxg` is on PATH -- through a real `cxg scan`, because the two disagree
# about nothing only if you look.
#
# Usage: tests/prove-coding-agent-command-trace.sh   Exit 0 = all directions hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-command-trace-composition.sh"
FIXTURES="$HERE/fixtures/coding-agent-command-trace"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-cmd-trace-test.XXXXXX")"
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
# variant-or-binary  want_status  want_findings
run_case() {
    local label="$1" target="$2" want_status="$3" want_findings="$4"
    local result got_status got_findings detail
    result="$(status_of "$target")" || { fail "$label: template did not run"; return; }
    IFS='	' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$label: $got_status ($got_findings finding(s)) -- ${detail:0:110}"
    else
        fail "$label: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
}

run_case "flawed twin" "$WORK/twins/cmdguard_flawed.py" confirmed 1
run_case "fixed twin"  "$WORK/twins/cmdguard_fixed.py"  refuted   0
# A binary with no command-trace surface must SKIP -- naming the missing
# precondition -- not refute (which would be a clean bill of health it never
# earned) and not confirm.
if command -v git >/dev/null 2>&1; then
    run_case "non-validator (git)" "$(command -v git)" skipped 0
else
    note "non-validator: SKIPPED (git not on PATH)"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/cmdguard_${variant}.py" \
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
    echo "coding-agent-command-trace-composition: confirmed on the flawed twin, refuted on the fixed one, skipped on a non-validator."
    exit 0
fi
echo "coding-agent-command-trace-composition: $FAILURES assertion(s) failed." >&2
exit 1

#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-shared-config-trust.sh in BOTH
# directions against the synthetic twin pair in
# tests/fixtures/coding-agent-config-trust/.
#
#   CONFIRMED on agentcli_defective.py  -- it honours managed settings planted
#                                          in a 0777 config root
#   REFUTED   on agentcli_fixed.py      -- same program, trust gate switched on
#
# A check nobody can make refute is not a check, so both halves are asserted.
# The template is exercised twice: through its raw probe contract, and -- when
# `cxg` is on PATH -- through a real `cxg scan`, because the two disagree about
# nothing only if you look.
#
# Usage: tests/run-coding-agent-config-trust.sh      Exit 0 = both directions hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-shared-config-trust.sh"
FIXTURES="$HERE/fixtures/coding-agent-config-trust"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-agent-cfg-test.XXXXXX")"
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
for pair in "defective	confirmed	1" "fixed	refuted	0"; do
    IFS='	' read -r variant want_status want_findings <<<"$pair"
    result="$(status_of "$WORK/twins/agentcli_${variant}.py")" || {
        fail "$variant: template did not run"; continue; }
    IFS='	' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$variant: $got_status ($got_findings finding(s)) -- $detail"
    else
        fail "$variant: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
done

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "defective	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/agentcli_${variant}.py" \
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
    echo "coding-agent-shared-config-trust: confirmed on the flawed twin, refuted on the fixed one."
    exit 0
fi
echo "coding-agent-shared-config-trust: $FAILURES assertion(s) failed." >&2
exit 1

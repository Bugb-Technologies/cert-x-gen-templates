#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-sandbox-trust-handoff.sh in EVERY
# direction it emits, against the synthetic twin set in
# tests/fixtures/coding-agent-sandbox-trust-handoff/.
#
#   CONFIRMED on sandbox-runner_flawed.py     -- the boundary confines the agent
#              process (direct escape blocked), but agent-authored consumer
#              surfaces are executed by the unsandboxed consumers AFTER the
#              sandbox exits: a nonce marker fires post-exit.
#   REFUTED   on sandbox-runner_fixed.py      -- same confinement plus a handoff
#              trust-downgrade: every consumer refuses the agent-authored surface.
#   SKIP      on sandbox-runner_nosandbox.py  -- the process is NOT confined (the
#              direct escape write succeeds), so there is no boundary to hand off
#              across; a marker firing later would prove nothing.
#   SKIP      on a non-sandbox binary (git)   -- no run-agent surface at all.
#
# A check nobody can make refute or skip is not a check, so all four directions
# are asserted. The template is exercised through its raw probe contract, and --
# when `cxg` is on PATH -- through a real `cxg scan`, because the two agree about
# nothing only if you look.
#
# Usage: tests/prove-coding-agent-sandbox-trust-handoff.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-sandbox-trust-handoff.sh"
FIXTURES="$HERE/fixtures/coding-agent-sandbox-trust-handoff"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-sandbox-handoff-test.XXXXXX")"
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

run_case "flawed twin"    "$WORK/twins/sandbox-runner_flawed.py"    confirmed 1
run_case "fixed twin"     "$WORK/twins/sandbox-runner_fixed.py"     refuted   0
# No boundary -> the escape write succeeds -> SKIP (a marker later proves no
# handoff). Naming the missing precondition, not a clean bill of health.
run_case "nosandbox twin" "$WORK/twins/sandbox-runner_nosandbox.py" skipped   0
# A binary with no sandbox-runner surface must SKIP, not refute or confirm.
if command -v git >/dev/null 2>&1; then
    run_case "non-sandbox (git)" "$(command -v git)" skipped 0
else
    note "non-sandbox: SKIPPED (git not on PATH)"
fi

# The confirmation must name each deferred consumer that fired post-exit. Guard
# against a template that "confirms" without actually observing the surfaces.
detail_flawed="$(status_of "$WORK/twins/sandbox-runner_flawed.py")"
for consumer in claude-hooks venv vscode-tasks git-altdir git-config; do
    if printf '%s' "$detail_flawed" | grep -q "$consumer"; then
        note "flawed: consumer '$consumer' named in the confirmation"
    else
        fail "flawed: confirmation did not name consumer '$consumer'"
    fi
done
# The third write path (allow-list flag mutation) must be recorded.
if printf '%s' "$detail_flawed" | grep -q 'flag-mutation=yes'; then
    note "flawed: allow-list flag mutation into a protected path was exercised"
else
    fail "flawed: allow-list flag mutation not recorded in the confirmation"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/sandbox-runner_${variant}.py" \
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
    echo "coding-agent-sandbox-trust-handoff: confirmed on the flawed twin, refuted on the fixed one, skipped on the unconfined twin and on a non-sandbox binary."
    exit 0
fi
echo "coding-agent-sandbox-trust-handoff: $FAILURES assertion(s) failed." >&2
exit 1

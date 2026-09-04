#!/usr/bin/env bash
# Prove templates/ai/mcp/mcp-child-env-inheritance.sh in EVERY direction it can
# report, against the synthetic triplet in tests/fixtures/mcp-child-env-inheritance/.
#
#   CONFIRMED on mcplaunch_flawed.py  -- child env = os.environ + declared, so the
#                                        undeclared credential canaries arrive
#   REFUTED   on mcplaunch_fixed.py   -- same program, child env scoped to a minimal
#                                        base + the manifest's declared `env`
#   SKIP      on mcplaunch_nodecl.py  -- spawns the child but never honours the
#                                        declaration: the differential's declared
#                                        half is missing, so no verdict is earned
#                                        (even though canaries DO leak here -- this
#                                        is the assertion that the template will not
#                                        confirm on an unmeasured surface)
#   SKIP      on a non-host            -- git has no stdio-launch surface
#
# A check nobody can make refute is not a check, and a check that cannot be made
# to decline is worse, so all four directions are asserted. The template is
# exercised through its raw probe contract, and -- when `cxg` is on PATH --
# through a real `cxg scan`, because the two disagree about nothing only if you
# look.
#
# The confirmation is additionally asserted to be zero-FP by construction: two
# consecutive runs must report DIFFERENT canary nonces, which is what proves the
# oracle keys on a value minted this run rather than on a name it expected to find.
#
# Usage: tests/prove-mcp-child-env-inheritance.sh   Exit 0 = all directions hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-child-env-inheritance.sh"
FIXTURES="$HERE/fixtures/mcp-child-env-inheritance"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-mcp-env-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

run_template() {
    CERT_X_GEN_TARGET_HOST="cli://$1" \
        bash "$TEMPLATE" "cli://$1" 80 --json
}

status_of() {
    run_template "$1" | python3 -c 'import json,sys; d=json.load(sys.stdin); m=d["metadata"]; print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))'
}

echo "probe contract"
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

run_case "flawed twin"          "$WORK/twins/mcplaunch_flawed.py" confirmed 1
run_case "fixed twin"           "$WORK/twins/mcplaunch_fixed.py"  refuted   0
# Canaries leak here, but the declaration never arrived, so the template has not
# measured anything and must decline rather than confirm.
run_case "declaration-ignored"  "$WORK/twins/mcplaunch_nodecl.py" skipped   0
if command -v git >/dev/null 2>&1; then
    run_case "non-host (git)" "$(command -v git)" skipped 0
else
    note "non-host: SKIPPED (git not on PATH)"
fi

echo "finding shape"
run_template "$WORK/twins/mcplaunch_flawed.py" >"$WORK/confirm-a.json"
run_template "$WORK/twins/mcplaunch_flawed.py" >"$WORK/confirm-b.json"
python3 - "$WORK/confirm-a.json" "$WORK/confirm-b.json" <<'PY'
import json, sys

a = json.load(open(sys.argv[1]))["findings"][0]
b = json.load(open(sys.argv[2]))["findings"][0]
problems = []

da, db = a["evidence"]["data"], b["evidence"]["data"]
if da["oracle"] != "property":
    problems.append("oracle is %r, expected 'property'" % da["oracle"])
if not da["declaration_honoured"]:
    problems.append("confirmation did not record the declared half of the differential")
if sorted(da["leaked_canaries"]) != sorted(db["leaked_canaries"]):
    problems.append("the two runs disagree about which canaries leaked")
if da["child_env_var_count"] <= da["declared_need_count"]:
    problems.append("child env is not larger than the declared need")
if "observations" not in da:
    problems.append("no soft observations recorded")

# Zero-FP by construction: the oracle keys on a value minted this run. Two runs
# must therefore carry different nonces in their evidence.
ra, rb = a["evidence"]["response"], b["evidence"]["response"]
if ra == rb:
    problems.append("two runs produced identical evidence -- the nonces are not fresh")

# The report must never carry a value this scan did not itself mint: the
# child-environment section of the evidence is a NAME list, not NAME=VALUE pairs
# (the one "count=N" header line aside), and it carries no canary value either.
env_section = a["evidence"]["response"].split("---")[-1]
pairs = [ln for ln in env_section.splitlines()
         if "=" in ln and not ln.startswith("count=")]
if pairs:
    problems.append("evidence carries NAME=VALUE pairs from the child env: %r" % pairs[:3])
if "CXG-CANARY-" in a["evidence"]["response"]:
    problems.append("evidence records a canary VALUE, not just its name")

if problems:
    for p in problems:
        print("  FAIL: %s" % p)
    sys.exit(1)
print("  confirmation carries a property oracle, fresh nonces, the honoured "
      "declaration and soft observations; no child values recorded")
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    for pair in "flawed	1" "fixed	0" "nodecl	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/mcplaunch_${variant}.py" \
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
    echo "mcp-child-env-inheritance: confirmed on the flawed twin, refuted on the scoped one, skipped on the declaration-ignoring twin and on a non-host."
    exit 0
fi
echo "mcp-child-env-inheritance: $FAILURES assertion(s) failed." >&2
exit 1

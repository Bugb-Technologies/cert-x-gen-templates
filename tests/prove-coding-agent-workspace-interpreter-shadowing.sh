#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-workspace-interpreter-shadowing.sh
# in ALL THREE directions against the synthetic twin pair in
# tests/fixtures/coding-agent-workspace-interpreter-shadowing/.
#
#   CONFIRMED on agentstub_defective.py -- runs python -c in the workspace with
#                                          the workspace on sys.path, so a
#                                          planted struct.py/json.py/shutil.py
#                                          shadows the standard library
#   REFUTED   on agentstub_fixed.py     -- same program, PYTHONSAFEPATH=1, so the
#                                          interpreter runs with the workspace
#                                          off its module search path (proven to
#                                          have actually run by the positive
#                                          control)
#   SKIPPED   on inertcli_none.py       -- same command surface, invokes no
#                                          interpreter at all, so there is no
#                                          module search path to shadow and the
#                                          template must not call that safety
#
# A check nobody can make refute is not a check, and a check that cannot say "I
# did not learn anything here" reports noise as safety, so all three are
# asserted. The template is exercised twice: through its raw probe contract, and
# -- when `cxg` is on PATH -- through a real `cxg scan`, because the two agree
# about nothing unless you look.
#
# Usage: tests/prove-coding-agent-workspace-interpreter-shadowing.sh
#        Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-workspace-interpreter-shadowing.sh"
FIXTURES="$HERE/fixtures/coding-agent-workspace-interpreter-shadowing"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-interp-shadow-test.XXXXXX")"
trap 'chmod -R u+rwX "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

# The SKIP arm: a CLI with the same command surface that never spawns an
# interpreter. Nothing about it is safe or unsafe; the template has simply not
# been able to exercise the class, and must say so rather than certify safety.
cat >"$WORK/twins/inertcli_none.py" <<'STUB'
#!/usr/bin/env python3
"""A CLI with the same commands that runs no interpreter in the workspace."""
import sys

USAGE = """\
Usage: inertcli <command> [args]

Commands:
  run                Report status (no interpreter is launched)
  check              Alias for run
  session            Start a session
  open               Open the workspace
  help               Print this message
"""

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
    elif argv[0] in ("run", "check", "session", "open"):
        # Handled entirely in-process; no python -c, no subprocess.
        print("inertcli: ready (no interpreter is launched in the workspace)")
    else:
        sys.stderr.write(USAGE)
        sys.exit(2)
STUB
chmod +x "$WORK/twins/inertcli_none.py"

probe() {
    CERT_X_GEN_TARGET_HOST="cli://$1" \
        bash "$TEMPLATE" "cli://$1" 80 --json \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); m=d["metadata"]; print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))'
}

echo "probe contract"
for pair in "agentstub_defective.py	confirmed	1" \
            "agentstub_fixed.py	refuted	0" \
            "inertcli_none.py	skipped	0"; do
    IFS='	' read -r binary want_status want_findings <<<"$pair"
    result="$(probe "$WORK/twins/$binary")" || { fail "$binary: template did not run"; continue; }
    IFS='	' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$binary: $got_status ($got_findings finding(s)) -- $detail"
    else
        fail "$binary: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
done

# The confirmation has to name WHICH stdlib modules were shadowed, has to carry
# a positive control proving the interpreter actually ran, and its matched
# pattern must be one of this run's own shadow nonces -- not a constant a false
# positive could hard-code.
echo "evidence"
EVIDENCE="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/agentstub_defective.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/agentstub_defective.py" 80 --json)"
python3 - "$EVIDENCE" <<'CHECK'
import json, sys

report = json.loads(sys.argv[1])
finding = report["findings"][0]
data = finding["evidence"]["data"]
problems = []

shadowed = set(filter(None, data["shadowed_modules"].split(",")))
# struct is the load-bearing one (both the agent's own import and zipfile's
# stdlib internal import route through it); require at least it.
if "struct" not in shadowed:
    problems.append("struct was not shadowed: %r" % sorted(shadowed))
if data.get("interpreter_ran") is not True:
    problems.append("positive control missing: interpreter_ran is not true")
if not data.get("positive_control"):
    problems.append("positive control line is empty")
pat = finding["evidence"]["matched_patterns"][0]
if not pat.startswith("CXG-SHADOW-"):
    problems.append("matched pattern is not a shadow nonce: %r" % pat)

if problems:
    for problem in problems:
        print("  FAIL: %s" % problem)
    sys.exit(1)
print("  shadowed %s, interpreter ran (control: %s)"
      % (",".join(sorted(shadowed)), data["positive_control"]))
CHECK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# A refutation must be earned: the fixed twin's interpreter has to have actually
# run (else "refuted" is just a silently-broken arm). The detail line carries
# the positive control.
echo "refutation is earned, not silent"
REFUTE_DETAIL="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/agentstub_fixed.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/agentstub_fixed.py" 80 --json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["metadata"]["detail"])')"
if printf '%s' "$REFUTE_DETAIL" | grep -q 'positive control: python -c/-m recorded'; then
    note "fixed twin: interpreter proven to run, no import resolved from the workspace"
else
    fail "fixed twin refutation lacks a positive control: $REFUTE_DETAIL"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    # The report path carries no file extension: cxg REPLACES one, so
    # `--output .../scan-defective.py` would land as `...-defective.json` and the
    # assertion would read a file that is not there. Name it without a dot.
    for pair in "defective	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/agentstub_${variant}.py" \
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
    echo "coding-agent-workspace-interpreter-shadowing: confirmed on the flawed twin, refuted on the fixed one, skipped on a tool that runs no interpreter."
    exit 0
fi
echo "coding-agent-workspace-interpreter-shadowing: $FAILURES assertion(s) failed." >&2
exit 1

#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-repo-config-autoexec.sh in ALL
# THREE directions against the synthetic twin pair in
# tests/fixtures/coding-agent-repo-config-autoexec/.
#
#   CONFIRMED on repoagent_defective.py  -- it applies repo-supplied config to a
#                                           workspace nobody approved
#   REFUTED   on repoagent_fixed.py      -- same program, workspace-trust gate on
#   SKIPPED   on a stub with no repo-scoped config layer at all -- the template
#                                           must not call that a clean bill of
#                                           health, because it never established
#                                           a surface to test
#
# A check nobody can make refute is not a check, and a check that cannot say "I
# did not learn anything here" reports noise as safety, so all three are
# asserted. The template is exercised twice: through its raw probe contract, and
# -- when `cxg` is on PATH -- through a real `cxg scan`, because the two agree
# about nothing unless you look.
#
# Usage: tests/prove-coding-agent-repo-config-autoexec.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-repo-config-autoexec.sh"
FIXTURES="$HERE/fixtures/coding-agent-repo-config-autoexec"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-repo-config-test.XXXXXX")"
trap 'chmod -R u+rwX "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

# The SKIP arm: a CLI with the same command surface and no repo-scoped config
# layer whatsoever. Nothing about it is trustworthy or untrustworthy; the
# template has simply learned nothing, and must say so.
cat >"$WORK/twins/inertcli_none.py" <<'STUB'
#!/usr/bin/env python3
"""A CLI with the same commands and no repo-scoped configuration layer."""
import sys

USAGE = """\
Usage: inertcli <command> [args]

Commands:
  open               Open the workspace in the working directory
  session            Start an agent session in this workspace
  config             Print the effective configuration
  help               Print this message
"""

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
    elif argv[0] in ("open", "session"):
        print("inertcli: ready (no repo-scoped configuration is read)")
    elif argv[0] == "config":
        print("inertcli: marker=builtin-default")
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
for pair in "repoagent_defective.py	confirmed	1" \
            "repoagent_fixed.py	refuted	0" \
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

# The confirmation has to name WHICH repo-scoped surfaces were honoured and has
# to have witnessed at least one command actually run. A confirmation that only
# parsed a marker is a weaker claim, and this fixture executes, so anything less
# means the probe lost its execution witness.
echo "evidence"
EVIDENCE="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/repoagent_defective.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/repoagent_defective.py" 80 --json)"
python3 - "$EVIDENCE" <<'CHECK'
import json, sys

report = json.loads(sys.argv[1])
finding = report["findings"][0]
data = finding["evidence"]["data"]
problems = []

expected = {"claude-settings-hook", "mcp-autoapprove", "cursor-mcp",
            "vscode-folderopen-task", "agents-md-directive", "tool-native-settings"}
honoured = {entry.split(":")[0]
            for entry in data["surfaces_honoured_unapproved"].split()}
missing = expected - honoured
if missing:
    problems.append("surfaces not honoured in the unapproved arm: %s"
                    % ", ".join(sorted(missing)))
if data["commands_executed_unapproved"] < 1:
    problems.append("no command execution witnessed in the unapproved arm")
if data["approved_checkout_mode"] != data["unapproved_checkout_mode"]:
    problems.append("arms differed in mode, so the differential is not provenance-only")
if not finding["evidence"]["matched_patterns"][0].startswith("CXG-REPOCFG-UNAPPROVED-"):
    problems.append("matched pattern is not an unapproved-arm nonce: %r"
                    % finding["evidence"]["matched_patterns"])

if problems:
    for problem in problems:
        print("  FAIL: %s" % problem)
    sys.exit(1)
print("  all six surfaces honoured, %d executed, arms identical at mode %s"
      % (data["commands_executed_unapproved"], data["approved_checkout_mode"]))
CHECK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    # The report path carries no file extension: cxg replaces one, so
    # `--output .../scan-repoagent_defective.py` lands as `...-defective.json`
    # and the assertion reads a file that is not there.
    for pair in "defective	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/repoagent_${variant}.py" \
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
    echo "coding-agent-repo-config-autoexec: confirmed on the flawed twin, refuted on the fixed one, skipped on a tool with no repo-scoped config layer."
    exit 0
fi
echo "coding-agent-repo-config-autoexec: $FAILURES assertion(s) failed." >&2
exit 1

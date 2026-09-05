#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-git-config-exec.sh in ALL THREE
# directions against the synthetic twin pair in
# tests/fixtures/coding-agent-git-config-exec/, and - when cxg is on PATH -
# through a REAL `cxg scan`, not just the raw probe contract.
#
#   CONFIRMED on gitagent_defective.py -- its background git honours the
#                                         malicious workspace's own .git/config,
#                                         so `git status` runs attacker code
#   REFUTED   on gitagent_fixed.py     -- same program, git-config trust gate on
#   SKIPPED   on a stub that gathers context WITHOUT git -- the class has nothing
#                                         to reach, and the template must say so
#                                         rather than issue a clean bill of health
#
# The GitSpawn mechanism (core.fsmonitor / clean filter / core.sshCommand /
# core.hooksPath executed by git on ordinary read operations) is reproduced
# faithfully: the flawed fixture really shells out to `git status`/`git diff`/
# `git ls-remote` against a workspace assembled AS FILES, exactly what a real
# vulnerable agent does, and git really runs the planted commands.
#
# Usage: tests/prove-coding-agent-git-config-exec.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-git-config-exec.sh"
FIXTURES="$HERE/fixtures/coding-agent-git-config-exec"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-gitspawn-test.XXXXXX")"
trap 'chmod -R u+rwX "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

command -v git >/dev/null 2>&1 || { echo "git is required to run this proof"; exit 1; }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

# The SKIP arm: same command surface, gathers context by READING FILES, never by
# shelling out to git. Nothing here is trustworthy or untrustworthy about git;
# the template has simply learned nothing and must say so.
cat >"$WORK/twins/nogitcli_none.py" <<'STUB'
#!/usr/bin/env python3
"""A context-gathering CLI that never shells out to git."""
import os, sys

USAGE = """\
Usage: nogitcli <command> [args]

Commands:
  open               Open the workspace in the working directory
  session            Start an agent session in this workspace
  context            Gather repository context for this workspace
  help               Print this message
"""

def gather():
    files = sorted(os.listdir("."))[:5]
    print("nogitcli: context from filesystem only: %s" % ", ".join(files))

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
    elif argv[0] in ("open", "session", "context"):
        print("nogitcli: opened %s" % os.getcwd())
        gather()
    else:
        sys.stderr.write(USAGE); sys.exit(2)
STUB
chmod +x "$WORK/twins/nogitcli_none.py"

probe() {
    CERT_X_GEN_TARGET_HOST="cli://$1" \
        bash "$TEMPLATE" "cli://$1" 80 --json \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); m=d["metadata"]; print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))'
}

echo "probe contract"
for pair in "gitagent_defective.py	confirmed	1" \
            "gitagent_fixed.py	refuted	0" \
            "nogitcli_none.py	skipped	0"; do
    IFS='	' read -r binary want_status want_findings <<<"$pair"
    result="$(probe "$WORK/twins/$binary")" || { fail "$binary: template did not run"; continue; }
    IFS='	' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$binary: $got_status ($got_findings finding(s)) -- ${detail:0:110}"
    else
        fail "$binary: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
done

# The confirmation must name a git-executed vector that actually fired, and its
# matched pattern must be a probe-arm nonce -- proof a git-run command wrote it,
# not that a marker was merely parsed.
echo "evidence"
EVIDENCE="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/gitagent_defective.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/gitagent_defective.py" 80 --json)"
python3 - "$EVIDENCE" <<'CHECK'
import json, sys
report = json.loads(sys.argv[1])
finding = report["findings"][0]
data = finding["evidence"]["data"]
problems = []

fired = set(f for f in data["vectors_fired_for_target"].split(",") if f)
if "fsmonitor" not in fired:
    problems.append("core.fsmonitor did not fire for the target -- the headline "
                    "GitSpawn vector (git status) must be witnessed")
if not fired:
    problems.append("no git-executed vector fired for the target")
if not data.get("target_ran_git"):
    problems.append("target_ran_git is not true")
if data.get("delivery") != "assembled-as-files-not-cloned":
    problems.append("delivery is not recorded as assembled-as-files (a clone "
                    "would not carry the config -- the class depends on this)")
if not finding["evidence"]["matched_patterns"][0].startswith("CXG-GITSPAWN-"):
    problems.append("matched pattern is not a GitSpawn probe nonce: %r"
                    % finding["evidence"]["matched_patterns"])

if problems:
    for p in problems:
        print("  FAIL: %s" % p)
    sys.exit(1)
print("  vectors fired for target: %s ; host-live: %s ; matched %s"
      % (data["vectors_fired_for_target"], data["vectors_live_on_host"],
         finding["evidence"]["matched_patterns"][0]))
CHECK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# A REAL cxg scan, not just the raw probe contract: the engine and the template
# agree about nothing unless you look.
if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    # The report path carries no file extension: cxg REPLACES one, so
    # `--output .../scan-defective.py` would land as `...-defective.json`.
    for pair in "defective	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/gitagent_${variant}.py" \
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
    echo "coding-agent-git-config-exec: confirmed on the flawed twin, refuted on the fixed one, skipped on a tool that runs no git."
    exit 0
fi
echo "coding-agent-git-config-exec: $FAILURES assertion(s) failed." >&2
exit 1

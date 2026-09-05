#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-repo-config-credential-redirect.sh
# in ALL THREE directions against the synthetic twin pair in
# tests/fixtures/coding-agent-repo-config-credential-redirect/.
#
#   CONFIRMED on envagent_defective.py -- it takes its API base URL, proxy and
#                                         CA anchors from an unapproved repo and
#                                         calls out carrying the operator's key
#   REFUTED   on envagent_fixed.py     -- same program, endpoint-control keys
#                                         refused from repo-scoped config
#   SKIPPED   on a stub that honours no configuration-supplied environment at
#                                         all -- the template never established
#                                         a surface, so it must not report a
#                                         clean bill of health it did not earn
#
# A check nobody can make refute is not a check, and a check that cannot say "I
# did not learn anything here" reports noise as safety, so all three are
# asserted. The template is exercised twice: through its raw probe contract, and
# -- when `cxg` is on PATH -- through a real `cxg scan`.
#
# Usage: tests/prove-coding-agent-repo-config-credential-redirect.sh
# Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-repo-config-credential-redirect.sh"
FIXTURES="$HERE/fixtures/coding-agent-repo-config-credential-redirect"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-cred-redirect-test.XXXXXX")"
trap 'chmod -R u+rwX "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

# The SKIP arm: a CLI with the same command surface that reads no
# configuration-supplied environment. Nothing about it is trustworthy or
# untrustworthy; the template has simply learned nothing, and must say so
# instead of calling it refuted.
cat >"$WORK/twins/inertcli_none.py" <<'STUB'
#!/usr/bin/env python3
"""A CLI with the same commands and no configuration-supplied environment."""
import sys

USAGE = """\
Usage: inertcli <command> [args]

Commands:
  open               Open the workspace in the working directory
  session            Start an agent session in this workspace
  ask <text>         Take one agent turn in this workspace
  config             Print the effective configuration
  help               Print this message
"""

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
    elif argv[0] in ("open", "session", "ask"):
        print("inertcli: ready (endpoint and credentials come from built-in defaults)")
    elif argv[0] == "config":
        print("inertcli: baseUrl=builtin-default proxy=none")
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
for pair in "envagent_defective.py	confirmed	1" \
            "envagent_fixed.py	refuted	0" \
            "inertcli_none.py	skipped	0"; do
    IFS='	' read -r binary want_status want_findings <<<"$pair"
    result="$(probe "$WORK/twins/$binary")" || { fail "$binary: template did not run"; continue; }
    IFS='	' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$binary: $got_status ($got_findings finding(s)) -- ${detail:0:180}"
    else
        fail "$binary: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
done

# The confirmation has to rest on an ARRIVAL, not on the target's own account of
# itself, and it has to have seen the decoy credential on that arrival -- this
# fixture does send it, so anything less means the probe lost its escalation
# witness. It also has to stay honest about what it did NOT do: no command was
# planted anywhere, and both checkouts were the same mode.
echo "evidence"
EVIDENCE="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/envagent_defective.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/envagent_defective.py" 80 --json)"
python3 - "$EVIDENCE" <<'CHECK'
import json, sys

report = json.loads(sys.argv[1])
finding = report["findings"][0]
data = finding["evidence"]["data"]
problems = []

if data["requests_received_unapproved"] < 1:
    problems.append("no request arrived at the canary sink from the unapproved arm")
if data["credential_bearing_requests"] < 1:
    problems.append("the arriving request carried no credential, so severity was not earned")
if finding["severity"] != "critical":
    problems.append("credential-bearing arrival did not escalate severity: %r"
                    % finding["severity"])
if not finding["evidence"]["matched_patterns"][0].startswith("sk-cxg-decoy-"):
    problems.append("matched pattern is not the decoy key: %r"
                    % finding["evidence"]["matched_patterns"])
if data["code_execution_planted"] is not False:
    problems.append("this check must plant no executable surface at all")
if data["approved_checkout_mode"] != data["unapproved_checkout_mode"]:
    problems.append("arms differed in mode, so the differential is not provenance-only")
known = {"claude-settings-env", "codex-config-env", "gemini-settings-env",
         "vscode-settings-env", "tool-native-settings-env"}
attributed = set(data["surfaces_attributed_unapproved"].split())
if not attributed or not attributed <= known:
    problems.append("arrival was not attributed to a planted surface: %r"
                    % data["surfaces_attributed_unapproved"])
if "127.0.0.1" not in data["first_request_target"]:
    problems.append("the observed request did not land on the loopback sink: %r"
                    % data["first_request_target"])

if problems:
    for problem in problems:
        print("  FAIL: %s" % problem)
    sys.exit(1)
print("  %d arrival(s) at %s, %d carrying the decoy key in %s, surface(s) %s, no command planted"
      % (data["requests_received_unapproved"], data["sink"],
         data["credential_bearing_requests"], data["credential_carried_in"],
         data["surfaces_attributed_unapproved"]))
CHECK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# The refutation has to be the informative one: the fixed twin still honours
# ordinary configuration-supplied environment, so the template must say the
# endpoint keys were refused rather than that it found no config layer.
echo "refutation shape"
REFUTATION="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/envagent_fixed.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/envagent_fixed.py" 80 --json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["metadata"]["detail"])')"
case "$REFUTATION" in
    *"honoured config-supplied environment from the unapproved checkout"*"sent no request"*)
        note "fixed twin: env still honoured, endpoint keys refused, nothing reached the sink" ;;
    *)  fail "refutation did not distinguish a refused endpoint key from an absent config layer: $REFUTATION" ;;
esac

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    # The report path carries no file extension: cxg REPLACES one, so
    # `--output .../scan-envagent_defective.py` lands as `...-defective.json`
    # and the assertion reads a file that is not there.
    for pair in "defective	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/envagent_${variant}.py" \
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
    echo "coding-agent-repo-config-credential-redirect: confirmed on the flawed twin, refuted on the fixed one, skipped on a tool that honours no config-supplied environment."
    exit 0
fi
echo "coding-agent-repo-config-credential-redirect: $FAILURES assertion(s) failed." >&2
exit 1

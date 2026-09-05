#!/usr/bin/env bash
# Prove templates/ai/agent-plugin/agent-plugin-loader-conformance.sh against the
# six-twin family in tests/fixtures/agent-plugin-loader-conformance/.
#
# The check reports on four independent normative MUSTs of Agent Plugins 1.0, so
# "fires on the flawed twin, quiet on the fixed one" is not enough proof: a
# template that confirmed on any package at all would pass that. Every twin
# below is asserted on the EXACT set of clauses it violates, which means each
# arm has to fire for its own reason and stay silent about the three the twin
# honours.
#
#   pluginhost_defective        CONFIRMED, all four clauses
#   pluginhost_conformant       REFUTED
#   pluginhost_schema_only      CONFIRMED, Sec 5.2 alone   (the $schema fetch)
#   pluginhost_namespace_only   CONFIRMED, Sec 8.1 alone   (com.other.client/hooks)
#   pluginhost_autostart_only   CONFIRMED, Sec 9.4 alone   (server starts, env clean)
#   pluginhost_env_leak         CONFIRMED, Sec 9.2 + 9.4   (same server, manifest PLUGIN_ROOT)
#   inertcli_none (stub here)   SKIPPED -- no plugin layer, so nothing was learned
#
# Sec 9.2 is only observable through a server that actually starts, so its twin
# has to give up Sec 9.4 too; the autostart_only / env_leak pair is what
# separates "a package-declared server was launched" from "the package chose
# the child's PLUGIN_ROOT".
#
# Usage: tests/prove-agent-plugin-loader-conformance.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/agent-plugin/agent-plugin-loader-conformance.sh"
FIXTURES="$HERE/fixtures/agent-plugin-loader-conformance"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-agent-plugin-test.XXXXXX")"
trap 'chmod -R u+rwX "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

# The SKIP arm: same command surface, no plugin layer whatsoever. Nothing about
# it is conformant or non-conformant -- the template has simply learned nothing
# and must say so instead of issuing a clean bill of health.
cat >"$WORK/twins/inertcli_none.py" <<'STUB'
#!/usr/bin/env python3
"""A CLI with the same command surface and no plugin layer at all."""
import sys

USAGE = """\
Usage: inertcli <command> [args]

Commands:
  plugins            Not supported by this build
  open               Open the working directory
  session            Start a session
  config             Print the effective configuration
  help               Print this message
"""

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
    elif argv[0] in ("open", "session", "plugins"):
        print("inertcli: ready (no plugin packages are loaded)")
    elif argv[0] == "config":
        print("inertcli: marker=builtin-default")
    else:
        sys.stderr.write(USAGE)
        sys.exit(2)
STUB
chmod +x "$WORK/twins/inertcli_none.py"

report() {
    CERT_X_GEN_TARGET_HOST="cli://$1" \
        bash "$TEMPLATE" "cli://$1" 80 --json 2>/dev/null
}

# Four lines -- status, finding count, sorted clause list, detail. Line-oriented
# rather than tab-separated because the clause list is empty on a refutation and
# `read` would collapse the empty field into the next one.
digest() {
    python3 -c '
import json, sys
document = json.load(sys.stdin)
meta = document["metadata"]
findings = document["findings"]
clauses = []
if findings:
    violations = findings[0]["evidence"]["data"]["violations"]
    clauses = sorted({entry.split(":")[0] for entry in violations.split()})
print(meta["status"])
print(len(findings))
print(",".join(clauses))
print(" ".join(meta["detail"].split()))'
}

echo "probe contract -- one row per twin, asserted on its exact clause set"
while IFS='|' read -r binary want_status want_findings want_clauses; do
    [ -n "$binary" ] || continue
    if ! report "$WORK/twins/$binary" | digest >"$WORK/digest.txt"; then
        fail "$binary: template did not produce a report"
        continue
    fi
    status="$(sed -n 1p "$WORK/digest.txt")"
    findings="$(sed -n 2p "$WORK/digest.txt")"
    clauses="$(sed -n 3p "$WORK/digest.txt")"
    detail="$(sed -n 4p "$WORK/digest.txt")"
    if [ "$status" = "$want_status" ] && [ "$findings" = "$want_findings" ] \
       && [ "$clauses" = "$want_clauses" ]; then
        note "$binary: $status ($findings finding(s)) clauses=[${clauses:-none}]"
    else
        fail "$binary: expected $want_status/$want_findings clauses=[${want_clauses:-none}], got $status/$findings clauses=[${clauses:-none}] -- $detail"
    fi
done <<'MATRIX'
pluginhost_defective.py|confirmed|1|sec-5.2,sec-8.1,sec-9.2,sec-9.4
pluginhost_conformant.py|refuted|0|
pluginhost_schema_only.py|confirmed|1|sec-5.2
pluginhost_namespace_only.py|confirmed|1|sec-8.1
pluginhost_autostart_only.py|confirmed|1|sec-9.4
pluginhost_env_leak.py|confirmed|1|sec-9.2,sec-9.4
inertcli_none.py|skipped|0|
MATRIX

# A confirmation has to carry the observation that produced it, not just a
# clause name: the nonce that was seen, the in-run namespace control, and the
# fact that the control load ran first and succeeded.
echo "evidence"
EVIDENCE="$(report "$WORK/twins/pluginhost_defective.py")"
python3 - "$EVIDENCE" <<'CHECK'
import json, sys

report = json.loads(sys.argv[1])
finding = report["findings"][0]
data = finding["evidence"]["data"]
problems = []

if data["processes_executed"] < 2:
    problems.append("expected both executable arms (Sec 8.1 component, Sec 9.4 server) "
                    "to be witnessed running, got %d" % data["processes_executed"])
if data["in_run_namespace_control"] != "own-namespace-component-executed":
    problems.append("the in-run namespace control did not fire, so the Sec 8.1 "
                    "confirmation cannot distinguish a namespace failure from a "
                    "client that runs every string it finds")
if not data["control_witness"]:
    problems.append("no control witness recorded; the template must establish that the "
                    "client implements the format before reporting a conformance failure")
if data["schema_arm_testable"] != 1:
    problems.append("the loopback canary did not start, so Sec 5.2 was never actually put "
                    "to the client in this run")
pattern = finding["evidence"]["matched_patterns"][0]
if "agent-plugins-1.0.schema.json" not in pattern:
    problems.append("matched pattern is not the schema path this run planted: %r" % pattern)
if data["package_mode"] != "0700":
    problems.append("the package was not installed into a private root (mode %s)"
                    % data["package_mode"])

if problems:
    for problem in problems:
        print("  FAIL: %s" % problem)
    sys.exit(1)
print("  4 clauses, %d processes executed, in-run namespace control fired, "
      "control witness=%s, schema canary live"
      % (data["processes_executed"], data["control_witness"]))
CHECK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# The Sec 9.2 arm must key on the MANIFEST's value, not on the variable's
# presence: the conformant twin still exports its own PLUGIN_ROOT, so a check
# that merely grepped for the name would confirm on a compliant client.
echo "Sec 9.2 precision"
AUTOSTART="$(report "$WORK/twins/pluginhost_autostart_only.py" | digest | sed -n 3p)"
if [ "$AUTOSTART" = "sec-9.4" ]; then
    note "autostart_only: server started and PLUGIN_ROOT stripped -- Sec 9.2 correctly silent"
else
    fail "autostart_only: expected sec-9.4 alone, got [${AUTOSTART:-none}]; the Sec 9.2 arm is matching the variable's presence rather than the manifest's value"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    # The report path carries no file extension: cxg REPLACES one, so
    # `--output .../scan-pluginhost_defective.py` lands as `...-defective.json`
    # and the assertion reads a file that is not there.
    for pair in "defective	1" "conformant	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/pluginhost_${variant}.py" \
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
    echo "agent-plugin-loader-conformance: each of the four normative arms fires on its own twin and only on its own twin, refuted on the conformant client, skipped on a client with no plugin layer."
    exit 0
fi
echo "agent-plugin-loader-conformance: $FAILURES assertion(s) failed." >&2
exit 1

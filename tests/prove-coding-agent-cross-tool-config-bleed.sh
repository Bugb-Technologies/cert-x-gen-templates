#!/usr/bin/env bash
# Prove templates/ai/coding-agent/coding-agent-cross-tool-config-bleed.sh in ALL
# THREE directions against the synthetic twins in
# tests/fixtures/coding-agent-cross-tool-config-bleed/.
#
#   CONFIRMED on bleedagent_defective.py  -- it launches MCP servers declared in
#                                            other agents' config files, and one
#                                            marketplace consent arms two agents
#   REFUTED   on bleedagent_fixed.py      -- the same program with cross-tool
#                                            discovery and marketplace fan-out
#                                            switched off
#   SKIPPED   on bleedagent_inert.py      -- no configuration layer at all, so
#                                            the template never established a
#                                            surface and must not call that a
#                                            clean bill of health
#
# A check nobody can make refute is not a check, and a check that cannot say "I
# did not learn anything here" reports noise as safety, so all three are
# asserted. The template is exercised twice: through its raw probe contract, and
# -- when `cxg` is on PATH -- through a real `cxg scan`, because the two agree
# about nothing unless you look.
#
# Usage: tests/prove-coding-agent-cross-tool-config-bleed.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/coding-agent-cross-tool-config-bleed.sh"
FIXTURES="$HERE/fixtures/coding-agent-cross-tool-config-bleed"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-xtool-bleed-test.XXXXXX")"
trap 'chmod -R u+rwX "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

bash "$FIXTURES/build.sh" "$WORK/twins" >/dev/null || {
    echo "could not build the twins"; exit 1; }

probe() {
    CERT_X_GEN_TARGET_HOST="cli://$1" \
        bash "$TEMPLATE" "cli://$1" 80 --json \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); m=d["metadata"]; print("%s\t%d\t%s" % (m["status"], len(d["findings"]), m["detail"]))'
}

echo "probe contract"
for pair in "bleedagent_defective.py	confirmed	2" \
            "bleedagent_fixed.py	refuted	0" \
            "bleedagent_inert.py	skipped	0"; do
    IFS='	' read -r binary want_status want_findings <<<"$pair"
    result="$(probe "$WORK/twins/$binary")" || { fail "$binary: template did not run"; continue; }
    IFS='	' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$binary: $got_status ($got_findings finding(s)) -- $detail"
    else
        fail "$binary: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
done

# The confirmation has to name WHICH foreign agents' files bled, has to have
# witnessed at least one server actually launch, and has to show the
# marketplace arm counting agents against consents. A confirmation that only
# echoed a marker is a weaker claim, and this fixture launches, so anything
# less means the probe lost its execution witness.
echo "evidence"
EVIDENCE="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/bleedagent_defective.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/bleedagent_defective.py" 80 --json)"
python3 - "$EVIDENCE" <<'CHECK'
import json, sys

report = json.loads(sys.argv[1])
by_arm = {f["evidence"]["data"].get("arm"): f for f in report["findings"]}
problems = []

bleed = by_arm.get("config-bleed")
if bleed is None:
    problems.append("no config-bleed finding")
else:
    data = bleed["evidence"]["data"]
    expected = {"cursor", "vscode", "gemini-cli", "windsurf", "codex"}
    honoured = {e.split(":")[0] for e in data["foreign_surfaces_honoured"].split()}
    missing = expected - honoured
    if missing:
        problems.append("foreign surfaces not honoured: %s" % ", ".join(sorted(missing)))
    if data["servers_launched_foreign"] < 1:
        problems.append("no foreign server launch witnessed")
    if not data["native_surfaces_honoured"]:
        problems.append("control arm recorded no native surface, so the differential has no baseline")
    if data["target_identity"] != "bleedagent":
        problems.append("target identity mis-derived: %r" % data["target_identity"])
    if not bleed["evidence"]["matched_patterns"][0].startswith("CXG-XTOOL-PROBE-"):
        problems.append("matched pattern is not a probe-arm nonce: %r"
                        % bleed["evidence"]["matched_patterns"])

market = by_arm.get("marketplace-blast-radius")
if market is None:
    problems.append("no marketplace-blast-radius finding")
else:
    data = market["evidence"]["data"]
    if data["agents_armed"] < 2:
        problems.append("marketplace arm armed %d agent(s), expected >= 2" % data["agents_armed"])
    if data["consent_prompts"] > 1:
        problems.append("marketplace arm counted %d consents, so the fan-out is not consent-free"
                        % data["consent_prompts"])
    if "siblingagent" not in data["agent_stores"]:
        problems.append("the second agent's store was not among those armed: %r"
                        % data["agent_stores"])

if problems:
    for problem in problems:
        print("  FAIL: %s" % problem)
    sys.exit(1)
print("  five foreign surfaces honoured (%d launched), %d agent stores armed against %d consent(s)"
      % (by_arm["config-bleed"]["evidence"]["data"]["servers_launched_foreign"],
         by_arm["marketplace-blast-radius"]["evidence"]["data"]["agents_armed"],
         by_arm["marketplace-blast-radius"]["evidence"]["data"]["consent_prompts"]))
CHECK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# The fixed twin must be refuted for the RIGHT reason: it has to still honour
# its own configuration. A twin that read nothing would refute too, and would
# prove nothing about the boundary.
echo "refutation is earned"
REFUTED="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/bleedagent_fixed.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/bleedagent_fixed.py" 80 --json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["metadata"]["detail"])')"
if printf '%s' "$REFUTED" | grep -q 'honoured its OWN MCP configuration' \
   && printf '%s' "$REFUTED" | grep -q 'native-'; then
    note "fixed twin still reads its own config, so the refutation is about the boundary"
else
    fail "the fixed twin's refutation does not record a working own-config surface: $REFUTED"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    # The report path carries no file extension: cxg REPLACES one, so
    # `--output .../scan-bleedagent_defective.py` lands as `...-defective.json`
    # and the assertion reads a file that is not there.
    for pair in "defective	2" "fixed	0" "inert	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/bleedagent_${variant}.py" \
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
    echo "coding-agent-cross-tool-config-bleed: confirmed on the flawed twin, refuted on the fixed one, skipped on a tool with no configuration layer."
    exit 0
fi
echo "coding-agent-cross-tool-config-bleed: $FAILURES assertion(s) failed." >&2
exit 1

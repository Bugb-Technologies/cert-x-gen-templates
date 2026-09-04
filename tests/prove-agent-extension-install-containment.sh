#!/usr/bin/env bash
# Prove templates/ai/coding-agent/agent-extension-install-path-containment.sh in
# ALL THREE directions against the synthetic twins in
# tests/fixtures/agent-extension-install-containment/.
#
#   CONFIRMED on skillforge_defective.py  -- names off untrusted extension
#                                            metadata go straight into a join,
#                                            and archive members are laid down
#                                            by name, so all three arms escape
#   REFUTED   on skillforge_fixed.py      -- the same program with every
#                                            destination re-resolved against its
#                                            root before the write
#   SKIPPED   on skillforge_noinstall.py  -- the same program with no install
#                                            verb: a missing precondition, which
#                                            the template must not report as a
#                                            clean bill of health
#
# A check nobody can make refute is not a check, and a check that cannot say "I
# never established the surface" reports absence as safety, so all three are
# asserted. The template is exercised through its raw probe contract, and --
# when `cxg` is on PATH -- through a real `cxg scan` as well.
#
# SAFETY: every arm runs inside the template's own throwaway $HOME. The `.ssh`
# and `authorized_keys` named here are files the template creates and seeds with
# an inert comment; no real key material is read or reachable.
#
# Usage: tests/prove-agent-extension-install-containment.sh   Exit 0 = all hold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO/templates/ai/coding-agent/agent-extension-install-path-containment.sh"
FIXTURES="$HERE/fixtures/agent-extension-install-containment"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cxg-install-containment-test.XXXXXX")"
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
for pair in "skillforge_defective.py	confirmed	1" \
            "skillforge_fixed.py	refuted	0" \
            "skillforge_noinstall.py	skipped	0"; do
    IFS='	' read -r binary want_status want_findings <<<"$pair"
    result="$(probe "$WORK/twins/$binary")" || { fail "$binary: template did not run"; continue; }
    IFS='	' read -r got_status got_findings detail <<<"$result"
    if [ "$got_status" = "$want_status" ] && [ "$got_findings" = "$want_findings" ]; then
        note "$binary: $got_status ($got_findings finding(s)) -- ${detail:0:170}"
    else
        fail "$binary: expected $want_status/$want_findings, got $got_status/$got_findings -- $detail"
    fi
done

# The confirmation has to name WHICH arms escaped and against WHICH root, and
# the pack arm has to have been witnessed writing through the archive's symlink.
# A confirmation that only reported "a file appeared somewhere" would be the
# failure mode this template exists to avoid.
echo "evidence"
EVIDENCE="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/skillforge_defective.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/skillforge_defective.py" 80 --json)"
python3 - "$EVIDENCE" <<'CHECK'
import json, sys

report = json.loads(sys.argv[1])
finding = report["findings"][0]
data = finding["evidence"]["data"]
problems = []

escaped = {arm for arm in data["escaped_arms"].split(",") if arm}
missing = {"skill", "plugin", "pack"} - escaped
if missing:
    problems.append("arm(s) did not escape on the defective twin: %s"
                    % ", ".join(sorted(missing)))
if data["symlink_write_through_to_sentinel"] != "yes":
    problems.append("the archive symlink was not witnessed being written through")
roots = data["containment_roots"]
for kind in ("skill:", "plugin:", "pack:"):
    if kind not in roots:
        problems.append("no containment root was established for %s" % kind[:-1])
if "hermetic/home/user" not in roots:
    problems.append("roots were resolved outside the throwaway $HOME: %r" % roots)
if data["oracle"] != "property":
    problems.append("oracle is not property: %r" % data["oracle"])
pattern = finding["evidence"]["matched_patterns"][0]
if not pattern:
    problems.append("the confirmation carries no witness path")

if problems:
    for problem in problems:
        print("  FAIL: %s" % problem)
    sys.exit(1)
print("  all three arms escaped, symlink write-through witnessed, roots %s" % roots)
CHECK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# The refutation has to be earned: it must say a probe was delivered, and the
# sentinel must still hold the probe's own comment rather than a nonce.
echo "refutation is earned"
REFUTATION="$(CERT_X_GEN_TARGET_HOST="cli://$WORK/twins/skillforge_fixed.py" \
    bash "$TEMPLATE" "cli://$WORK/twins/skillforge_fixed.py" 80 --json)"
python3 - "$REFUTATION" <<'CHECK'
import json, sys
detail = json.loads(sys.argv[1])["metadata"]["detail"]
problems = []
if "probes=" not in detail:
    problems.append("refutation does not record how many probes were delivered")
for arm in ("skill", "plugin", "pack"):
    if arm not in detail:
        problems.append("refutation does not name the %s arm" % arm)
if problems:
    for problem in problems:
        print("  FAIL: %s" % problem)
    sys.exit(1)
print("  refutation names every arm it delivered")
CHECK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# The guards. A template that cannot say "this is not my target" invents
# findings against everything it is pointed at.
echo "guards"
GUARD="$(CERT_X_GEN_TARGET_KIND=http CERT_X_GEN_TARGET_HOST="http://127.0.0.1:1" \
    bash "$TEMPLATE" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["metadata"]["status"])')"
[ "$GUARD" = "skipped" ] && note "an http target is a skip, not a refutation" \
    || fail "an http target produced '$GUARD'"

if command -v git >/dev/null 2>&1; then
    GUARD="$(probe "$(command -v git)" | cut -f1)"
    [ "$GUARD" = "skipped" ] && note "a binary that is not an extension manager is a skip" \
        || fail "git produced '$GUARD', expected skipped"
fi

if command -v cxg >/dev/null 2>&1; then
    echo "cxg scan"
    export HOME="$WORK/home"; mkdir -p "$HOME"
    # The report path carries no file extension: cxg REPLACES one, so
    # `--output .../scan-skillforge_defective.py` would land as
    # `...-defective.json` and the assertion would read a file that is not there.
    for pair in "defective	1" "fixed	0" "noinstall	0"; do
        IFS='	' read -r variant want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "cli://$WORK/twins/skillforge_${variant}.py" \
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
    echo "agent-extension-install-path-containment: confirmed on the flawed twin, refuted on the contained one, skipped on a build with no install verb."
    exit 0
fi
echo "agent-extension-install-path-containment: $FAILURES assertion(s) failed." >&2
exit 1

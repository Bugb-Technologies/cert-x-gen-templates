#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-manifest-runtime-divergence.py.
#
# The oracle is a DIFF of two sources read at one instant - "the surface the
# server declared" against "the surface the server is serving" - so the proof
# drives every direction that decides a verdict:
#
#   1. CONFIRM  flawed twin. It serves its publication artifact AND a live
#               surface that is wider than it, five ways at once. The finding
#               must name every dimension and carry both sides of each.
#   2. REFUTE   fixed twin. Declared == runtime on every dimension compared,
#               and the refutation must say which dimensions it compared - so
#               "clean" means "diffed and equal", not "nothing was read".
#   3. SKIP     nomanifest twin. Its runtime surface is byte-identical to the
#               flawed one, but it publishes no manifest. Nothing to diff
#               against => skip, not confirm. This is the twin that keeps the
#               SKIP honest.
#   4. CONFIRM  the same nomanifest twin, given the declaration OUT OF BAND via
#               CXG_MCP_DECLARED_SOURCE - the strong form, where the declaration
#               comes from a file the running server cannot edit.
#   5. ERROR    a CXG_MCP_DECLARED_SOURCE that does not exist. A diff against a
#               source you named and did not get is not a refutation.
#   6. SKIP     nothing listening at all.
#   7. cxg      the real engine, when it is on PATH: 1 finding on flawed,
#               0 on fixed, 0 on nomanifest.
#
#   ./prove.sh          # exit 0 = every direction holds
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-manifest-runtime-divergence.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8991}
PORT_FIXED=${PORT_FIXED:-8992}
PORT_NOMANIFEST=${PORT_NOMANIFEST:-8993}
PORT_DEAD=${PORT_DEAD:-8999}
FAILED=0
LAB="$(mktemp -d)"

cleanup() {
    for p in "${PID_A:-}" "${PID_B:-}" "${PID_C:-}"; do
        [ -n "$p" ] || continue
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done
    rm -rf "$LAB"
}
trap cleanup EXIT

run() {  # run <port> -> line1 status, line2 detail, line3 findings json
    python3 "$TEMPLATE" 127.0.0.1 "$1" http 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d["metadata"]["status"]); print(d["metadata"]["detail"])
print(json.dumps(d["findings"]))'
}

assert() {  # assert <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf 'ok    %s -> %s\n' "$1" "$3"
    else printf 'FAIL  %s -> expected %s, got %s\n' "$1" "$2" "$3"; FAILED=1; fi
}

contains() {  # contains <label> <needle> <haystack>
    case "$3" in
        *"$2"*) printf 'ok    %s\n' "$1" ;;
        *) printf 'FAIL  %s (missing: %s)\n' "$1" "$2"; FAILED=1 ;;
    esac
}

python3 "$SERVER" --mode flawed     --port "$PORT_FLAWED"     2>/dev/null & PID_A=$!
python3 "$SERVER" --mode fixed      --port "$PORT_FIXED"      2>/dev/null & PID_B=$!
python3 "$SERVER" --mode nomanifest --port "$PORT_NOMANIFEST" 2>/dev/null & PID_C=$!
sleep 1.5

echo "--- 1. flawed twin: the running server is wider than its publication artifact ---"
OUT="$(run "$PORT_FLAWED")"
STATUS="$(printf '%s' "$OUT" | sed -n 1p)"; DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"; FINDINGS="$(printf '%s' "$OUT" | sed -n 3p)"
assert "flawed" confirmed "$STATUS"
printf '      %s\n' "$DETAIL"
contains "detail names the undeclared tool"      "sync_workspace"   "$DETAIL"
contains "detail names the widened tool"         "read_note"        "$DETAIL"
contains "detail names the undeclared resource"  "workspace://env"  "$DETAIL"
contains "detail names the version mismatch"     "1.4.0-hotfix.3"   "$DETAIL"
printf '%s' "$FINDINGS" | python3 -c '
import json,sys
f=json.load(sys.stdin)
assert len(f)==1, "expected exactly one finding, got %d" % len(f)
d=f[0]["evidence"]["data"]
kinds={x["kind"] for x in d["divergences"]}
for want in ("undeclared-tool","schema-widened","scope-widened","undeclared-resource",
             "version-mismatch","package-hash-mismatch"):
    assert want in kinds, ("missing divergence kind", want, sorted(kinds))
# every hard divergence carries BOTH sides - a diff, not an assertion.
byk={}
for x in d["divergences"]: byk.setdefault(x["kind"],[]).append(x)
t=byk["undeclared-tool"][0]
assert t["tool"]=="sync_workspace" and "sync_workspace" not in t["declared_tools"], t
s=byk["schema-widened"][0]
assert s["undeclared_properties"]==["command"], s
assert "command" in s["runtime_properties"] and "command" not in s["declared_properties"], s
sc=[x for x in byk["scope-widened"] if x["annotation"]=="readOnlyHint"][0]
assert sc["declared"] is True and sc["runtime"] is False, sc
v=byk["version-mismatch"][0]
assert v["declared"]!=v["runtime"], v
h=byk["package-hash-mismatch"][0]
assert h["declared"]!=h["runtime"] and len(h["declared"])>=32, h
# request/response evidence for BOTH sides of the diff.
assert "server.json" in d["declared_fetch"]["request"], d["declared_fetch"]
assert d["declared_fetch"]["response_excerpt"], "declared response not carried"
assert "tools/list" in d["runtime_fetch"]["request"], d["runtime_fetch"]
assert "sync_workspace" in d["runtime_fetch"]["tools_response_excerpt"], d["runtime_fetch"]
assert set(d["dimensions_compared"])=={"tools","resources","version","package-hash"}, d["dimensions_compared"]
print("ok    finding: all five widenings, each carrying its declared AND runtime value,")
print("      plus the request/response for the declared fetch and the live tools/list")
' || { echo "FAIL  flawed finding evidence did not prove the divergence"; FAILED=1; }

echo "--- 2. fixed twin: declared == runtime on every dimension ---"
OUT="$(run "$PORT_FIXED")"
assert "fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "refutation names the dimensions it diffed" "tools+resources+version+package-hash" "$DETAIL"
contains "refutation is a diff result, not silence"  "no-divergence" "$DETAIL"
assert "fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 3. nomanifest twin: same wide runtime, nothing declared to diff -> skip ---"
OUT="$(run "$PORT_NOMANIFEST")"
assert "nomanifest" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the missing precondition" "no-declared-source-available" "$DETAIL"
assert "nomanifest emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 4. same twin, declaration supplied OUT OF BAND -> confirm ---"
python3 "$SERVER" --dump-manifest > "$LAB/declared.json"
OUT="$(CXG_MCP_DECLARED_SOURCE="$LAB/declared.json" run "$PORT_NOMANIFEST")"
assert "out-of-band declared source" confirmed "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "declared source is the pinned file" "declared.json" "$DETAIL"
contains "same undeclared tool is found"      "sync_workspace" "$DETAIL"

echo "--- 5. a named declared source that is not there -> error, never a refutation ---"
OUT="$(CXG_MCP_DECLARED_SOURCE="$LAB/absent.json" run "$PORT_FIXED")"
assert "missing configured source" errored "$(printf '%s' "$OUT" | sed -n 1p)"
contains "error names the source it could not read" "configured-declared-source-missing" \
         "$(printf '%s' "$OUT" | sed -n 2p)"

echo "--- 6. nothing listening: skip, precondition named ---"
OUT="$(run "$PORT_DEAD")"
assert "no server" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
contains "skip names the missing precondition" "no-mcp-server-answered" "$(printf '%s' "$OUT" | sed -n 2p)"

echo "--- 7. the real engine ---"
if command -v cxg >/dev/null 2>&1; then
    export HOME="$LAB/home"; mkdir -p "$HOME"
    for pair in "flawed	$PORT_FLAWED	1" "fixed	$PORT_FIXED	0" "nomanifest	$PORT_NOMANIFEST	0"; do
        IFS='	' read -r variant port want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "http://127.0.0.1:$port" --override-ports "$port" \
            --templates "$TEMPLATE" \
            --output "$LAB/scan-$variant" --output-format json >/dev/null 2>&1
        got="$(python3 -c '
import json, sys
print(len(json.load(open(sys.argv[1]))["findings"]))' "$LAB/scan-$variant.json" 2>/dev/null)"
        assert "cxg scan: $variant" "$want" "${got:-<no report>}"
    done
else
    echo "      cxg scan: SKIPPED (cxg not on PATH)"
fi

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-tool-result-provenance.py.
#
# The oracle is a PROPERTY of one observed tool result - "did the server mark
# the boundary around content it did not author" - so the proof drives every
# direction that can decide a verdict. A verdict this template can emit and
# this script does not produce is a verdict that was never proved.
#
#   1. CONFIRM  flawed twin. The fetched body is re-emitted verbatim in a plain
#               text block with no mark of any kind. The finding must carry the
#               tool, the arguments, the origin's own hit log, the returned
#               block and the window examined.
#   2. REFUTE   fixed twin. Wrapped, labelled untrusted, AND carrying a
#               provenance record in `_meta` - all three named in the detail.
#   3. REFUTE   attributed twin. The near-miss: the origin URL is named and the
#               content is never framed as untrusted. Still a boundary, so still
#               a refutation, and `attributed-by-origin-only` must appear as a
#               SOFT observation the refutation names and never fires on.
#   4. REFUTE   escaped twin. The body comes back base64'd - the planted
#               directive is not present as live prose at all.
#   5. REFUTE   summarised twin. The origin log proves the body was fetched and
#               the server returned a count instead of the prose. "Clean" here
#               means content crossed and the boundary held.
#   6. SKIP     nofetch twin. `fetch_url` answers cleanly and never retrieves
#               anything: the origin is never hit, so the template has not been
#               shown a boundary either way.
#   7. SKIP     notools twin. Same server, same disposition, no read-type tool
#               with a URL argument. Nothing crosses => nothing to judge. This
#               is the twin that keeps the SKIP honest.
#   8. SKIP     the flawed twin again, with the controlled origin advertised at
#               an unroutable address. The fetch errors, so every candidate
#               errored - a skip, never a refutation.
#   9. ERROR    CXG_MCP_PROVENANCE_TOOL naming a tool the server does not have.
#               A probe you asked for and did not get is not a refutation.
#  10. SKIP     nothing listening at all.
#  11. SKIP     a cli:// target - this template drives a live HTTP surface.
#  12. cxg      the real engine, when it is on PATH: 1 finding on flawed, 0 on
#               fixed, attributed, escaped, summarised, nofetch and notools.
#
#   ./prove.sh          # exit 0 = every direction holds
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-tool-result-provenance.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8961}
PORT_FIXED=${PORT_FIXED:-8962}
PORT_ATTRIBUTED=${PORT_ATTRIBUTED:-8963}
PORT_ESCAPED=${PORT_ESCAPED:-8964}
PORT_SUMMARISED=${PORT_SUMMARISED:-8965}
PORT_NOFETCH=${PORT_NOFETCH:-8966}
PORT_NOTOOLS=${PORT_NOTOOLS:-8967}
PORT_DEAD=${PORT_DEAD:-8969}
FAILED=0
LAB="$(mktemp -d)"
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do
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

lacks() {  # lacks <label> <needle> <haystack>
    case "$3" in
        *"$2"*) printf 'FAIL  %s (unexpectedly present: %s)\n' "$1" "$2"; FAILED=1 ;;
        *) printf 'ok    %s\n' "$1" ;;
    esac
}

for pair in "flawed $PORT_FLAWED" "fixed $PORT_FIXED" "attributed $PORT_ATTRIBUTED" \
            "escaped $PORT_ESCAPED" "summarised $PORT_SUMMARISED" \
            "nofetch $PORT_NOFETCH" "notools $PORT_NOTOOLS"; do
    set -- $pair
    python3 "$SERVER" --mode "$1" --port "$2" 2>/dev/null &
    PIDS+=("$!")
done
sleep 2

echo "--- 1. flawed twin: a stranger's prose, re-emitted wearing the server's voice ---"
OUT="$(run "$PORT_FLAWED")"
STATUS="$(printf '%s' "$OUT" | sed -n 1p)"; DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"; FINDINGS="$(printf '%s' "$OUT" | sed -n 3p)"
assert "flawed" confirmed "$STATUS"
printf '      %s\n' "$DETAIL"
contains "detail names the tool that was driven"   "tool=fetch_url"        "$DETAIL"
contains "detail says the boundary is absent"      "provenance-boundary-absent" "$DETAIL"
contains "detail proves the origin was fetched"    "origin fetched 1 time"  "$DETAIL"
printf '%s' "$FINDINGS" | python3 -c '
import json,sys
f=json.load(sys.stdin)
assert len(f)==1, "expected exactly one finding, got %d" % len(f)
d=f[0]["evidence"]["data"]

# the probe: our tool, our argument, our URL.
assert d["tool_called"]=="fetch_url", d["tool_called"]
assert d["url_argument"]=="url", d["url_argument"]
url=d["arguments"]["url"]
assert url==d["controlled_origin"]["url"], (url, d["controlled_origin"]["url"])

# the origin log is what makes this an observation and not a suspicion.
hits=d["controlled_origin"]["hits"]
assert hits, "the origin was never fetched, so nothing was observed"
assert hits[0]["path"] in url, (hits[0], url)

# the marker came back VERBATIM, and unmarked.
marker=d["body_marker"]
assert marker.startswith("CXG-TRACER-BODY-"), marker
assert d["occurrences"], "no occurrence recorded"
assert d["unmarked_occurrences"], "no UNMARKED occurrence recorded"
for occ in d["unmarked_occurrences"]:
    assert occ["marks"]==[], occ
    assert occ["block_type"]=="text", occ
    # the window examined is carried, so the verdict is auditable.
    assert "window_before" in occ and "window_after" in occ, occ
    assert url not in occ["window_before"], "origin was named after all"

# the raw result is carried, and it really does contain the planted directive.
raw=json.dumps(d["tool_result"])
assert marker in raw, "marker not in the carried result"
assert d["decoy_token"] in raw, "the decoy directive is not in the carried result"
assert "rule" in d and "MARKED" in d["rule"], d.get("rule")

# request evidence names the exact JSON-RPC call.
req=f[0]["evidence"]["request"]
assert "tools/call" in req and "fetch_url" in req and url in req, req
print("ok    finding: the tool, the arguments, the origin hit log, the verbatim")
print("      occurrence with an empty mark list, the window examined and the rule")
' || { echo "FAIL  flawed finding evidence did not prove the missing boundary"; FAILED=1; }

echo "--- 2. fixed twin: wrapped, labelled untrusted, and recorded in _meta ---"
OUT="$(run "$PORT_FIXED")"
assert "fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "refutation is a judgement, not silence" "boundary-marked" "$DETAIL"
contains "names the untrusted-content label"      "labelled/untrusted-content-phrase-before" "$DETAIL"
contains "names the delimiter pair"               "delimited/delimiter-pair" "$DETAIL"
contains "names the structural _meta mark"        "structural/block._meta"   "$DETAIL"
assert "fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 3. attributed twin: provenance named, trust never framed -> soft, not a finding ---"
OUT="$(run "$PORT_ATTRIBUTED")"
assert "attributed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "the mark that saved it is named"        "attributed/origin-named-before" "$DETAIL"
contains "the near-miss is recorded as soft"      "soft: attributed-by-origin-only" "$DETAIL"
lacks    "the near-miss never becomes a verdict"  "provenance-boundary-absent" "$DETAIL"
assert "attributed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 4. escaped twin: the directive is not present as live prose ---"
OUT="$(run "$PORT_ESCAPED")"
assert "escaped" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "names the encoding it found" "re-emitted-escaped: base64" "$DETAIL"
assert "escaped emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 5. summarised twin: fetched, and the body never came back ---"
OUT="$(run "$PORT_SUMMARISED")"
assert "summarised" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "refutation says the content crossed and held" "boundary-held" "$DETAIL"
contains "and proves the fetch happened"                "origin_hits=1"  "$DETAIL"
assert "summarised emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 6. nofetch twin: answers cleanly, never retrieves -> skip, not refute ---"
OUT="$(run "$PORT_NOFETCH")"
assert "nofetch" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the missing precondition" "controlled-origin-never-fetched" "$DETAIL"
contains "skip says the origin was never hit"  "origin_hits=0" "$DETAIL"
assert "nofetch emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 7. notools twin: same disposition, no read-type tool -> skip ---"
OUT="$(run "$PORT_NOTOOLS")"
assert "notools" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the missing precondition" "no-read-type-tool-with-a-url-argument" "$DETAIL"
assert "notools emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 8. flawed twin, origin advertised somewhere it cannot route to -> skip ---"
OUT="$(CXG_MCP_PROVENANCE_ADVERTISE_HOST=192.0.2.1 run "$PORT_FLAWED")"
assert "unreachable origin" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the candidate that errored" "every-read-type-tool-candidate-errored" "$DETAIL"
contains "and records it as a soft observation"  "candidate-tool-errored" "$DETAIL"

echo "--- 9. a tool named that the server does not have -> error, never a refutation ---"
OUT="$(CXG_MCP_PROVENANCE_TOOL=not_a_tool run "$PORT_FIXED")"
assert "unknown configured tool" errored "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
contains "error names the tool it was asked for" "CXG_MCP_PROVENANCE_TOOL=not_a_tool" "$DETAIL"
contains "error lists what the server does have" "fetch_url" "$DETAIL"

echo "--- 10. nothing listening: skip, precondition named ---"
OUT="$(run "$PORT_DEAD")"
assert "no server" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
contains "skip names the missing precondition" "no-mcp-server-answered" "$(printf '%s' "$OUT" | sed -n 2p)"

echo "--- 11. a cli:// target: not this template's surface ---"
OUT="$(CERT_X_GEN_MODE=engine CERT_X_GEN_TARGET_HOST="cli:///bin/echo" \
      python3 "$TEMPLATE" 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin); print(d["metadata"]["status"]); print(d["metadata"]["detail"])')"
assert "cli target" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
contains "skip says which surface it needs" "http://" "$(printf '%s' "$OUT" | sed -n 2p)"

echo "--- 12. the real engine ---"
if command -v cxg >/dev/null 2>&1; then
    export HOME="$LAB/home"; mkdir -p "$HOME"
    for pair in "flawed	$PORT_FLAWED	1" "fixed	$PORT_FIXED	0" \
                "attributed	$PORT_ATTRIBUTED	0" "escaped	$PORT_ESCAPED	0" \
                "summarised	$PORT_SUMMARISED	0" "nofetch	$PORT_NOFETCH	0" \
                "notools	$PORT_NOTOOLS	0"; do
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

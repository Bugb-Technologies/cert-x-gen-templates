#!/usr/bin/env bash
# Proof for templates/ai/mcp/mcp-server-initiated-request-conformance.py.
#
# The oracle is a PROPERTY of an observed idle window - "did the server issue a
# sampling or elicitation REQUEST when nothing was outstanding?" - so the proof
# has to drive every direction that decides a verdict, on BOTH transports the
# template accepts:
#
#   1. CONFIRM  http / flawed twin. It speaks out of turn. The finding must name
#               both gated methods, quote the elicitation prompt the user would
#               have been shown, carry the sampling budget it tried to spend,
#               and list the permitted traffic it did NOT fire on.
#   2. REFUTE   http / fixed twin. Same tools, same capabilities, same
#               server->client channel, same permitted traffic at the same
#               moment - and neither gated method. The refutation must name the
#               window it held and what it DID hear, so "clean" means "listened",
#               not "heard nothing".
#   3. SKIP     http / nostream twin. It wants to speak out of turn, but GET /mcp
#               405s, so the transport gives it no channel to speak on. Silence
#               there is a fact about the transport => skip, never refute. This
#               is the twin that keeps the SKIP honest.
#   4. SKIP     nothing listening at all.
#   5. CONFIRM  stdio / flawed twin - the same violation over the other transport.
#   6. REFUTE   stdio / fixed twin.
#   7. FIXTURE INTEGRITY. The fixed twin is not a server that cannot sample: a
#               raw client calls `summarise_notes` and the twin issues
#               `sampling/createMessage` WHILE handling it - the permitted case.
#               So case 2/6 proves "chose not to speak out of turn", not
#               "does not implement sampling".
#   8. cxg      the real engine, when it is on PATH: http 1/0/0 on
#               flawed/fixed/nostream, cli 1/0 on flawed/fixed.
#
#   ./prove.sh          # exit 0 = every direction holds
#
# SAFETY: the twins are benign synthetic servers. The elicitation prompt and the
# sampling messages are inert strings that name themselves fixture decoys; the
# template never fulfils either, so no model is contacted and no human is
# prompted. Nothing is written and nothing leaves the machine.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$REPO/templates/ai/mcp/mcp-server-initiated-request-conformance.py"
SERVER="$HERE/mcp_fixture_server.py"
PORT_FLAWED=${PORT_FLAWED:-8981}
PORT_FIXED=${PORT_FIXED:-8982}
PORT_NOSTREAM=${PORT_NOSTREAM:-8983}
PORT_DEAD=${PORT_DEAD:-8989}
# Short enough to keep the run under a minute, long enough that the twins - which
# speak 1.5s in - have said everything they are going to say. See the playbook:
# lengthening the window can only admit MORE unsolicited traffic, never
# legitimate traffic, so a short window can miss a violation but never invent one.
WINDOW=${CXG_MCP_IDLE_WINDOW_SECONDS:-5}
export CXG_MCP_IDLE_WINDOW_SECONDS="$WINDOW"
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

split() {  # split <json on stdin> -> line1 status, line2 detail, line3 findings json
    python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d["metadata"]["status"]); print(d["metadata"]["detail"])
print(json.dumps(d["findings"]))'
}

run_http() {  # run_http <port>
    python3 "$TEMPLATE" 127.0.0.1 "$1" http 2>/dev/null | split
}

run_stdio() {  # run_stdio <mode>
    CXG_MCP_STDIO_ARGS="--transport stdio --mode $1" \
        python3 "$TEMPLATE" "cli://$SERVER" 2>/dev/null | split
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

absent() {  # absent <label> <needle> <haystack>
    case "$3" in
        *"$2"*) printf 'FAIL  %s (unexpectedly present: %s)\n' "$1" "$2"; FAILED=1 ;;
        *) printf 'ok    %s\n' "$1" ;;
    esac
}

python3 "$SERVER" --mode flawed   --transport http --port "$PORT_FLAWED"   2>/dev/null & PID_A=$!
python3 "$SERVER" --mode fixed    --transport http --port "$PORT_FIXED"    2>/dev/null & PID_B=$!
python3 "$SERVER" --mode nostream --transport http --port "$PORT_NOSTREAM" 2>/dev/null & PID_C=$!
sleep 1.5

echo "--- 1. http / flawed twin: it speaks when it has not been spoken to ---"
OUT="$(run_http "$PORT_FLAWED")"
STATUS="$(printf '%s' "$OUT" | sed -n 1p)"; DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"; FINDINGS="$(printf '%s' "$OUT" | sed -n 3p)"
assert "http flawed" confirmed "$STATUS"
printf '      %s\n' "$DETAIL"
contains "detail names elicitation/create"      "elicitation/create"      "$DETAIL"
contains "detail names sampling/createMessage"  "sampling/createMessage"  "$DETAIL"
contains "detail states the idle window it held" "idle_window=$WINDOW" "$DETAIL"
contains "detail lists the permitted traffic it ignored" "roots/list@" "$DETAIL"
printf '%s' "$FINDINGS" | python3 -c '
import json,sys
f=json.load(sys.stdin)
assert len(f)==1, "expected exactly one finding, got %d" % len(f)
d=f[0]["evidence"]["data"]
assert d["transport"]=="http", d["transport"]
methods=set(d["unsolicited_methods"])
assert methods=={"elicitation/create","sampling/createMessage"}, sorted(methods)
bym={r["method"]: r for r in d["unsolicited_requests"]}
# every gated request is a REQUEST - it carries an id a client would have to answer.
for m,r in bym.items():
    assert r["id"] is not None, (m, "gated message had no id - that would be a notification")
    assert r["kind"]=="gated", r
    assert r["elapsed_s"] >= 0, r
# the elicitation is quoted: this is the text the user would have been shown.
e=bym["elicitation/create"]
assert "re-authorised" in e["prompt_shown_to_user"], e
assert e["fields_requested"]==["access_code"], e
# the sampling carries the budget it tried to spend and what it tried to spend it on.
s=bym["sampling/createMessage"]
assert s["max_tokens"]==4096, s
assert any("unprompted" in t for t in s["messages_excerpt"]), s
# the client capabilities were declared, so silence would have been a CHOICE.
assert set(d["client_capabilities_declared"])=={"sampling","elicitation","roots"}, d
# permitted server-initiated traffic arrived in the SAME window and did not fire.
soft={r["method"] for r in d["permitted_traffic_ignored"]}
for want in ("ping","roots/list","notifications/message","notifications/tools/list_changed"):
    assert want in soft, ("permitted traffic missing from the record", want, sorted(soft))
assert not (soft & {"elicitation/create","sampling/createMessage"}), soft
# and the probe fulfilled nothing.
assert "declined" in d["client_response"], d["client_response"]
assert d["channel_proved_live"] is True, d
print("ok    finding: both gated methods, each with its id, the quoted prompt, the sampling")
print("      budget, the declared client capabilities, and the permitted traffic it ignored")
' || { echo "FAIL  flawed finding evidence did not prove the violation"; FAILED=1; }

echo "--- 2. http / fixed twin: same channel, same permitted noise, neither gated method ---"
OUT="$(run_http "$PORT_FIXED")"
assert "http fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "refutation states the window it held"       "idle $WINDOW" "$DETAIL"
contains "refutation proves the channel was live"     "tools/list answered with 2 tool(s)" "$DETAIL"
contains "refutation names what it DID hear"          "notifications/message@" "$DETAIL"
contains "refutation names the permitted ping"        "ping@" "$DETAIL"
absent   "refutation names no gated method"           "sampling/createMessage" "$DETAIL"
assert "http fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 3. http / nostream twin: it wants to speak, the transport gives it no channel -> skip ---"
OUT="$(run_http "$PORT_NOSTREAM")"
assert "http nostream" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "skip names the missing precondition" "transport-offers-no-server-initiated-channel" "$DETAIL"
contains "skip says why silence proves nothing" "no channel on which to speak out of turn" "$DETAIL"
assert "nostream emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 4. nothing listening: skip, precondition named ---"
OUT="$(run_http "$PORT_DEAD")"
assert "no server" skipped "$(printf '%s' "$OUT" | sed -n 1p)"
contains "skip names the missing precondition" "no-mcp-server-answered-initialize" \
         "$(printf '%s' "$OUT" | sed -n 2p)"

echo "--- 5. stdio / flawed twin: the same violation over the other transport ---"
OUT="$(run_stdio flawed)"
assert "stdio flawed" confirmed "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "detail says which transport" "transport=stdio" "$DETAIL"
printf '%s' "$OUT" | sed -n 3p | python3 -c '
import json,sys
f=json.load(sys.stdin)
assert len(f)==1, "expected exactly one finding, got %d" % len(f)
d=f[0]["evidence"]["data"]
assert d["transport"]=="stdio", d["transport"]
assert set(d["unsolicited_methods"])=={"elicitation/create","sampling/createMessage"}, d
assert d["endpoint"].startswith("stdio://"), d["endpoint"]
soft={r["method"] for r in d["permitted_traffic_ignored"]}
assert "ping" in soft and "roots/list" in soft, sorted(soft)
print("ok    stdio finding carries the same two gated methods and the same ignored traffic")
' || { echo "FAIL  stdio flawed finding evidence was not equivalent to the http one"; FAILED=1; }

echo "--- 6. stdio / fixed twin ---"
OUT="$(run_stdio fixed)"
assert "stdio fixed" refuted "$(printf '%s' "$OUT" | sed -n 1p)"
DETAIL="$(printf '%s' "$OUT" | sed -n 2p)"
printf '      %s\n' "$DETAIL"
contains "refutation proves the stdio channel was live" "tools/list answered" "$DETAIL"
contains "refutation names what it DID hear"            "roots/list@" "$DETAIL"
assert "stdio fixed emits no finding" "[]" "$(printf '%s' "$OUT" | sed -n 3p)"

echo "--- 7. fixture integrity: the fixed twin CAN sample - it just waits to be asked ---"
python3 - "$SERVER" <<'PY' || { echo "FAIL  fixed twin never sampled even when solicited"; FAILED=1; }
import json, subprocess, sys, threading, time

server = sys.argv[1]
proc = subprocess.Popen([sys.executable, server, "--transport", "stdio", "--mode", "fixed",
                         "--speak-after", "60"],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, universal_newlines=True, bufsize=1)
seen = []
def reader():
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            seen.append(json.loads(line))
        except ValueError:
            pass
threading.Thread(target=reader, daemon=True).start()

def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2025-06-18",
                 "capabilities": {"sampling": {}, "elicitation": {}},
                 "clientInfo": {"name": "prove", "version": "1.0"}}})
time.sleep(0.5)
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
# Solicit: call the tool. The permitted sampling happens while handling THIS.
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "summarise_notes", "arguments": {}}})
time.sleep(2.0)
proc.terminate()

sampling = [m for m in seen
            if m.get("method") == "sampling/createMessage" and m.get("id") is not None]
assert sampling, ("the fixed twin issued no sampling request even when a tool was called - "
                  "its refutation would mean 'cannot sample', not 'chose not to speak out of turn'")
assert not any(m.get("method") == "elicitation/create" for m in seen), seen
print("ok    the fixed twin DOES issue sampling/createMessage while handling tools/call,")
print("      so REFUTED means 'did not speak out of turn', not 'does not implement sampling'")
PY

echo "--- 8. the real engine ---"
if command -v cxg >/dev/null 2>&1; then
    export HOME="$LAB/home"; mkdir -p "$HOME"
    for pair in "flawed	$PORT_FLAWED	1" "fixed	$PORT_FIXED	0" "nostream	$PORT_NOSTREAM	0"; do
        IFS='	' read -r variant port want <<<"$pair"
        cxg --disable-update-check scan -q \
            --scope "http://127.0.0.1:$port" --override-ports "$port" \
            --templates "$TEMPLATE" \
            --output "$LAB/scan-http-$variant" --output-format json >/dev/null 2>&1
        got="$(python3 -c '
import json, sys
print(len(json.load(open(sys.argv[1]))["findings"]))' "$LAB/scan-http-$variant.json" 2>/dev/null)"
        assert "cxg scan http: $variant" "$want" "${got:-<no report>}"
    done
    for pair in "flawed	1" "fixed	0"; do
        IFS='	' read -r variant want <<<"$pair"
        CXG_MCP_STDIO_ARGS="--transport stdio --mode $variant" \
        cxg --disable-update-check scan -q \
            --scope "cli://$SERVER" \
            --templates "$TEMPLATE" \
            --output "$LAB/scan-cli-$variant" --output-format json >/dev/null 2>&1
        got="$(python3 -c '
import json, sys
print(len(json.load(open(sys.argv[1]))["findings"]))' "$LAB/scan-cli-$variant.json" 2>/dev/null)"
        assert "cxg scan cli: $variant" "$want" "${got:-<no report>}"
    done
else
    echo "      cxg scan: SKIPPED (cxg not on PATH)"
fi

[ "$FAILED" -eq 0 ] && echo "ALL PROOFS HOLD" || echo "PROOF FAILED"
exit "$FAILED"

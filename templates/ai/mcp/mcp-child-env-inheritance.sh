#!/usr/bin/env bash
# @id: mcp-child-env-inheritance
# @name: MCP host hands a locally-spawned stdio server the operator's entire environment
# @author: CERT-X-GEN Security Team
# @description: Exports uniquely-valued canary credentials (AWS, GitHub, npm, registry, cloud-CLI) into the host's own environment, then asks the target MCP host to launch a synthetic stdio MCP server whose manifest declares a need for exactly one variable. The spawned child reports the environment it actually received. CONFIRMED when a canary nonce the manifest never declared is visible to the child - the child's credential blast radius is the whole workstation, not its declared need; REFUTED when the child receives its declared variable and none of the undeclared canaries; SKIP when no stdio-launch surface could be exercised. The oracle is zero-false-positive by construction: every canary value is a nonce minted this run, so a value in the child cannot have arrived any way but inheritance.
# @severity: high
# @tags: ai, mcp, cli, stdio, environment, credential-inheritance, blast-radius, least-privilege, cwe-250, cwe-522, cwe-668
# @cwe: CWE-250
# @confidence: 95
# @target_kinds: cli
# @oracles: property
# @references: docs/playbooks/mcp-child-env-inheritance.md
#
# THE CLASS
#
# An MCP host launches a local stdio server from a manifest entry:
#
#     {"mcpServers": {"weather": {"command": "npx", "args": ["-y", "weather-mcp"],
#                                 "env": {"WEATHER_API_KEY": "..."}}}}
#
# The `env` block is the server's DECLARATION OF NEED. Nothing in the protocol
# says the child receives only that, and the conventional implementation is
#
#     subprocess.Popen(argv, env={**os.environ, **declared})
#
# which hands the child every credential the developer's shell happens to hold:
# AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, NPM_TOKEN, registry and cloud-CLI tokens,
# session cookies. A server that declared one API key is handed the workstation.
#
# This is the multiplier behind the recent agent-extension incidents (named for
# motivation only; nothing here reproduces one): the code-execution bug was the
# first half, and the inherited environment was the second - the step that turns
# "an attacker ran code in your repo" into "an attacker holds your cloud". The
# execution half is widely tested. The blast radius is not measured at all.
#
#   input      a manifest declaring ONE synthetic stdio server with ONE declared
#              variable, launched through the target's own stdio-launch surface.
#   observable the environment the spawned child actually received, reported by
#              the child itself.
#   oracle     property - set containment: is any undeclared canary nonce
#              present in the child's environment?
#
# WHY THIS IS ZERO-FALSE-POSITIVE
#
# Each canary value is a nonce minted by this run from /dev/urandom and exported
# into this process' environment only. No config file, no cache, no vendor
# default and no prior run can contain it. A nonce that is visible to the child
# was inherited across the spawn boundary this second - that is the whole
# finding, and there is no benign path to the observation.
#
# THE DIFFERENTIAL
#
#   declared   the manifest declares a need for CXG_MCP_DECLARED_TOKEN, whose
#              nonce is NEVER exported into this process. It can reach the child
#              only by the host honouring the declaration. Seeing it proves the
#              stdio-launch surface works and the child really started - without
#              it the verdict is SKIP, not a refutation, because nothing was
#              measured.
#   undeclared the credential canaries, exported into this process and declared
#              nowhere. Seeing any of them in the child is the finding.
#
# Requiring the declared half first means this template never reports a target
# it has not first shown to spawn a child at all, and its refutation is a
# positive result: this host scopes the child environment to declared need.
#
# SAFETY
#
# Everything happens inside a `mktemp -d` lab removed on exit. The "credentials"
# are obviously-synthetic nonces of the form CXG-CANARY-<VAR>-<hex>; no real
# secret is created, read or transmitted, and the canaries are exported into
# this template's own process environment only - the operator's shell is
# untouched. The spawned server is a synthetic shim written into the lab that
# reports its own environment and answers one MCP initialize. No network, no CVE
# reproduction, nothing written outside the lab.
#
# The evidence this template emits carries the NAMES of the child's environment
# variables and the values of ITS OWN nonces - never the values of any variable
# it did not itself mint, so a scan report cannot become a secret leak.
set -uo pipefail

# ---------------------------------------------------------------------------
# Probe-contract inputs. CERT_X_GEN_TARGET_KIND is part of the richer CLI
# contract but is not set by every shipping engine build, which passes only the
# scope string in CERT_X_GEN_TARGET_HOST (`cli:///path/to/binary`).
# ---------------------------------------------------------------------------
CXG_RAW="${CERT_X_GEN_TARGET_HOST:-}"
CXG_KIND="${CERT_X_GEN_TARGET_KIND:-}"
CXG_INSTR="${CERT_X_GEN_TARGET_INSTRUMENTATION:-unknown}"

CXG_BIN="$CXG_RAW"
case "$CXG_RAW" in
    cli://*)
        [ -n "$CXG_KIND" ] || CXG_KIND="cli"
        # `cli:///abs/path` -> `/abs/path`; the third slash is the empty
        # authority component of the URL, not part of the path.
        CXG_BIN="${CXG_RAW#cli://}"
        ;;
    *)
        if [ -z "$CXG_KIND" ] && [ -n "$CXG_RAW" ] && [ -f "$CXG_RAW" ] && [ -x "$CXG_RAW" ]; then
            CXG_KIND="cli"
        fi
        ;;
esac
CXG_TIMEOUT="${CXG_MCP_TIMEOUT:-20}"
CXG_PROBES_DELIVERED=0

# ---------------------------------------------------------------------------
# The JSON contract. Built with json.dumps, never by interpolation.
# ---------------------------------------------------------------------------
cxg_emit() {
    CXG_F="${3:-[]}" CXG_S="$1" CXG_D="$2" CXG_I="$CXG_INSTR" python3 -c '
import json, os
detail = os.environ["CXG_D"]
try:
    findings = json.loads(os.environ["CXG_F"])
except ValueError as exc:
    findings = []
    detail += " (finding-json-invalid: %s)" % exc
print(json.dumps({"findings": findings,
                  "metadata": {"status": os.environ["CXG_S"],
                               "detail": detail,
                               "instrumentation": os.environ["CXG_I"]}}))'
}

# Every verdict exits 0 and carries its status in the JSON. The shipped engine
# discards a shell template's findings when the template exits non-zero, so a
# confirmation that signalled itself with an exit code would be a finding cxg
# never records.
cxg_confirm() { cxg_emit confirmed "$1" "$2"; exit 0; }
cxg_error()   { cxg_emit errored   "$1"; exit 0; }
cxg_skip()    { cxg_emit skipped   "$1"; exit 0; }

# A refutation asserts the target was exercised. Without a delivered probe this
# template has learned nothing and says so, rather than issuing a clean bill of
# health it did not earn.
cxg_refute() {
    if [ "$CXG_PROBES_DELIVERED" -eq 0 ]; then
        cxg_emit skipped "no-probe-delivered (nothing reached the target, so a refutation would be unearned): $1"
        exit 0
    fi
    cxg_emit refuted "$1 probes=$CXG_PROBES_DELIVERED"
    exit 0
}

cxg_finding() {
    CXG_SEV="$1" CXG_CONF="$2" CXG_TITLE="$3" CXG_DESC="$4" CXG_CWE="$5" \
    CXG_REQ="$6" CXG_RESP="$7" CXG_PAT="$8" CXG_DATA="${9:-{\}}" python3 -c '
import json, os

def visible(s):
    return "".join(c if (31 < ord(c) < 127 or c in "\n\t") else "\\x%02x" % ord(c)
                   for c in s)

try:
    data = json.loads(os.environ["CXG_DATA"])
except ValueError:
    data = {"note": "data-json-invalid"}
print(json.dumps([{
    "severity":    os.environ["CXG_SEV"],
    "confidence":  int(os.environ["CXG_CONF"]),
    "title":       os.environ["CXG_TITLE"],
    "description": os.environ["CXG_DESC"],
    "cwe_ids":     [c.strip() for c in os.environ["CXG_CWE"].split(",") if c.strip()],
    "evidence": {
        "request":          os.environ["CXG_REQ"],
        "response":         visible(os.environ["CXG_RESP"][:1500]),
        "matched_patterns": [p.strip() for p in os.environ["CXG_PAT"].split(",") if p.strip()],
        "data":             data,
    },
}]))'
}

cxg_timeout() {
    secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"; return $?; fi
    if command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"; return $?; fi
    "$@" & child=$!
    ( sleep "$secs"; kill -TERM "$child" 2>/dev/null; sleep 1
      kill -KILL "$child" 2>/dev/null ) >/dev/null 2>&1 & watchdog=$!
    rc=0; wait "$child" 2>/dev/null || rc=$?
    kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null || true
    [ "$rc" -eq 143 ] && rc=124
    return "$rc"
}

# ---------------------------------------------------------------------------
# Guards and lab.
# ---------------------------------------------------------------------------
[ "$CXG_KIND" = "cli" ] || cxg_skip "not-a-cli-target(kind=${CXG_KIND:-none})"
[ -n "$CXG_BIN" ]       || cxg_error "no-target-path"
[ -x "$CXG_BIN" ]       || cxg_error "target-not-executable($CXG_BIN)"
command -v python3 >/dev/null 2>&1 || cxg_error "python3-required-for-the-stdio-shim"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-mcp-env.XXXXXX")" || cxg_error "lab-setup-failed"
# shellcheck disable=SC2064  # $LAB must expand now, not at trap time
trap "rm -rf '$LAB'" EXIT

REPORT="$LAB/child-environ.json"

# ---------------------------------------------------------------------------
# The synthetic stdio MCP server. It reports the environment it was handed and
# answers one `initialize`, so a host that expects a real handshake is
# satisfied. The report PATH arrives on argv, never through the environment -
# a server that can only be told where to write via an env var could not be
# used to measure a host that scrubs the environment.
# ---------------------------------------------------------------------------
cat >"$LAB/envshim.py" <<'SHIM'
#!/usr/bin/env python3
"""Synthetic stdio MCP server: reports its own environment, then handshakes.

Written into a scan lab by templates/ai/mcp/mcp-child-env-inheritance.sh. It is
the measuring instrument, not a tool: it declares one tool, executes nothing,
opens no network connection, and writes exactly one file - the path handed to it
on argv - containing the environment the host chose to give it.
"""
import json
import os
import sys

report_path = sys.argv[1] if len(sys.argv) > 1 else None
if report_path:
    try:
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(dict(os.environ), fh)
    except OSError:
        pass

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("method") == "initialize":
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "cxg-env-probe", "version": "0"},
            },
        }) + "\n")
        sys.stdout.flush()
    elif msg.get("method") == "tools/list":
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "result": {"tools": [{
                "name": "report_environment_scope",
                "description": "Reports which declared variables this server received.",
                "inputSchema": {"type": "object", "properties": {}},
            }]},
        }) + "\n")
        sys.stdout.flush()
SHIM

# ---------------------------------------------------------------------------
# Canaries. Values no correct run can invent, so seeing one is proof, not
# inference. The credential-shaped names are exported into THIS process only,
# which is what the host under test will (or will not) pass on.
# ---------------------------------------------------------------------------
nonce() { printf '%s-%s' "$1" "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"; }

CANARY_VARS="AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN GITHUB_TOKEN NPM_TOKEN ANTHROPIC_API_KEY SLACK_BOT_TOKEN"
: >"$LAB/canaries.env"
for v in $CANARY_VARS; do
    val="$(nonce "CXG-CANARY-$v")"
    export "$v=$val"
    printf '%s\t%s\n' "$v" "$val" >>"$LAB/canaries.env"
done
CANARY_COUNT="$(wc -l <"$LAB/canaries.env" | tr -d ' ')"

# The declared half of the differential: minted, written into the manifest, and
# deliberately NOT exported. It can reach the child only through the manifest.
DECLARED_VAR="CXG_MCP_DECLARED_TOKEN"
DECLARED_NONCE="$(nonce CXG-DECLARED)"
unset "$DECLARED_VAR"

# ---------------------------------------------------------------------------
# The manifest: one stdio server, one declared variable. Conventional shape, so
# a host that reads `mcp.json` reads this.
# ---------------------------------------------------------------------------
CONFIG="$LAB/mcp.json"
CXG_PY="$(command -v python3)" CXG_SHIM="$LAB/envshim.py" CXG_REPORT="$REPORT" \
CXG_DVAR="$DECLARED_VAR" CXG_DVAL="$DECLARED_NONCE" python3 -c '
import json, os
print(json.dumps({"mcpServers": {"cxg-env-probe": {
    "command": os.environ["CXG_PY"],
    "args": [os.environ["CXG_SHIM"], os.environ["CXG_REPORT"]],
    "env": {os.environ["CXG_DVAR"]: os.environ["CXG_DVAL"]},
}}}, indent=2))' >"$CONFIG" || cxg_error "manifest-write-failed"

# ---------------------------------------------------------------------------
# Discovery. Find the subcommand under which the target launches the stdio
# servers a manifest declares. Operator override first, then the conventional
# names. A run counts only when the child actually reported - help text is not
# evidence that anything was spawned.
# ---------------------------------------------------------------------------
SUBS="${CXG_MCP_LAUNCH_SUBCOMMAND:-} launch start start-server serve spawn run-server mcp connect up"

LAUNCH_SUB=""
LAUNCH_OUT=""
LAUNCH_RC=0
for SUB in $SUBS; do
    [ -n "$SUB" ] || continue
    rm -f "$REPORT"
    OUT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$SUB" "$CONFIG" 2>&1)"
    RC=$?
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
    if [ -s "$REPORT" ]; then
        LAUNCH_SUB="$SUB"; LAUNCH_OUT="$OUT"; LAUNCH_RC=$RC
        break
    fi
done

[ -n "$LAUNCH_SUB" ] || cxg_skip "no-stdio-launch-surface (no subcommand spawned the stdio MCP server this manifest declares -- the synthetic server never reported an environment, so nothing was measured. This check needs a host that launches locally-declared stdio servers; name its subcommand with CXG_MCP_LAUNCH_SUBCOMMAND if it has one)"

# ---------------------------------------------------------------------------
# Read the environment the child was handed, and classify it. Only names and
# this template's own nonce values ever leave this block: a scan report must not
# become the secret leak it is reporting.
# ---------------------------------------------------------------------------
CLASSIFY="$(CXG_REPORT="$REPORT" CXG_CANARIES="$LAB/canaries.env" \
            CXG_DVAR="$DECLARED_VAR" CXG_DVAL="$DECLARED_NONCE" python3 -c '
import json, os, sys

child = json.load(open(os.environ["CXG_REPORT"], encoding="utf-8"))
values = set(child.values())

leaked, held = [], []
for line in open(os.environ["CXG_CANARIES"], encoding="utf-8"):
    name, _, val = line.rstrip("\n").partition("\t")
    if not name:
        continue
    (leaked if val in values else held).append(name)

declared_ok = child.get(os.environ["CXG_DVAR"]) == os.environ["CXG_DVAL"]

# Undeclared names carried through that are not one of our canaries: reported as
# a soft observation only. A name is not a secret, and a base variable such as
# PATH is legitimate - this number is context for the operator, never the oracle.
declared_names = {os.environ["CXG_DVAR"]}
extra = sorted(k for k in child if k not in declared_names)

json.dump({
    "leaked": sorted(leaked),
    "held": sorted(held),
    "declared_ok": declared_ok,
    "child_var_count": len(child),
    "child_var_names": extra[:80],
}, sys.stdout)')" || cxg_error "child-environment-report-unreadable"

read -r LEAKED_N LEAKED_LIST DECLARED_OK CHILD_N <<<"$(CXG_C="$CLASSIFY" python3 -c '
import json, os
c = json.loads(os.environ["CXG_C"])
print(len(c["leaked"]), ",".join(c["leaked"]) or "-",
      "yes" if c["declared_ok"] else "no", c["child_var_count"])')"

# The surface proof. Without the declared nonce the child either did not start
# from this manifest or the host ignored the declaration - either way nothing
# about inheritance was measured, and a verdict would be invented.
if [ "$DECLARED_OK" != "yes" ]; then
    cxg_skip "declaration-not-honoured (the child reported an environment of $CHILD_N variable(s) under \`$(basename "$CXG_BIN") $LAUNCH_SUB\`, but the manifest's declared variable $DECLARED_VAR did not arrive with its nonce. The declared half of the differential is what proves this host launches the server the manifest describes; without it neither a confirmation nor a refutation is earned)"
fi

CHILD_NAMES="$(CXG_C="$CLASSIFY" python3 -c '
import json, os
print(" ".join(json.loads(os.environ["CXG_C"])["child_var_names"]))')"

# ---------------------------------------------------------------------------
# Oracle: set containment. Any canary nonce in the child that the manifest never
# declared is inherited privilege the server did not ask for.
# ---------------------------------------------------------------------------
if [ "$LEAKED_N" -gt 0 ]; then
    FINDINGS="$(cxg_finding \
        high 95 \
        "Locally-spawned stdio MCP server inherits undeclared developer credentials" \
        "Launched through \`$(basename "$CXG_BIN") $LAUNCH_SUB\`, the manifest declared one stdio server needing exactly one variable ($DECLARED_VAR). The server received that variable - so the host honours the declaration - and it also received $LEAKED_N credential canary value(s) the manifest never mentioned: $LEAKED_LIST. Each canary value is a nonce minted by this scan from /dev/urandom moments before the launch and exported into the scanning process only; no config file, cache, vendor default or earlier run can contain it, so its presence in the child is proof of environment inheritance across the spawn boundary and nothing else. The child was handed $CHILD_N variables in total against a declared need of 1. The consequence is blast radius: any code the server runs - its own, a dependency's, or an attacker's after a supply-chain or prompt-injection foothold - reads the operator's cloud, source-forge and registry credentials without touching a credential file, without a prompt and without leaving a trace in the host's tool log. This is the multiplier that turns local agent code execution into cloud-account compromise. Remediate by constructing the child environment explicitly - a minimal process base plus exactly the manifest's declared \`env\` - rather than \`{**os.environ, **declared}\`, and by treating an undeclared variable reaching a server as a policy violation." \
        "CWE-250,CWE-522,CWE-668" \
        "$(basename "$CXG_BIN") $LAUNCH_SUB <manifest declaring 1 stdio server with 1 declared env var>" \
        "host output:
$LAUNCH_OUT
--- child-reported environment (variable NAMES only; no value this scan did not itself mint is recorded) ---
count=$CHILD_N
$CHILD_NAMES" \
        "undeclared-canary-nonce-visible-to-child,declared-variable-honoured" \
        "$(CXG_C="$CLASSIFY" CXG_SUB="$LAUNCH_SUB" CXG_RC="$LAUNCH_RC" CXG_DVAR="$DECLARED_VAR" python3 -c '
import json, os
c = json.loads(os.environ["CXG_C"])
print(json.dumps({
    "oracle": "property",
    "post_condition": "an undeclared canary nonce is present in the spawned child environment",
    "leaked_canaries": c["leaked"],
    "withheld_canaries": c["held"],
    "declared_variable": os.environ["CXG_DVAR"],
    "declaration_honoured": c["declared_ok"],
    "child_env_var_count": c["child_var_count"],
    "declared_need_count": 1,
    "launch_subcommand": os.environ["CXG_SUB"],
    "target_exit_code": int(os.environ["CXG_RC"]),
    "observations": {
        "note": "child_env_var_names is context, not the oracle: a name is not a secret and a base variable such as PATH is legitimate.",
        "child_env_var_names": c["child_var_names"],
    },
}))')")"
    cxg_confirm "oracle=property($LEAKED_N undeclared credential canary nonce(s) visible to the spawned stdio server: $LEAKED_LIST; child held $CHILD_N vars against a declared need of 1; sub=$LAUNCH_SUB) exit=$LAUNCH_RC" "$FINDINGS"
fi

cxg_refute "the stdio server was spawned through \`$(basename "$CXG_BIN") $LAUNCH_SUB\` and received its declared variable $DECLARED_VAR, but none of the $CANARY_COUNT credential canaries exported into the host process reached it (child held $CHILD_N variable(s)) -- this host scopes the child environment to declared need; exit=$LAUNCH_RC"

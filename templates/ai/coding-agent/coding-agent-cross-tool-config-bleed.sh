#!/usr/bin/env bash
# @id: coding-agent-cross-tool-config-bleed
# @name: Coding agent honours another agent's configuration, and one marketplace consent arms more than one agent
# @author: CERT-X-GEN Security Team
# @description: Runs a coding-agent CLI twice against configuration surfaces that are identical except for whose tool they belong to. The control arm plants a marker-bearing MCP server in the target's OWN config path and establishes that the target is config-driven at all. The probe arm plants the same declaration only in FOREIGN surfaces - .cursor/mcp.json, .vscode/mcp.json plus chat.mcp.discovery.enabled, .gemini/settings.json, ~/.codeium/windsurf/mcp_config.json, ~/.codex/config.toml - and no surface of the target's own; honouring one of those proves a declaration planted for tool A is executed by tool B. A second arm installs one synthetic marketplace entry and counts consent prompts against the number of distinct agent plugin stores the install writes to, because a single consent that arms two agents is the blast radius, not the install.
# @severity: high
# @tags: ai, coding-agent, cli, agent-posture, cross-tool, blast-radius, mcp, mcp-discovery, marketplace, plugin, config-bleed, trust-boundary, differential, cwe-1188, cwe-829, cwe-441, cwe-732
# @cwe: CWE-1188
# @confidence: 88
# @target_kinds: cli
# @oracles: property
# @references: https://code.visualstudio.com/docs/copilot/customization/mcp-servers
#
# THE CLASS
#
# A developer machine now runs several agents at once, and each of them keeps a
# configuration file that declares executable things: MCP servers to launch,
# plugins to load, commands to auto-approve. Those files were never designed as
# a shared bus, but they are being read as one. VS Code ships
# `chat.mcp.discovery.enabled`, which imports MCP server declarations written
# for *other* tools on the machine and treats them as its own. Marketplaces
# have gone the same way: one entry, one "install", and it lands in more than
# one agent's plugin store.
#
# The consequence is a blast radius nobody scoped. An operator who audited one
# tool's config, or who accepted one install prompt, has decided on behalf of
# every other agent that reads the same surface. A declaration planted where
# tool A looks -- in a repository, in a shared machine account, in a
# marketplace entry -- is honoured by tool B, whose own config file is clean
# and whose own consent was never asked.
#
#   input      one marker-bearing MCP server declaration, planted TWICE: once
#              in the target's own config path (the control), once only in five
#              foreign agents' config paths (the probe). Plus one synthetic
#              marketplace entry declaring two agents.
#   observable a declaration the target does not own took effect - its command
#              ran, writing its own nonce into this template's lab, or its
#              marker was echoed - after the control arm already proved the
#              target reads configuration of this shape. And: an install that
#              wrote into more distinct agent plugin stores than it asked
#              consents for.
#   oracle     property -- a differential post-condition over two runs that
#              differ only in WHOSE tool the configuration file belongs to,
#              and a counting post-condition over consents versus agents armed.
#
# WHY THE CONTROL COMES FIRST
#
# A tool that reads no configuration at all would "pass" a foreign-surface
# probe for the most boring reason there is. Requiring the target to honour its
# OWN planted declaration before the foreign arm runs means this template never
# reports a tool it has not already shown to be config-driven, and it emits
# `skipped` -- not `refuted` -- when it never found that surface. The
# refutation it prints when the foreign arm is ignored is a positive result
# worth having: this tool reads its own configuration and only its own.
#
# NOT THE SAME CHECK AS ITS NEIGHBOURS
#
# The `coding-agent-*-config-trust` family varies the PERMISSIONS of the
# directory a config came from; `coding-agent-repo-config-autoexec` varies its
# PROVENANCE, whether a human approved that workspace. This template holds both
# fixed - every surface in both arms sits in the same private 0700 workspace
# and the same probe-controlled $HOME, planted by the same user in the same
# second - and varies OWNERSHIP-BY-TOOL: which agent the file was written for.
# A tool can gate workspace trust perfectly and still execute the MCP server
# that the workspace declared for a completely different agent.
#
# SAFETY
#
# Nothing is written outside a `mktemp -d` lab removed on exit; $HOME is
# redirected into that lab for every probe run, so no real agent's real
# configuration is read or written. Every planted "server" is a command whose
# entire body is `printf <nonce> > <lab>/<canary>`, and the "marketplace" is a
# JSON file this template wrote a moment earlier. No CVE is reproduced against
# any real tool's machine state.
set -uo pipefail

CXG_RAW="${CERT_X_GEN_TARGET_HOST:-}"
CXG_KIND="${CERT_X_GEN_TARGET_KIND:-}"
CXG_INSTR="${CERT_X_GEN_TARGET_INSTRUMENTATION:-unknown}"

CXG_BIN="$CXG_RAW"
case "$CXG_RAW" in
    cli://*)
        [ -n "$CXG_KIND" ] || CXG_KIND="cli"
        CXG_BIN="${CXG_RAW#cli://}"
        ;;
    *)
        if [ -z "$CXG_KIND" ] && [ -n "$CXG_RAW" ] && [ -f "$CXG_RAW" ] && [ -x "$CXG_RAW" ]; then
            CXG_KIND="cli"
        fi
        ;;
esac
CXG_TIMEOUT="${CXG_AGENT_TIMEOUT:-10}"
CXG_PROBES_DELIVERED=0
CXG_PROBE_BUDGET="${CXG_AGENT_PROBE_BUDGET:-32}"

# ---------------------------------------------------------------------------
# The JSON contract. Built with json.dumps, never by interpolation: this
# template handles target output verbatim and a half-cut glyph would turn a
# finding into a silent zero-finding.
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

# Findings accumulate one JSON object per line, because this template can carry
# two independent results - a configuration bleed and a marketplace fan-out -
# and folding them into one finding would lose whichever the operator needed.
cxg_add_finding() {
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
print(json.dumps({
    "severity":    os.environ["CXG_SEV"],
    "confidence":  int(os.environ["CXG_CONF"]),
    "title":       os.environ["CXG_TITLE"],
    "description": os.environ["CXG_DESC"],
    "cwe_ids":     [c.strip() for c in os.environ["CXG_CWE"].split(",") if c.strip()],
    "evidence": {
        "request":          os.environ["CXG_REQ"],
        "response":         visible(os.environ["CXG_RESP"][:1600]),
        "matched_patterns": [p.strip() for p in os.environ["CXG_PAT"].split(",") if p.strip()],
        "data":             data,
    },
}))' >>"$FINDINGS_FILE"
}

cxg_findings_array() {
    python3 -c '
import json, sys
print(json.dumps([json.loads(line) for line in open(sys.argv[1]) if line.strip()]))' "$FINDINGS_FILE"
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
command -v python3 >/dev/null 2>&1 || cxg_error "python3-required-to-build-probe-documents"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-cross-tool-bleed.XXXXXX")" || cxg_error "lab-setup-failed"
# shellcheck disable=SC2064  # $LAB must expand now, not at trap time
trap "chmod -R u+rwX '$LAB' 2>/dev/null; rm -rf '$LAB'" EXIT
CANARIES="$LAB/canaries"
FINDINGS_FILE="$LAB/findings.ndjson"
mkdir -p "$CANARIES" || cxg_error "lab-layout-failed"
: >"$FINDINGS_FILE"

HELP_TEXT=""
for probe in --help help -h; do
    HELP_TEXT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$probe" 2>&1)"
    printf '%s' "$HELP_TEXT" | grep -qiE 'usage|commands?:|options?:' && break
    HELP_TEXT=""
done
if [ -z "$HELP_TEXT" ]; then
    HELP_TEXT="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" 2>&1)"
fi
[ -n "$HELP_TEXT" ] || cxg_error "target-produced-no-output-at-all"

# The leading token of the program name is the tool's identity for config
# purposes: `bleedagent_defective.py` -> bleedagent, `claude` -> claude. Twin
# suffixes and file extensions are not part of it. This identity is what makes
# a surface "the target's own" versus "somebody else's".
STEM="$(basename "$CXG_BIN" | sed 's/[._-].*$//' | tr -cd 'A-Za-z0-9' | tr 'A-Z' 'a-z')"
[ -n "$STEM" ] || STEM="tool"

salt() { od -An -N8 -tx1 /dev/urandom | tr -d ' \n'; }

# ---------------------------------------------------------------------------
# Plant the configuration surfaces for one arm.
#
# `native` writes only into the target's own paths; `foreign` writes only into
# five other agents' paths and never touches a path containing the target's own
# stem, so a confirmation can never be the target reading its own file under a
# name this template mis-attributed. Each surface carries its own nonce and a
# command whose entire body writes that nonce to one file in this lab.
#
# Emits `<surface>\t<nonce>\t<path>` per line for the caller to keep.
# ---------------------------------------------------------------------------
plant_surfaces() {
    CXG_WS="$1" CXG_HOME="$2" CXG_ARM="$3" CXG_SET="$4" CXG_SALT="$5" \
    CXG_STEM="$STEM" CXG_CANARIES="$CANARIES" python3 - <<'PY'
import json, os

ws       = os.environ["CXG_WS"]
home     = os.environ["CXG_HOME"]
arm      = os.environ["CXG_ARM"]
which    = os.environ["CXG_SET"]
salt     = os.environ["CXG_SALT"]
stem     = os.environ["CXG_STEM"]
canaries = os.environ["CXG_CANARIES"]

def nonce(surface):
    return "CXG-XTOOL-%s-%s-%s" % (arm.upper(), surface.upper().replace("-", ""), salt)

def canary(surface):
    return os.path.join(canaries, "%s.%s.txt" % (arm, surface))

def shell(surface):
    # The entire payload: one nonce into one file in the probe's own lab.
    return ["sh", "-c", "printf %%s %s > %s" % (nonce(surface), canary(surface))]

def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path

def server(surface):
    argv = shell(surface)
    return {"command": argv[0], "args": argv[1:], "marker": nonce(surface)}

def mcp_document(surface, key="mcpServers"):
    return json.dumps({"marker": nonce(surface),
                       key: {"cxg-canary": server(surface)}}, indent=2) + "\n"

def toml_document(surface):
    argv = shell(surface)
    return "\n".join([
        "# synthetic probe configuration",
        "[mcp_servers.cxg-canary]",
        'marker = "%s"' % nonce(surface),
        'command = "%s"' % argv[0],
        'args = [%s]' % ", ".join('"%s"' % a.replace('"', '\\"') for a in argv[1:]),
        "",
    ])

# (surface, path, writer). NATIVE is the target's own; FOREIGN belongs to five
# other agents and is what the probe arm plants.
NATIVE = [
    ("native-workspace", os.path.join(ws, "." + stem, "mcp.json"), mcp_document),
    ("native-user",      os.path.join(home, "." + stem, "mcp.json"), mcp_document),
    ("native-config",    os.path.join(home, ".config", stem, "mcp.json"), mcp_document),
]

FOREIGN = [
    ("cursor",      os.path.join(ws, ".cursor", "mcp.json"), mcp_document),
    ("vscode",      os.path.join(ws, ".vscode", "mcp.json"),
     lambda s: mcp_document(s, key="servers")),
    ("gemini-cli",  os.path.join(ws, ".gemini", "settings.json"), mcp_document),
    ("windsurf",    os.path.join(home, ".codeium", "windsurf", "mcp_config.json"), mcp_document),
    ("codex",       os.path.join(home, ".codex", "config.toml"), toml_document),
]

planted = []
if which == "native":
    for surface, path, writer in NATIVE:
        planted.append((surface, write(path, writer(surface))))
else:
    for surface, path, writer in FOREIGN:
        # A foreign surface that happens to belong to the target itself is not
        # foreign. Dropping it keeps the differential honest when the target is
        # cursor, code, gemini, windsurf or codex.
        if stem and stem in path.replace(os.sep, " ").split():
            continue
        if ("." + stem) in path or ("/" + stem + "/") in path:
            continue
        planted.append((surface, write(path, writer(surface))))
    # The documented switch this class is named for. Planted as an inert repo
    # setting: a tool that needs it before it fans out gets it, so a refutation
    # is not "the flag was missing".
    write(os.path.join(ws, ".vscode", "settings.json"),
          json.dumps({"chat.mcp.discovery.enabled": True,
                      "chat.mcp.autostart": "newAndOutdated"}, indent=2) + "\n")

for surface, path in planted:
    print("%s\t%s\t%s" % (surface, nonce(surface), path))
PY
}

# ---------------------------------------------------------------------------
# Subcommands: a help listing's "  name   description" shape, filtered to the
# ones that open a workspace, start a session or print configuration -- where a
# declared MCP server either launches or shows up in the output.
# ---------------------------------------------------------------------------
list_subcommands() {
    printf '%s' "$HELP_TEXT" | python3 -c '
import re, sys
NAME = re.compile(r"^[ \t]{1,8}([a-z][a-z0-9][a-z0-9_.-]*)\b(.*)$")
SEP = re.compile(r"(?:[ ]{2,}|\t)\S")
NOT_A_COMMAND = {"usage", "options", "option", "commands", "command",
                 "arguments", "args", "flags", "environment", "examples",
                 "example", "see", "note", "notes", "where", "for", "the"}
seen, out = set(), []
for line in sys.stdin.read().splitlines():
    m = NAME.match(line)
    if not m:
        continue
    name, rest = m.group(1), m.group(2)
    if not SEP.search(rest) or name in seen or name in NOT_A_COMMAND:
        continue
    seen.add(name)
    out.append(name)
print("\n".join(out))'
}

ALL_SUBS="$(list_subcommands)"
SUBS="$(printf '%s\n' "$ALL_SUBS" | grep -E '^(open|session|sessions|start|chat|ask|run|agent|serve|mcp|config|configure|settings|status|info|doctor|list)$' | head -8)"
SUBS="$(printf '%s\n%s\n' "$SUBS" "" | grep -v '^$')"

# ---------------------------------------------------------------------------
# Run one arm from inside its workspace and say which surfaces it honoured.
#
# `honoured` means one of two facts, both of which require the target to have
# read a planted file: that surface's declared server ran (its canary exists,
# holding that surface's nonce), or its marker took effect visibly (the nonce
# is in the output). The two are recorded separately because a launch is a much
# stronger claim than an echo.
# ---------------------------------------------------------------------------
LAST_OUT=""
LAST_RC=0
HONOURED=""          # "surface:witness:path" per line
LAUNCHED=0

run_arm() {
    arm="$1" ws="$2" arm_home="$3" sub="$4"
    rm -f "$CANARIES/$arm."*.txt 2>/dev/null

    if [ -n "$sub" ]; then
        LAST_OUT="$(cd "$ws" && HOME="$arm_home" XDG_CONFIG_HOME="$arm_home/.config" \
            cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$sub" </dev/null 2>&1)"
    else
        LAST_OUT="$(cd "$ws" && HOME="$arm_home" XDG_CONFIG_HOME="$arm_home/.config" \
            cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" </dev/null 2>&1)"
    fi
    LAST_RC=$?
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))

    HONOURED=""
    LAUNCHED=0
    while IFS="$(printf '\t')" read -r surface nonce path; do
        [ -n "$surface" ] || continue
        canary="$CANARIES/$arm.$surface.txt"
        if [ -f "$canary" ] && grep -qF "$nonce" "$canary" 2>/dev/null; then
            HONOURED="$HONOURED$surface:server-launched:$path
"
            LAUNCHED=$((LAUNCHED + 1))
        elif printf '%s' "$LAST_OUT" | grep -qF "$nonce"; then
            HONOURED="$HONOURED$surface:marker-applied:$path
"
        fi
    done <"$LAB/$arm.tsv"

    [ -n "$HONOURED" ]
}

summarise() { printf '%s' "$1" | grep -v '^$' | cut -d: -f1,2 | paste -sd' ' - ; }
count_of()  { printf '%s' "$1" | grep -c ':' ; }

# ---------------------------------------------------------------------------
# Arm 1 -- the configuration bleed.
# ---------------------------------------------------------------------------
CONTROL_WS="$LAB/control/repo"
PROBE_WS="$LAB/probe/repo"
CONTROL_HOME="$LAB/home-control"
PROBE_HOME="$LAB/home-probe"
mkdir -p "$CONTROL_WS" "$PROBE_WS" "$CONTROL_HOME" "$PROBE_HOME" || cxg_error "lab-layout-failed"
chmod 0700 "$CONTROL_WS" "$PROBE_WS" "$CONTROL_HOME" "$PROBE_HOME"

CONTROL_SALT="$(salt)"
PROBE_SALT="$(salt)"
plant_surfaces "$CONTROL_WS" "$CONTROL_HOME" control native  "$CONTROL_SALT" >"$LAB/control.tsv" || cxg_error "could-not-plant-native-surfaces"
plant_surfaces "$PROBE_WS"   "$PROBE_HOME"   probe   foreign "$PROBE_SALT"   >"$LAB/probe.tsv"   || cxg_error "could-not-plant-foreign-surfaces"

[ -s "$LAB/probe.tsv" ] || cxg_skip "no-foreign-surface-left-to-plant(the target's own identity '$STEM' claims every foreign path this template knows, so there is no other agent's file to bleed from)"

# The probe arm must contain NO surface belonging to the target. If one slipped
# in, a confirmation would be this tool reading its own config, which is the
# feature, not the finding.
if [ -e "$PROBE_WS/.$STEM" ] || [ -e "$PROBE_HOME/.$STEM" ] || [ -e "$PROBE_HOME/.config/$STEM" ]; then
    cxg_error "probe-arm-contains-a-native-surface(stem=$STEM; the differential would not isolate cross-tool ownership)"
fi

CONTROL_SUB=""
CONTROL_HONOURED=""
CONTROL_LAUNCHED=0
TRIED=0
while IFS= read -r SUB; do
    [ "$CXG_PROBES_DELIVERED" -lt "$CXG_PROBE_BUDGET" ] || break
    TRIED=$((TRIED + 1))
    if run_arm control "$CONTROL_WS" "$CONTROL_HOME" "$SUB"; then
        CONTROL_SUB="$SUB"
        CONTROL_HONOURED="$HONOURED"
        CONTROL_LAUNCHED="$LAUNCHED"
        break
    fi
done <<OUTER
$SUBS

OUTER

[ -n "$CONTROL_HONOURED" ] || cxg_skip "no-mcp-config-surface(tried $TRIED subcommand(s) within a $CXG_PROBE_BUDGET-probe budget; opened in a workspace carrying a marker-bearing MCP server declaration in the target's OWN config paths - workspace, \$HOME and XDG - the target honoured none of them. Either it reads no MCP configuration of this shape, or its own config path is not one of the three this template plants, so there is no established surface whose cross-tool boundary could be tested)"

CONTROL_SUMMARY="$(summarise "$CONTROL_HONOURED")"
BLEED_SUMMARY=""
BLEED_COUNT=0

if run_arm probe "$PROBE_WS" "$PROBE_HOME" "$CONTROL_SUB"; then
    BLEED_HONOURED="$HONOURED"
    BLEED_LAUNCHED="$LAUNCHED"
    BLEED_SUMMARY="$(summarise "$BLEED_HONOURED")"
    BLEED_COUNT="$(count_of "$BLEED_HONOURED")"
    WITNESS_SURFACE="$(printf '%s' "$BLEED_HONOURED" | grep -v '^$' | head -1 | cut -d: -f1)"
    WITNESS_NONCE="$(awk -F'\t' -v s="$WITNESS_SURFACE" '$1 == s { print $2; exit }' "$LAB/probe.tsv")"

    if [ "$BLEED_LAUNCHED" -gt 0 ]; then
        BLEED_SEV=high; BLEED_CONF=90
        BLEED_STRENGTH="Execution, not just parsing: $BLEED_LAUNCHED of the foreign declarations were launched as servers, each writing its own nonce into this probe's lab."
    else
        BLEED_SEV=medium; BLEED_CONF=76
        BLEED_STRENGTH="The foreign declarations took effect visibly but no launch was witnessed in this configuration. That still places another tool's configuration file inside this tool's trust boundary - the same file that sets a marker declares a command - but the execution step was not observed here."
    fi

    cxg_add_finding \
        "$BLEED_SEV" "$BLEED_CONF" \
        "Coding agent honours MCP server declarations written for a different agent" \
        "Opened in a private workspace whose only MCP configuration belongs to OTHER agents, the target honoured $BLEED_COUNT foreign surface(s): $BLEED_SUMMARY. $BLEED_STRENGTH The control run proves this is a cross-tool boundary failure rather than an absence of config support: a byte-shaped-identical declaration in the target's OWN config paths was honoured the same way ($CONTROL_SUMMARY), and the two arms differ in nothing but whose tool the file was written for - same invoking user, same 0700 workspace, same probe-controlled \$HOME, planted seconds apart. The probe arm contains no surface of the target's own, so the honoured declaration cannot be the target reading its own configuration. This is the blast radius the operator never scoped: an MCP server declared in .cursor/mcp.json, .vscode/mcp.json, .gemini/settings.json, a Windsurf config or a Codex config.toml is code the machine's OTHER agents now launch, so auditing or hardening one agent's configuration decides nothing for the rest, and a declaration planted where any single tool looks reaches all of them. Remediate by reading only configuration this tool owns unless the operator opts in per foreign source, showing which foreign file each imported server came from, and re-prompting when an imported declaration changes." \
        "CWE-1188,CWE-829,CWE-441,CWE-732" \
        "cd <workspace carrying only foreign agents' MCP config> && $(basename "$CXG_BIN") ${CONTROL_SUB:-<no subcommand>}" \
        "$LAST_OUT" \
        "${WITNESS_NONCE:-$PROBE_SALT}" \
        "{\"arm\":\"config-bleed\",\"oracle\":\"property\",\"post_condition\":\"a foreign agent's MCP declaration took effect after an own-config control\",\"foreign_surfaces_honoured\":\"$BLEED_SUMMARY\",\"native_surfaces_honoured\":\"$CONTROL_SUMMARY\",\"servers_launched_foreign\":$BLEED_LAUNCHED,\"servers_launched_native\":$CONTROL_LAUNCHED,\"control_subcommand\":\"${CONTROL_SUB:-}\",\"target_identity\":\"$STEM\",\"differential_axis\":\"which-tool-owns-the-file\",\"target_exit_code\":$LAST_RC}"
fi

# ---------------------------------------------------------------------------
# Arm 2 -- the marketplace blast radius.
#
# One entry, installed once. The finding is not that it installed; it is that
# the number of distinct agent plugin stores it wrote into exceeded the number
# of consents it asked for. Newly created files only: the marketplace entry
# this template planted holds the marker too, and counting it would make every
# tool look like it fanned out.
# ---------------------------------------------------------------------------
MARKET_WS="$LAB/market/repo"
MARKET_HOME="$LAB/home-market"
mkdir -p "$MARKET_WS" "$MARKET_HOME" || cxg_error "lab-layout-failed"
MARKET_SALT="$(salt)"
MARKET_MARKER="CXG-XTOOL-MARKETPLACE-$MARKET_SALT"
MARKET_ENTRY="cxg-canary-plugin"

CXG_HOME="$MARKET_HOME" CXG_WS="$MARKET_WS" CXG_STEM="$STEM" \
CXG_MARKER="$MARKET_MARKER" CXG_ENTRY="$MARKET_ENTRY" python3 - <<'PY'
import json, os

home  = os.environ["CXG_HOME"]
ws    = os.environ["CXG_WS"]
stem  = os.environ["CXG_STEM"]
marker = os.environ["CXG_MARKER"]
entry_name = os.environ["CXG_ENTRY"]

entry = {
    "name": entry_name,
    "version": "0.0.1",
    "source": "cxg-synthetic-marketplace",
    "description": "A benign probe entry that installs nothing but a marker.",
    "install_marker": marker,
    # The entry names more than one agent because that is the shape of a
    # marketplace shared across agents: the operator sees one name.
    "agents": [stem, "siblingagent"],
    "targets": [stem, "siblingagent"],
}

for base in (os.path.join(home, "." + stem, "marketplace"),
             os.path.join(home, "." + stem, "marketplaces"),
             os.path.join(home, ".config", stem, "marketplace"),
             os.path.join(ws, "." + stem, "marketplace")):
    os.makedirs(base, exist_ok=True)
    with open(os.path.join(base, entry_name + ".json"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, indent=2) + "\n")
PY

INSTALL_SUB="$(printf '%s\n' "$ALL_SUBS" | grep -E '^(install|add|plugin|plugins|extension|extensions|marketplace)$' | head -1)"
MARKET_AGENTS=0
MARKET_CONSENTS=0
MARKET_SUMMARY="not-attempted"
MARKET_OUT=""

if [ -n "$INSTALL_SUB" ]; then
    find "$MARKET_HOME" -type f 2>/dev/null | LC_ALL=C sort >"$LAB/market-before.txt"
    MARKET_OUT="$(cd "$MARKET_WS" && HOME="$MARKET_HOME" XDG_CONFIG_HOME="$MARKET_HOME/.config" \
        cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$INSTALL_SUB" "$MARKET_ENTRY" </dev/null 2>&1)"
    MARKET_RC=$?
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
    find "$MARKET_HOME" -type f 2>/dev/null | LC_ALL=C sort >"$LAB/market-after.txt"

    # Which distinct agents' stores are NEW and carry the entry's marker.
    MARKET_SUMMARY="$(comm -13 "$LAB/market-before.txt" "$LAB/market-after.txt" \
        | while IFS= read -r f; do
              grep -qF "$MARKET_MARKER" "$f" 2>/dev/null && printf '%s\n' "$f"
          done \
        | CXG_HOME="$MARKET_HOME" python3 -c '
import os, sys
home = os.environ["CXG_HOME"]
agents = []
for path in sys.stdin.read().split():
    rest = os.path.relpath(path, home)
    parts = [p for p in rest.split(os.sep) if p]
    if parts and parts[0] == ".config":
        parts = parts[1:]
    if not parts:
        continue
    agent = parts[0].lstrip(".")
    if agent and agent not in agents:
        agents.append(agent)
print(" ".join(sorted(agents)))')"
    MARKET_AGENTS="$(printf '%s' "$MARKET_SUMMARY" | wc -w | tr -d ' ')"

    # A consent is a line that asks the operator to allow this install. Counted
    # from the target's own output, because that is all an operator sees.
    MARKET_CONSENTS="$(printf '%s\n' "$MARKET_OUT" \
        | grep -ciE '\[y/n\]|\(y/n\)|confirm|do you (want|wish)|allow this|approve|proceed\?|continue\?' || true)"
    MARKET_CONSENTS="${MARKET_CONSENTS:-0}"

    if [ "$MARKET_AGENTS" -ge 2 ] && [ "$MARKET_CONSENTS" -le 1 ]; then
        cxg_add_finding \
            high 85 \
            "One marketplace consent arms more than one agent" \
            "A single synthetic marketplace entry ($MARKET_ENTRY), installed once with \`$(basename "$CXG_BIN") $INSTALL_SUB $MARKET_ENTRY\` and no interactive input, wrote the entry's marker into $MARKET_AGENTS distinct agent plugin stores under the probe-controlled \$HOME ($MARKET_SUMMARY) while asking for $MARKET_CONSENTS consent(s). Only files created by that install were counted, so the marketplace source documents this template planted cannot inflate the number. The install itself is not the defect - installing what the operator asked for is the feature. The defect is that the consent the operator gave was scoped to one thing and applied to several: a marketplace entry is executable configuration, and one entry that lands in a second agent's plugin store means whoever publishes it chooses what loads inside agents the operator never named and, in the usual case, never opened the config of. Remediate by scoping each consent to exactly one agent, naming every agent an entry will reach in the prompt before it is granted, and requiring a fresh consent when an already-installed entry adds an agent to its target list." \
            "CWE-1188,CWE-829,CWE-441" \
            "cd <clean lab home> && $(basename "$CXG_BIN") $INSTALL_SUB $MARKET_ENTRY  # stdin closed, nothing answered" \
            "$MARKET_OUT" \
            "$MARKET_MARKER" \
            "{\"arm\":\"marketplace-blast-radius\",\"oracle\":\"property\",\"post_condition\":\"distinct agent plugin stores armed exceeded consents asked\",\"agents_armed\":$MARKET_AGENTS,\"agent_stores\":\"$MARKET_SUMMARY\",\"consent_prompts\":$MARKET_CONSENTS,\"install_subcommand\":\"$INSTALL_SUB\",\"entry\":\"$MARKET_ENTRY\",\"counted\":\"files created by this install only\",\"target_exit_code\":$MARKET_RC}"
    fi
else
    MARKET_SUMMARY="no-install-subcommand"
fi

# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------
if [ -s "$FINDINGS_FILE" ]; then
    FINDINGS="$(cxg_findings_array)"
    cxg_confirm "oracle=property(cross-tool-config-bleed foreign=${BLEED_SUMMARY:-none} native=$CONTROL_SUMMARY sub=${CONTROL_SUB:-<bare>}; marketplace agents_armed=$MARKET_AGENTS consents=$MARKET_CONSENTS stores=$MARKET_SUMMARY)" "$FINDINGS"
fi

cxg_refute "target honoured its OWN MCP configuration (subcommand '${CONTROL_SUB:-<bare>}', surfaces: $CONTROL_SUMMARY) but honoured none of the five foreign agents' declarations planted in an otherwise identical workspace and \$HOME, with chat.mcp.discovery.enabled set alongside them; and the marketplace arm armed $MARKET_AGENTS agent store(s) [${MARKET_SUMMARY:-none}] against $MARKET_CONSENTS consent(s) -- this tool reads its own configuration and only its own, and its install consent is scoped to what it arms"

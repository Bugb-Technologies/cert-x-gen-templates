#!/usr/bin/env bash
# @id: coding-agent-config-allowlist-trust
# @name: Coding-agent CLI takes its command allowlist from attacker-writable configuration, or matches it by command name
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Establishes first that the coding-agent CLI refuses to run a marker shell command unattended when no configuration grants it, then grants it through a config-declared allowlist and re-runs. Honouring that allowlist from a 0700 root proves the tool takes execution authority from configuration; honouring the byte-identical allowlist from a 0777 world-writable root proves any local user can grant it. A third arm allowlists only a benign command name and submits that name followed by a marker command, which separates an allowlist matched on the command NAME from one matched on the command actually run. Every arm's payload is a printf of a random nonce into the probe's own scratch directory.
# @tags: ai, coding-agent, cli, config-trust, allowlist, approval-bypass, privilege-escalation, cwe-732, cwe-863, cwe-183, cve-2026-35603
# @cwe: CWE-732
# @confidence: 93
# @target_kinds: cli
# @oracles: property
# @references: https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/
#
# THE CLASS
#
# A coding-agent CLI will not run a shell command unattended unless something
# grants it permission. That grant is almost always a list in a config file -
# `permissions.allow` with `Bash(<cmd>)` entries, a `commandAllowlist`,
# `coreTools` with `run_shell_command(<cmd>)`, an `allowed_commands` array in a
# TOML profile. The list IS the approval prompt, moved to disk.
#
# Which puts the whole approval model behind two questions nobody asks of a
# config file:
#
#   1. WHO MAY WRITE THE LIST? CVE-2026-35603 found four shipping agents that
#      read managed settings out of a directory the Users group could write.
#      An allowlist in such a file is an approval prompt any local account can
#      answer on your behalf, in advance, silently.
#
#   2. WHAT DOES AN ENTRY ACTUALLY MATCH? An allowlist written as command
#      *names* - `git`, `npm`, `echo` - and matched by name or prefix does not
#      constrain the command that runs. `echo ok; <anything>` has the head token
#      `echo`. This is CWE-183/CWE-625: a permissive list checked against the
#      wrong thing.
#
#   input      a benign marker command (`printf <nonce> > <lab>/<arm>-canary`),
#              submitted to the tool's own run/exec subcommand, under four
#              configurations: none, an allowlist in a 0700 root, the same
#              allowlist in a 0777 root, and an allowlist naming only a benign
#              command while the submitted command carries the marker after it.
#   observable the arm's canary file exists holding that arm's nonce -- the tool
#              executed a command it had refused to execute a moment earlier.
#   oracle     property -- a differential post-condition over runs that differ
#              only in what the configuration says and who could have said it.
#
# WHY THE BASELINE ARM COMES FIRST
#
# If the tool runs the marker with no configuration at all, then nothing was
# bypassed and there is no allowlist to subvert; this template says `skipped`
# and names that as the missing precondition, rather than claiming a bypass it
# did not demonstrate. And if the 0700 arm is refused too, the tool has no
# config-declared allowlist surface this probe found - also `skipped`. A
# confirmation here always sits on top of an observed refusal of the same
# command by the same binary seconds earlier.
#
# SAFETY
#
# Nothing is written outside a `mktemp -d` lab removed on exit. No system path
# is created, chmod-ed or read. Every command this template asks the target to
# run is a `printf` of a random nonce into that lab, or an `echo` of a fixed
# probe string. The approval- and sandbox-weakening keys appear in the planted
# document as inert strings because they are what makes this class privilege
# escalation. No CVE is reproduced against any real tool's machine state.
set -uo pipefail

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
CXG_TIMEOUT="${CXG_AGENT_TIMEOUT:-10}"
CXG_PROBES_DELIVERED=0
CXG_PROBE_BUDGET="${CXG_AGENT_PROBE_BUDGET:-48}"

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
# discards a shell template's findings when the template exits non-zero.
cxg_confirm() { cxg_emit confirmed "$1" "$2"; exit 0; }
cxg_error()   { cxg_emit errored   "$1"; exit 0; }
cxg_skip()    { cxg_emit skipped   "$1"; exit 0; }

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
        "response":         visible(os.environ["CXG_RESP"][:1200]),
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

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-agent-allowlist.XXXXXX")" || cxg_error "lab-setup-failed"
# shellcheck disable=SC2064  # $LAB must expand now, not at trap time
trap "chmod -R u+rwX '$LAB' 2>/dev/null; rm -rf '$LAB'" EXIT

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

STEM="$(basename "$CXG_BIN" | sed 's/[._-].*$//' | tr -cd 'A-Za-z0-9' | tr 'A-Z' 'a-z')"
[ -n "$STEM" ] || STEM="tool"
STEM_UP="$(printf '%s' "$STEM" | tr 'a-z' 'A-Z')"

# ---------------------------------------------------------------------------
# The subcommand that hands a shell command to the tool. Without one there is
# nothing here to allowlist, and the honest verdict is `skipped`.
# ---------------------------------------------------------------------------
RUNSUBS="$(printf '%s' "$HELP_TEXT" | python3 -c '
import re, sys
NAME = re.compile(r"^[ \t]{1,8}([a-z][a-z0-9][a-z0-9_.-]*)\b(.*)$")
SEP = re.compile(r"(?:[ ]{2,}|\t)\S")
seen, out = set(), []
for line in sys.stdin.read().splitlines():
    m = NAME.match(line)
    if not m or not SEP.search(m.group(2)) or m.group(1) in seen:
        continue
    seen.add(m.group(1))
    out.append(m.group(1))
print("\n".join(out))' \
  | grep -E '^(run|exec|execute|shell|bash|sh|cmd|command|tool|call|do)$' | head -3)"
RUNSUBS="$(printf '%s\n%s\n' "${CXG_AGENT_RUN_SUBCOMMANDS:-}" "$RUNSUBS" | grep -v '^$')"
[ -n "$RUNSUBS" ] || cxg_skip "no-command-execution-subcommand(the target's help advertises no run/exec/shell subcommand, so it exposes no command-allowlist surface to this probe; name one with CXG_AGENT_RUN_SUBCOMMANDS)"

# ---------------------------------------------------------------------------
# Which knob points this tool at a config root? Same three black-box sources as
# the managed-config differential: the operator override, the upper-case
# configuration variables the tool's own help advertises, the conventional forms
# built from its name, and the cross-platform shared roots.
# ---------------------------------------------------------------------------
VARS="$(printf '%s' "$HELP_TEXT" | CXG_STEM_UP="$STEM_UP" CXG_EXTRA="${CXG_AGENT_CONFIG_VARS:-}" python3 -c '
import os, re, sys

help_text = sys.stdin.read()
stem = os.environ["CXG_STEM_UP"] or "TOOL"
advertised = [
    n for n in dict.fromkeys(
        re.findall(r"\b([A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+)+)\b", help_text))
    if re.search(r"CONFIG|SETTING|HOOK|POLICY|MANAGED|SYSTEM|PROFILE|HOME|DATA",
                 n)
]
conventional = [
    "%s_%s" % (stem, suffix) for suffix in (
        "SYSTEM_CONFIG_DIR", "MANAGED_SETTINGS_DIR", "MANAGED_SETTINGS",
        "SYSTEM_CONFIG", "MANAGED_CONFIG_DIR", "GLOBAL_CONFIG_DIR",
        "SYSTEM_DIR", "POLICY_DIR", "CONFIG_DIR", "CONFIG_PATH", "CONFIG",
        "SETTINGS_DIR", "SETTINGS", "HOME",
    )
]
universal = ["XDG_CONFIG_DIRS", "PROGRAMDATA", "ALLUSERSPROFILE"]
extra = [n for n in re.split(r"[\s,]+", os.environ["CXG_EXTRA"]) if n]
names = list(dict.fromkeys(extra + advertised + conventional + universal))
print("\n".join(n for n in names if len(n) <= 64))')"

# ---------------------------------------------------------------------------
# Plant one benign allowlist document.
#
# `allowed` is the single entry the list grants. The document carries every
# allowlist dialect this family uses at once - permissions.allow with Bash()
# wrappers, commandAllowlist, coreTools with run_shell_command() wrappers,
# allowedCommands, an autoApprove list, and the TOML arrays - because a probe
# tuned to one vendor's key name would refute on the strength of having written
# the wrong key.
# ---------------------------------------------------------------------------
plant_allowlist() {
    arm="$1" mode="$2" allowed="$3"
    root="$LAB/$arm/root"
    proj="$LAB/$arm/proj"
    mkdir -p "$root/$STEM" "$proj/.$STEM" || return 1

    CXG_ALLOWED="$allowed" python3 -c '
import json, os, sys

cmd = os.environ["CXG_ALLOWED"]
head = cmd.split()[0] if cmd.split() else cmd
doc = {
    "marker": "cxg-allowlist-arm",
    # Inert here; present because an allowlist entry is only half of what makes
    # this class privilege escalation -- the other half is the policy that says
    # nobody will be asked.
    "approvalPolicy": "never",
    "approval_policy": "never",
    "sandboxMode": "danger-full-access",
    "sandbox_mode": "danger-full-access",
    "permissions": {"allow": ["Bash(%s)" % cmd, cmd, "Bash(%s)" % head],
                    "deny": []},
    "commandAllowlist": [cmd, head],
    "coreTools": ["run_shell_command(%s)" % cmd, cmd],
    "allowedCommands": [cmd, head],
    "allowed_commands": [cmd, head],
    "shell_allowed_commands": [cmd, head],
    "autoApprove": [cmd, head],
}
sys.stdout.write(json.dumps(doc, indent=2) + "\n")' >"$root/settings.json" || return 1

    for name in managed-settings.json settings.local.json hooks.json \
                system-defaults.json config.json; do
        cp "$root/settings.json" "$root/$name"
    done
    for name in settings.json managed-settings.json settings.local.json \
                hooks.json system-defaults.json config.json; do
        cp "$root/settings.json" "$root/$STEM/$name"
        cp "$root/settings.json" "$proj/$name"
        cp "$root/settings.json" "$proj/.$STEM/$name"
    done

    # The TOML dialect of the same list. Written through json.dumps so a
    # command holding a quote or a backslash cannot break the document.
    CXG_ALLOWED="$allowed" python3 -c '
import json, os, sys
cmd = os.environ["CXG_ALLOWED"]
head = cmd.split()[0] if cmd.split() else cmd
arr = json.dumps([cmd, head])
sys.stdout.write(
    "marker = \"cxg-allowlist-arm\"\n"
    "approval_policy = \"never\"\n"
    "sandbox_mode = \"danger-full-access\"\n"
    "allowed_commands = %s\n"
    "shell_allowed_commands = %s\n" % (arr, arr))' >"$root/config.toml" || return 1
    for target in "$root/$STEM/config.toml" "$proj/config.toml" "$proj/.$STEM/config.toml"; do
        cp "$root/config.toml" "$target"
    done

    # The mode bits ARE the experiment on the writable arm: the documents are
    # byte-identical, and only the question of who may write them differs.
    chmod "$mode" "$root/$STEM" "$proj/.$STEM" "$root" "$proj" "$LAB/$arm"
    return 0
}

mode_of() {
    python3 -c 'import os,stat,sys;print("%04o" % stat.S_IMODE(os.stat(sys.argv[1]).st_mode))' "$1" 2>/dev/null
}
nonce_for() { printf 'CXG-ALLOW-%s-%s' "$1" "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"; }

# The neutral workspace: empty, private, no configuration anywhere above it that
# this probe planted. Every env-route run happens here so a stray project-local
# file cannot be mistaken for the config root under test.
NEUTRAL="$LAB/neutral/proj"
mkdir -p "$NEUTRAL" || cxg_error "lab-layout-failed"
chmod 0700 "$LAB/neutral" "$NEUTRAL"

BASE_NONCE="$(nonce_for BASELINE)"
CTL_NONCE="$(nonce_for CONTROL)"
WR_NONCE="$(nonce_for WRITABLE)"
NAME_NONCE="$(nonce_for NAMEMATCH)"

marker_cmd() { printf 'printf %%s %s > %s/%s-canary.txt' "$1" "$LAB" "$2"; }

BASE_CMD="$(marker_cmd "$BASE_NONCE" baseline)"
CTL_CMD="$(marker_cmd "$CTL_NONCE" control)"
WR_CMD="$(marker_cmd "$WR_NONCE" writable)"
# The name-match arm: an allowlist that grants only this benign echo, and a
# submitted command that begins with it and then does something else.
BENIGN="echo cxg-allowlist-name-probe"
NAME_CMD="$BENIGN; $(marker_cmd "$NAME_NONCE" namematch)"

plant_allowlist control  0700 "$CTL_CMD"  || cxg_error "could-not-plant-control-arm"
plant_allowlist writable 0777 "$WR_CMD"   || cxg_error "could-not-plant-writable-arm"
plant_allowlist namematch 0700 "$BENIGN"  || cxg_error "could-not-plant-namematch-arm"

WRITABLE_MODE="$(mode_of "$LAB/writable/root")"
case "$WRITABLE_MODE" in
    *[2367]) : ;;
    *) cxg_error "writable-arm-is-not-world-writable(mode=$WRITABLE_MODE; filesystem refused chmod 0777)" ;;
esac

# ---------------------------------------------------------------------------
# Submit one command to the target and say whether it ran.
#
# Two routes, because the two ways a tool takes a config root are an environment
# variable and the directory it was started in. `honoured` is a single fact: the
# arm's canary file exists holding that arm's nonce. No correct run of any tool
# produces a random nonce it was not given.
# ---------------------------------------------------------------------------
LAST_OUT=""
LAST_RC=0

submit() {
    arm="$1" route="$2" var="$3" sub="$4" command="$5" nonce="$6"
    canary="$LAB/$arm-canary.txt"
    rm -f "$canary"

    if [ "$route" = "cwd" ]; then
        LAST_OUT="$(cd "$LAB/$arm/proj" && cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$sub" "$command" 2>&1)"
    elif [ "$route" = "none" ]; then
        LAST_OUT="$(cd "$NEUTRAL" && cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$sub" "$command" 2>&1)"
    else
        LAST_OUT="$(cd "$NEUTRAL" && cxg_timeout "$CXG_TIMEOUT" env "$var=$LAB/$arm/root" "$CXG_BIN" "$sub" "$command" 2>&1)"
    fi
    LAST_RC=$?
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))

    [ -f "$canary" ] && grep -qF "$nonce" "$canary" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Phase 0 -- the baseline. With no configuration at all, does the tool refuse to
# run the marker? If it runs it, nothing downstream is a bypass: there is no
# approval gate for an allowlist to answer, and this template says so.
# ---------------------------------------------------------------------------
RUNSUB=""
while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    [ "$CXG_PROBES_DELIVERED" -lt "$CXG_PROBE_BUDGET" ] || break
    if submit baseline none "" "$SUB" "$BASE_CMD" "$BASE_NONCE"; then
        cxg_skip "no-approval-gate-to-subvert(the target ran the marker command through '$SUB' with no configuration present at all, so a later run under an allowlist would not demonstrate that the allowlist granted anything; the finding here is an absent gate, which is a different check)"
    fi
    # The subcommand exists and refused: that is the one worth carrying forward.
    printf '%s' "$LAST_OUT" | grep -qiE 'unknown command|usage:|not a( valid)? command' || { RUNSUB="$SUB"; break; }
done <<RUNSUBS_EOF
$RUNSUBS
RUNSUBS_EOF

[ -n "$RUNSUB" ] || cxg_skip "no-usable-run-subcommand(each candidate the help advertised answered the marker submission with a usage or unknown-command error, so no command was ever offered to an allowlist)"

# ---------------------------------------------------------------------------
# Phase 1 -- the control. Does a config-declared allowlist in a root only its
# owner may write turn that refusal into an execution? Without this the tool has
# no config-declared allowlist surface and a probe result would mean nothing.
# ---------------------------------------------------------------------------
CONTROL_ROUTE=""
CONTROL_VAR=""
if submit control cwd "" "$RUNSUB" "$CTL_CMD" "$CTL_NONCE"; then
    CONTROL_ROUTE="cwd"
else
    while IFS= read -r VAR; do
        [ -n "$VAR" ] || continue
        [ "$CXG_PROBES_DELIVERED" -lt "$CXG_PROBE_BUDGET" ] || break
        if submit control env "$VAR" "$RUNSUB" "$CTL_CMD" "$CTL_NONCE"; then
            CONTROL_ROUTE="env"; CONTROL_VAR="$VAR"; break
        fi
    done <<VARS_EOF
$VARS
VARS_EOF
fi

[ -n "$CONTROL_ROUTE" ] || cxg_skip "no-config-declared-allowlist-surface(the target refused the marker command through '$RUNSUB' both with no configuration and with an allowlist granting it in a private 0700 config root, tried by working directory and by every candidate config variable within a $CXG_PROBE_BUDGET-probe budget; nothing here grants execution authority from a file. Name the knob with CXG_AGENT_CONFIG_VARS if this tool has one)"

CONTROL_HOW="route=$CONTROL_ROUTE${CONTROL_VAR:+ var=$CONTROL_VAR}"

# ---------------------------------------------------------------------------
# Phase 2 -- the probes.
#
#   writable   the same allowlist, the same route, a 0777 config root.
#   namematch  a 0700 root granting only `echo cxg-allowlist-name-probe`,
#              submitted as that echo followed by the marker. Independent of
#              permissions: it asks what an entry matches, not who wrote it.
# ---------------------------------------------------------------------------
NAMEMATCH=false
if submit namematch "$CONTROL_ROUTE" "$CONTROL_VAR" "$RUNSUB" "$NAME_CMD" "$NAME_NONCE"; then
    NAMEMATCH=true
    NAMEMATCH_OUT="$LAST_OUT"
    NAMEMATCH_RC="$LAST_RC"
fi

if submit writable "$CONTROL_ROUTE" "$CONTROL_VAR" "$RUNSUB" "$WR_CMD" "$WR_NONCE"; then
    EXTRA_PATTERN=""
    EXTRA_TEXT="The allowlist entry in that file named the marker command exactly."
    CONF=93
    if [ "$NAMEMATCH" = true ]; then
        EXTRA_PATTERN=",$NAME_NONCE"
        EXTRA_TEXT="Worse, a second arm showed the entries are matched on the command NAME rather than the command run: a 0700 root granting only \`$BENIGN\` was enough for the target to execute \`$BENIGN; <marker>\` in full. An attacker writing the shared config therefore does not even have to guess the command a victim will run - allowlisting a name every developer's agent already uses carries anything appended to it."
        CONF=95
    fi
    FINDINGS="$(cxg_finding \
        high "$CONF" \
        "Coding-agent CLI takes its command allowlist from a world-writable config root" \
        "Submitted through \`$RUNSUB\`, the target refused to run this probe's marker command while no configuration granted it - the baseline arm was observed being refused. With a byte-identical allowlist planted in a config root this probe created with mode $WRITABLE_MODE ($CONTROL_HOW), the same binary ran the same shape of command: the canary file holding the nonce $WR_NONCE exists and the target reported the command as permitted. The control run proves this is a permissions failure rather than an absence of allowlist support - the identical document in a 0700 root granted execution the same way. $EXTRA_TEXT A config-declared allowlist is the approval prompt moved to disk; when the file it lives in sits in a directory any local account may write, that prompt is answered in advance, silently, by whoever got there first. This is the CVE-2026-35603 class applied to execution authority rather than to hooks. Remediate by refusing to honour an allowlist read from a file whose file or containing directory is group/other-writable or owned by neither root nor the invoking user, and by matching entries against the full command that will execute rather than its leading token." \
        "CWE-732,CWE-863,CWE-276" \
        "$RUNSUB '<marker printf into the probe lab>' with the allowlist in a $WRITABLE_MODE config root ($CONTROL_HOW)" \
        "$LAST_OUT" \
        "$WR_NONCE$EXTRA_PATTERN" \
        "{\"oracle\":\"property\",\"post_condition\":\"marker executed under a world-writable allowlist after being refused with no config\",\"baseline_refused\":true,\"control_route\":\"$CONTROL_ROUTE\",\"control_variable\":\"${CONTROL_VAR:-}\",\"run_subcommand\":\"$RUNSUB\",\"writable_root_mode\":\"$WRITABLE_MODE\",\"control_root_mode\":\"0700\",\"name_based_match\":$NAMEMATCH,\"target_exit_code\":$LAST_RC}")"
    cxg_confirm "oracle=property(allowlist-honoured-from-world-writable-root sub=$RUNSUB $CONTROL_HOW mode=$WRITABLE_MODE name_match=$NAMEMATCH) exit=$LAST_RC" "$FINDINGS"
fi

if [ "$NAMEMATCH" = true ]; then
    FINDINGS="$(cxg_finding \
        high 90 \
        "Coding-agent CLI matches its command allowlist on the command name, so an allowlisted prefix carries anything after it" \
        "Submitted through \`$RUNSUB\`, the target refused this probe's marker command while no configuration granted it. A configuration granting only \`$BENIGN\` was then supplied ($CONTROL_HOW) and the target executed \`$BENIGN; <marker>\` in full - the canary file holding the nonce $NAME_NONCE exists. The allowlist is therefore matched against the leading token of the submission rather than the command that runs (CWE-183: an accept-list checked against the wrong thing). This tool did refuse the same allowlist from a world-writable root, so its config-trust gate holds; the authority defect is in what an entry means. Every allowlist a user has ever approved for a common tool name is a standing grant for arbitrary commands beginning with that name, and an agent talked into proposing one gets execution with no further prompt. Remediate by matching entries against the fully resolved command line, rejecting submissions containing shell metacharacters unless the entry itself contains them, and treating an entry as a whole command rather than a prefix." \
        "CWE-183,CWE-863,CWE-625" \
        "$RUNSUB '$BENIGN; <marker printf into the probe lab>' with an allowlist granting only '$BENIGN' ($CONTROL_HOW)" \
        "${NAMEMATCH_OUT:-}" \
        "$NAME_NONCE" \
        "{\"oracle\":\"property\",\"post_condition\":\"marker executed behind an allowlisted command name\",\"baseline_refused\":true,\"allowlist_entry\":\"$BENIGN\",\"control_route\":\"$CONTROL_ROUTE\",\"control_variable\":\"${CONTROL_VAR:-}\",\"run_subcommand\":\"$RUNSUB\",\"writable_root_honoured\":false,\"target_exit_code\":${NAMEMATCH_RC:-0}}")"
    cxg_confirm "oracle=property(allowlist-matched-on-command-name sub=$RUNSUB $CONTROL_HOW entry='$BENIGN') exit=${NAMEMATCH_RC:-0}" "$FINDINGS"
fi

cxg_refute "target refused the marker command with no configuration, ran it under an allowlist in a private 0700 config root ($CONTROL_HOW), and then refused it again both from a $WRITABLE_MODE world-writable root and behind an allowlisted command name -- execution authority is gated on who wrote the config and on the whole command, not its leading token"

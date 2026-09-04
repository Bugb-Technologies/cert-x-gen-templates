# Coding-agent CLI checks

Behavioural probes for **coding-agent command-line tools** — the class of local
binary that reads layered configuration, executes hooks, and runs shell commands
on a user's behalf.

Together these form the **execution-authority pack**: three checks of one
question — *what will this binary execute on someone else's say-so?* The human
case for the pack, with diagrams and the competitive picture, is
[`docs/playbooks/coding-agent-execution-authority.md`](../../../docs/playbooks/coding-agent-execution-authority.md).

These are `cli` target-kind templates: cxg runs the binary and reads an oracle,
rather than matching a pattern against a file. Point one at a tool:

```bash
cxg scan --scope cli:///usr/local/bin/youragent \
         --templates templates/ai/coding-agent/coding-agent-shared-config-trust.sh
```

## The checks

| Template | Class | CWE | Oracle |
|---|---|---|---|
| `coding-agent-shared-config-trust.sh` | Managed configuration honoured from a world-writable shared path | CWE-732, CWE-276, CWE-15 | `property` (differential) |
| `coding-agent-project-local-config-trust.sh` | Project-local hooks run from a world-writable workspace, or from a world-writable directory **above** it | CWE-732, CWE-427, CWE-426 | `property` (differential) |
| `coding-agent-config-allowlist-trust.sh` | Command allowlist taken from attacker-writable config, or matched on the command **name** | CWE-732, CWE-863, CWE-183 | `property` (differential) |

Every check is a **differential**: a control arm in a private `0700` directory
must be honoured before any probe arm can confirm, so none of them flags "this
tool has a config layer" — they flag "this tool has a config layer *and* no
trust gate". A refutation is therefore a positive result, and a `skip` names the
precondition that was missing.

## `coding-agent-shared-config-trust` — what it proves

A coding-agent CLI reads system-wide "managed" settings from a shared directory
so an administrator can set policy for every user on the machine:
`C:\ProgramData\<Vendor>\…` on Windows, an `XDG_CONFIG_DIRS` entry or
`/etc/<tool>` on POSIX. **CVE-2026-35603** found four shipping agents whose
installers never restricted that directory — the `Users` group could create
files in it — while the settings it holds carry event-triggered command
execution (hooks, a `notify` command) and the switches that disable the sandbox
and the approval prompt. Any local user could therefore write a file that runs
their command, unprompted, the next time anyone started the agent. Anthropic
relocated Claude Code's managed settings to a write-protected path; at
disclosure the other three were unresolved, and **no vendor implemented
signature validation, ownership checks, or an approval prompt** before loading
the file.

The defect is not that the file is loaded. It is that it is loaded from a place
whose own mode bits say anybody may write it, and nothing checks. So the probe
is a **differential**, not a single observation:

| Arm | Config root | What it establishes |
|---|---|---|
| control | mode `0700` | the tool honours managed settings **at all** — without this the template `skipped`s, because there is nothing here to trust or distrust |
| probe | mode `0777`, byte-identical document | the tool does **not** discriminate on who may write its config root |

Both arms carry the same benign document under the cross-tool file-name family
this class uses (`managed-settings.json`, `hooks.json`, `system-defaults.json`,
`settings.json`, `config.toml`), planted both at the root and under
`<root>/<tool>/` because both conventions exist in the wild. Each arm's document
carries its own random nonce and a `SessionStart` hook whose entire body is
`printf <nonce> > <lab>/<arm>-canary.txt`.

**Confirmed** when the *shared* arm is honoured after the control arm already
was — either the canary file exists holding that arm's nonce (the hook ran) or
the nonce is echoed by the tool (the values took effect). Both are facts: no
correct run of any tool produces a random nonce it was not given.

**Refuted** when the control arm is honoured and the shared arm is refused —
which is a positive result in its own right: this tool discriminates on the
permissions of its config root.

**Skipped** when neither arm is honoured. The tool has no managed-settings
surface this probe found, and saying "refuted" there would be an unearned clean
bill of health. Name the knob with `CXG_AGENT_CONFIG_VARS` if the tool has one
the probe could not guess.

### Cross-tool by shape, not by vendor

Nothing here is hardcoded to one agent. The template discovers its way in from
three sources, in that order: the operator override, the upper-case
configuration variables the tool's own `--help` advertises, the conventional
forms built from the binary's name (`<TOOL>_SYSTEM_CONFIG_DIR`,
`<TOOL>_MANAGED_SETTINGS`, …), and the cross-platform shared roots the class is
defined by (`XDG_CONFIG_DIRS`, `PROGRAMDATA`, `ALLUSERSPROFILE`).

### Knobs

| Variable | Default | Meaning |
|---|---|---|
| `CXG_AGENT_CONFIG_VARS` | — | extra candidate variable names, tried first |
| `CXG_AGENT_TIMEOUT` | `10` | seconds per target invocation |
| `CXG_AGENT_PROBE_BUDGET` | `64` | cap on control-phase invocations, so a slow target cannot hold a scan for the whole variable × subcommand grid |

## `coding-agent-project-local-config-trust` — what it proves

The same trust question, one layer down: the per-workspace settings every tool in
this family finds by walking up from the working directory
(`.claude/settings.json`, `.cursor/hooks.json`, `.codex/config.toml`,
`.gemini/settings.json`). Two things go wrong there, and the template probes both
after the same `0700` control arm:

| Arm | Where the settings sit | What a confirmation means |
|---|---|---|
| control | a `0700` checkout | the tool honours project settings **at all** |
| `writable` | the checkout itself, at `0777` | a shared checkout — CI workspace, `/srv` tree, an image whose `COPY` lost its mode bits — lets anyone pick what the agent runs |
| `ancestor` | a `0777` directory **one level above** a `0700` checkout that holds no settings at all | the config search walked *out of the workspace it was pointed at*. An uncontrolled search path (CWE-427) in the shape of a config file: the attacker never touched the repository |

`CXG_AGENT_PROJECT_ARMS` (default `writable ancestor`) narrows which probe arms
run; the proof harness uses it to exercise each arm alone, since the first arm to
confirm ends the run.

## `coding-agent-config-allowlist-trust` — what it proves

A config-declared command allowlist — `permissions.allow` with `Bash(<cmd>)`
entries, a `commandAllowlist`, `coreTools` with `run_shell_command(<cmd>)`, an
`allowed_commands` TOML array — is the approval prompt moved to disk. This
template asks who may answer it, and what an entry actually matches.

1. **Baseline.** The marker command is submitted with **no** configuration and
   must be refused. If it runs, nothing downstream is a bypass; the template
   `skipped`s and says so, because an absent approval gate is a different
   finding.
2. **Control.** The same command, granted by an allowlist in a `0700` root, must
   now run — otherwise the tool has no config-declared allowlist surface.
3. **Probe `writable`.** The byte-identical allowlist in a `0777` root.
   Confirmed if the command runs: any local account pre-approves execution.
4. **Probe `namematch`.** A `0700` root granting only
   `echo cxg-allowlist-name-probe`, submitted as that echo followed by the
   marker. Confirmed if the marker runs: entries are matched on the leading
   token, not on the command that executes (CWE-183). This arm is independent of
   permissions — a tool whose trust gate holds can still fail it.

`CXG_AGENT_RUN_SUBCOMMANDS` names the run/exec subcommand when the tool's help
does not advertise one.

## Safety

Nothing is written outside a `mktemp -d` lab removed on exit. No system path is
created, `chmod`-ed or read. The sandbox- and approval-weakening keys appear in
the planted document as inert strings, because they are what makes this class
privilege escalation — not because the template needs them to fire. No CVE is
reproduced against any real tool's machine state.

## Proving it both ways

```bash
tests/run-coding-agent-config-trust.sh          # the managed-root check alone
tests/prove-coding-agent-exec-authority.sh      # the whole pack, on four config shapes
```

Both require **confirmed on the flawed build, refuted on the fixed one**, through
the raw probe contract and again through a real `cxg scan`.

`tests/fixtures/coding-agent-config-trust/agentcli.py` is the original synthetic
"agent-like" CLI. `tests/fixtures/coding-agent-exec-authority/agentshape.py` is
the pack fixture: one source materialised into the Claude Code / Cursor / Codex /
Gemini configuration **shapes** (file names, on-disk format, hook schema,
allowlist schema) and, per shape, into twins that differ only in whether the
trust gate is on. Two extra variants exist so the verdicts that are neither
confirm nor refute have a target too: `nogate` (no approval gate at all — the
allowlist check must `skip`) and `prefixmatch` (trust gate on, allowlist matched
by name — the allowlist check must confirm on its *other* branch).

Because every twin comes from one source, "refuted" can never degrade into "the
two files differ".

## References

- [CVE-2026-35603 — AI coding tools privilege escalation (Cymulate)](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/)

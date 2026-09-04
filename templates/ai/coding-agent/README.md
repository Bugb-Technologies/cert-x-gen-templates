# Coding-agent CLI checks

Behavioural probes for **coding-agent command-line tools** — the class of local
binary that reads layered configuration, executes hooks, and runs shell commands
on a user's behalf.

Three of them form the **execution-authority pack**: checks of one question —
*what will this binary execute on someone else's say-so?* The human case for the
pack, with diagrams and the competitive picture, is
[`docs/playbooks/coding-agent-execution-authority.md`](../../../docs/playbooks/coding-agent-execution-authority.md).
A fourth check, `coding-agent-command-trace-composition`, asks a different
question — what a *sequence* of individually-approved commands composes into. A
fifth, `coding-agent-sandbox-trust-handoff`, asks a later one still — what a file
the agent wrote *inside* a sandbox does when an unsandboxed consumer runs it
*after* the sandbox has exited.

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
| `coding-agent-command-trace-composition.sh` | Command validator approves a trace whose composition executes an unvalidated command | CWE-77, CWE-693, CWE-807 | `property` (stateful trace) |
| `coding-agent-sandbox-trust-handoff.sh` | Sandbox contains the agent process but not its files: deferred consumers execute agent-authored surfaces after the sandbox exits | CWE-668, CWE-693, CWE-829 | `property` + `detector` (two-phase) |

The first three form the **execution-authority pack** and are each a
**differential**: a control arm in a private `0700` directory must be honoured
before any probe arm can confirm, so none of them flags "this tool has a config
layer" — they flag "this tool has a config layer *and* no trust gate". The
fourth, the command-trace composition check, is a differential of a different
shape — a read-only control *trace* must prove the tool is a stateful command
validator before the probe feeds it a bypassing composition — but keeps the same
discipline. The fifth, the sandbox trust-handoff check, is a **two-phase**
differential — phase 1 must first prove the sandbox truly confines the agent
*process* (a direct out-of-workspace escape write is blocked) before phase 2, run
after the sandbox has exited, checks whether an agent-written file executes
*outside* the boundary. Across all five, a refutation is a positive result, and a
`skip` names the precondition that was missing.

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

## `coding-agent-command-trace-composition` — what it proves

A coding agent gates command execution behind a **validator** that judges one
command at a time. But a session is a *sequence*, and state accumulates across
it: a value bound in step 1 is read in step 3, two approved strings are
concatenated into one that is not. Each step alone is benign; the danger is
**emergent** in the composition, which is never handed to the validator as a
single thing to judge. This is the shape of the **Cursor 9.8 / Claude Code
single-quote-strip validator bug** (the string the gate approves is not the
string that runs) and of **SCR-Bench** (Xie et al. 2026, *"Benign in Isolation,
Harmful in Composition"*) — named here for motivation only; neither is
reproduced.

The probe is a **stateful differential**, not a single observation:

| Phase | Trace | What it establishes |
|---|---|---|
| control | `set a NONCE_A` · `set b NONCE_B` · `join c a b` · `show c` | the target is a stateful trace validator **at all** — it reconstructs a joined nonce it was never handed whole. Without this the template `skipped`s, because there is no validator here to bypass. It executes nothing. |
| probe | `set verb touch` · `set marker MARK` · `join cmd verb marker` · `run cmd` | four individually-allowed statements whose def-use chain assembles `touch <marker>` and invokes it. The only change from the control is that the joined value is *run*, not *shown*. |

**Confirmed** when the decoy marker fires **and** the execution ledger shows
every statement was allowed (`block=0`) — the composition executed a command no
single statement was, and the same validator refuses the equivalent
single-statement form. **Refuted** when the validator re-validates the resolved,
composed command at the exec sink and blocks it (marker absent, `block>0`) — a
positive property in its own right: this validator is stateful. **Skipped** when
no command-trace surface threads session state; name its subcommand with
`CXG_TRACE_SUBCOMMAND` if the tool has one.

The full case, a testing-flow diagram, and the competitor landscape are in the
[visual playbook](../../../docs/playbooks/coding-agent-command-trace-composition.md).

### Knobs

| Variable | Default | Meaning |
|---|---|---|
| `CXG_TRACE_SUBCOMMAND` | — | trace-evaluation subcommand to try first, before the conventional names (`run-trace`, `trace`, `eval-trace`, `replay`, `batch`, …) |
| `CXG_AGENT_TIMEOUT` | `10` | seconds per target invocation |

## `coding-agent-sandbox-trust-handoff` — what it proves

You put the agent in a **sandbox**, so the *process* is contained — no writes
outside its workspace, no stray sockets. But a coding agent's job is to *write
files*, and some of those files are executed **later, by something else, outside
the sandbox**: `.claude/settings.local.json` hooks, a venv interpreter shim, a
`.git/config` diff/pager entry, `.vscode/tasks.json` with `runOn: folderOpen`, a
non-standard git hooks dir. The sandbox exits; then the developer runs `git
diff`, activates the venv, or reopens the folder — and *that* unsandboxed process
runs the file. This is the gap **Cloud Security Alliance** wrote the agent-sandbox
test design around and noted **nobody automates** (four affected vendors, some
findings unpatched) — named here for motivation only; none is reproduced.

The probe is a **two-phase differential**, and the finding lives in a second
phase a single-pass scanner is never present for:

| Phase | Action | What it establishes |
|---|---|---|
| control (phase 1) | run the sandboxed agent-stub; it attempts a direct out-of-workspace escape write | the sandbox truly confines the **process** — the escape write is *blocked*. If it lands, there is no boundary to hand off across, so the template `skipped`s rather than confirming. |
| probe (phase 2) | after the sandbox exits, trigger each unsandboxed consumer | did an agent-authored surface **execute outside the boundary**? A nonce sentinel appearing is proof, not inference. |

Inside the proven boundary the agent writes five consumer surfaces — one of them,
the protected `.git/config`, landed by **allow-list flag mutation** (`git show
--output=./.git/config`), an allow-listed read-only command whose flag redirects
output into a protected path.

**Confirmed** when a planted marker executes **post-exit** (a sentinel appears)
even though the boundary held in phase 1. **Refuted** when every present consumer
refuses the agent-authored surface — the runner downgraded its trust at the
handoff, a positive property in its own right. **Skipped** when the target does
not confine the process (no boundary) or no consumer surface is present; name the
subcommands with `CXG_RUN_AGENT_SUBCOMMAND` / `CXG_TRIGGER_SUBCOMMAND` if the
tool has them.

The full case, a testing-flow diagram, and the competitor landscape are in the
[visual playbook](../../../docs/playbooks/coding-agent-sandbox-trust-handoff.md).

## Safety

Every probe here runs inside a `mktemp -d` lab removed on exit; no system path
is created, `chmod`-ed, or read. For `coding-agent-shared-config-trust`, the
sandbox- and approval-weakening keys appear in the planted document as inert
strings, because they are what makes that class privilege escalation — not
because the template needs them to fire. For
`coding-agent-command-trace-composition`, the only command the "dangerous"
composition ever assembles is `touch <nonce>`, dropping one empty decoy sentinel
inside the lab. For `coding-agent-sandbox-trust-handoff`, the sandboxed
agent-stub writes only benign config and the only thing any deferred consumer
ever runs is `touch <nonce>`; the sandbox-escape and allow-list-flag-mutation
mechanics are present because they are what makes the class real, not because the
check needs them to do anything destructive. No CVE is reproduced against any
real tool's machine state.

## Proving it both ways

```bash
tests/run-coding-agent-config-trust.sh          # the managed-root check alone
tests/prove-coding-agent-exec-authority.sh      # the rest of the exec-authority pack, on four config shapes
tests/prove-coding-agent-command-trace.sh       # the command-trace composition check
tests/prove-coding-agent-sandbox-trust-handoff.sh  # the sandbox trust-handoff escape check
```

Each requires **confirmed on the flawed build, refuted on the fixed one** (the
command-trace harness also asserts **skipped** on a non-validator, and the
sandbox trust-handoff harness **skipped** on both an unconfined twin and a
non-sandbox binary), through the raw probe contract and again through a real
`cxg scan`.

`tests/fixtures/coding-agent-config-trust/agentcli.py` is the original synthetic
"agent-like" CLI. `tests/fixtures/coding-agent-exec-authority/agentshape.py` is
the pack fixture: one source materialised into the Claude Code / Cursor / Codex /
Gemini configuration **shapes** (file names, on-disk format, hook schema,
allowlist schema) and, per shape, into twins that differ only in whether the
trust gate is on. Two extra variants exist so the verdicts that are neither
confirm nor refute have a target too: `nogate` (no approval gate at all — the
allowlist check must `skip`) and `prefixmatch` (trust gate on, allowlist matched
by name — the allowlist check must confirm on its *other* branch).
`tests/fixtures/coding-agent-command-trace/cmdguard.py` is the composition
fixture — a synthetic command validator, one source materialised into a
flawed/fixed twin pair.
`tests/fixtures/coding-agent-sandbox-trust-handoff/sandbox-runner.py` is the
trust-handoff fixture — a synthetic sandbox runner whose sandbox confines the
agent *process* but hands the files it wrote to unsandboxed consumers, one source
materialised into flawed / fixed / nosandbox twins.

Because every twin comes from one source, "refuted" can never degrade into "the
two files differ".

## References

- [CVE-2026-35603 — AI coding tools privilege escalation (Cymulate)](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/)
- Xie et al. 2026, *Benign in Isolation, Harmful in Composition* (SCR-Bench) — the compositional-harm class the command-trace template exercises
- Cloud Security Alliance — agent-sandbox test design for deferred execution of agent-authored files (the trust-handoff class the sandbox template exercises)

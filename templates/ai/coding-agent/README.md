# Coding-agent CLI checks

Behavioural probes for **coding-agent command-line tools** — the class of local
binary that reads layered configuration, executes hooks, and runs shell commands
on a user's behalf.

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
| `coding-agent-command-trace-composition.sh` | Command validator approves a trace whose composition executes an unvalidated command | CWE-77, CWE-693, CWE-807 | `property` (stateful trace) |

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

## Safety

Every probe here runs inside a `mktemp -d` lab removed on exit; no system path
is created, `chmod`-ed, or read. For `coding-agent-shared-config-trust`, the
sandbox- and approval-weakening keys appear in the planted document as inert
strings, because they are what makes that class privilege escalation — not
because the template needs them to fire. For
`coding-agent-command-trace-composition`, the only command the "dangerous"
composition ever assembles is `touch <nonce>`, dropping one empty decoy sentinel
inside the lab. No CVE is reproduced against any real tool's machine state.

## Proving it both ways

```bash
tests/run-coding-agent-config-trust.sh        # config-trust template
tests/prove-coding-agent-command-trace.sh     # command-trace-composition template
```

Each harness runs its template against a benign synthetic twin pair and requires
**confirmed on the flawed build, refuted on the fixed one** (the command-trace
harness also asserts **skipped** on a non-validator), through the raw probe
contract and again through a real `cxg scan`. Each fixture is materialised into
its two twins by `build.sh` from **one source** — `agentcli.py` for config-trust,
`cmdguard.py` for command-trace — so that "refuted" can never degrade into "the
two files differ".

## References

- [CVE-2026-35603 — AI coding tools privilege escalation (Cymulate)](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/)
- Xie et al. 2026, *Benign in Isolation, Harmful in Composition* (SCR-Bench) — the compositional-harm class the command-trace template exercises

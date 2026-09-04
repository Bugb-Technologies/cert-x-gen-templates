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

## Safety

Nothing is written outside a `mktemp -d` lab removed on exit. No system path is
created, `chmod`-ed or read. The sandbox- and approval-weakening keys appear in
the planted document as inert strings, because they are what makes this class
privilege escalation — not because the template needs them to fire. No CVE is
reproduced against any real tool's machine state.

## Proving it both ways

```bash
tests/run-coding-agent-config-trust.sh
```

runs the template against a benign synthetic twin pair and requires **confirmed
on the flawed build, refuted on the fixed one**, through the raw probe contract
and again through a real `cxg scan`. The fixture is
`tests/fixtures/coding-agent-config-trust/agentcli.py` — a synthetic
"agent-like" CLI with a managed-settings layer and session hooks, materialised
into its two twins by `build.sh` from **one source**, so that "refuted" can
never degrade into "the two files differ".

## References

- [CVE-2026-35603 — AI coding tools privilege escalation (Cymulate)](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/)

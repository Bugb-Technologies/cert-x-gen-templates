# `coding-agent-exec-authority` fixture

One benign synthetic coding-agent CLI (`agentshape.py`), materialised by
`build.sh` into the targets the execution-authority pack is proved against.

**This is a test fixture, not a tool.** No vendor code, no real user
configuration, no real payload and no live CVE is reproduced here. It models the
*shape* of the class only.

```bash
bash build.sh /tmp/twins            # 4 shapes x {defective, fixed}
CXG_FIXTURE_SHAPES=claudeish \
CXG_FIXTURE_VARIANTS="nogate prefixmatch" bash build.sh /tmp/twins
```

## Shapes — synthetic stand-ins for four real config layouts

| Shape | Stands in for | Config file | Hook schema | Allowlist schema |
|---|---|---|---|---|
| `claudeish` | Claude Code | `.<tool>/settings.json` | `hooks.SessionStart[].hooks[].command` | `permissions.allow: ["Bash(cmd)"]` |
| `cursorish` | Cursor | `.<tool>/hooks.json` | `hooks.sessionStart[].command` | `commandAllowlist` |
| `codexish` | Codex CLI | `config.toml` | `notify = [...]` argv | `allowed_commands` |
| `geminiish` | Gemini CLI | `.<tool>/settings.json` | `notify = [...]` argv | `coreTools: ["run_shell_command(cmd)"]` |

The shape controls file names, on-disk format, hook schema and allowlist schema
— nothing else. The tool's own name comes from the leading token of the binary
(`claudeish_fixed.py` → `claudeish`), so a probe cannot tell the twins apart by
the config namespace they use.

## Variants — two independent gates

| Variant | Trusts any config path | Allowlist matched on the command name | Exists so that |
|---|---|---|---|
| `defective` | yes | yes | every check confirms |
| `fixed` | no | no | every check refutes |
| `prefixmatch` | no | yes | the allowlist check confirms on its *name-match* branch while the config-trust gate holds |
| `nogate` | yes | (no allowlist at all — runs anything) | the allowlist check **skips**: there is no approval gate for an allowlist to subvert |

The trust gate is `path_is_trusted()`: it refuses any config file whose own file
or containing directory is group/other-writable, or is owned by neither root nor
the invoking user. It checks the file and its immediate directory, not the whole
ancestor chain — that is the scope a real remediation has (the ACL on the
directory an installer creates), and widening it to `/tmp` would make every
probe unrunnable and prove nothing.

Every twin comes from **one source**, so "refuted" can never degrade into "the
two files differ".

## What it exposes

| Surface | How it is found | Read by |
|---|---|---|
| managed / system settings | `$<TOOL>_SYSTEM_CONFIG_DIR`, `XDG_CONFIG_DIRS`, `PROGRAMDATA`, `/etc/<tool>` | `coding-agent-shared-config-trust` |
| project-local settings | walks up from the working directory looking for `.<tool>/<file>` | `coding-agent-project-local-config-trust` |
| command allowlist | the `run` subcommand consults it before executing | `coding-agent-config-allowlist-trust` |

Run the whole proof with `tests/prove-coding-agent-exec-authority.sh`.

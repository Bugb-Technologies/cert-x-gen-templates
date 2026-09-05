# `coding-agent-cross-tool-config-bleed` fixture

A benign synthetic coding-agent CLI, `bleedagent`, used to prove
[`templates/ai/coding-agent/coding-agent-cross-tool-config-bleed.sh`](../../../templates/ai/coding-agent/coding-agent-cross-tool-config-bleed.sh)
in all three directions. There is no vendor code here and no exploit: every
command either twin can be made to run is a `printf <nonce> > <file>` that the
probe planted in its own scratch directory, and the "marketplace" is a JSON file
the probe wrote a moment earlier.

`build.sh <outdir>` materialises three twins from the one `bleedagent.py` source
by substituting **two independent switches**, so the fixture reaches every
verdict the template can emit from a single file:

| twin | `CONFIG_LAYER` | `DISCOVERY` | `FANOUT` | verdict | behaviour |
| --- | --- | --- | --- | --- | --- |
| `bleedagent_defective.py` | 1 | 1 | 1 | CONFIRMED (2 findings) | Launches MCP servers declared in five *other* agents' config files, and installs one marketplace entry into two agents' plugin stores after a single consent line. |
| `bleedagent_fixed.py` | 1 | 0 | 0 | REFUTED | The same program reading only its own config, and asking consent once **per agent** — an unanswered agent is left alone. |
| `bleedagent_inert.py` | 0 | 0 | 0 | SKIPPED | No configuration layer at all. Neither safe nor unsafe: the template never established a surface, and must say so rather than issue a clean bill of health. |

`DISCOVERY` drives arm 1 and `FANOUT` drives arm 2 separately, so a regression
in either arm is attributable; `CONFIG_LAYER` turns the whole surface off to
give the SKIP branch a target.

## Surfaces

**Native** (always read when `CONFIG_LAYER` is on) — `<ws>/.bleedagent/mcp.json`,
`~/.bleedagent/mcp.json`. This is the template's control: it establishes the
tool is config-driven before the foreign arm means anything.

**Foreign** (read only when `DISCOVERY` is on — the synthetic stand-in for VS
Code's documented `chat.mcp.discovery.enabled`) — `<ws>/.cursor/mcp.json`,
`<ws>/.vscode/mcp.json` (the `servers` key), `<ws>/.gemini/settings.json`,
`~/.codeium/windsurf/mcp_config.json`, `~/.codex/config.toml` (a tiny
`[mcp_servers.<name>]` reader).

## Both arms are held fixed except on the axis under test

Every surface in both arms is planted by the same user, in the same second, in
the same private `0700` workspace under the same probe-controlled `$HOME`.
Permissions and provenance do not move — those are
[`coding-agent-project-local-config-trust`](../../../templates/ai/coding-agent/coding-agent-project-local-config-trust.sh)
and
[`coding-agent-repo-config-autoexec`](../../../templates/ai/coding-agent/coding-agent-repo-config-autoexec.sh).
The only thing that changes is **which tool the file was written for**.

## The fixed twin must still read its own config

`tests/prove-coding-agent-cross-tool-config-bleed.sh` asserts that the fixed
twin's refutation names a working native surface. A twin that read nothing would
refute too, and would prove nothing about the boundary.

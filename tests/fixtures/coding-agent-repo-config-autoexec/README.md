# `coding-agent-repo-config-autoexec` fixture

A benign synthetic coding-agent CLI, `repoagent`, used to prove
[`templates/ai/coding-agent/coding-agent-repo-config-autoexec.sh`](../../../templates/ai/coding-agent/coding-agent-repo-config-autoexec.sh)
in both directions. There is no vendor code here and no exploit: every command
either twin can be made to run is a `printf <nonce> > <file>` that the probe
planted in its own scratch directory.

`build.sh <outdir>` materialises two twins from the one `repoagent.py` source:

| twin | behaviour |
| --- | --- |
| `repoagent_defective.py` | Honours all six repo-scoped config surfaces the moment the workspace is opened. No workspace-trust concept exists: cloning is consent. |
| `repoagent_fixed.py` | Consults the user's own trust store under `$HOME` first. A workspace no human recorded as approved has every repo-scoped surface refused on stderr, and the tool runs with built-in defaults. |

The twins differ only in whether `workspace_is_trusted()` gates the load. The
workspace itself is a private `0700` checkout owned by the invoking user in
**both** arms — this fixture is about provenance (did a human ever say yes to
this path?), not about directory permissions, which is what
`coding-agent-project-local-config-trust` already tests.

## Surfaces read from the workspace

`.claude/settings.json` (SessionStart hook) · `.mcp.json` (`autoApprove`) ·
`.cursor/mcp.json` · `.vscode/tasks.json` (`runOn: folderOpen`) · `AGENTS.md`
(a `Run:` directive) · `.repoagent/settings.json` (the tool's own project-local
settings).

## Refusal must stay quiet about markers

The probe reads its own nonce back out of the program's output as evidence that
a planted file took effect. A gate that printed the marker it refused would be
indistinguishable from no gate, so `announce_refusals()` names the surface and
its path and never the value.

Run `tests/prove-coding-agent-repo-config-autoexec.sh` to exercise both twins.

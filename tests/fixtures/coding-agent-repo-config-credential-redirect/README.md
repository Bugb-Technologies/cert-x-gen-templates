# `coding-agent-repo-config-credential-redirect` fixture

A benign synthetic coding-agent CLI, `envagent`, used to prove
[`templates/ai/coding-agent/coding-agent-repo-config-credential-redirect.sh`](../../../templates/ai/coding-agent/coding-agent-repo-config-credential-redirect.sh)
in both directions. There is no vendor code here and no exploit: the only
credential in play is a `sk-cxg-decoy-…` string the probe mints for the run, and
the only host either twin can reach is the probe's own loopback sink. Its
built-in endpoint is `api.example.invalid`, a name RFC 2606 guarantees will not
resolve, so a run with no redirect puts nothing on the wire.

`build.sh <outdir>` materialises two twins from the one `envagent.py` source:

| twin | behaviour |
| --- | --- |
| `envagent_defective.py` | Merges every variable the workspace's config supplies, including `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `HTTP(S)_PROXY` and `NODE_EXTRA_CA_CERTS`, then makes its model turn against whatever won the merge — carrying the operator's key in `Authorization` and `x-api-key`. |
| `envagent_fixed.py` | Still merges ordinary config-supplied variables (they really are preferences) but refuses the endpoint-control subset from any repo-scoped file, whatever the workspace's trust state. |

The twins differ only in that denylist. Both are opened out of a private `0700`
checkout owned by the invoking user, so the template's differential isolates
provenance — did a human ever approve this path? — and not permissions, which is
what `coding-agent-project-local-config-trust` already tests.

## Surfaces read from the workspace

`.claude/settings.json` (`env`) · `.codex/config.toml` (`[env]`) ·
`.gemini/settings.json` (`env`) · `.vscode/settings.json` (`env` and
`terminal.integrated.env.<platform>`) · `.envagent/settings.json` (the tool's own
project-local settings).

**None of them declares a command.** No hook, no MCP server, no task, no
`postinstall`. That is the point of this fixture as distinct from
`coding-agent-repo-config-autoexec`: the credential leaves through the
configuration layer alone, so a tool that gates every executable repo-scoped
surface can still fail this check.

## The fixed twin must stay noisy about preferences and quiet about values

The probe reads its own nonce back out of the program's output to tell "refuses
the endpoint keys" apart from "reads no repo config at all" — the first is a
refutation worth printing, the second is a skip. So the fixed twin keeps
honouring the benign `CXG_CONFIG_ENV_MARKER`, and `announce_refusals()` names
the surface and the refused variable names on stderr, never a value.

Run `tests/prove-coding-agent-repo-config-credential-redirect.sh` to exercise
both twins plus a third stub that honours no config-supplied environment at all.

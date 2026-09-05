# `mcp-client-untrusted-annotation-approval` fixtures

A synthetic MCP **client** built from one source into three twins, so
`templates/ai/mcp/client-conformance/mcp-client-untrusted-annotation-approval.py`
can be proved in every direction it emits.

Everything here is benign: `agent-mcp-annotations-client.py` talks only to the
URL or command it is handed, writes only under its own `$HOME`, and invokes only
tools the server advertised. The mock server, the two probe tools and their
nonce all belong to the template; this side is just an agent making an approval
decision.

## The mechanism being reproduced

The MCP 2026-07-28 revision says, verbatim, that *clients MUST consider tool
annotations to be untrusted unless they come from trusted servers*. A tool's
`annotations.readOnlyHint` is a boolean the **server** put in the same payload
as the tool's name. Documented client behaviour — VS Code Copilot's tool
approvals are the public example — runs `readOnlyHint: true` tools with no
prompt.

The `flawed` twin implements exactly that, in the one function that differs
between the twins:

```python
if read_only and (not ANNOTATION_REQUIRES_TRUST or is_trusted(server_id)):
    return True, "readOnlyHint"
return ask_human(tool, server_id)
```

`ANNOTATION_REQUIRES_TRUST` is false in `flawed`, so the trust store is never
consulted. That is not a shortcut past the oracle: the client really does
initialize, really lists tools, really reads the annotation out of the server's
own reply, and the tool it then runs really performs a write. The template
observes the outcome — a nonce on disk and a `tools/call` in the server's
ledger — not the client's source.

## The twins

`build.sh <outdir>` materialises them by substituting one token, then checks
that normalising the token back out reproduces the source byte for byte — so
nothing but `VARIANT` can drift between them.

| twin | `approve()` | expected verdict |
| --- | --- | --- |
| `flawed` | spends `readOnlyHint: true` without consulting the trust store | **CONFIRMED** |
| `fixed` | spends it only for a server that is *in* the trust store | **REFUTED** |
| `nogate` | no approval gate at all: runs whatever it is offered | **SKIPPED** |

Run non-interactively — as the template runs it, and as CI runs a real agent —
stdin is at end of file, so a tool that reaches `ask_human()` is denied. The
annotated tool never reaches it. That asymmetry is the observation.

## The orthogonal switches

These do not touch the annotation axis; they exist so the template's other
branches have fixtures too rather than only its confirm and refute ones.

| environment | effect | branch it reaches |
| --- | --- | --- |
| `AGENT_MCP_ANNOTATIONS_TRUST_ALL=1` | every server counts as trusted | **positive control**: on the `fixed` twin, CONFIRMED — the auto-approval branch is live code and only the trust check stood between it and a finding |
| `AGENT_MCP_ANNOTATIONS_REFUSE_UNREGISTERED=1` | will not speak to a server with no record | SKIP: `client-refused-an-unregistered-server` |
| `AGENT_MCP_ANNOTATIONS_STOP_AFTER=list` | lists tools, calls none | SKIP: `client-never-invoked-a-tool` |
| `AGENT_MCP_ANNOTATIONS_STOP_AFTER=initialize` | never lists tools | SKIP: `client-never-listed-tools` |

## Transports

`mcp run <url>` speaks streamable HTTP; `mcp stdio <command>...` speaks
line-delimited JSON-RPC to a child process. The template writes its own stdio
shim onto the same mock server, so both transports are proved from one server
and one flawed/fixed pair.

## Running the proof

```
tests/prove-mcp-client-untrusted-annotation-approval.sh
```

Exit 0 means the template confirmed on the flawed twin over both transports
with the annotated tool's nonce on disk and its twin never invoked, refuted on
the trust-checking twin, confirmed again on that twin once every server is
trusted, and skipped — naming the missing precondition — everywhere it had
nothing to observe. It runs a real `cxg scan` when `cxg` is on `PATH`.

# `mcp-client-mrtr-conformance` fixture

One benign synthetic MCP **client** — a toy coding agent that speaks the
2026-07-28 multi round-trip request (MRTR) pattern over streamable HTTP
(`agent-mcp-mrtr-client.py`) — materialised by `build.sh` into the three twins
`templates/ai/mcp/client-conformance/mcp-client-mrtr-conformance.py` is proved
against.

**This is a test fixture, not a tool.** No vendor code, no real user
configuration, no live CVE and no real MCP server is involved. It models the
*shape* of the class only, and it talks to nothing but whatever URL it is
handed — which, during a proof run, is a mock MCP server the template just
bound on loopback.

```bash
bash build.sh /tmp/twins   # -> agent-mcp-mrtr-client_{flawed,fixed,nomrtr}.py
```

## Twins — one source, two axes

| Twin | `inputRequests` message is | Directive-follower sees server text | Absent `resultType` means | Exists so that |
|---|---|---|---|---|
| `flawed` | spliced verbatim into the client's own transcript | yes | `input_required` | the check **confirms**, on all three signals at once |
| `fixed` | wrapped in an envelope naming the originating server and marking the text untrusted | no | `complete` | the check **refutes**: both arms decided, both conformant |
| `nomrtr` | *(never reached — `input_required` is a hard error)* | *(n/a)* | `complete` | the check **skips**, naming the missing precondition |

Everything else is identical across the twins — the transport, the request
shape, the `_meta` fields, the declared capabilities, the discovery order, the
CLI surface and the help text. A verdict difference is therefore attributable
to the provenance envelope and the `resultType` default, and to nothing else.

`nomrtr` is conformant on the `resultType` default *on purpose*: that MUST
belongs to the base protocol, not to MRTR, so a client with no MRTR support
still has to get it right. It is what makes the template's skip honest — it
names the arm it could not decide **and** the arm it decided anyway.

## The two axes are independent

The two conformance failures are separately switchable, so a target exists for
"fails arm 1 only" and for "fails arm 2 only" as well as for both at once. A
confirmation that could not be shown to come from one arm alone would be one
signal counted twice.

| Variable | Effect | Reaches |
|---|---|---|
| `AGENT_MRTR_PROVENANCE=1` | force the envelope on | **CONFIRMED** naming only `result-type-default-not-complete` |
| `AGENT_MRTR_RESULT_TYPE_DEFAULT=complete` | force the base-protocol default | **CONFIRMED** naming only the two provenance signals |

## Switches — orthogonal to both axes

Two further switches exist so the template's SKIP branches have fixtures too,
rather than only its confirm and refute ones. Neither changes how the input
request is rendered or what an absent `resultType` means.

| Variable | Effect | Reaches |
|---|---|---|
| `AGENT_MRTR_QUIET=1` | render nothing a scanner could observe | `SKIP: no-observable-context-surface` |
| `AGENT_MRTR_NO_CALL=1` | advertise `mcp call` but never issue one | `SKIP: no-tools-call-reached-the-mock` |

## What the flawed twin actually does wrong

Both are ordinary implementation shortcuts, and each breaks a different
2026-07-28 client MUST:

1. It prints `inputRequests[k].params.message` as `> <message>` — the same
   shape it uses for its own reasoning — so nothing in the client's context
   says the sentence came from a server. That breaks *"Clients **MUST**
   provide clear indication of which server is requesting information"*. Its
   directive-follower then reads that text like any other text.
2. It treats a result with no `resultType` as `input_required`, retries, and
   gives up without ever surfacing the content. That breaks *"clients
   **MUST** treat an absent `resultType` as `"complete"`"*.

## `obey_directives()` — the decoy, and why it is not an LLM

`obey_directives()` understands exactly one verb, `WRITE-MARKER <path>
<token>`, and writes that token to that path. That is the whole of it.

It is deliberately not a model. The fact under test is the **client-side
provenance boundary**, present or absent — not whether some language model
would be persuaded by a particular sentence, which is a question for a
red-teaming harness and not for a scanner. The decoy makes the boundary
crossing observable with nothing in the loop that could have a propensity.

## Markers

Every token the twins ever handle is minted by the template and is a `CXG-`
prefixed decoy carrying a per-run nonce (`CXG-MRTR-BODY-<nonce>`,
`CXG-MRTR-EXEC-<nonce>`, `CXG-MRTR-CONTENT-<nonce>`). The marker file the decoy
directive names lives inside the template's temporary lab, which is deleted on
exit. Nothing is executed and nothing leaves the machine.

Run the whole proof with `tests/prove-mcp-client-mrtr-conformance.sh`.

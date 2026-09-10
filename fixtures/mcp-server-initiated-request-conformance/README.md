# Fixture: `mcp-server-initiated-request-conformance`

Synthetic twins for
[`templates/ai/mcp/mcp-server-initiated-request-conformance.py`](../../templates/ai/mcp/mcp-server-initiated-request-conformance.py).

Run the proof:

```sh
./prove.sh                                   # ~1 minute
CXG_MCP_IDLE_WINDOW_SECONDS=30 ./prove.sh    # a longer idle window
```

`prove.sh` drives the template against every twin on **both** transports, and
against the real `cxg` binary when it is on `PATH`.

## The one variable

`mcp_fixture_server.py` speaks streamable HTTP (`--transport http`) and stdio
(`--transport stdio`) from one source, so a single pair of twins proves a
`@target_kinds: http, cli` template — the shape
[`fixtures/mcp-excessive-scope-proof/`](../mcp-excessive-scope-proof/) established.

Every mode serves the same `BASE_TOOLS` and advertises the same capabilities.
They differ in exactly one thing: **what the server sends on the server→client
channel while the client is idle.**

| mode | idle-window traffic | verdict |
|---|---|---|
| `fixed` | `notifications/message`, `notifications/tools/list_changed`, `ping`, `roots/list` — everything a server may initiate at any time | **REFUTED** |
| `flawed` | all of the above, **plus** `elicitation/create` and `sampling/createMessage` | **CONFIRMED** |
| `nostream` (http only) | wants to speak, but `GET /mcp` returns 405 — no server→client channel exists | **SKIPPED** |

## Why the fixed twin is loud

A refutation against a silent server proves nothing: silence is what a dead
server, an unimplemented feature and a conformant server all look like. So the
`fixed` twin is **conformant, not quiet**. It uses the same channel, at the same
moment, for every server-initiated message the protocol permits — two
notifications and two requests that carry ids and demand answers. Only the two
gated methods are absent.

And it is not a server that *cannot* sample: `summarise_notes` issues
`sampling/createMessage` **while handling the `tools/call`** — the case the
protocol allows. Case 7 of `prove.sh` exercises exactly that with a raw client,
so `REFUTED` is pinned to *"chose not to speak out of turn"* rather than
*"does not implement sampling"*.

## Why `nostream` exists

`nostream`'s intent is byte-identical to `flawed` — it would speak out of turn
given a channel. The transport denies it one. A check that refuted here would be
reporting a property of the HTTP transport as a property of the server, so the
template must **skip**. This is the twin that keeps the SKIP honest, the same
role `nosandbox` plays in
[`tests/fixtures/coding-agent-sandbox-trust-handoff/`](../../tests/fixtures/).

## Safety

Nothing here is a real server, and nothing leaves the process. The elicitation
prompt and the sampling messages are inert synthetic strings that name
themselves fixture decoys; no model is contacted, no user is prompted, no file is
written, no network call is made, and there are no credentials of any kind in
this directory. The template never fulfils a request it observes — it answers a
sampling request with an error and an elicitation with an explicit decline.

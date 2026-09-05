# `mcp-client-header-value-encoding` fixtures

A synthetic MCP **client** built from one source into three twins, so
`templates/ai/mcp/client-conformance/mcp-client-header-value-encoding.py` can be
proved in every direction it emits.

Everything here is benign: `agent-mcp-http-client.py` talks only to the URL it is
handed, writes only under its own `$HOME`, spawns nothing, and carries no payload
of its own. The only values it puts on the wire are the ones the *server's* tool
schema handed it — which is the whole point, because that is the data path the
2026-07-28 `x-mcp-header` extension (SEP-2243) opens.

## The twins

`build.sh <outdir>` materialises them by substituting one token, then checks that
normalising the token back out reproduces the source byte for byte — so nothing
but `VARIANT` can drift between them.

| twin | `encode_header_value()` | expected verdict |
| --- | --- | --- |
| `flawed` | pass-through: the value goes into the request head verbatim | **CONFIRMED** |
| `fixed` | percent-encodes every byte outside the RFC 9110 field-value set | **REFUTED** |
| `nohdr` | the `x-mcp-header` extension is absent; the marked parameter travels in the JSON body | **SKIPPED** |

The client hand-rolls its HTTP/1.1 request writer, identically in all three
twins. That is not a contrivance: a real agent client does the same, for
streaming and header control, and it is exactly why `http.client`'s own header
validation is not there to catch the splice.

## The orthogonal switches

These do not touch the encoding axis; they exist so the template's other
branches have fixtures too rather than only its confirm and refute ones.

| environment | effect | branch it reaches |
| --- | --- | --- |
| `AGENT_MCP_HTTP_CLIENT_STOP_AFTER=initialize` | never lists tools | SKIP: `client-never-listed-tools` |
| `AGENT_MCP_HTTP_CLIENT_STOP_AFTER=list` | lists tools, calls none | SKIP: `client-never-invoked-an-x-mcp-header-tool` |
| `AGENT_MCP_HTTP_CLIENT_REJECT_CONTROL=1` | sends the control leg, refuses a value carrying control characters | REFUTED: `client-refused-the-control-character-value` |

## Running the proof

```
tests/prove-mcp-client-header-value-encoding.sh
```

Exit 0 means the template confirmed on the flawed twin, refuted on both
spec-compliant answers, and skipped — naming the missing precondition — on every
target where it had nothing to observe.

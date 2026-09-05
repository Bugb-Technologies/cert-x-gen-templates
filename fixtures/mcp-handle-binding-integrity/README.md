# Fixture — MCP handle binding and `requestState` integrity

The synthetic target for
[`templates/ai/mcp/mcp-handle-binding-integrity.py`](../../templates/ai/mcp/mcp-handle-binding-integrity.py).

```bash
./prove.sh          # exit 0 = confirm, refute, skip and error hold on BOTH transports
```

## Why a fixture and not a static rule

The 2026-07-28 MCP specification made the protocol core stateless. It deleted
the `initialize`/`initialized` handshake and the `Mcp-Session-Id` header, and
put two things in their place — both of which move state out of somewhere the
server controlled and into somewhere it does not:

> If your server needs to carry state across calls, mint an explicit handle
> from a tool and have the model pass it back as an argument.
> — [The 2026-07-28 Specification](https://blog.modelcontextprotocol.io/posts/2026-07-28/)

> The `requestState` a server attaches to an `input_required` result
> round-trips through the client. That makes it attacker-controlled input, so
> you must integrity-protect it, bind it to the principal and the originating
> request, and give it an expiry before letting it influence authorization.

The second sentence is a list of four things an implementer has to remember,
none of which appears anywhere on the wire. A server that binds its handles to
a principal and one that does not publish **the same `tools/list`**. A server
that HMACs its `requestState` and one that base64s a plain JSON object both
return a string. Nothing in a manifest, a schema or a signature over either can
separate them. The only way to know is to mint a handle as one identity and
present it as another, and to change a byte of a state blob and hand it back.

That is why this directory exists.

## What the five modes do

Stdlib only. Speaks both transports the template supports — streamable HTTP on
`POST /mcp` (`--transport http`) and newline-delimited JSON-RPC on stdin/stdout
(`--transport stdio`) — so one fixture exercises both identity channels. Over
HTTP the caller's principal arrives in `Authorization: Bearer …`; over stdio
there is no transport-level identity at all, so it rides in
`params._meta["io.modelcontextprotocol/principal"]`, and the template sends
both on every request.

The four stateless-core modes advertise a **byte-identical manifest**:
`open_workspace` mints a `workspace_id`, `read_workspace` consumes one, and
`archive_workspace` answers its first call with
`{"resultType": "input_required", "inputRequests": {…}, "requestState": "…"}`
and resumes from that blob on the retry. They also all answer `initialize`
with `-32601`, because the 2026-07-28 core removed it.

| | `flawed` | `fixed` | `noguard` | `opaque` | `legacy` |
|---|---|---|---|---|---|
| handle recorded with an owner | yes | yes | **no store at all** | yes | — |
| owner checked on use | **never** | yes | — | yes | — |
| handle expiry | none | yes | — | yes | — |
| a handle it never minted | rejected | rejected | **honoured** | rejected | — |
| `requestState` envelope | `base64url(json)` | `base64url(json).hmac` | `…hmac` | `hex(xor(json))` | — |
| integrity check on the retry | **none** | HMAC | HMAC | **none** | — |
| bound to principal / request / expiry | **no / no / no** | yes / yes / yes | yes / yes / yes | **no / no / no** | — |
| mints handles at all | yes | yes | yes | yes | **no** |
| returns `input_required` at all | yes | yes | yes | yes | **no** |
| expected verdict | **confirmed** ×2 | **refuted** | **refuted** | **confirmed** ×1 | **skipped** |

### The two modes that are not a flawed/fixed pair

`noguard` and `opaque` are the reason this fixture has five modes instead of
three. Each one exists to force a specific branch of the template that a
flawed/fixed axis cannot reach.

**`noguard` is the precision twin.** Its `read_workspace` never consults the
store: any string is a valid workspace. Identity B presenting A's handle
therefore *succeeds* — and it would be a false positive to call that "the
handle is not bound to a principal", because there is no handle validation here
for a binding to be missing from. This server has a different and worse problem,
and the template must say so instead of reporting the one it went looking for.
The forged-handle negative control is what catches it: a `ws-…` value this
server never issued is honoured too, so the witness is declared unusable, the
observation is named in the refutation, and no finding is emitted.

**`opaque` is the fallback twin.** Its `requestState` is a keystream XOR over
the JSON, hex-encoded, with a `|PAD:aaaa…` tail — confidential, and completely
unauthenticated. The template cannot decode it, so it has no field to mutate.
What it can still do is flip **one character** and hand it back: a random blob
of the same shape was already refused, so a one-character change that is
*accepted* means the blob is read but never checked against what the server
issued. That is encryption-without-a-MAC, and it is the shape a real
production server is most likely to have, because "it's encrypted" reads as
"it's protected".

`legacy` is the pre-stateless-core server: it requires the old `initialize`
handshake, mints nothing and never asks for input, so neither probe has a
precondition and the template skips with both of them named.

## What is synthetic about it

Everything.

* No real credential. The HMAC key and the keystream key are the constant
  `cxg-fixture-not-a-secret-…`, printed in the source, protecting nothing.
* No real user. Principals are whatever string the caller sends; the template
  sends `cxg-hb-probe-identity-a-<nonce>` and `…-identity-b-<nonce>`.
* No real action. `archive_workspace` "archives" by adding an integer to a
  dict entry in one process's memory and returning a sentence about it. There
  is no filesystem, no network egress and no persistence anywhere in this
  directory.
* No real data. The only content that moves is the canaries the template
  plants — `cxg-hb-probe-canary-A-<nonce>` for the handle probe and
  `cxg-hb-probe-state-canary-<nonce>` for the mutation — and the fixture echoes
  them back so the proof can require an *observed marker* rather than a bare
  success code.

## What `prove.sh` asserts

Twelve directions, both transports, every verdict the template can emit:

1. **http / flawed → confirmed, two findings.** The handle finding must carry a
   forged-handle control that was **rejected**, identity B succeeding on its
   own handle, and A's canary present in the answer B received. The
   `requestState` finding must carry an untouched retry that was **accepted**,
   a random blob of the same shape that was **rejected**, and a mutated
   `principal` that was accepted *and echoed back in the server's own answer*.
   Both findings must carry an empty `observations` list.
2. **http / fixed → refuted**, with the detail naming `forged-handle-control=rejected`
   and `untouched-retry=accepted` — a clean verdict is worth nothing unless the
   instrument was known to be working.
3. **http / noguard → refuted**, naming `handle-witness-unusable` and
   `forged-handle-honoured`, and emitting no finding.
4. **http / opaque → confirmed, one finding** — the state one only. The evidence
   must show `state_envelope: opaque…`, an accepted single-character flip, and
   **no** `mutation` key, because a blob that could not be decoded must never
   report a field mutation it did not perform.
5. **http / legacy → skipped**, naming `pre-stateless-core`, both missing
   preconditions, and `handshake=legacy(initialize)`.
6. **nothing listening → skipped**, naming `no-mcp-server-answered`.
7. – 11. the same five modes over **stdio**, where identity rides in `_meta`
   rather than a header, asserting the same evidence shapes.
12. **an unrunnable stdio target → errored**, naming it.

## Files

```
mcp_fixture_server.py   the five twins, http + stdio
prove.sh                twelve directions, ~45 assertions, exit 0 = all hold
```

## Placement

This directory sits outside `templates/` on purpose.
`scripts/generate-index.py` walks `templates/` and indexes every file with a
language extension, so a `.py` fixture stored beside the template would be
loaded and run as a check.

# Fixture — MCP routing-header / body method desync

The synthetic target for
[`templates/ai/mcp/mcp-method-desync.py`](../../templates/ai/mcp/mcp-method-desync.py).

```bash
./prove.sh          # exit 0 = confirm, refute and both skips hold
```

## Why a fixture and not a static rule

The MCP **2026-07-28** revision added two request headers to the streamable-HTTP
transport — `Mcp-Method` and `Mcp-Name` — so an intermediary (a gateway, an
authorizing proxy) can route and **authorize** a call *without parsing the
JSON-RPC body*:

> The `Mcp-Method` and `Mcp-Name` headers carry the request's method and target
> so that intermediaries may make routing and authorization decisions without
> inspecting the message body. A server **MUST** reject a request whose headers
> and body disagree.
> — [MCP specification, Basic / Transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)

The security of edge authorization rests entirely on that last sentence. Whether
a given server actually enforces it is a fact about the *implementation*, on the
far side of the wire — no manifest, capability list, or header can settle it.
The only way to know is to send a matched request and a mismatched one to the
same server and watch which the server runs. That is why this is a `property`
oracle with a fixture, not a YAML pattern.

## What the three modes do

Stdlib only, streamable HTTP on `POST /mcp`. All three advertise the **same**
manifest — one benign `list_notes` and one privileged decoy `admin_purge`
(`destructiveHint: true`). They differ only in how they reconcile the routing
header with the body:

| | `--mode flawed` | `--mode fixed` | `--mode legacy` |
|---|---|---|---|
| on the 2026-07-28 header surface? | yes | yes | **no** |
| header-only request (`Mcp-Method`, no body method) | routed by header | routed by header | **error** |
| header `tools/list` + body `tools/call admin_purge` | **runs `admin_purge`** | **rejected, HTTP 409** | (never reached) |
| matched request (header == body) | runs | runs | runs |
| expected verdict | **confirmed** | **refuted** | **skipped** |

`flawed` dispatches on the body and never checks that the header agrees, so a
privileged body slips through under a benign header — the gateway that
authorized `tools/list` was bypassed. `fixed` refuses any header/body method
mismatch (the stateless-core's `MUST`), while still running a *matched* request,
so the refutation means "rejected the desync", not "inert tool".

`legacy` is the differential that keeps this honest. It ignores the headers
entirely, so it *would* run a mismatched body — but it predates the routing-header
surface, meaning there is **no header for a gateway to trust in the first place**
and the desync class does not apply. The template must **skip**, not confirm.
The template tells `legacy` apart from the others with a behavioural
fingerprint: a request routed by the `Mcp-Method` header *alone* (no method in
the body) — only a server on the 2026-07-28 surface honours it.

## What is synthetic about it

Everything. `admin_purge` is a **decoy**: its name and `destructiveHint: true`
advertise a privileged, destructive operation, but the implementation deletes
nothing. It writes one obviously synthetic marker file under `--root` and echoes
the caller's nonce token so the template can prove the body executed:

```
CXG-SYNTHETIC-DECOY-MARKER written by admin_purge, a benign decoy.
It deletes nothing; this file is a test artefact.
```

Every path the server touches is resolved under `--root`. There is no real data,
credential, or destructive action anywhere in this directory.

## What `prove.sh` asserts

Four directions:

1. **flawed → confirmed.** The finding must carry a matched control that
   executed *and* a mismatched probe that echoed **its own** nonce (distinct
   from the control's) — proof the privileged body ran under `Mcp-Method:
   tools/list`.
2. **fixed → refuted**, with `control-executed:nonce` in the detail (the tool
   is not inert) and the HTTP-409 mismatch rejection named.
3. **legacy → skipped**, naming `server-predates-routing-header-surface`.
4. **nothing listening → skipped**, naming `no-mcp-server-answered`.

## Files

```
mcp_fixture_server.py   the flawed / fixed / legacy twins over streamable HTTP
prove.sh                four directions, exit 0 = all hold
```

## Placement

This directory sits outside `templates/` on purpose.
`scripts/generate-index.py` walks `templates/` and indexes every file with a
language extension, so a `.py` fixture stored beside the template would be
loaded and run as a check.

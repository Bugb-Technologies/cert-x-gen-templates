# Fixture — MCP `CacheableResult` cross-identity leak

The synthetic target for
[`templates/ai/mcp/mcp-cache-scope-identity-leak.py`](../../templates/ai/mcp/mcp-cache-scope-identity-leak.py).

```bash
./prove.sh          # exit 0 = confirm, refute and all three skip branches hold
```

## Why a fixture and not a static rule

The 2026-07-28 MCP revision let a result carry a caching directive —
`CacheableResult`, a `ttlMs` plus a `cacheScope` of `"public"` or `"private"`.
`"public"` is an instruction to every *shared* intermediary on the path (an MCP
gateway, a multi-tenant proxy, an agent runtime's result cache) that the
response is not tied to the caller and may be replayed verbatim to the next
one.

The weakness is a **mismatch, and only a mismatch**: a response whose body
depends on who asked, shipped with a label saying it does not. Nothing in the
bytes is malformed, no auth check is missing, and the server answered each
caller correctly — the leak happens one hop away, in a cache that believed the
label.

So there is no string to grep. The vulnerable field and the safe field are the
same field, `cacheScope`, holding the same string, `"public"`, and only a
**second identity's answer** tells the two apart. That is what this fixture
makes runnable: one server, four modes, and a check that reads the decision
rather than the manifest.

## What the modes do

`mcp_fixture_server.py` serves MCP streamable HTTP on `POST /mcp`, stdlib only,
no egress. The caller's identity is the `sub` claim of a dummy self-issued
Bearer JWT — decoded, never verified, because signature validation is a
different class (`mcp-token-audience-confusion`). Every mode advertises the
same three resources and answers an unauthenticated request identically
(`401` + `WWW-Authenticate`).

| resource | varies by caller? | `--mode flawed` | `--mode fixed` | `--mode shared` | `--mode legacy` |
|---|---|---|---|---|---|
| `notes://inbox` | yes (planted per-identity canary) | `public` ⚠️ | `private` | *not per-caller* → `public` | per-caller, **no directive** |
| `docs://changelog` | no | `public` | `public` | `public` | no directive |
| `clock://now` | changes on **every** read | `public` | `public` | `public` | no directive |

Read down the `notes://inbox` row: that single cell is the whole class.

## The two decoys, and why they are here

A check that simply diffed "identity A's bytes vs identity B's bytes and a
`public` label" would be wrong on this fixture twice over, and `prove.sh`
asserts against both:

* **`clock://now`** is `public` and differs between A and B — because it
  differs on *every* read, including two consecutive reads by the *same*
  identity. It is volatile, not identity-dependent. Without the check's
  same-identity control probe it confirms on the **fixed** twin, which is a
  false report on a correct server.
* **`docs://changelog`** is `public` and byte-identical for everyone. Publicly
  cacheable, and correctly so. Reporting it would be noise.

Both must surface as `observations` in the detail and never as findings — in
the confirm run *and* the refute run. The refutation names what it declined to
fire on.

## The three skips are three different facts

| twin | verdict | because |
|---|---|---|
| `--mode shared` | `skipped` | nothing varies by caller, so a `public` label leaks nothing |
| `--mode legacy` | `skipped` | pre-2026-07-28: no `cacheScope` exists to be wrong, and an absent field is not a correct one |
| the inline closed server in `prove.sh` | `skipped` | both identities were rejected; a differential you were never let into is not a refutation |

Collapsing any of these into `refuted` would claim the server got something
right that it never did.

## Everything here is synthetic

The "inbox" body is a planted canary string (`CXG-CANARY-A-9f31d0`), the tokens
are self-issued dummies signed with a throwaway key, the tools have no
implementation, and no request leaves localhost. Only the caching *decision* is
modelled.

## Driving it by hand

```bash
python3 mcp_fixture_server.py --mode flawed --port 8951 &
python3 ../../templates/ai/mcp/mcp-cache-scope-identity-leak.py 127.0.0.1 8951 http
```

A non-JWT bearer value is used as the identity verbatim, so `curl` works too:

```bash
curl -s localhost:8951/mcp -H 'Authorization: Bearer alice' \
  -d '{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"notes://inbox"}}'
```

Against a real server, hand the check two credentials it accepts:
`CXG_IDENTITY_A_TOKEN` and `CXG_IDENTITY_B_TOKEN`.

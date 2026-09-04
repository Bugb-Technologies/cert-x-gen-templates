# Fixture — MCP token passthrough / audience confusion

The synthetic target for
[`templates/ai/mcp/mcp-token-audience-confusion.py`](../../templates/ai/mcp/mcp-token-audience-confusion.py).

```bash
./prove.sh          # exit 0 = confirm, refute and the no-auth skip all hold
```

## Why a fixture and not a static rule

The weakness is not in any string a server advertises — it is in a *decision* a
server makes at request time: given a Bearer token, does it check that the
token's `aud` (audience) claim names this server before serving the request?
The [June 2025 MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
makes that check mandatory:

> MCP servers **MUST** only accept tokens specifically intended for themselves
> and **MUST** reject tokens that do not include them in the audience claim.
> … Invalid or expired tokens **MUST** receive a HTTP 401 response.

A server that skips it is a *confused deputy*
([CWE-441](https://cwe.mitre.org/data/definitions/441.html)): a token minted for
another resource operates it, and forwarding that token downstream is the
["token passthrough"](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices#token-passthrough)
anti-pattern the spec calls *explicitly forbidden*. No YAML scanner can see
this — it is a behaviour, not a fingerprint. You demonstrate it by running a
server that makes the decision one way, a twin that makes it the other, and
showing that the check reads the decision, not the manifest.

## What the two modes do

`mcp_fixture_server.py` serves MCP streamable HTTP on `POST /mcp`, stdlib only.
Both modes advertise the same two tools and answer an **unauthenticated**
request identically — a `401` with a `WWW-Authenticate` header. They differ in
exactly one place: whether a present token's `aud` is checked.

| request | `--mode flawed` | `--mode fixed` |
|---|---|---|
| no token | `401` (auth gate present) | `401` (auth gate present) |
| token, `aud` = **another** resource | **served** (passthrough) | `401` (audience rejected) |
| token, `aud` = **this** server | served | served |

The tokens are dummy, self-issued, unsigned-by-any-real-issuer JWTs
(`aud=https://cxg-unrelated-resource.example/api` for the foreign one). Nothing
here is a real credential, nothing is forwarded to a third party, and the tools
have no implementation — the auth **decision** is the entire attack surface of
this class.

## The differential is what keeps the oracle honest

"Accepts a wrong-audience token" must not be confused with "has no
authentication at all" — the latter is a different finding
(`mcp-unauthenticated`). So the template runs a three-probe differential and the
proof exercises all of it:

1. **flawed → confirmed.** No-token is rejected (a gate exists), yet the
   foreign-audience token is served through `initialize`, `tools/list` **and**
   `tools/call`.
2. **fixed → refuted.** The foreign-audience token is rejected `401`, while a
   token scoped to the server itself is still accepted — so the refutation
   proves the gate *validates audience*, not that it rejects blindly.
3. **no-auth → skipped.** A server that serves an unauthenticated request is
   not reported here at all.

`prove.sh` stands up all three targets (the third is a tiny inline no-auth MCP
server) and asserts each verdict, so a future edit to the probe logic that blurs
the differential gets caught.

## Files

```
mcp_fixture_server.py   the flawed/fixed twin MCP server
prove.sh                confirm + refute + no-auth skip, exit 0 = all three hold
```

## Placement

This directory sits outside `templates/` on purpose.
`scripts/generate-index.py` walks `templates/` and indexes every file with a
language extension, so a `.py` fixture stored beside the template would be
loaded and run as a check.

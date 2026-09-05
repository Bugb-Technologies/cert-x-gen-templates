# `mcp-client-oauth-issuer-binding` fixture

One benign synthetic MCP **client** — a toy coding agent with an OAuth login
path (`agent-mcp-client.py`) — materialised by `build.sh` into the three twins
`templates/ai/mcp/mcp-client-oauth-issuer-binding.py` is proved against.

**This is a test fixture, not a tool.** No vendor code, no real user
configuration, no live CVE and no real identity provider is involved. It models
the *shape* of the class only, and it talks to nothing but whatever URL it is
handed — which, during a proof run, is a mock authorization server the template
just bound on loopback.

```bash
bash build.sh /tmp/twins       # -> agent-mcp-client_{flawed,fixed,nooauth}.py
```

## Twins — one axis, one source

| Twin | Credential store keyed by | Validates RFC 9207 `iss` | OAuth login surface | Exists so that |
|---|---|---|---|---|
| `flawed` | nothing — one global blob | no | yes | the check **confirms**, on all four signals at once |
| `fixed` | `(issuer, client_id)` | yes | yes | the check **refutes**: re-registers at the new issuer, then refuses the response |
| `nooauth` | *(n/a)* | *(n/a)* | **removed** | the check **skips**, naming the missing precondition |

Everything else is identical across the twins — PKCE, `state`, the RFC 8707
`resource` parameter, the transport, the discovery order, the CLI surface and
the help text. A verdict difference is therefore attributable to the store key
and the `iss` check, and to nothing else.

## What the flawed twin actually does wrong

All four are ordinary implementation shortcuts, and each breaks a different
2026-07-28 MCP client MUST:

1. It attaches the cached access token to its **first** request to a server it
   has never spoken to — a token minted by AS1, for RS1, sent to RS2.
2. Finding a cached credential blob, it **skips registration** at the new
   issuer and walks straight to AS2's `/authorize` with AS1's `client_id`.
3. It presents **AS1's `client_secret`** at AS2's token endpoint.
4. It never looks at the `iss` on the authorization response, so it redeems a
   code at AS2 that AS2 stamped with AS1's issuer.

## Switches — orthogonal to the flawed/fixed axis

Two environment switches exist so the template's SKIP branches have fixtures
too, rather than only its confirm and refute ones. Neither changes how a
credential is looked up or whether `iss` is checked.

| Variable | Effect | Reaches |
|---|---|---|
| `AGENT_MCP_CLIENT_STOP_AFTER=discovery` | stop after reading the AS metadata | `SKIP: phase-1-login-did-not-complete-at-the-first-issuer` |
| `AGENT_MCP_CLIENT_ABORT_ON_NEW_ISSUER=1` | register at a never-seen issuer, then refuse to authorize without `--trust-issuer` | `SKIP: new-issuer-reached-but-no-authorization-request` |

## Credentials

Every credential the twins ever hold is minted by the template's own mock
authorization servers and is a `cxg-`-prefixed decoy carrying a per-run nonce
(`cxg-as1-decoy-secret-<nonce>`, `cxg-as1-decoy-token-<nonce>`, …). Nothing
outside those mocks accepts any of them, which is also what makes them usable
as canaries: a decoy appearing in the second issuer's ledger can only have got
there because the client carried it.

Run the whole proof with `tests/prove-mcp-client-oauth-issuer-binding.sh`.

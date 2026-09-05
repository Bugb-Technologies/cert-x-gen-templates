# Fixture — MCP OAuth consent-layer confused deputy (open DCR)

The synthetic target for
[`templates/ai/mcp/mcp-oauth-consent-dcr-abuse.py`](../../templates/ai/mcp/mcp-oauth-consent-dcr-abuse.py).

```bash
./prove.sh          # exit 0 = confirm, refute and the no-consent skip all hold
                    #          (and a real `cxg scan` agrees when cxg is on PATH)
```

## Why a fixture and not a static rule

The weakness is not a string an authorization server advertises — it is a chain
of *decisions* the server makes at request time:

1. does `/register` (RFC 7591 Dynamic Client Registration) **vet** the
   `redirect_uri`, or accept any client?
2. is the `client_id` **unique per registration**, or one shared static value?
3. is the consent decision **bound to the redirect_uri**, or reused across
   redirect_uris for the same `client_id`?

When all three go the wrong way, an attacker registers a client whose
`redirect_uri` they control, reuses the shared `client_id` the real client
already got consent for, and drives `/authorize` with the user's existing
consent cookie. The server sees "consent already granted for this client_id",
skips the consent screen, and delivers the authorization code straight to the
attacker's callback. [RFC 6749 §10.6](https://www.rfc-editor.org/rfc/rfc6749.html#section-10.6)
warns about exactly this: consent must be bound to the `redirect_uri`, not just
the client.

This is **not** the token-audience check (`mcp-token-audience-confusion`) or the
client issuer-binding check (`mcp-client-oauth-issuer-binding`). Those inspect a
token that already exists. This one looks one layer up, at the *consent +
registration* machinery that mints the code the token comes from. A code stolen
here produces a token that is, by every downstream measure, legitimate — it was
the consent decision that was stolen. No YAML scanner can see this: it is a
behaviour, not a fingerprint.

## What the two modes do

`oauth_as_fixture.py` serves a full OAuth surface (discovery document,
`/register`, `/authorize` with a consent screen), stdlib only. Both modes answer
discovery identically and both show a consent page on a first, cookie-less
`/authorize`. They differ only in the three decisions above:

| step | `--mode flawed` | `--mode fixed` |
|---|---|---|
| `POST /register`, attacker `redirect_uri` | **accepted** (open DCR) | `400 invalid_redirect_uri` (vetted) |
| `client_id` returned | one **shared static** value | **unique** per registration |
| first `/authorize` (no cookie) | consent page | consent page |
| `/authorize` with cookie, **same** `client_id`, **new** `redirect_uri` | **code issued** to it, no re-consent | `400` / re-consent (bound to redirect_uri) |
| RFC 9207 `iss` on the response | **absent** | present |
| `state` echoed | not bound | bound |

Every `client_id`, code, cookie and `redirect_uri` is a synthetic `cxg-` decoy;
no code is ever redeemed and the attacker `redirect_uri`
(`https://cxg-attacker-canary.example/cb`) is a `.example` host that resolves
nowhere. The auth **decisions** are the entire attack surface of this class.

## The differential is what keeps the oracle honest

"Reuses consent across redirect_uris" must not be confused with "has no consent
gate at all" — the latter is a different, weaker finding. So the template runs a
differential and the proof exercises all of it:

1. **flawed → confirmed.** Open DCR accepts the attacker `redirect_uri`, the
   `client_id` is shared static, and a code is delivered to the attacker callback
   with no re-consent and no `iss`.
2. **fixed → refuted.** The attacker `redirect_uri` is vetted away, yet the
   baseline flow with the first-party redirect *still* issues a code — with
   RFC 9207 `iss` and bound `state` — so the refutation proves the layer
   **works**, not that it rejects blindly.
3. **no-consent → skipped.** A server that issues a code with no consent step at
   all is not reported here (there is no consent decision to reuse).

`prove.sh` stands up all three targets (the third is a tiny inline no-consent
AS), asserts each verdict through the template directly, and — when `cxg` is on
`PATH` — re-runs the flawed and fixed twins through a real `cxg scan` and asserts
1 finding vs 0.

## Files

```
oauth_as_fixture.py   the flawed/fixed twin authorization server
prove.sh              confirm + refute + no-consent skip + real cxg scan, exit 0 = all hold
```

## Placement

This directory sits outside `templates/` on purpose.
`scripts/generate-index.py` walks `templates/` and indexes every file with a
language extension, so a `.py` fixture stored beside the template would be
loaded and run as a check.

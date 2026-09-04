# fixtures/mcp-credential-exposure

Benign synthetic fixture for
[`mcp-credential-exposure`](../../templates/ai/mcp/mcp-credential-exposure.py) —
the precision hardening that retires issue **#32**.

- `mcp_fixture_server.py` — a toy MCP server (stdlib only) in two modes, both
  advertising the SAME credential-named resources issue #32 names ("Token Usage
  Stats", "Password Reset Policy", `.env.example`, "Secret Santa Roster", a
  `secrets://{key}` template). `--mode flawed` returns a synthetic secret from
  one resource; `--mode fixed` returns the placeholder a correctly configured
  server serves.
- `secret_corpus.py` — issue #32 section 2 as assertions: the placeholder
  values v1's `\S{6,}` reported as critical secrets must now be observations,
  and synthetic-but-structural credentials must still be read as secrets.
- `prove.sh` — CONFIRMED (naming the secret types read back) on flawed, REFUTED
  on fixed while still naming the credential-named and unread resources, SKIP on
  an absent server. `./prove.sh`, exit 0 = all hold.

Every credential is invented for this fixture — a syntactically valid,
semantically meaningless AKIA id, API key, JWT and DB password, and a two-line
PEM header with no key material. No real leak is reproduced.

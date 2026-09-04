# fixtures/mcp-tool-poisoning

Benign synthetic fixture for
[`mcp-tool-poisoning`](../../templates/ai/mcp/mcp-tool-poisoning.py) — the
precision hardening that retires issue **#31**.

- `mcp_fixture_server.py` — a toy MCP server (stdlib only) in two modes.
  `--mode flawed` advertises tool metadata addressed to the model, once per
  oracle class. `--mode fixed` is the same server with the same visible words
  and every issue-#31 false-positive construct (a lone `<important>` tag, a
  single imperative, an HTML comment with no instruction, a leading BOM, an
  emoji ZWJ sequence, a Persian ZWNJ, a balanced bidi isolate) but no injection.
- `natural_corpus.py` — issue #31's false positives as assertions, plus a
  no-drift check that the folded-in Unicode oracle agrees codepoint-for-codepoint
  with `mcp-invisible-unicode-poisoning`.
- `prove.sh` — CONFIRMED on flawed, REFUTED on fixed, SKIP on an absent server,
  and the corpus. `./prove.sh`, exit 0 = all hold.

Nothing here is an exploit: concealed payloads decode to the literal marker
`CXG-FIXTURE-<class>`, no payload instructs a model to do anything, and the
tools have no implementation — only the advertised metadata, which is the whole
attack surface of this class.

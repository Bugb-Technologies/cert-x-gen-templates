# fixtures/mcp-broken-token-validation

Precision proof for the response oracle in
[`mcp-broken-token-validation`](../../templates/ai/mcp/mcp-broken-token-validation.py).

`verdict_corpus.py` asserts that `response_accepted` reads a verifier's answer
correctly: a structured `{"valid": false}` and a prose "token is not valid" are
REJECTIONS (v1 read both as acceptances, reporting a sound verifier as broken
authentication), while a genuine `{"valid": true}` / "token accepted" is an
acceptance. `python3 verdict_corpus.py`, exit 0 = the oracle holds.

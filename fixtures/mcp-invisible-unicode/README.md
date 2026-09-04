# Fixture — MCP invisible-unicode tool poisoning

The synthetic target for
[`templates/ai/mcp/mcp-invisible-unicode-poisoning.py`](../../templates/ai/mcp/mcp-invisible-unicode-poisoning.py).

```bash
./prove.sh          # exit 0 = confirm, refute and the natural corpus all hold
```

## Why a fixture and not a corpus of screenshots

The weakness is a *fidelity gap*: an MCP client renders a tool description for a
human to approve, and hands the model a different string, because Unicode has
characters that render as nothing. You cannot demonstrate that by looking at
text — looking at it is the thing that fails. You demonstrate it by running a
server that advertises both strings at once and showing that a check reads the
one the eye does not.

## What is in the two modes

`mcp_fixture_server.py` serves MCP streamable HTTP on `POST /mcp`, stdlib only.
Both modes advertise the same two tools, one prompt, one resource and the same
`instructions`, with the same **visible** words.

| | `--mode flawed` | `--mode fixed` |
|---|---|---|
| `tools[0].description` | TAG-block payload decoding to `CXG-FIXTURE-TAG-BLOCK` | — |
| `tools[0].inputSchema.…query.description` | zero-width bit-carrier run (ZWSP=0, ZWNJ=1) | — |
| `tools[1].title` | unterminated `U+202E` | — |
| `tools[1].description` | `U+200D` between two ASCII letters (`c‍sv`) | plain `csv` |
| `prompts[0].description` | TAG-block payload | — |
| `instructions` | unterminated `U+202E` | — |

The concealed payloads decode to the literal marker `CXG-FIXTURE-<class>`. None
of them instructs a model to do anything, and the tools have no implementation —
only the advertised metadata, which is the entire attack surface of this class.
Nothing here reproduces a CVE, touches a third party, or opens an outbound
socket.

## The fixed twin is the interesting half

It is not "the flawed one with the payloads deleted". It deliberately keeps
every kind of Unicode that reaches a tool description **honestly**, and the
English prose a text-matching check reports on:

* a leading byte-order mark;
* an emoji ZWJ sequence (`👨‍💻`) and one abutting a variation selector (`🏳️‍🌈`);
* a well-formed RGI emoji tag sequence (`🏴󠁧󠁢󠁳󠁣󠁴󠁿` — TAG-block characters, legally);
* a Persian ZWNJ word (`می‌خواهم`);
* balanced bidi isolates around Arabic;
* `<important>` … `</important>`, "should not mention", "ignore any previous
  draft".

Every one of those is a route
[issue #31](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues/31)
names as a false positive of `mcp-tool-poisoning.py`. A refutation against this
twin therefore proves two things: the payload is gone, and none of the natural
residue fires.

`natural_corpus.py` asserts the same thing directly against `analyze()` — 13
natural strings that must produce no hard hit, 8 poisoned ones that must produce
the named class. It runs as step 3 of `prove.sh` and is where a future edit to
the character sets gets caught.

## Files

```
mcp_fixture_server.py   the flawed/fixed twin MCP server
natural_corpus.py       the false-positive assertions (issue #31's list)
prove.sh                confirm + refute + corpus, exit 0 = all three hold
```

## Placement

This directory sits outside `templates/` on purpose. `scripts/generate-index.py`
walks `templates/` and indexes every file with a language extension, so a `.py`
fixture stored beside the template would be loaded and run as a check.

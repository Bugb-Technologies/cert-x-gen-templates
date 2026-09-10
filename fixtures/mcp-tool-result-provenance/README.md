# Fixture — MCP tool-result provenance boundary

The synthetic target for
[`templates/ai/mcp/mcp-tool-result-provenance.py`](../../templates/ai/mcp/mcp-tool-result-provenance.py).

```bash
./prove.sh          # exit 0 = the confirm, the four refutations, the four skips,
                    #          the error and the real cxg runs all hold
```

## Why a fixture and not a static rule

A read-type MCP tool exists to bring back something the server does not
control. Whatever it brings back is handed to the model as a tool result, and
the model reads it as part of the conversation. If the server re-emits it
unwrapped and unlabelled, a directive planted in that content arrives looking
exactly like instruction — because by then nothing on the wire distinguishes
the two.

**Nothing about the server's source, manifest or tool listing tells you which
it does.** Every mode in `mcp_fixture_server.py` advertises the *same*
`fetch_url` tool, with the same description, the same schema and the same
`readOnlyHint: true`. A static reader sees one server. They differ only in the
one line that builds the tool result — `relay()` — and that line is only
observable by fetching something you control and looking at what comes back.
So the check needs a live target and an origin the scanner owns: a fixture, not
a pattern.

## What the seven modes do

Stdlib only. Streamable HTTP on `POST /mcp`. Every mode fetches the same bytes
from the same scanner-controlled origin through **one** retrieval path
(`_retrieve`) and advertises **one** tool definition (`FETCH_TOOL`). The only
variable that moves is what `relay()` does with those bytes on the way out.

| `--mode` | what comes back in the tool result | verdict |
|---|---|---|
| `flawed` | the body, in a plain `text` block, and nothing else | **confirmed** |
| `fixed` | `<untrusted-content source="…" trust="none">` … `</untrusted-content>` **plus** a provenance record in the block's `_meta` | **refuted** |
| `attributed` | `Retrieved <url>` then the body — provenance named, trust never framed | **refuted** + soft `attributed-by-origin-only` |
| `escaped` | the body base64'd behind a short preamble | **refuted** (`re-emitted-escaped: base64`) |
| `summarised` | a byte and line count instead of the prose | **refuted** (`boundary-held`) |
| `nofetch` | a canned answer; the origin is never hit | **skipped** (`controlled-origin-never-fetched`) |
| `notools` | no read-type tool at all — only `list_notes` | **skipped** (`no-read-type-tool-with-a-url-argument`) |

`nofetch` and `notools` are the twins that keep the SKIP honest. Both servers
would relay raw if they ever relayed anything — `relay()` is unchanged and its
default arm is the flawed one — but one never retrieves and the other has
nothing to retrieve with. The template must decline on both rather than confirm
on a disposition it never observed. `attributed` is the near-miss that keeps
the CONFIRM honest in the other direction: it is weaker than `fixed` and it is
still a boundary, so it refutes, and the weakness is recorded as an
`observations` entry the refutation names and never fires on.

## What is synthetic about it

Everything. There is no real server, no real page and no real service. The
document the scanner serves is dull filler about widget throughput; the
"directive" planted in it is an inert decoy that asks a reader to echo a token
— it executes nothing, exfiltrates nothing, and no model is in the loop. Its
only job is to make one boundary observable. `fetch_url` performs a plain `GET`
against whatever URL it is handed, which in the proof is always the scanner's
own loopback origin, and the body it returns is never executed, never written
to disk and never forwarded. There is no credential anywhere in this directory.

The document is also checked, at runtime, for *not* containing any attribution
phrase and *not* containing its own URL (`_selfcheck_document`), so a server can
never be credited with provenance the document supplied for it.

## What `prove.sh` asserts

Twelve directions — every verdict the template can emit has a twin that
produces it:

1. **flawed → confirmed**, with the finding carrying the tool and arguments
   called, the origin's own hit log (proof the server *went and got it*), the
   verbatim occurrence with an empty mark list, the exact window examined, and
   the rule that was applied.
2. **fixed → refuted**, naming all three marks it found: the untrusted-content
   label, the delimiter pair, and the `_meta` provenance key.
3. **attributed → refuted**, naming the mark that saved it *and* recording
   `attributed-by-origin-only` as a soft observation that never becomes a verdict.
4. **escaped → refuted**, naming `re-emitted-escaped: base64`.
5. **summarised → refuted** with `boundary-held`, and `origin_hits=1` proving
   the content really did cross.
6. **nofetch → skipped**, naming `controlled-origin-never-fetched`.
7. **notools → skipped**, naming `no-read-type-tool-with-a-url-argument`.
8. **flawed with the origin advertised at an unroutable address → skipped**,
   naming `every-read-type-tool-candidate-errored` — never a refutation.
9. **`CXG_MCP_PROVENANCE_TOOL` naming a tool that is not there → errored**,
   listing what the server does have.
10. **nothing listening → skipped**, naming `no-mcp-server-answered`.
11. **a `cli://` target → skipped**, saying which surface it needs.
12. **the real `cxg` engine** (when on `PATH`): 1 finding on `flawed`, 0 on
    `fixed`, `attributed`, `escaped`, `summarised`, `nofetch` and `notools`.

## Files

```
mcp_fixture_server.py   the seven twins, one relay() apart
prove.sh                twelve directions, exit 0 = all hold
```

`tests/prove-mcp-tool-result-provenance.sh` is a thin entry point that runs this
harness, so `tests/` has one uniform place to start a proof from.

## Placement

This directory sits outside `templates/` on purpose.
`scripts/generate-index.py` walks `templates/` and indexes every file with a
language extension, so a `.py` fixture stored beside the template would be
loaded and run as a check.

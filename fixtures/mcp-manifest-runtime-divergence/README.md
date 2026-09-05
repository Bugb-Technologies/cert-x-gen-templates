# Fixture — MCP declared-manifest / runtime-surface divergence

The synthetic target for
[`templates/ai/mcp/mcp-manifest-runtime-divergence.py`](../../templates/ai/mcp/mcp-manifest-runtime-divergence.py).

```bash
./prove.sh          # exit 0 = confirm, refute, both skips, the error and the real cxg runs all hold
```

## Why a fixture and not a static rule

An MCP Registry listing records what a publisher **declared**: identity, version,
package integrity hash, and the tool surface shipped alongside it. The registry
is explicit that this is a record of a submission, not a certificate about a
process — a listing does not certify that runtime behaviour matches, or will
remain unchanged from, what was declared. Verifying that the server answering
you is the server that was listed is left to the consumer, and no static
manifest linter can do it, because half the comparison only exists on the wire.

The sibling [`mcp-rug-pull-detection`](../../templates/ai/mcp/mcp-rug-pull-detection.py)
diffs a server against **itself over time** and has the matching blind spot: a
server that was already wider than its listing on day one never mutates, so its
first observation becomes the baseline and the baseline is already the lie. This
template diffs the server against **its own declaration**, at one instant. Both
sides have to be read live, so it needs a live target — a fixture, not a pattern.

## What the three modes do

Stdlib only. Streamable HTTP on `POST /mcp`, plus the publication artifact at
`GET /.well-known/mcp/server.json`. All three modes are built from **one** source
of truth in `mcp_fixture_server.py` — `BASE_TOOLS`, `BASE_RESOURCES`,
`DECLARED_VERSION`, `DECLARED_SHA256` — which is exactly what the declared
manifest always says. They differ only in what the running server does with it:

| | `--mode flawed` | `--mode fixed` | `--mode nomanifest` |
|---|---|---|---|
| publishes a manifest? | yes | yes | **no — every well-known path 404s** |
| tools at runtime | `read_note`, `list_notes`, **`sync_workspace`** | `read_note`, `list_notes` | same as `flawed` |
| `read_note` input schema | declared props **+ `command`** | as declared | as `flawed` |
| `read_note` scope | declared `readOnlyHint: true`, **runs `false` + `destructiveHint: true`** | as declared | as `flawed` |
| resources at runtime | declared **+ `workspace://env`** | as declared | as `flawed` |
| version / package sha256 | **`1.4.0-hotfix.3` / `dead…`** vs declared `1.4.0` / `cafe…` | as declared | as `flawed` |
| expected verdict | **confirmed** | **refuted** | **skipped** |

`nomanifest` is the differential that keeps this honest. Its runtime surface is
byte-identical to `flawed` — undeclared tool and all — but there is no declared
side to diff against, so the template must **skip**, not confirm. Hand it the
declaration out of band (`CXG_MCP_DECLARED_SOURCE=<file>`, direction 4 of
`prove.sh`) and the same twin confirms: the verdict tracks whether a declaration
was available, never how alarming the runtime looks on its own.

## What is synthetic about it

Everything. There is no real server, no real registry entry, and no real
package. `sync_workspace` is a **decoy**: its name, its `include_secrets`
argument and its `destructiveHint: true` advertise an outbound sync, and the
implementation returns a fixed string — it writes nothing, contacts nothing, and
there is no credential anywhere in this directory. The two hashes are obviously
synthetic fill (`cafe…`, `dead…`, 64 hex each) and identify no real artifact.

## What `prove.sh` asserts

Seven directions:

1. **flawed → confirmed**, with every one of the five widenings present, each
   carrying **both** sides (declared *and* runtime value), plus the request and
   response for the declared fetch and for the live `tools/list`.
2. **fixed → refuted**, naming the dimensions it actually diffed
   (`tools+resources+version+package-hash`) — so "clean" means "compared and
   equal", not "nothing was read".
3. **nomanifest → skipped**, naming `no-declared-source-available`.
4. **nomanifest + `CXG_MCP_DECLARED_SOURCE` → confirmed** — the strong form,
   where the declaration comes from a file the running server cannot edit.
5. **a named-but-missing declared source → errored**, never a refutation.
6. **nothing listening → skipped**, naming `no-mcp-server-answered`.
7. **the real `cxg` engine** (when on `PATH`): 1 finding on `flawed`, 0 on
   `fixed`, 0 on `nomanifest`.

## Files

```
mcp_fixture_server.py   the flawed / fixed / nomanifest twins, plus --dump-manifest
prove.sh                seven directions, exit 0 = all hold
```

## Placement

This directory sits outside `templates/` on purpose.
`scripts/generate-index.py` walks `templates/` and indexes every file with a
language extension, so a `.py` fixture stored beside the template would be
loaded and run as a check.

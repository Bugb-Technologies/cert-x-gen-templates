# Fixture — MCP out-of-scope tool action

The synthetic target for
[`templates/ai/mcp/mcp-excessive-scope-proof.py`](../../templates/ai/mcp/mcp-excessive-scope-proof.py).

```bash
./prove.sh          # exit 0 = confirm, refute and skip hold on BOTH witnesses
```

## Why a fixture and not a static rule

MCP lets a server annotate a tool with a promise about its own behaviour:

> `readOnlyHint`: If true, the tool does not modify its environment.
> … Clients **MUST** consider tool annotations to be untrusted unless they come
> from trusted servers.
> — [MCP specification, Tools / Tool annotations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)

The spec hands you a claim and, in the same breath, tells you not to trust it.
Nothing in the manifest can settle it: the promise is about what the
*implementation* does, and the implementation is on the other side of the wire.
The only way to know is to call the tool and watch.

That is the whole reason this directory exists. `mcp_fixture_server.py` runs the
same manifest two ways, and the check has to read the behaviour, not the
declaration.

## What the three modes do

Stdlib only. Speaks both transports the template supports — streamable HTTP on
`POST /mcp` (`--transport http`) and newline-delimited JSON-RPC on stdin/stdout
(`--transport stdio`) — so one fixture exercises both witnesses.

`flawed` and `fixed` advertise a **byte-identical manifest**: `read_note` carries
`annotations.readOnlyHint: true`, `destructiveHint: false`, and a description
that promises a read and nothing more. A manifest scanner cannot tell them
apart. They differ only in what `read_note` *does*:

| | `--mode flawed` | `--mode fixed` | `--mode broad` |
|---|---|---|---|
| manifest | `read_note`, `list_notes`, both `readOnlyHint: true` | identical | one `file_manager`, `readOnlyHint: false`, `destructiveHint: true` |
| every `read_note` call | appends to `<root>/.cxg-read-audit.log` | writes nothing | — |
| `read_note` on a miss | **creates the requested path** with a decoy marker, then reports "not found" | reports "not found", writes nothing | — |
| second read of that path | succeeds, returning the marker | still "not found" | — |
| expected verdict | **confirmed** | **refuted** | **skipped** |

`broad` is the differential that keeps this check distinct from
`mcp-excessive-tool-permissions`. Its tool *declares* write and delete, so
"acted outside its declared scope" is not defined for it — an over-broad
declaration is the other template's finding. `broad` writes nothing either; it
only declares that it could.

The flawed twin's two writes are not arbitrary. They are the two shapes this
class actually takes in the wild — an undeclared audit/telemetry trail, and a
read-through cache that memoises a miss — and each is visible to a different
witness:

* the **audit log** lands somewhere the caller never named, so only a witness
  that can see the server's filesystem finds it → the stdio/lab witness;
* the **memoised miss** changes what the *protocol itself* returns, so a remote
  observer with no filesystem access still sees it → `read(P)` said absent, an
  identical `read(P)` said present.

## What is synthetic about it

Everything. There is no real data, no real credential and no destructive
implementation anywhere in this directory. The marker the flawed twin plants
says so on its face:

```
CXG-SYNTHETIC-DECOY-MARKER placeholder written by read_note while memoising a
cache miss. This file is a test artefact.
```

Every path the server touches is resolved **under `--root`** — an absolute
request path that points outside the root is re-rooted, never followed — so the
fixture cannot write outside the lab even if the template asks it to. The
`broad` twin's `file_manager` is inert: it declares write and delete and
implements neither.

## What `prove.sh` asserts

Six directions, twenty assertions, both witnesses:

1. **http / flawed → confirmed.** The finding must carry `read_1: absent`,
   `read_2: present`, a **passing negative control** (a never-repeated nonce
   path that stayed absent), and the decoy bytes the tool itself wrote.
2. **http / fixed → refuted.** The same probe stays absent both times, and the
   detail must say the negative control was live — so the refutation means "no
   write", not "no signal".
3. **http / broad → skipped**, naming `no-tool-declares-a-narrow-scope`.
4. **stdio / flawed → confirmed.** The lab diff must contain
   `.cxg-read-audit.log`, the control run (identical session, zero `tools/call`)
   must have written nothing to subtract, calls must actually have been made,
   and the witness self-test must read `live`.
5. **stdio / fixed → refuted**, with `filesystem-witness-selftest=live` in the
   detail — a clean verdict is only worth anything if the instrument was known
   to be working.
6. **nothing listening → skipped**, naming the missing precondition.

## Files

```
mcp_fixture_server.py   the flawed / fixed / broad twins, http + stdio
prove.sh                six directions across both witnesses, exit 0 = all hold
```

## Placement

This directory sits outside `templates/` on purpose.
`scripts/generate-index.py` walks `templates/` and indexes every file with a
language extension, so a `.py` fixture stored beside the template would be
loaded and run as a check.

# Template gaps at reachable exposure

`scripts/graph-template-gaps.py` answers one roadmap question with evidence:
**which kinds of exposure do real applications reach from their HTTP routes,
and which of those does no template in this repository probe?**

It reads a code graph for each application in a set, takes every sink class
each route handler reaches through the call graph (SQL, command execution,
template rendering, outbound network, file system, crypto) and every route
framework, maps them onto the templates here, and ranks the uncovered ones by
how many applications reach them and through how many entry points.

The graph tooling is **optional**. Nothing else in this repository needs it,
and CI does not run it.

## Install the graph tooling

The graph comes from `codegraph-mcp`, an MCP server shipped inside the `bravos`
package and fronted by its `bravos graph` command:

```sh
pipx install bravos              # or: pip install bravos
bravos graph build path/to/app   # index one repository (seconds on a small app)
```

The script needs two graph queries, `codegraph_routes` and
`codegraph_attack_surface`. **bravos 0.3.1, the release on PyPI when this was
written, predates both**: its `bravos graph` has no `routes` or
`attack-surface` question. Check yours with:

```sh
bravos graph routes --help       # "has no question called 'routes'" = too old
```

With tooling that is too old the script still runs, reports every repository
as `not measured` with the reason, prints **NO RESULT**, and exits `3` - it
never reports an empty gap list. To use a newer `codegraph-mcp` than the one
your bravos carries, point `CODEGRAPH_MCP` (or `CXG_CODEGRAPH_MCP`, which
cert-x-gen reads too) at the binary. Graphs are stored outside the repository;
set `BRAVOS_CODEGRAPH_DIR` to choose where.

## Run it

```sh
python3 scripts/graph-template-gaps.py \
    --repo path/to/app-one --repo path/to/app-two \
    --save-answers /tmp/graph-answers          # optional: keep the raw answers

# re-run later, or on another machine, without the graph tooling:
python3 scripts/graph-template-gaps.py --answers /tmp/graph-answers/*.json
```

`--repo NAME=PATH` names a repository; `--format json` emits the full result;
`--top N` trims the capability gap table. Answers saved by `bravos graph routes
--json` / `attack-surface --json` are accepted as they are.

| exit | meaning |
|---|---|
| 0 | report written; at least one repository passed the graph's confidence gate |
| 2 | bad arguments or unreadable input |
| 3 | report written, but no repository was measured: there is no result |

## The confidence gate

Every attack-surface answer carries the graph's own verdict, and the script
honours it rather than second-guessing it:

- `sinks_reached`, `no_sinks_reached` - measured; counted.
- `insufficient_resolution` - the graph resolved too few of the project's calls
  to walk (it publishes the measured shortfall, e.g. "0.06 resolved call edges
  per function, below the 0.5 this ranking needs"). That repository's sink
  reach is **unknown** and is reported that way. It is never counted as a
  repository that reaches nothing, and every count in the report is stated as
  "over the N repositories that passed".
- Missing tooling, tooling too old to publish the queries, or no graph built -
  `not measured`, with the reason.

Route frameworks are registration facts that do not depend on call resolution,
so they are counted even below the gate. A framework the graph does not
recognise produces no routes at all, so an absent framework is unseen, not
unused.

Two more limits are printed with every report. The attack surface gives one
example sink per entry point and class, so per class the counts are complete
but the split into capabilities (subprocess vs `eval`, both `exec`) is a floor.
And some sinks are recognised only by a method name in a scope that imports the
library; those are counted as *inferred*.

## How coverage is decided

All of it lives in `scripts/graph-gap-map.json`, so every judgement is a line a
reviewer can disagree with:

- **`sink_rules`** maps each rule of the graph's sink catalogue (`go.os_exec`,
  `py.unsafe_deserialise`, `java.net`, ...) to the capabilities a template would
  have to probe. `callee_refinements` re-read a rule by the call it makes where
  one rule bundles different exposures (a JWT call inside `java.crypto`; MD5 vs
  SHA-256 inside a hash rule). A rule the map does not know yet falls back to its
  class and is named in the report.
- **The pool** is `templates/web/` plus named extras, each with a reason. A
  template covers a capability when its declared tags match; a template with no
  tags is read by the CWE ids and words of its first 50 lines, the window the
  engine reads annotations from.
- **Ecosystem-specific capabilities** (SSTI, code evaluation, deserialisation)
  also need the template to name the reaching code's ecosystem: a Jinja2 probe
  says nothing about Go templates.
- **`pinned`** and **`not_coverage`** override the tag match for one template,
  each with its reason, and the report prints the `not_coverage` ones it applied.

`python3 scripts/test_graph_template_gaps.py` covers the gate, the ranking, the
coverage rules and the live transport against a stand-in server; it needs no
graph tooling.

## Run of 2026-10-01

Six open-source applications, each at a pinned commit, against this
repository's templates, with a `codegraph-mcp` that publishes both queries
(graph format 12):

| application | commit | language / framework | graph verdict |
|---|---|---|---|
| [gophish](https://github.com/gophish/gophish) | `9561846` | Go / gorilla/mux, 48 routes | sinks_reached, 46 entry points |
| [govwa](https://github.com/0c34/govwa) | `4058f79` | Go / httprouter, 20 routes | sinks_reached, 17 entry points |
| [VAmPI](https://github.com/erev0s/VAmPI) | `f16052d` | Python / connexion, 14 routes | sinks_reached, 14 entry points |
| [WebGoat](https://github.com/WebGoat/WebGoat) | `3284a8e` | Java / Spring, 211 routes | sinks_reached, 211 entry points |
| [NodeGoat](https://github.com/OWASP/NodeGoat) | `c5cb68a` | JavaScript / Express, 20 routes | **below the gate**: 0.06 resolved call edges per function |
| [pygoat](https://github.com/adeyosemanputra/pygoat) | `19d17cc` | Python / Django + Flask, 137 routes | **below the gate**: 0.20 resolved call edges per function |

Sink counts are over the four that passed. NodeGoat's and pygoat's reach is
unknown, not absent; their frameworks are counted.

**Reachable sink capabilities with no template**

| # | capability | ecosystem | apps reaching | entry points | example |
|---|---|---|---|---|---|
| 1 | Server-side template injection | Go | 2/4 (gophish, govwa) | 25 (11 inferred) | gophish `ANY /{path:.*}` -> `template.New(...).Parse(text)` on stored, user-authored content (`models/template_context.go:79`) |
| 2 | Signed / encrypted value tampering and token randomness | any | 2/4 (gophish, WebGoat) | 9 (1 inferred) | WebGoat spoof-cookie lesson -> `EncDec.encode`; gophish webhook -> `hmac.New` |
| 3 | Server-side request forgery | any | 2/4 (gophish, WebGoat) | 8 (5 inferred) | gophish `ANY /api/campaigns/` -> `http.NewRequest` (`webhook/webhook.go:88`) |
| 4 | Weak hash (MD5 / SHA-1) | any | 1/4 (govwa) | 4 | govwa `GET /login` -> `md5.New` (`user/user.go:160`) |
| 5 | Insecure deserialisation over HTTP | Java | 1/4 (WebGoat) | 2 (2 inferred) | WebGoat `POST /VulnerableComponents/attack1` -> `xstream.fromXML` |

Read with care: the graph sees that a handler reaches template rendering, not
whether the template *source* is caller-controlled. In gophish it is (stored
templates are compiled with `text/template`); govwa renders fixed files, so its
share of row 1 is rendering reach whose real exposure is the XSS side.
`deserialization-gadget-scan` matches row 5 on its tags but probes RMI/JMX
services, not an HTTP route, so it is not counted.

**Route frameworks with no template**: Django (pygoat, 127 routes), gorilla/mux
(gophish, 48), Express (NodeGoat, 20), httprouter (govwa, 20), Connexion
(VAmPI, 14), Flask (pygoat, 10). Spring is covered by `spring4shell-detection`.

**Already covered**: SQL injection (4/4 apps, 64 entry points), XSS (2/4, 29),
JWT tampering (2/4, 17), path traversal (2/4, 3), password guessing (1/4, 5).

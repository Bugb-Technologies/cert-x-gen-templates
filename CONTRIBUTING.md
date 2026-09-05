# Contributing to CERT-X-GEN Templates

Thank you for considering contributing to CERT-X-GEN Templates! 🎉

A template in this repository is a **program that decides**, not a pattern that
matches. It runs against a target, observes something specific, and returns a
verdict it can defend. Everything below exists to keep that bar.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How can I contribute?](#how-can-i-contribute)
- [What makes a good template](#what-makes-a-good-template)
- [Repository layout](#repository-layout)
- [Template anatomy](#template-anatomy)
- [Fixtures — proving it both ways](#fixtures--proving-it-both-ways)
- [Playbooks](#playbooks)
- [Development workflow](#development-workflow)
- [The five CI checks](#the-five-ci-checks)
- [Style guide](#style-guide)
- [Review process](#review-process)
- [Recognition](#recognition)
- [Questions?](#questions)

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you're expected to uphold this code.

## How can I contribute?

### 1. Reporting a template bug

- Open a [bug report](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues/new?template=bug_report.yml)
- Search existing issues for the template id first
- Name the template, the target, and which verdict you expected versus got

Bugs in the **cxg engine itself** (crashes, CLI flags, scan orchestration,
output formats) belong on the
[engine repo](https://github.com/Bugb-Technologies/cert-x-gen/issues).

**Security vulnerabilities do not go in the issue tracker.** Email
**security@bugb.io** — see [SECURITY.md](SECURITY.md).

### 2. Proposing a new template

- Open a [template proposal](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues/new?template=new_template.yml)
- It asks for the weakness class, the target, the oracle, and the
  CONFIRMED / REFUTED / SKIP conditions — the same things the template's own
  header and its `prove.sh` will have to answer
- You do not need working code to open one. Agreeing the oracle first is
  cheaper than rewriting the template after review

### 3. Suggesting an improvement

- Open a [feature request](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues/new?template=feature_request.yml)
  for repo tooling, CI, docs, playbooks, or a refinement to an existing template

### 4. Improving documentation

Fix typos, clarify explanations, add examples, correct anything outdated. Docs
PRs are held to the same review bar as templates and are just as welcome.

## What makes a good template

✅ **Must have:**

- A `@id` that is **unique across the whole repo**. A duplicate `@id` is not a
  warning: the engine keeps one template per id and silently drops the rest, so
  both templates stop running.
- The full annotation set in the **first 50 lines** — that is all the engine
  reads.
- A **specific oracle**: it fires on a structural conjunction, an observed
  secret, or a marker the template itself planted. Not on a string, status code,
  or banner that occurs naturally in an ordinary response.
- An honest **SKIP** branch. A check that cannot say "the surface I audit is not
  present here" is asserting the surface rather than establishing it.
- Graceful failure. Emit an empty findings array; never crash the scan.
- **No third-party traffic.** A scan touches the target and nothing else — no
  callback hosts, no public resolvers, no external services.

⚠️ **Best practices:**

- Record every near-miss (a lone tag, a BOM, a credential-*named* resource, a
  placeholder value) as an `observations` / `soft` entry that the refutation
  names but never fires on. That is the precision idiom the MCP checks share.
- Reference CVE / CWE / advisories in `@references`.
- State the axis your differential holds fixed, and assert it at runtime. A
  confirmation that let two variables move proves nothing about either.

❌ **Avoid:**

- Templates that disrupt the service they audit.
- Hardcoded credentials, or absolute paths (CI rejects them).
- Duplicate coverage. Two templates that move the same variable are one
  template.
- Exploit framing. The template describes an **audit and what it exposes** —
  not an exploit, manipulation, or confusion.

## Repository layout

Templates live under `templates/<category>/<subject>/`. The categories are
fixed:

```
ai  cli-baseline  databases  devops  messaging
monitoring  network  recon  tooling  web
```

A **new category directory must also be added to `VALID_CATEGORIES` in
`.github/scripts/check_hygiene.py`**, or CI fails.

```
templates/          the checks themselves, one file each
fixtures/<id>/      synthetic targets, one directory per template id
tests/              prove harnesses; tests/fixtures/ for large ones
docs/playbooks/     one human-facing playbook per differentiated template
scripts/            generate-index.py and friends
```

**Never put a fixture beside its template.** `discover()` in
`scripts/generate-index.py` indexes every file under `templates/` that carries a
language extension, so a `.py` fixture parked there is loaded and run as a
check.

Non-template companion files under `templates/` can be swallowed by
`.gitignore` (its C/C++ section ignores `*.lib`, `*.a`, `*.out`, `*.exe`), and
nothing in CI looks at a file that is not a template. **After adding any
non-`.sh` file under `templates/`, run `git check-ignore -v <path>`** and add a
negation if it hits.

## Template anatomy

Metadata is a comment block in the file's **first 50 lines**, in the file's own
comment syntax:

```python
#!/usr/bin/env python3
# @id: mcp-tool-poisoning
# @name: MCP Tool Poisoning (Model-Directed Instructions in Tool Metadata)
# @author: Your Name
# @severity: high
# @description: One line saying what this observes and what it exposes
# @tags: mcp, ai, agent, tool-poisoning, cwe-1427
# @cwe: CWE-1427
# @cvss: 8.2
# @target_kinds: http
# @oracles: property
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/1427.html
# @confidence: 90
# @version: 2.0.0
```

The engine hands the template its target through the environment and reads a
JSON findings array on stdout. Read a shipped template in your language before
writing one —
[`templates/ai/mcp/mcp-tool-poisoning.py`](templates/ai/mcp/mcp-tool-poisoning.py)
is the reference for the output shape, and
[`docs/TEMPLATE_GUIDE.md`](docs/TEMPLATE_GUIDE.md) covers the general anatomy.
Skeletons ship with the published template set:

```bash
ls ~/.cert-x-gen/templates/official/templates/skeleton/
```

### `cli` target-kind caveats

Verified against the CI-pinned `cxg` (`CXG_VERSION` in
`.github/workflows/ci.yml`), which is behind the engine source — re-check when
the pin moves.

- **A shell template must `exit 0`, even when it confirms.** The pinned engine
  discards a shell template's findings entirely on a non-zero exit, and
  `@allow_nonzero_exit: true` does not change that. Carry the verdict in the
  emitted JSON's `metadata.status`, never in the exit code.
- **`CERT_X_GEN_TARGET_KIND` and `CERT_X_GEN_TARGET_INSTRUMENTATION` are not
  set**, and the `cli://` prefix is left on `CERT_X_GEN_TARGET_HOST`. A `cli`
  template gets the raw scope string (`cli:///abs/path`) plus
  `CERT_X_GEN_TARGET_PORT` and `CERT_X_GEN_MODE`; derive the kind and the binary
  path from that string. This applies to Python templates taking `cli` too.
- **There is no `--input` / `--arg` / `--stdin-file`.** Extra argv for a spawned
  binary needs its own environment variable.
- **Per-finding `cwe_ids` are overwritten by the engine** from the template's
  own annotations, so a finding's CWE list does not survive as emitted.
- **`cxg scan --output <path>` replaces a file extension rather than appending
  one.** A harness that writes `--output scan-agent_x.py` then reads
  `scan-agent_x.py.json` silently finds nothing. Name report paths without a
  dot.

## Fixtures — proving it both ways

A template's synthetic target lives in `fixtures/<template-id>/` (or, when it is
too large, at `tests/fixtures/<template-id>/` with its runner in `tests/`).

Build the **flawed and fixed twins from one source**, and ship a `prove.sh` that
asserts **both directions** — the flawed twin confirms, the fixed twin refutes.
A check is only proved when **every verdict it can emit has a fixture that
produces it, `skipped` included**. Prefer independent switches over a single
flawed/fixed axis so one source can reach all branches.

Worked examples, in increasing order of subtlety:

| Shape | Example |
|---|---|
| Plain flawed/fixed twin | [`fixtures/mcp-invisible-unicode/`](fixtures/mcp-invisible-unicode/) |
| Adds the SKIP path a differential must keep distinct from a refutation | [`fixtures/mcp-token-audience-confusion/`](fixtures/mcp-token-audience-confusion/) |
| One server serving both `http` and `cli` from one twin pair | [`fixtures/mcp-excessive-scope-proof/`](fixtures/mcp-excessive-scope-proof/) |
| Four variants from one source reaching all four branches | [`tests/fixtures/coding-agent-exec-authority/`](tests/fixtures/coding-agent-exec-authority/) |
| A `cli` template proved both ways | [`tests/run-coding-agent-config-trust.sh`](tests/run-coding-agent-config-trust.sh), [`tests/prove-supply-chain-install-hook.sh`](tests/prove-supply-chain-install-hook.sh) |
| A **stateful** check whose finding lives in a *sequence* | [`tests/prove-coding-agent-command-trace.sh`](tests/prove-coding-agent-command-trace.sh) |
| A **two-phase, post-exit boundary** check | [`tests/prove-coding-agent-sandbox-trust-handoff.sh`](tests/prove-coding-agent-sandbox-trust-handoff.sh) |

Behavioural harnesses are slow (minutes) and are **not** among the CI checks —
run yours by hand before pushing.

## Playbooks

A differentiated template ships a human-facing playbook at
`docs/playbooks/<template-id>.md`: the case for the check, a ` ```mermaid ` probe-flow
diagram ending at the CONFIRMED / REFUTED / SKIP decision, a competitor table,
and why behavioural beats static here. Describe and link the template; never
paste it.

[`docs/playbooks/coding-agent-execution-authority.md`](docs/playbooks/coding-agent-execution-authority.md)
is the worked example. No CI check covers this directory, so **validate your
mermaid before pushing** — GitHub renders it natively and a parse error just
shows the source.

## Development workflow

### Fork and clone

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/cert-x-gen-templates.git
cd cert-x-gen-templates
git remote add upstream https://github.com/Bugb-Technologies/cert-x-gen-templates.git
```

### Create a branch

```bash
git checkout -b template/mcp-handle-binding-integrity
```

### Make your changes

1. Add the template under the right category.
2. Add its fixture and `prove.sh`; run it both ways.
3. Add its playbook under `docs/playbooks/`.
4. Update `CHANGELOG.md`.

**Do not commit `TEMPLATE_REGISTRY.json` or `templates/TEMPLATE_REGISTRY.md`.**
The JSON registry is regenerated on `main` by the `registry` job in
`.github/workflows/ci.yml` after every merge, and CI fails a pull request that
edits either file. Both carry repo-wide counts, which is why two concurrent
template PRs always used to conflict there and nowhere else. Running
`python3 scripts/generate-index.py` locally is a *check*, not something to
commit — restore an accidental edit with:

```bash
git checkout origin/main -- TEMPLATE_REGISTRY.json
```

`templates/TEMPLATE_REGISTRY.md` is a human-maintained index. A new category
does belong in it, but that edit rides the periodic `curation` pass, not your
template PR.

**Do not edit `AGENTS.md`** as part of a template PR.

### Run the checks locally

Run checks 1–4 of [the five CI checks](#the-five-ci-checks) before you push.

### Commit

```bash
git commit -m "Add MCP handle binding integrity template

- Confirms when a handle minted by server A is readable via server B
- Refutes when the client scopes handles per server
- Skips when the session exposes no resource handles
- Fixture: fixtures/mcp-handle-binding-integrity/ (prove.sh, both directions)
"
```

First line a summary (50 chars or so), blank line, then what it detects and how
it was proved, plus any issue references.

### Push and open a pull request

```bash
git push origin template/mcp-handle-binding-integrity
```

Then open a Pull Request. `.github/PULL_REQUEST_TEMPLATE.md` fills in a
checklist that mirrors what CI enforces — work through it rather than deleting
it.

## The five CI checks

`.github/workflows/ci.yml` gates every pull request on five checks. Run 1–4
locally first.

**1. Every template loads through the engine.**

```bash
cxg --disable-update-check -vv template list --no-color > loader.log 2>&1
.github/scripts/check_loader.py
```

The engine loader — not `cxg template validate`. The two disagree about what is
valid, and the loader is the side that decides what actually runs; it WARNs once
per unloadable template and continues, so nothing else in a scan reveals a dead
template.

> Locally this fails on WARN and dedup lines coming from `~/.cert-x-gen/templates`,
> the published set cxg merges in. Run with a throwaway home to see this repo
> alone: `HOME=$(mktemp -d) cxg --disable-update-check -vv template list`.
> CI has no such cache.

**2. The registry generates cleanly.**

```bash
python3 scripts/generate-index.py   # must exit 0, no load_failures, no id_collisions
```

Do **not** commit the result. Only files with a recognised language extension
(see `EXT_LANG` in that script) count as templates; `.lib`, `.md` and friends
are ignored.

**3. Generator guard tests.**

```bash
python3 scripts/test_generate_index.py
```

**4. Hygiene.**

```bash
python3 .github/scripts/check_hygiene.py
```

CI runs this against the registry regenerated in check 2, so run check 2 first.
It rejects absolute paths, empty names, registry paths outside `templates/`, and
any template outside the valid categories.

**5. No hand-edited registry.** Pull-request only — see the rule above.

> `scripts/generate-index.py` skips a `tests/` directory; the engine loader does
> not. A fixture parked under `templates/**/tests/` therefore makes checks 1 and
> 2 report different totals.

## Style guide

### Naming

- **Template ids:** lowercase, hyphenated, `subject-weakness` shaped —
  `redis-unauth`, `mcp-handle-binding-integrity`, `coding-agent-repo-config-autoexec`.
- **Files:** match the template id, plus the language extension —
  `redis-unauth.py`, `mcp-handle-binding-integrity.py`.

### Code

- **Python:** PEP 8, type hints encouraged, docstrings on functions. A template
  must be a **single self-contained file** — no imports from a sibling helper.
  Where an oracle is genuinely shared it is *duplicated*, and a no-drift test
  pins the copies together (`fixtures/mcp-tool-poisoning/natural_corpus.py`
  runs three copies of the invisible-Unicode oracle over one corpus and fails on
  any disagreement — change one copy and you must change the others).
- **Go:** `gofmt`, standard library where possible.
- **Shell:** shellcheck-clean, quote variables, `set -euo pipefail` — and see the
  `exit 0` rule above.
- **JavaScript:** modern ES6+, async/await, JSDoc comments.
- **YAML:** two-space indentation, descriptive names, blank lines between
  sections.

## Review process

1. **Automated checks** — the five above must be green.
2. **Maintainer review** — oracle precision, false-positive surface, the
   fixture proving every verdict, terminology, and whether it duplicates an
   existing check.
3. **Community feedback** — other contributors may comment; address feedback
   promptly.

## Recognition

Contributors are listed in [CONTRIBUTORS.md](CONTRIBUTORS.md) and named in
release notes.

## Questions?

- 💬 Discord: [Join our community](https://discord.gg/cert-x-gen)
- 💬 [GitHub Discussions](https://github.com/Bugb-Technologies/cert-x-gen/discussions) — questions and ideas
- 🐛 [GitHub Issues](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues) — template bugs and proposals
- 🔒 Security: **security@bugb.io** (see [SECURITY.md](SECURITY.md))

Thank you for contributing! 🚀

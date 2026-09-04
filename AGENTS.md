# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Adding templates / a new category

CI (`.github/workflows/ci.yml`) gates every PR on four checks; run them locally before pushing:
1. **Engine loads all templates** — `cxg --disable-update-check -vv template list` then `.github/scripts/check_loader.py`. Locally this fails on WARN/dedup lines from `~/.cert-x-gen/templates` (the published set cxg merges in); run with a throwaway `HOME=$(mktemp -d)` to see this repo alone. CI has no such cache.
2. **Registry is current** — regenerate with `python3 scripts/generate-index.py` and commit `TEMPLATE_REGISTRY.json`; it is generated, never hand-edited. Only files with a language extension (see `EXT_LANG`) count as templates — `.lib`, `.md`, etc. are ignored.
3. **Generator guard tests** — `python3 scripts/test_generate_index.py`.
4. **Hygiene** — `python3 .github/scripts/check_hygiene.py`. A **new category directory under `templates/` must be added to `VALID_CATEGORIES` in `.github/scripts/check_hygiene.py`**, or this fails.

A template's non-template companions can be swallowed by `.gitignore` — its C/C++ section
ignores `*.lib`, `*.a`, `*.out`, `*.exe`, and none of the four CI checks look at a file that
is not a template, so a missing helper is invisible until a scan errors. `cli-baseline.lib`
shipped absent for exactly this reason. **After adding any non-`.sh` file under `templates/`,
run `git check-ignore -v <path>`** and add a negation if it hits.

Template metadata (`@id`, `@name`, `@severity`, …) is read from the **first 50 lines only**; every `@id` must be unique repo-wide or the engine drops all colliders. `templates/TEMPLATE_REGISTRY.md` is a human-maintained index — update it too when adding a category.

## Fixtures

A template's synthetic target lives in `fixtures/<template-id>/`, **never** beside the template: `discover()` in `scripts/generate-index.py` indexes every file under `templates/` carrying a language extension, so a `.py` fixture stored there is loaded and run as a check. An extension the engine does not recognise (`cli-baseline.lib`) is the only way to keep a non-template file inside `templates/`. Give each fixture a flawed/fixed twin built from one source plus a `prove.sh` that asserts **both** directions: `fixtures/mcp-invisible-unicode/` is the shape, and `fixtures/mcp-token-audience-confusion/` adds the SKIP path a differential check must keep distinct from a refutation.

The generator and the engine disagree about `tests/`: `discover()` skips a `tests/` directory, the engine loader does not. A fixture parked under `templates/**/tests/` therefore makes CI check 1 and check 2 report different totals. Behavioural fixtures too large for `fixtures/<template-id>/` live at the repo root under `tests/fixtures/` with their runner in `tests/`.

## Writing a `cli` target-kind template

Verified against the CI-pinned `cxg` (`CXG_VERSION` in `.github/workflows/ci.yml`,
currently `v1.3.0`), which is behind the engine source; re-check when the pin moves.

- **A shell template must `exit 0`, even when it confirms.** The pinned engine
  discards a shell template's findings entirely if the process exits non-zero, and
  `@allow_nonzero_exit: true` does not change that. Carry the verdict in the emitted
  JSON's `metadata.status`, never in the exit code.
- **`CERT_X_GEN_TARGET_KIND` and `CERT_X_GEN_TARGET_INSTRUMENTATION` are not set,
  and the `cli://` prefix is left on `CERT_X_GEN_TARGET_HOST`.** A `cli` template
  receives only `CERT_X_GEN_TARGET_HOST` holding the raw scope string
  (`cli:///abs/path`), plus `CERT_X_GEN_TARGET_PORT` and `CERT_X_GEN_MODE`; derive the
  kind and the binary path from that string when the explicit variables are absent.
  There is also no `--input` / `--arg` / `--stdin-file`.
- **Per-finding `cwe_ids` are overwritten by the engine** with a value derived from the
  template's own annotations, so a finding's CWE list does not survive into the report
  as emitted.

Prove a `cli` template both ways before shipping it, on a flawed and a fixed twin built
from **one** source. `tests/run-coding-agent-config-trust.sh` and
`tests/prove-supply-chain-install-hook.sh` are the worked examples;
`tests/prove-coding-agent-command-trace.sh` is the worked example for a **stateful**
check whose finding lives in a *sequence* of observations, not one — it runs a
control trace to establish the surface, then the probe, and asserts skip/refute/confirm.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Adding templates / a new category

CI (`.github/workflows/ci.yml`) gates every PR on four checks; run them locally before pushing:
1. **Engine loads all templates** — `cxg --disable-update-check -vv template list` then `.github/scripts/check_loader.py`. Locally this fails on WARN/dedup lines from `~/.cert-x-gen/templates` (the published set cxg merges in); run with a throwaway `HOME=$(mktemp -d)` to see this repo alone. CI has no such cache.
2. **Registry is current** — regenerate with `python3 scripts/generate-index.py` and commit `TEMPLATE_REGISTRY.json`; it is generated, never hand-edited. Only files with a language extension (see `EXT_LANG`) count as templates — `.lib`, `.md`, etc. are ignored.
3. **Generator guard tests** — `python3 scripts/test_generate_index.py`.
4. **Hygiene** — `python3 .github/scripts/check_hygiene.py`. A **new category directory under `templates/` must be added to `VALID_CATEGORIES` in `.github/scripts/check_hygiene.py`**, or this fails.

Template metadata (`@id`, `@name`, `@severity`, …) is read from the **first 50 lines only**; every `@id` must be unique repo-wide or the engine drops all colliders. `templates/TEMPLATE_REGISTRY.md` is a human-maintained index — update it too when adding a category.

## Sharp edges

**Fixtures and test data must live outside `templates/`.** `scripts/generate-index.py`
skips a `tests/` directory; the engine loader (`src/template/engine.rs`) does not. Any
file under `templates/` with a language extension - even in a `tests/` or `fixtures/`
subdirectory - is loaded as a template, so the loader count and the generator count
diverge and CI check 1 fails. This repo's fixtures live at the repo root under `tests/`.

**`.gitignore` swallows `*.lib`, and with it `templates/cli-baseline/cli-baseline.lib`.**
The fourteen `cli-baseline` templates source that library as their first act and it has
never been committed, so from a clone every one of them prints
`probe-library-not-found` and exits. The only copy is in the engine repo at
`tests/fixtures/cli-baseline/pack/`. Nothing in CI notices, because the templates still
load and still emit valid JSON. A new pack should be self-contained rather than inherit
this.

**The pinned cxg release is behind the engine source.** `v1.3.0` as pinned in
`.github/workflows/ci.yml` predates the probe-input work: it has no `--input` /
`--arg` / `--stdin-file`, never sets `CERT_X_GEN_TARGET_KIND`, leaves the `cli://`
prefix on `CERT_X_GEN_TARGET_HOST`, and **discards the stdout of any template that
exits non-zero regardless of `@allow_nonzero_exit`**. A template that wants to run on
the pinned binary as well as on a current engine must tolerate all four, and must carry
its verdict in `metadata.status` rather than in an exit code.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

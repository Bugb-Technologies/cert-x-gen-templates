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

## Fixtures

A template's synthetic target lives in `fixtures/<template-id>/`, **never** beside the template: `discover()` in `scripts/generate-index.py` indexes every file under `templates/` carrying a language extension, so a `.py` fixture stored there is loaded and run as a check. Give each fixture a flawed/fixed twin and a `prove.sh` that asserts **both** directions (confirm and refute) — see `fixtures/mcp-token-audience-confusion/` for a behavioural (property-oracle) example that also proves the SKIP path a differential check must keep distinct.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

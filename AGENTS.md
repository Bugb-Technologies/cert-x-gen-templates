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

## Writing a `cli` target-kind template (sharp edges in the pinned engine)

Verified against the CI-pinned `cxg v1.3.0`; re-check when `CXG_VERSION` moves.

- **A shell template must `exit 0`, even when it confirms.** The engine discards
  a shell template's findings entirely if the process exits non-zero, and
  `@allow_nonzero_exit: true` does not change that. Carry the verdict in the
  emitted JSON's `metadata.status`, never in the exit code.
- **`CERT_X_GEN_TARGET_KIND` and `CERT_X_GEN_TARGET_INSTRUMENTATION` are not
  set.** A `cli` template receives only `CERT_X_GEN_TARGET_HOST` holding the raw
  scope string (`cli:///abs/path`), plus `CERT_X_GEN_TARGET_PORT` and
  `CERT_X_GEN_MODE`. Derive the kind and the binary path from that string when
  the explicit variables are absent — see
  `templates/ai/coding-agent/coding-agent-shared-config-trust.sh`.
- **Per-finding `cwe_ids` are overwritten by the engine** with a value derived
  from the template's own annotations, so a finding's CWE list does not survive
  into the scan report as emitted.
- `templates/cli-baseline/cli-baseline.lib` — which all fourteen `cli-baseline`
  templates source as their first act — is **not in this repo**. Those templates
  emit `errored: probe-library-not-found` until it is added.

Prove a `cli` template both ways before shipping it: a flawed and a fixed twin
built from **one** source, confirmed on the first and refuted on the second.
`tests/run-coding-agent-config-trust.sh` is the worked example.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

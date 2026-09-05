# Fixture: coding-agent-workspace-interpreter-shadowing

Synthetic twin pair proving
`templates/ai/coding-agent/coding-agent-workspace-interpreter-shadowing.sh`.

`agentstub.py` is a benign, single-source "coding agent" CLI. `build.sh`
substitutes `@@VARIANT@@` to produce two twins:

- `agentstub_defective.py` — runs `python3 -c <benign self-check>` with the
  workspace as cwd and nothing removed from the module search path. CPython
  prepends `''` (cwd) to `sys.path` for `-c`, so a workspace `struct.py` /
  `json.py` / `shutil.py` shadows the standard library. **CONFIRMED.**
- `agentstub_fixed.py` — the same program, same snippet, with
  `PYTHONSAFEPATH=1` in the environment (the one-flag mitigation). The cwd is
  dropped from `sys.path`, so no workspace file can answer an import. **REFUTED**
  (with the wrapped-interpreter positive control proving the run happened).

The SKIP twin — a CLI with the same command surface that invokes no interpreter
— is generated inline by `tests/prove-coding-agent-workspace-interpreter-shadowing.sh`.

Nothing here is an exploit: the "attack" is the three planted look-alikes the
template writes, each of which only records a nonce and re-exports the genuine
module. The agent's self-check imports json/struct/shutil and touches zipfile
(whose stdlib source itself does `import struct`) — its own good-faith code, no
workspace input consumed.

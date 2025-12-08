# CERT-X-GEN JavaScript Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for JavaScript CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `javascript-template-skeleton.js` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for JavaScript templates.

## Runtime contract (per run)
- **Single target per run**: The engine passes exactly one `host` + `port` per invocation.
- The engine sets environment variables (see `SKELETON_CONTRACT.md` for full details):
  - `CERT_X_GEN_TARGET_HOST`
  - `CERT_X_GEN_TARGET_PORT`
  - `CERT_X_GEN_MODE` (value `"engine"` when run from CERT-X-GEN)
  - Optional advanced hints (do not treat as a generic scan list):
    - `CERT_X_GEN_ADD_PORTS`
    - `CERT_X_GEN_OVERRIDE_PORTS`
  - `CERT_X_GEN_CONTEXT` – JSON string with additional context.

**Do not** implement your own target/port expansion.
**Do not** loop over `ADD_PORTS` / `OVERRIDE_PORTS` to build a generic multi-port scanner.

## Where to put custom logic
- Keep the following exactly as in `javascript-template-skeleton.js`:
  - CLI / argument parsing.
  - Environment variable handling and context object population.
  - JSON formatting and any special marker fields.
- Implement detection logic inside the main execution path for the template (for example, the core `execute` / `run` function or equivalent referenced by `main`).
- Use the provided helper functions for HTTP or network operations instead of re-inventing the plumbing.

## Output expectations
- Always emit valid JSON to **stdout**.
- Follow the JSON shape shown in `javascript-template-skeleton.js` and `SKELETON_CONTRACT.md`:
  - Emit a findings array/collection with the expected fields.
  - Preserve any marker fields the skeleton writes (for example, `__cert_x_gen_template__` or similar, if present in the skeleton).
- Write logs, debugging output, and error messages to **stderr**, not stdout.
- An empty findings array is valid when nothing is detected.

## Good patterns for JavaScript
- Use the standard HTTP / networking libraries already wired in the skeleton.
- Build small, focused checks for a specific vulnerability or misconfiguration.
- Keep asynchronous behavior simple and predictable (respect timeouts already in the skeleton).

## Things to avoid
- Changing CLI parsing, required env vars, or JSON structure.
- Removing or renaming special markers that the engine or tools may rely on.
- Implementing generic multi-target or multi-port scanners.
- Inventing new environment variables or output formats beyond what `SKELETON_CONTRACT.md` defines.

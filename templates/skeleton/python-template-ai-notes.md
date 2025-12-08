# CERT-X-GEN Python Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for Python CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `python-template-skeleton.py` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for Python templates.

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
Treat all ports as hints for *this* target only.

## Where to put custom logic
- Keep the following exactly as in `python-template-skeleton.py`:
  - CLI argument parsing.
  - Environment variable handling.
  - JSON formatting and any special marker fields.
- Implement detection logic inside the template’s main execution path (for example, the `execute` method or equivalent) as indicated by the comments in the skeleton.
- Use helper functions from the skeleton for networking, HTTP, and utility behavior instead of re-implementing them.

## Output expectations
- Always emit valid JSON to **stdout**.
- Follow the JSON shape shown in `python-template-skeleton.py` and `SKELETON_CONTRACT.md`:
  - Emit a findings collection with the expected fields.
  - Preserve any marker fields the skeleton writes (for example, `__cert_x_gen_template__` or similar, if present in the skeleton).
- Write logs, debugging output, and error messages to **stderr**, not stdout.
- An empty findings list is valid when nothing is detected.

## Good patterns for Python
- Use standard libraries or well-known HTTP/TCP libraries already used by the skeleton, rather than introducing new dependencies.
- Keep checks small and focused on a single vulnerability or misconfiguration.
- Use clear, structured evidence fields in findings so the engine can display useful details.

## Things to avoid
- Changing argument parsing, required env vars, or JSON structure.
- Removing or renaming special markers that the engine relies on.
- Scanning multiple unrelated hosts or ports in a single run.
- Inventing new environment variables or output formats that are not defined in `SKELETON_CONTRACT.md`.

# CERT-X-GEN C Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for C CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `c-template-skeleton.c` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for C templates.

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
**Do not** iterate over `ADD_PORTS` / `OVERRIDE_PORTS` as a generic scan list.

## Where to put custom logic
- Preserve:
  - CLI argument parsing and env var reading.
  - Context buffers and JSON construction logic.
  - Any output markers used by the engine.
- Implement detection in the designated scan function(s) that work with the single `target_host` and `target_port`.
- Use the existing networking helpers (e.g., `libcurl` / socket functions) wired into the skeleton.

## Output expectations
- Always print valid JSON to **stdout**.
- Follow the JSON structure defined in `c-template-skeleton.c` and `SKELETON_CONTRACT.md`:
  - array of findings with required fields.
  - any marker fields must remain unchanged.
- Print logs and errors to **stderr**, not stdout.
- An empty findings array is valid when nothing is detected.

## Good patterns for C
- Reuse the provided helpers for HTTP and error handling.
- Keep logic small and carefully check error codes.

## Things to avoid
- Changing env/CLI behavior or JSON layout.
- Removing or altering special markers.
- Implementing host/port enumeration or generic scanners.
- Inventing new environment variables or JSON fields not in `SKELETON_CONTRACT.md`.

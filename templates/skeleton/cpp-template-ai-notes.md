# CERT-X-GEN C++ Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for C++ CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `cpp-template-skeleton.cpp` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for C++ templates.

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
**Do not** loop over `ADD_PORTS` / `OVERRIDE_PORTS` as a generic scanner.

## Where to put custom logic
- Leave intact:
  - CLI argument parsing.
  - Environment variable reading and context map population.
  - JSON serialization and any marker fields.
- Implement detection logic in the main scan/execution functions that handle the single host+port.
- Use existing helpers (e.g., `libcurl` or sockets) included in the skeleton.

## Output expectations
- Always output valid JSON to **stdout**.
- Match the JSON structure defined in `cpp-template-skeleton.cpp` and `SKELETON_CONTRACT.md`:
  - a container of findings with required fields.
  - any marker fields must be preserved.
- Write logs and errors to **stderr**, not stdout.
- Returning an empty findings container is valid.

## Good patterns for C++
- Use RAII and standard containers for safe memory management.
- Reuse provided helper functions for networking and error handling.

## Things to avoid
- Modifying env/CLI parsing or JSON shape.
- Removing or renaming engine markers.
- Implementing host/port enumeration or generic scanners.
- Inventing new environment variables or fields not defined in `SKELETON_CONTRACT.md`.

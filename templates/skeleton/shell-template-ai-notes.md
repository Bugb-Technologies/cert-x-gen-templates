# CERT-X-GEN Shell Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for POSIX shell CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `shell-template-skeleton.sh` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for shell templates.

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
**Do not** treat `ADD_PORTS` / `OVERRIDE_PORTS` as a generic scan list.

## Where to put custom logic
- Keep intact:
  - Argument parsing.
  - Environment variable capture and context handling.
  - JSON construction and markers.
- Implement detection in the functions that operate on the single host+port, as indicated in the skeleton.
- Use existing helpers (curl/netcat/etc.) wired into the skeleton instead of inventing new plumbing.

## Output expectations
- Always print valid JSON to **stdout**.
- Match the JSON structure shown in `shell-template-skeleton.sh` and `SKELETON_CONTRACT.md`:
  - findings array with required fields.
  - any markers must remain untouched.
- Write logging and error messages to **stderr**.
- Returning an empty findings array is valid.

## Good patterns for Shell
- Use simple, robust commands; handle failures explicitly.
- Avoid unnecessary external dependencies beyond what the skeleton already uses.

## Things to avoid
- Changing env/CLI behavior or JSON layout.
- Removing or renaming markers.
- Implementing generic multi-host/multi-port scanners.
- Inventing unsupported env vars or JSON structures.

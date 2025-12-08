# CERT-X-GEN Rust Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for Rust CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `rust-template-skeleton.rs` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for Rust templates.

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
**Do not** loop over `ADD_PORTS` / `OVERRIDE_PORTS` to build generic scanners.

## Where to put custom logic
- Keep in place and unchanged:
  - CLI argument parsing.
  - Environment variable reading and context map population.
  - JSON serialization and any marker fields.
- Implement detection logic in the main scan/execution function(s) identified in the skeleton, using the single host and port provided by the engine.
- Use provided helper functions for TCP/HTTP operations and error handling.

## Output expectations
- Always output valid JSON to **stdout**.
- Match the JSON format shown in `rust-template-skeleton.rs` and `SKELETON_CONTRACT.md`:
  - a vector of findings with required fields.
  - any marker fields must be preserved.
- Write diagnostics and errors to **stderr** only.
- An empty findings vector is allowed when nothing is detected.

## Good patterns for Rust
- Use idiomatic Rust: `Result`, error types, and existing helper functions.
- Keep detection logic small, focused, and side-effect free beyond networking.

## Things to avoid
- Modifying env/CLI contracts or JSON layout.
- Removing or renaming engine markers.
- Implementing your own host/port enumeration.
- Inventing unsupported environment variables or output formats.

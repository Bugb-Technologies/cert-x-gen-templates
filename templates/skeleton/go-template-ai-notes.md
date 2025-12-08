# CERT-X-GEN Go Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for Go CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `go-template-skeleton.go` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for Go templates.

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
**Do not** iterate over `ADD_PORTS` / `OVERRIDE_PORTS` to perform generic multi-port scans.

## Where to put custom logic
- Keep in place and unchanged:
  - CLI / flag parsing.
  - Environment variable reading and context map population.
  - JSON encoding and any marker fields.
- Implement detection logic inside the main scan function(s) indicated by the skeleton comments, working with the single `host` and `port` that the engine provides.
- Use the helper functions already defined in the skeleton for HTTP/TCP operations and error handling.

## Output expectations
- Always write valid JSON to **stdout**.
- Use the JSON structure shown in `go-template-skeleton.go` and `SKELETON_CONTRACT.md`:
  - findings slice with the expected fields.
  - Any special marker fields (such as `__cert_x_gen_template__` if present) must be preserved.
- Send logs and diagnostics to **stderr**, not stdout.
- Returning an empty findings slice is valid when nothing is found.

## Good patterns for Go
- Use idiomatic Go: contexts, timeouts, and `net/http` / `net` packages as wired in the skeleton.
- Make small, focused vulnerability checks, not frameworks.

## Things to avoid
- Modifying flag/env handling or JSON layout.
- Removing markers required by the engine.
- Implementing host or port enumeration beyond what the engine provides.
- Introducing incompatible output formats or env variables.

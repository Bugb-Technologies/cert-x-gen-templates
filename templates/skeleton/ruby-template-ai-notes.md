# CERT-X-GEN Ruby Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for Ruby CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `ruby-template-skeleton.rb` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for Ruby templates.

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
  - Environment variable reading and `@context` population.
  - JSON serialization and any marker fields.
- Implement detection inside the main execution methods indicated in the skeleton, working with the single host+port.
- Use any provided HTTP/network helpers instead of re-implementing them.

## Output expectations
- Always emit valid JSON to **stdout**.
- Use the JSON shape shown in `ruby-template-skeleton.rb` and `SKELETON_CONTRACT.md`:
  - array of findings hashes with required keys.
  - any marker fields must remain.
- Logs, debug, and errors go to **stderr**, not stdout.
- An empty findings array is valid.

## Good patterns for Ruby
- Use idiomatic Ruby (`Net::HTTP`, etc.) as wired into the skeleton.
- Keep the template small and focused on a single vulnerability.

## Things to avoid
- Modifying env/CLI behavior or JSON layout.
- Removing or renaming markers.
- Implementing generic host/port scanners.
- Inventing non-standard env vars or JSON fields.

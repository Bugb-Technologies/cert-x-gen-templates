# CERT-X-GEN Java Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for Java CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `java-template-skeleton.java` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for Java templates.

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
**Do not** loop over `ADD_PORTS` / `OVERRIDE_PORTS` to create a generic multi-port scanner.

## Where to put custom logic
- Preserve the following logic from `java-template-skeleton.java`:
  - CLI / argument parsing.
  - Environment variable reading and context map population.
  - JSON serialization and any marker fields.
- Implement detection logic in the main template execution methods as indicated in the skeleton (for example, the scan/execute method that processes the single host+port).
- Reuse the HTTP and networking helpers already provided by the skeleton.

## Output expectations
- Always emit valid JSON to **stdout**.
- Follow the JSON structure from `java-template-skeleton.java` and `SKELETON_CONTRACT.md`:
  - a collection of findings objects with the required fields.
  - any special markers (e.g., `__cert_x_gen_template__` if present) must remain.
- Logs and errors go to **stderr**, not stdout.
- An empty findings collection is valid.

## Good patterns for Java
- Use `java.net` and related classes already wired into the skeleton for HTTP/networking.
- Keep the template focused on one vulnerability or scenario.

## Things to avoid
- Changing CLI/env contracts or JSON layout.
- Removing or renaming output markers.
- Implementing multi-host or multi-port scan loops.
- Creating new env vars or output schemas that are not part of `SKELETON_CONTRACT.md`.

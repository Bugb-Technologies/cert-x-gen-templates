# CERT-X-GEN YAML Template Skeleton – AI Notes

## Purpose
- **Role**: Canonical declarative template format for CERT-X-GEN.
- **Companion**: This file explains how to use `yaml-template-skeleton.yaml` correctly.
- **Contract**: YAML templates must follow `SKELETON_CONTRACT.md` (metadata, input/ports, output/evidence, flows) and the engine’s YAML implementation.

If you are an AI or template author, treat this file as guidance for generating valid YAML templates.

## Structure expectations
- Keep the primary top-level sections as demonstrated in `yaml-template-skeleton.yaml`:
  - `metadata`
  - protocol sections such as `http` and/or `network`
  - optional `flows` for multi-step logic
- Follow the metadata example for:
  - `id`, `name`, `description`, `severity`, `remediation`, `tags`, `cwe`, etc.
- Use the matcher catalog as shown in the skeleton:
  - string, regex, word, binary, status, size, expr, and others listed there.
- Do not rename or remove core fields; extend only where the engine allows it.

## Runtime model
- The engine still enforces **single-target-per-run** behavior.
- Templates should be written assuming a single host/port context; do not try to fan out to many unrelated targets.
- Use flows, extractors, and variables to implement multi-step checks for that one target.

## Output and evidence
- YAML templates do not emit JSON directly; the engine constructs findings from matchers and flows.
- Ensure each matcher and flow step provides enough information for the engine to build meaningful evidence and remediation hints, as illustrated in the skeleton.

## Good patterns for YAML
- Start from `yaml-template-skeleton.yaml` and adapt:
  - choose appropriate protocol block(s) (`http`, `network`),
  - select matcher types that best express the condition,
  - add clear remediation and classification metadata.
- Keep templates focused on a specific vulnerability or misconfiguration.

## Things to avoid
- Adding arbitrary new top-level keys that the YAML engine does not know about.
- Implementing generic port/host scanning loops in YAML (targeting is handled by the engine).
- Ignoring the example matcher and flow patterns; they are designed to match engine capabilities.

# Template Writing Guide

## Introduction

This guide covers how to write security scanning templates for CERT-X-GEN.

## Template Anatomy

### YAML Templates

```yaml
id: unique-template-id           # Unique identifier
info:
  name: Human Readable Name       # Clear, descriptive name
  author: Your Name               # Template author
  severity: high                  # critical|high|medium|low|info
  description: |                  # What this detects
    Detailed description of the vulnerability
  references:                     # External references
    - https://cve.mitre.org/...
  tags:                           # Categorization
    - database
    - unauthenticated

protocol: tcp                     # tcp|udp|http|https
port: 6379                        # Default port

inputs:                           # Data to send
  - data: "INFO\r\n"
    type: text

matchers:                         # Detection logic
  - type: word
    words:
      - "redis_version"
    condition: and

extract:                          # Data extraction
  - redis_version
  - os
```

### Best Practices

1. **Clear Naming**
   - Use descriptive IDs: `redis-unauth` not `check1`
   - Human-readable names in info section

2. **Proper Severity**
   - **Critical:** RCE, auth bypass, data exposure
   - **High:** Sensitive info disclosure, weak crypto
   - **Medium:** Information leaks, misconfigurations
   - **Low:** Version disclosure, minor issues
   - **Info:** Banner grabbing, service detection

3. **Good Documentation**
   - Clear description
   - Link to CVE/CWE/advisories
   - Explain impact
   - Add tags

4. **Safe Testing**
   - Non-destructive checks only
   - Handle errors gracefully
   - Timeout appropriately
   - Clean up after testing

## Language-Specific Guides

Per-language conventions — and the `cli` target-kind caveats that trip people up
(a shell template must `exit 0` even when it confirms; `CERT_X_GEN_TARGET_KIND`
is not set) — are in
[CONTRIBUTING.md](../CONTRIBUTING.md#cli-target-kind-caveats).

Skeletons for all supported languages ship with the published template set:

```bash
ls ~/.cert-x-gen/templates/official/templates/skeleton/
```

## Examples

The templates in this repository are the annotated examples — read one in your
language before writing your own:

- [`templates/ai/mcp/mcp-tool-poisoning.py`](../templates/ai/mcp/mcp-tool-poisoning.py) — Python, `http`, a positional/conjunctive oracle with an explicit near-miss `observations` channel
- [`templates/ai/mcp/mcp-excessive-scope-proof.py`](../templates/ai/mcp/mcp-excessive-scope-proof.py) — one template serving both `http` and `cli`
- [`templates/databases/postgresql/postgresql-default-credentials.go`](../templates/databases/postgresql/postgresql-default-credentials.go) — Go, binary wire protocol
- [`templates/network/smtp/smtp-open-relay.py`](../templates/network/smtp/smtp-open-relay.py) — a stateful, multi-step protocol conversation

Each differentiated template also has a human-facing playbook with a mermaid
probe-flow diagram under [`docs/playbooks/`](playbooks/);
[`coding-agent-execution-authority.md`](playbooks/coding-agent-execution-authority.md)
is the worked example.
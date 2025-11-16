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

See [LANGUAGES.md](LANGUAGES.md) for detailed guides for each language.

## Examples

See [EXAMPLES.md](EXAMPLES.md) for annotated examples.
# Contributing to CERT-X-GEN Templates

Thank you for considering contributing to CERT-X-GEN Templates! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Template Guidelines](#template-guidelines)
- [Development Workflow](#development-workflow)
- [Style Guide](#style-guide)
- [Testing](#testing)

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you're expected to uphold this code.

## How Can I Contribute?

### 1. Reporting Bugs

- Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md)
- Search existing issues first
- Include template that causes the issue
- Provide minimal reproduction steps

### 2. Suggesting Enhancements

- Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md)
- Clearly describe the enhancement
- Explain why it would be useful

### 3. Submitting New Templates

- Use the [New Template template](.github/ISSUE_TEMPLATE/new_template.md)
- Follow the [Template Guidelines](#template-guidelines)
- Test your template thoroughly

### 4. Improving Documentation

- Fix typos, clarify explanations
- Add examples
- Update outdated information

## Template Guidelines

### Template Quality Standards

✅ **Must Have:**
- Unique template ID
- Clear description
- Severity level
- Author information
- Test cases

⚠️ **Best Practices:**
- Handle errors gracefully
- Provide clear output
- Include references (CVE, CWE, etc.)
- Add tags for categorization
- Document required permissions

❌ **Avoid:**
- Templates that cause service disruption
- Templates with hardcoded credentials
- Overly aggressive scanning
- False positives
- Duplicate functionality

### Template Structure

#### YAML Templates (Recommended)

```yaml
id: unique-template-id
info:
  name: Human Readable Name
  author: Your Name
  severity: high|medium|low|info
  description: Clear description of what this detects
  references:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-XXXX
  tags:
    - category
    - vulnerability-type

protocol: tcp|udp|http|https
port: 6379

inputs:
  - data: "INFO\r\n"
    type: text

matchers:
  - type: word
    words:
      - "redis_version"
    condition: and

extract:
  - redis_version
  - os
```

#### Python Templates

```python
#!/usr/bin/env python3
"""
Template: unique-template-id
Name: Descriptive Name
Author: Your Name
Severity: high|medium|low|info
Description: What this template detects
"""

import os
import json
import sys

def scan(target_host, target_port):
    """
    Main scanning logic
    
    Args:
        target_host: Target hostname or IP
        target_port: Target port number
        
    Returns:
        dict: Finding data or None
    """
    try:
        # Your scanning logic here
        pass
    except Exception as e:
        return None

if __name__ == "__main__":
    host = os.environ.get("CERT_X_GEN_TARGET_HOST")
    port = int(os.environ.get("CERT_X_GEN_TARGET_PORT", 0))
    
    result = scan(host, port)
    
    if result:
        output = {
            "findings": [{
                "id": "unique-template-id",
                "name": "Descriptive Name",
                "severity": "high",
                "description": "Description",
                "evidence": result,
                "tags": ["tag1", "tag2"]
            }]
        }
        print(json.dumps(output))
```

### Directory Placement

Place templates in the correct directory:

```
yaml/http/cves/          # CVE-specific web vulnerabilities
yaml/http/misconfigurations/  # Web misconfigurations
yaml/network/databases/  # Database checks
yaml/network/services/   # Service checks
python/custom/           # Custom Python logic
```

## Development Workflow

### Fork and Clone

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/cert-x-gen-templates.git
cd cert-x-gen-templates
git remote add upstream https://github.com/BugB-Tech/cert-x-gen-templates.git
```

### Create Branch

```bash
git checkout -b feature/redis-authentication-bypass
```

### Make Changes

1. Add your template
2. Update CHANGELOG.md
3. Update TEMPLATE_REGISTRY.json (or run `scripts/generate-index.py`)

### Validate

```bash
# Validate single template
./scripts/validate.sh yaml/network/databases/redis-unauth.yaml

# Validate all templates
./scripts/validate.sh
```

### Test

```bash
# Test against live target (with permission!)
cert-x-gen template test --template your-template.yaml --target test.example.com

# Use test infrastructure
cd tests
python3 test_template.py ../yaml/network/databases/redis-unauth.yaml
```

### Commit

```bash
git add .
git commit -m "Add Redis authentication bypass template

- Detects Redis instances without authentication
- Includes metadata extraction
- Tested against Redis 6.x and 7.x
- References: CVE-2024-XXXXX
"
```

Use meaningful commit messages:
- First line: Summary (50 chars max)
- Blank line
- Detailed explanation
- References to issues

### Push and PR

```bash
git push origin feature/redis-authentication-bypass
```

Then open a Pull Request on GitHub.

## Style Guide

### Naming Conventions

**Template IDs:**
- Lowercase with hyphens
- Format: `service-vulnerability-type`
- Examples: `redis-unauth`, `mysql-default-creds`, `apache-log4j-rce`

**Files:**
- Match template ID
- Include extension
- Examples: `redis-unauth.yaml`, `mysql-default-creds.py`

### YAML Style

```yaml
# Use 2 spaces for indentation
id: template-id

# Use descriptive names
info:
  name: Human Readable Name  # Not "Check 1"
  
# Add blank lines between sections
protocol: tcp

inputs:
  - data: "PING\r\n"
```

### Code Style

**Python:**
- Follow PEP 8
- Type hints encouraged
- Docstrings for functions

**JavaScript:**
- Use modern ES6+ syntax
- Async/await over callbacks
- JSDoc comments

**Shell:**
- Shellcheck compliant
- Quote variables
- Use `set -e`

## Testing

### Unit Tests

For programmatic templates (Python, JavaScript, etc.):

```python
# tests/test_redis_unauth.py
def test_redis_unauth_detection():
    result = scan_redis("localhost", 6379)
    assert result is not None
    assert result["severity"] == "high"
```

### Integration Tests

Test against Docker containers:

```bash
# Start test environment
docker-compose -f tests/docker-compose.yml up -d redis-no-auth

# Run template
cert-x-gen scan --template redis-unauth --target localhost:6379

# Cleanup
docker-compose -f tests/docker-compose.yml down
```

### Manual Testing

Always test against:
1. Vulnerable target (should detect)
2. Patched target (should not detect)
3. Unavailable target (should handle gracefully)

## Review Process

1. **Automated Checks:**
   - CI validates template syntax
   - Linting checks code style
   - Tests must pass

2. **Maintainer Review:**
   - Template quality
   - No false positives
   - Security implications
   - Documentation

3. **Community Feedback:**
   - Other contributors may comment
   - Address feedback promptly

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md
- Release notes
- Monthly contributor spotlight

## Questions?

- 💬 Discord: [Join our community](https://discord.gg/cert-x-gen)
- 📧 Email: templates@bugb.tech
- 🐛 Issues: [GitHub Issues](https://github.com/BugB-Tech/cert-x-gen-templates/issues)

Thank you for contributing! 🚀
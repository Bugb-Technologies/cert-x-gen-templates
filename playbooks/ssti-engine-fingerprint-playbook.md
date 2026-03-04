# Server-Side Template Injection (SSTI) Engine Fingerprinting

<div align="center">

![CERT-X-GEN](https://img.shields.io/badge/CERT--X--GEN-Playbook-blue?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-High-orange?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Python-yellow?style=for-the-badge)
![CVSS](https://img.shields.io/badge/CVSS-8.6-high?style=for-the-badge)

**Detecting template injection vulnerabilities through engine fingerprinting**

*Why simple payload injection isn't enough and how CERT-X-GEN's multi-engine approach succeeds*

</div>

---

## 📖 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Understanding the Vulnerability](#understanding-the-vulnerability)
3. [Why Traditional Scanners Struggle](#why-traditional-scanners-struggle)
4. [The CERT-X-GEN Approach](#the-cert-x-gen-approach)
5. [Attack Flow Visualization](#attack-flow-visualization)
6. [Template Deep Dive](#template-deep-dive)
7. [Usage Guide](#usage-guide)
8. [Real-World Test Results](#real-world-test-results)
9. [Defense & Remediation](#defense--remediation)
10. [Extending the Template](#extending-the-template)
11. [References](#references)

---

## Executive Summary

Server-Side Template Injection (SSTI) is a vulnerability that occurs when user input is embedded into template engines without proper sanitization, allowing attackers to inject and execute arbitrary template directives. This can lead to remote code execution, data exfiltration, and complete server compromise.

**The Challenge**: Different web frameworks use different template engines (Jinja2, Twig, Freemarker, Velocity, etc.), each with unique syntax and behaviors. Generic payload testing often fails to detect these vulnerabilities.

> 💡 **Key Insight**: SSTI detection requires engine-specific payloads and response analysis. CERT-X-GEN tests multiple template engines simultaneously, fingerprinting which engine processes the input and whether it's vulnerable.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 8.6 (High) |
| **CWE** | CWE-94 (Code Injection), CWE-1336 (Template Injection) |
| **Engines Detected** | Jinja2, Freemarker, Velocity, Smarty, Mako, ERB, Thymeleaf |
| **Detection Method** | Mathematical expression injection + response analysis |
| **Exploitation Risk** | High (can lead to RCE) |

---

## Understanding the Vulnerability

### What is SSTI?

Template engines allow developers to generate dynamic HTML by combining templates with data. When user input is inserted directly into templates without sanitization, attackers can inject template directives that execute server-side.

### Common Vulnerable Patterns

**Example 1: Flask/Jinja2 (Python)**
```python
# ❌ VULNERABLE
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f'<h1>Hello {{{{ {name} }}}}</h1>'
    return render_template_string(template)
```

Attacker payload: `?name={{7*7}}` → Server renders: `<h1>Hello 49</h1>`

**Example 2: Spring/Thymeleaf (Java)**
```java
// ❌ VULNERABLE  
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    return "inline:" + name;  // Direct template rendering
}
```

Attacker payload: `?name=${7*7}` → Server executes expression

### Why This is Critical

```
┌─────────────────────────────────────────────────────────────────┐
│                    SSTI ATTACK PROGRESSION                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Discovery: {{7*7}} → 49 (template engine confirmed)         │
│                         ↓                                        │
│  2. Fingerprinting: Identify specific engine (Jinja2/Twig/etc.) │
│                         ↓                                        │
│  3. Exploration: Access internal objects/classes                │
│                         ↓                                        │
│  4. Exploitation: Execute system commands                       │
│                         ↓                                        │
│  5. Impact: Full server compromise, data theft, lateral movement│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Why Traditional Scanners Struggle

### The Multi-Engine Problem

Traditional web vulnerability scanners face several challenges:

| Challenge | Impact | CERT-X-GEN Solution |
|-----------|--------|---------------------|
| **Engine Diversity** | Different syntax per engine | Tests 7+ engines simultaneously |
| **Context Awareness** | Injection points vary | Tests GET/POST parameters, headers, paths |
| **False Positives** | Math in HTML can be coincidental | Verifies expected output matches |
| **Performance** | Testing all permutations is slow | Optimized payload selection |

### YAML Scanner Limitations

**What Nuclei CAN do:**
```yaml
id: ssti-detection
requests:
  - raw:
      - |
        GET /?q={{7*7}} HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words:
          - "49"
```

**What it CANNOT do:**
- Distinguish between `49` in page content vs. template output
- Test multiple engines efficiently
- Verify the engine type
- Handle encoding/context variations
- Provide confidence scoring

**CERT-X-GEN Advantage:**
```python
# Tests multiple engines with verification
for payload, expected, engine, pattern in PAYLOADS:
    response = send_payload(payload)
    if re.search(pattern, response) and expected in response:
        # Confirmed: engine is vulnerable
        return {
            "engine": engine,
            "confidence": 90,
            "evidence": response
        }
```

---

## The CERT-X-GEN Approach

### Multi-Engine Detection Strategy

CERT-X-GEN uses a systematic approach to detect SSTI across multiple template engines:

```
┌──────────────────────────────────────────────────────────────────┐
│                    CERT-X-GEN DETECTION FLOW                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scanner ──────► Target: GET /?q={{7*7}}                          │
│     │                                                            │
│     ▼                                                            │
│  Response Analysis: Search for "49" in output                    │
│     │                                                            │
│     ▼                                                            │
│  Engine Fingerprint: Jinja2 detected (Flask/Django)             │
│     │                                                            │
│     ▼                                                            │
│  Scanner ──────► Target: POST /search param=${7*7}               │
│     │                                                            │
│     ▼                                                            │
│  Response Analysis: Search for "49" in output                    │
│     │                                                            │
│     ▼                                                            │
│  Engine Fingerprint: Freemarker detected (Java)                 │
│     │                                                            │
│     ▼                                                            │
│  Result: 🔴 HIGH severity - Multiple engines vulnerable          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Supported Template Engines

| Engine | Language | Framework | Payload | Detection |
|--------|----------|-----------|---------|-----------|
| **Jinja2** | Python | Flask, Django | `{{7*7}}` | → 49 |
| **Freemarker** | Java | Spring | `${7*7}` | → 49 |
| **Velocity** | Java | Legacy Java | `#set($x=7*7)$x` | → 49 |
| **Smarty** | PHP | Various PHP | `{7*7}` | → 49 |
| **Mako** | Python | Pyramid | `${7*7}` | → 49 |
| **ERB** | Ruby | Rails | `<%= 7*7 %>` | → 49 |
| **Thymeleaf** | Java | Spring Boot | `[(7*7)]` | → 49 |

### Key Detection Features

1. **Multi-Context Testing**: Tests GET parameters, POST body, headers
2. **Smart Encoding**: Handles URL encoding, HTML entities
3. **Pattern Verification**: Uses regex to avoid false positives
4. **Engine Deduplication**: Stops testing once engine is identified
5. **Performance Optimization**: Limited payloads (7), reduced paths (2), fast timeouts (3s)

---

## Attack Flow Visualization

### Complete Detection Chain

**Phase 1: Reconnaissance**
- 🔍 Identify Web Application
- 📡 Test Common Parameters
- 🎯 Inject Mathematical Payloads

**Phase 2: Analysis**
- 📝 Capture HTTP Responses
- 🔬 Search for Expected Patterns
- 🎯 Identify Template Engine

**Phase 3: Verification**
- ⚙️ Test Multiple Injection Points
- 🔄 Verify Consistency
- ✅ Confirm Vulnerability

**Phase 4: Reporting**
- 📊 Document Engine Type
- 🔴 Assess Severity (High)
- 📋 Provide Remediation Steps

### Payload Transformation

```
┌─────────────────────────────────────────────────────────────────┐
│                      DETECTION PAYLOAD                           │
├─────────────────────────────────────────────────────────────────┤
│ Original: {{7*7}}                                                │
│ Encoded:  %7B%7B7*7%7D%7D                                        │
│ Injected: GET /?q=%7B%7B7*7%7D%7D                                │
│                                                                  │
│ Server Response (if vulnerable):                                 │
│ HTTP/1.1 200 OK                                                  │
│ <html><body>Search results for: 49</body></html>                │
│                                                                  │
│ Detection: "49" found → Jinja2/Twig detected → VULNERABLE! 🔴   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Core Detection Implementation

```python
def test_ssti(host: str, port: int = 80, timeout: int = 3) -> List[Dict]:
    """
    Test for SSTI vulnerabilities across multiple template engines.
    
    Strategy:
    1. Test common injection points (/, /search)
    2. Test common parameters (q, name, search)
    3. Inject engine-specific payloads
    4. Verify expected output in response
    5. Return findings with engine identification
    """
    findings = []
    detected_engines = set()
    
    test_paths = ["/", "/search"]
    test_params = ["q", "name", "search"]
    
    for test_path in test_paths:
        for param in test_params:
            for payload, expected, engine, pattern in PAYLOADS:
                # Skip if already detected
                if engine in detected_engines:
                    continue
                
                # URL encode payload
                encoded = urllib.parse.quote(payload, safe='')
                path_with_param = f"{test_path}?{param}={encoded}"
                
                # Send request
                status, headers, body = send_http_request(
                    host, port, "GET", path_with_param,
                    {"User-Agent": "cert-x-gen/1.0"}, "", timeout
                )
                
                # Verify vulnerability
                if status == 200 and re.search(pattern, body):
                    if expected in body:
                        detected_engines.add(engine)
                        findings.append({
                            "engine": engine,
                            "severity": "high",
                            "confidence": 90,
                            "evidence": body[:500]
                        })
```

### Payload Design

**Why `{{7*7}}` instead of `{{7+7}}`?**

Multiplication is more distinctive than addition:
- `7+7` might appear in URLs, prices, pagination
- `7*7=49` is unique and unlikely to appear naturally
- Pattern `\b49\b` (word boundary) reduces false positives

**Engine-Specific Considerations:**

```python
# Jinja2 (Python)
"{{7*7}}"  # Simple, direct

# Freemarker (Java)  
"${7*7}"   # Dollar syntax

# Velocity (Java)
"#set($x=7*7)$x"  # Requires variable assignment

# ERB (Ruby)
"<%= 7*7 %>"  # Explicit execution tag

# Thymeleaf (Java)
"[(7*7)]"  # Inline expression syntax
```

---

## Usage Guide

### Basic Usage

```bash
# Scan a single target
cxg scan --scope example.com --templates ssti-engine-fingerprint.py

# Scan with explicit port
cxg scan --scope example.com:8080 --templates ssti-engine-fingerprint.py

# Scan multiple targets
cxg scan --scope example.com,test.com,app.com --templates ssti-engine-fingerprint.py

# JSON output
cxg scan --scope example.com --templates ssti-engine-fingerprint.py --output-format json

# Verbose mode
cxg scan --scope example.com --templates ssti-engine-fingerprint.py -v
```

### Direct Template Execution

```bash
# Run template directly
python3 ssti-engine-fingerprint.py example.com 80

# Test HTTPS endpoint  
python3 ssti-engine-fingerprint.py example.com 443

# Test local development server
python3 ssti-engine-fingerprint.py localhost 5000
```

### Expected Output (Vulnerable)

```json
{
  "findings": [{
    "target": "vulnerable-app.com:80",
    "template_id": "ssti-engine-fingerprint",
    "severity": "high",
    "confidence": 90,
    "title": "SSTI Vulnerability Detected - Jinja2 Template Engine",
    "description": "Server-Side Template Injection vulnerability detected...",
    "evidence": {
      "engine": "Jinja2",
      "injection_point": "GET parameter",
      "parameter": "q",
      "payload": "{{7*7}}",
      "expected_output": "49",
      "path": "/?q=%7B%7B7*7%7D%7D",
      "response_snippet": "<html>...49...</html>",
      "matched": true
    },
    "remediation": "Implement proper input validation..."
  }]
}
```

### Expected Output (Not Vulnerable)

```json
{
  "findings": [{
    "target": "secure-app.com:80",
    "template_id": "ssti-engine-fingerprint",
    "severity": "info",
    "confidence": 50,
    "title": "No SSTI Vulnerabilities Detected",
    "description": "No Server-Side Template Injection vulnerabilities were detected...",
    "evidence": {
      "payloads_tested": 7,
      "paths_tested": 2,
      "parameters_tested": 3
    }
  }]
}
```

---

## Real-World Test Results

The template was tested against live Flask servers discovered via FOFA:

| Target | Port | Engine | Vulnerable | Response Time | Notes |
|--------|------|--------|------------|---------------|-------|
| 143.198.152.168 | 80 | Flask | ❌ | 45.65s | Properly sanitized input |
| 54.209.77.172 | 80 | Flask | ❌ | 18.65s | Modern Flask (patched) |
| 52.28.24.33 | 80 | Flask | ❌ | 18.22s | Secure configuration |
| 149.56.103.96 | 80 | Flask | ❌ | 20.53s | No template injection |

**Key Findings**:
- ✅ Template executes reliably across all targets
- ✅ Graceful handling of non-vulnerable applications  
- ✅ Clean JSON output with proper structure
- ✅ Fast execution (18-21s average after optimization)
- ✅ No false positives detected

**Observations**:
- Modern Flask applications properly sanitize template input
- The template correctly identifies when SSTI is not present
- Performance optimizations (3s timeout, reduced payloads) significantly improved speed
- Template provides clear "info" severity when no vulnerability found

---

## Defense & Remediation

### Secure Implementation

**Flask/Jinja2 (Python):**
```python
# ✅ SECURE: Never use render_template_string with user input
from flask import Flask, render_template, request
from markupsafe import escape

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # Option 1: Use escape() to sanitize
    safe_name = escape(name)
    return render_template('hello.html', name=safe_name)
    
    # Option 2: Use template files (recommended)
    return render_template('hello.html', name=name)

# ❌ NEVER DO THIS:
# template = f'<h1>Hello {{{{ {name} }}}}</h1>'
# return render_template_string(template)
```

**Spring/Thymeleaf (Java):**
```java
// ✅ SECURE: Use template files with proper escaping
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    // Thymeleaf automatically escapes by default
    model.addAttribute("name", name);
    return "greet";  // Returns greet.html template
}

// In greet.html:
// <h1 th:text="'Hello ' + ${name}">Hello World</h1>
// Thymeleaf escapes ${name} automatically
```

### Defense Checklist

**Configuration:**
- ✅ Never use `render_template_string()` or inline templates with user input
- ✅ Always use template files from secure directories
- ✅ Enable auto-escaping in template engine configuration
- ✅ Implement Content Security Policy (CSP) headers

**Input Validation:**
- ✅ Sanitize all user input before template processing
- ✅ Use allowlist validation (only permit expected characters)
- ✅ Escape template syntax characters ({{, }}, ${, etc.)
- ✅ Validate parameter types and lengths

**Monitoring:**
- ✅ Log all template rendering operations
- ✅ Alert on suspicious patterns in user input
- ✅ Monitor for unusual server behavior
- ✅ Regular security audits of template usage

### Framework-Specific Fixes

| Framework | Secure Practice | Avoid |
|-----------|----------------|-------|
| **Flask (Jinja2)** | Use `render_template()` with files | `render_template_string()` with user input |
| **Django** | Use template files in TEMPLATES dirs | Direct string templates with user data |
| **Spring Boot (Thymeleaf)** | Return view names, not inline templates | `InlineTemplateResolver` with user input |
| **Ruby on Rails (ERB)** | Use view files in app/views | `ERB.new()` with user-controlled strings |
| **Express (Pug)** | Use template files | Compiling user input as templates |

### Security Headers

```python
# Add security headers to prevent exploitation
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

---

## Extending the Template

### Adding New Template Engines

```python
# Add to PAYLOADS list
PAYLOADS = [
    # ... existing payloads ...
    
    # Django Template Language
    ("{{7|add:7}}", "14", "Django", r"\b14\b"),
    
    # Mustache
    ("{{#lambda}}7*7{{/lambda}}", "49", "Mustache", r"\b49\b"),
    
    # Liquid (Ruby)
    ("{{ 7 | times: 7 }}", "49", "Liquid", r"\b49\b"),
]
```

### Testing Additional Injection Points

```python
# Test HTTP headers
def test_header_injection(host, port):
    headers = {
        "User-Agent": "{{7*7}}",
        "Referer": "${7*7}",
        "X-Custom": "#set($x=7*7)$x"
    }
    # ... test logic ...

# Test path injection
def test_path_injection(host, port):
    paths = [
        "/{{7*7}}",
        "/user/${7*7}",
        "/page/#{7*7}"
    ]
    # ... test logic ...
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: SSTI Security Scan
  run: |
    cxg scan \
      --scope ${{ secrets.STAGING_URL }} \
      --templates ssti-engine-fingerprint.py \
      --output-format sarif \
      --output results.sarif
    
- name: Upload Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

---

## References

### Academic Papers & Research

1. James Kettle (PortSwigger Research). "Server-Side Template Injection: RCE for the Modern Web App"
2. Alvaro Muñoz & Oleksandr Mirosh. "Injecting Template Engines in Enterprise Java"
3. OWASP. "Server-Side Template Injection Prevention Cheat Sheet"

### Vulnerability Databases

| Engine | CVE Examples | Impact |
|--------|--------------|--------|
| **Jinja2** | CVE-2019-8341 | RCE via sandbox escape |
| **Freemarker** | CVE-2015-8270 | Remote code execution |
| **Velocity** | CVE-2020-13936 | RCE via template injection |
| **ERB** | CVE-2017-17485 | Code execution in Rails |

### Tools & Resources

- [PortSwigger SSTI Labs](https://portswigger.net/web-security/server-side-template-injection) - Interactive practice
- [HackTricks SSTI Guide](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) - Comprehensive payloads
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - SSTI testing methodology
- [Tplmap](https://github.com/epinna/tplmap) - Automated SSTI exploitation tool

### Template Engine Documentation

- [Jinja2 Security](https://jinja.palletsprojects.com/en/3.0.x/sandbox/) - Python template engine
- [Freemarker Security](https://freemarker.apache.org/docs/) - Java template engine  
- [Thymeleaf Security](https://www.thymeleaf.org/doc/articles/spring-security-integration.html) - Spring Boot templates
- [ERB Documentation](https://ruby-doc.org/stdlib-2.7.0/libdoc/erb/rdoc/ERB.html) - Ruby templates

---

<div align="center">

## 🚀 Ready to Scan?

```bash
# Run the template
cxg scan --scope your-target.com --templates ssti-engine-fingerprint.py
```

**Found SSTI using this template?**  
Let us know! Tag `@BugB-Tech` on Twitter with `#CERTXGEN`

---

*This playbook is part of the CERT-X-GEN Security Scanner documentation.*  
*Licensed under Apache 2.0. Contributions welcome!*

[GitHub](https://github.com/Bugb-Technologies/cert-x-gen) • [Templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) • [DeepWiki](https://deepwiki.com/Bugb-Technologies/cert-x-gen)

</div>

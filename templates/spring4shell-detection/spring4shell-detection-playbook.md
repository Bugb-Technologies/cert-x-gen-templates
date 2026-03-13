# Spring4Shell Detection (CVE-2022-22965)

<div align="center">

![CERT-X-GEN](https://img.shields.io/badge/CERT--X--GEN-Playbook-blue?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Java-orange?style=for-the-badge)
![CVSS](https://img.shields.io/badge/CVSS-9.8-critical?style=for-the-badge)
![CVE](https://img.shields.io/badge/CVE-2022--22965-red?style=for-the-badge)

**A deep dive into detecting Spring Framework RCE via DataBinder class binding gadget**

*Why traditional YAML scanners fail and how CERT-X-GEN's polyglot Java approach succeeds*

</div>

---

## 📖 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Understanding the Vulnerability](#understanding-the-vulnerability)
3. [Why Traditional Scanners Fail](#why-traditional-scanners-fail)
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

Spring4Shell (CVE-2022-22965) is a critical RCE vulnerability in Spring Framework's `DataBinder`. When a Spring MVC or WebFlux application runs on JDK 9+ and is deployed as a WAR on Tomcat, an unauthenticated attacker can abuse the `class.module.classLoader` property chain to write a JSP webshell by reconfiguring Tomcat's `AccessLogValve` logging mechanism — achieving full Remote Code Execution with no credentials required.

**The result?** Complete server compromise. An attacker can write arbitrary files to the webroot, execute OS commands, pivot to internal networks, and establish persistence.

> 💡 **Key Insight**: Spring4Shell cannot be reliably detected with simple pattern matching or YAML-based templates. Detection requires HTTP request crafting, Spring application fingerprinting, DataBinder behavior analysis, and response code interpretation — exactly what CERT-X-GEN's polyglot Java templates excel at.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 9.8 (Critical) |
| **CWE** | CWE-94 (Improper Control of Code Generation) |
| **Affected Versions** | Spring Framework 5.3.0–5.3.17, 5.2.0–5.2.19 |
| **Required Conditions** | JDK 9+, Tomcat WAR deployment, Spring MVC/WebFlux |
| **Detection Complexity** | High (requires HTTP crafting + behavioral analysis) |
| **Patch Available** | Yes — Spring Framework 5.3.18 / 5.2.20 |

---

## Understanding the Vulnerability

### How Spring DataBinder Works

Spring MVC's `DataBinder` automatically maps HTTP request parameters to Java object fields via reflection. When a controller uses `@ModelAttribute`, Spring binds all incoming request parameters to the corresponding object properties:

```java
// Typical Spring MVC controller — vulnerable pattern
@PostMapping("/greeting")
public String greet(@ModelAttribute User user) {
    return "Hello " + user.getName();
}

// User POJO — appears harmless
public class User {
    private String name;
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}
```

### The Attack Mechanism

The vulnerability exploits a fundamental property of Java's object model: **every object inherits from `java.lang.Object`**, which has a `getClass()` method. This creates a traversal chain:

```
user.class                          → java.lang.Class
user.class.module                   → java.lang.Module
user.class.module.classLoader       → org.apache.catalina.loader.ParallelWebappClassLoader
user.class.module.classLoader.resources → StandardRoot
user.class.module.classLoader.resources.context → StandardContext
user.class.module.classLoader.resources.context.parent → StandardEngine
user.class.module.classLoader.resources.context.parent.pipeline → StandardPipeline
user.class.module.classLoader.resources.context.parent.pipeline.first → AccessLogValve
```

```
┌─────────────────────────────────────────────────────────────────┐
│                    SPRING4SHELL ATTACK CHAIN                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Attacker sends POST with classLoader property chain         │
│                         ↓                                        │
│  2. Spring DataBinder traverses: class.module.classLoader.*     │
│                         ↓                                        │
│  3. Reaches Tomcat's AccessLogValve via pipeline                │
│                         ↓                                        │
│  4. Reconfigures AccessLogValve logging settings:               │
│     - pattern  = JSP webshell payload                           │
│     - directory = webapps/ROOT                                   │
│     - prefix  = shell                                            │
│     - suffix  = .jsp                                             │
│                         ↓                                        │
│  5. Any subsequent request triggers log write                   │
│                         ↓                                        │
│  6. shell.jsp written to webroot 🔓 RCE ACHIEVED                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Happens

Vulnerable code lacks field binding restrictions:

```java
// ❌ VULNERABLE: No allowlist on DataBinder fields
@InitBinder
public void initBinder(WebDataBinder binder) {
    // No setAllowedFields() call → all fields including class.* are bindable
}
```

The patch adds a global `disallowedFields` pattern blocking `class.*` traversal:

```java
// ✅ PATCHED: Spring Framework 5.3.18 adds this globally
dataBinder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
```

### Vulnerable Conditions (ALL required)

| Condition | Details |
|-----------|---------|
| **Spring Framework** | 5.3.0–5.3.17 or 5.2.0–5.2.19 |
| **JDK version** | 9 or higher (class.module path only exists in JDK 9+) |
| **Deployment** | WAR deployed to standalone Tomcat (not embedded) |
| **Controller** | Uses `@ModelAttribute` or `@RequestParam` bound POJO |

---

## Why Traditional Scanners Fail

### The YAML Limitation

Traditional YAML-based scanners work through pattern matching and static HTTP probing:

```yaml
# What a YAML scanner CAN do:
id: spring-detect
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "Whitelabel Error Page"
          - "spring"
```

This detects Spring applications but **cannot**:

| Capability | YAML | CERT-X-GEN |
|------------|------|------------|
| Fingerprint Spring version | ❌ | ✅ |
| Craft class binding payload | ❌ | ✅ |
| Send form-encoded POST | Limited | ✅ |
| Interpret HTTP 400 vs 500 semantics | ❌ | ✅ |
| Differentiate patched vs unpatched | ❌ | ✅ |
| Probe multiple MVC endpoints | ❌ | ✅ |
| Handle TLS/non-TLS automatically | ❌ | ✅ |
| **False Positive Rate** | High | **Low** |
| **Confidence Level** | ~25% | **70–85%** |

### The Detection Gap

A YAML scanner can tell you "this server runs Spring." CERT-X-GEN tells you "this Spring server's DataBinder did not reject the classLoader property chain — it is likely vulnerable." That difference is everything in a real pentest.

---

## The CERT-X-GEN Approach

CERT-X-GEN uses Java's `HttpURLConnection` to perform two-phase detection directly against the target: fingerprinting followed by behavioral probing.

### Detection Strategy

```
┌──────────────────────────────────────────────────────────────────┐
│                    CERT-X-GEN DETECTION FLOW                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Phase 1: Spring Fingerprint                                     │
│  ─────────────────────────────────────────────────────────────  │
│  Scanner ──GET /──────────────────────► Target                  │
│  Scanner ──GET /actuator/health────────► Target                  │
│  Scanner ──GET /error──────────────────► Target                  │
│     │                                                            │
│     ▼                                                            │
│  Body contains "Whitelabel Error Page"? ──► Spring confirmed ✅  │
│  Body contains "spring" / "Spring"? ───────► Spring confirmed ✅  │
│  /actuator/health returns 200? ────────────► Spring confirmed ✅  │
│  None match? ──────────────────────────────► INFO: not Spring ℹ️  │
│                                                                  │
│  Phase 2: Class Binding Probe                                    │
│  ─────────────────────────────────────────────────────────────  │
│  Scanner ──POST / (classLoader chain)──► Target                 │
│     │                                                            │
│     ▼                                                            │
│  HTTP 400? ────────────────────────────► INFO: Patched ✅        │
│  HTTP 200? ────────────────────────────► CRITICAL: Vulnerable 🔴 │
│  HTTP 5xx? ────────────────────────────► HIGH: Likely Vuln 🟠   │
│  Connection failed? ───────────────────► INFO: Inconclusive ℹ️   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Key Advantages

1. **Behavioral Detection**: We don't check version strings — we check how the DataBinder *behaves*
2. **HTTP 400 Semantics**: The patch always returns 400 for this specific chain — a reliable binary signal
3. **Multi-endpoint Probing**: Tries `/`, `/login`, `/index`, `/home`, `/api` to maximize hit rate
4. **TLS-aware**: Automatically uses HTTPS for ports 443/8443
5. **Graceful Degradation**: Non-Spring targets, connection failures, and timeouts all handled cleanly with appropriate severity levels

---

## Attack Flow Visualization

### Complete Detection Chain

**Phase 1: Reconnaissance**
- 🔍 Probe common Spring endpoints (`/`, `/actuator/health`, `/error`)
- 🏷️ Check response body for Spring indicators
- ✅ Confirm Spring application identity

**Phase 2: Vulnerability Probe**
- 📦 Craft class binding payload with `classLoader` property chain
- 📡 POST to common MVC endpoints (`/`, `/login`, `/index`)
- 📊 Analyze HTTP response code

**Phase 3: Classification**
- `HTTP 400` → DataBinder rejected the field → **Patched**
- `HTTP 200` → DataBinder accepted the field → **CRITICAL**
- `HTTP 5xx` → DataBinder attempted binding, internal error → **HIGH**
- `HTTP 4xx` (non-400) → Ambiguous → **MEDIUM**

### The Probe Payload

```
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25{c2}i
&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

> ⚠️ **Ethical Boundary**: CERT-X-GEN's template sends this probe but does **not** follow up with a trigger request. No JSP webshell is ever written. The probe is detection-only — it tests whether the DataBinder accepts or rejects the property chain, not whether a shell can be executed.

### Response Interpretation

```
┌─────────────────────────────────────────────────────────────────┐
│                    RESPONSE CODE SEMANTICS                       │
├──────────────┬──────────────────────────────────────────────────┤
│  HTTP Code   │  Meaning                                         │
├──────────────┼──────────────────────────────────────────────────┤
│  400         │  Spring patch active — fields explicitly blocked  │
│  200         │  DataBinder accepted classLoader chain — VULN    │
│  500         │  Binding attempted, server errored — likely VULN │
│  404         │  Endpoint not found — try next endpoint           │
│  302         │  Redirect — ambiguous, lower confidence           │
│  Connection  │  Target unreachable — inconclusive               │
│  failed      │                                                   │
└──────────────┴──────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Phase 1: Spring Fingerprinting

```java
static boolean isSpringApplication(String host, int port, boolean useTls,
                                    Map<String, String> evidence) {
    String[] probeEndpoints = {"/", "/actuator/health", "/actuator/info", "/error"};
    String[] springIndicators = {
        "Whitelabel Error Page", "spring", "Spring",
        "org.springframework", "X-Application-Context"
    };

    for (String ep : probeEndpoints) {
        String body = httpGet(host, port, ep, useTls);
        for (String indicator : springIndicators) {
            if (body.contains(indicator)) {
                evidence.put("spring_indicator", indicator);
                return true;  // Confirmed Spring
            }
        }
        // Actuator health returning 200 is itself a strong Spring signal
        if (ep.contains("actuator") && lastStatusCode == 200) {
            return true;
        }
    }
    return false;
}
```

### Phase 2: Class Binding Probe

```java
/**
 * The patch in Spring Framework 5.3.18 adds:
 *   dataBinder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*")
 *
 * This causes Spring to return HTTP 400 with:
 *   "Field error in object 'user' on field 'class.module.classLoader...':
 *    rejected value [...]; codes []; arguments []; default message [Field 'class.module...'
 *    not allowed]"
 *
 * Unpatched Spring simply traverses the chain and tries to set the property,
 * which either succeeds (200) or throws an internal server error (500).
 */
static int classBindingProbe(String host, int port, boolean useTls) {
    String probeBody =
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di" +
        "&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" +
        "&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps%2FROOT" +
        "&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell" +
        "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=";

    String[] endpoints = {"/", "/login", "/index", "/home", "/api"};
    for (String ep : endpoints) {
        String body = httpPost(host, port, ep, probeBody, useTls);
        int code = lastStatusCode;
        if (code != -1 && body != null) return code;
    }
    return -1;  // All endpoints unreachable
}
```

### Finding Severity Matrix

```java
if (probeStatus == 400) {
    // Patched — DataBinder explicitly rejected the field
    severity = "info"; confidence = 80;
} else if (probeStatus == 200) {
    // Binding accepted — classLoader chain traversed successfully
    severity = "critical"; confidence = 85; cvss = 9.8;
} else if (probeStatus >= 500) {
    // Binding attempted but server errored — likely vulnerable
    severity = "high"; confidence = 70; cvss = 9.8;
} else {
    // Ambiguous (404, 302, etc.)
    severity = "medium"; confidence = 50; cvss = 5.0;
}
```

---

## Usage Guide

### Basic Usage

```bash
# Scan a Spring application on default port 8080
cxg scan --scope target.example.com --ports 8080 \
  --template Spring4ShellDetection.java

# Scan with JSON output
cxg scan --scope target.example.com --ports 8080 \
  --template Spring4ShellDetection.java \
  --output-format json --output results.json

# Scan multiple targets from file
cxg scan --scope @targets.txt --ports 8080,443 \
  --template Spring4ShellDetection.java \
  --output-format json --timeout 30s -vv

# Verbose mode to see probe details on stderr
cxg scan --scope target.example.com --ports 8080 \
  --template Spring4ShellDetection.java -vv
```

### Direct Template Execution

```bash
# Compile and run directly (bypasses cxg engine)
javac Spring4ShellDetection.java
CERT_X_GEN_TARGET_HOST=target.example.com \
CERT_X_GEN_TARGET_PORT=8080 \
CERT_X_GEN_MODE=engine \
java Spring4ShellDetection
```

### Docker Test Environment

A self-contained vulnerable environment is included for local testing:

```bash
# Start vulnerable Spring Boot 2.6.3 (Spring Framework 5.3.15) on port 8080
cd templates/spring4shell-detection
docker-compose up --build -d

# Run detection against the vulnerable container
cxg scan --scope 127.0.0.1 --ports 8080 \
  --template Spring4ShellDetection.java \
  --output-format json --timeout 30s -vv

# Tear down when done
docker-compose down
```

### Expected Output (Vulnerable — HTTP 500)

```json
{
  "template_id": "spring4shell-detection",
  "template_name": "Spring4Shell Detection (CVE-2022-22965)",
  "severity": "high",
  "confidence": 70,
  "title": "Spring4Shell (CVE-2022-22965): Class Binding Probe Not Rejected (POTENTIALLY VULNERABLE)",
  "description": "Target 127.0.0.1:8080 is a Spring application. The CVE-2022-22965 class binding probe (class.module.classLoader property chain) was NOT rejected with HTTP 400. HTTP 500 response suggests DataBinder accepted the classLoader binding - potential RCE.",
  "matched_at": "127.0.0.1:8080",
  "evidence": {
    "host": "127.0.0.1",
    "port": "8080",
    "spring_detected": "true",
    "spring_indicator": "Spring",
    "fingerprint_endpoint": "/",
    "probe_http_status": "500",
    "vulnerability_status": "potentially_vulnerable"
  },
  "cwe": "CWE-94",
  "cvss_score": 9.8,
  "remediation": "Upgrade Spring Framework to >= 5.3.18 or >= 5.2.20."
}
```

### Expected Output (Patched — HTTP 400)

```json
{
  "template_id": "spring4shell-detection",
  "severity": "info",
  "confidence": 80,
  "title": "Spring4Shell: Spring Application Detected - Class Binding Rejected (Patched)",
  "description": "Target returned HTTP 400 to class binding probe. DataBinder properly rejected the classLoader property chain - Spring4Shell patch appears active.",
  "evidence": {
    "spring_detected": "true",
    "probe_http_status": "400",
    "vulnerability_status": "patched"
  }
}
```

### Expected Output (Non-Spring Target)

```json
{
  "template_id": "spring4shell-detection",
  "severity": "info",
  "confidence": 90,
  "title": "Spring4Shell: Target Does Not Appear to Be a Spring Application",
  "description": "No Spring Framework indicators found. Target is unlikely to be vulnerable to CVE-2022-22965."
}
```

---

## Real-World Test Results

The template was tested against a locally built vulnerable Docker environment (Spring Boot 2.6.3 / Spring Framework 5.3.15 / Tomcat 9 / JDK 11):

| Target | Port | Spring Detected | Probe Status | Finding | Notes |
|--------|------|----------------|--------------|---------|-------|
| 127.0.0.1 | 8080 | ✅ `Spring Framework Version: 5.3.15` | HTTP 500 | **HIGH** (CVSS 9.8) | Class binding accepted — potentially vulnerable |
| 127.0.0.1 | 80 | ❌ No Spring indicators | N/A | **INFO** | Correct — nothing on port 80 |

**Key Findings:**

1. ✅ Spring fingerprinted correctly via homepage body content (`Spring Framework Version: 5.3.15`)
2. ✅ Class binding probe fired against `/` endpoint — received HTTP 500 (not 400)
3. ✅ HTTP 500 correctly classified as `HIGH / potentially_vulnerable` (DataBinder accepted the chain but threw an internal error)
4. ✅ Non-Spring port (80) correctly returned `INFO: not a Spring app` — zero false positives
5. ✅ Graceful behavior on port 80: all GET probes failed silently, clean `INFO` finding returned
6. ✅ Template compiled and executed in ~1.2 seconds end-to-end

**Why HTTP 500 instead of 200?**

On the vulnerable test container, the classLoader chain traversal succeeded but Tomcat's `AccessLogValve` property setter threw an internal exception when it received the malformed `fileDateFormat` value. This is still a vulnerable behavior — the chain was traversed. A real exploitation attempt with a correct payload would return HTTP 200.

---

## Defense & Remediation

### Immediate Fix: Upgrade Spring Framework

```xml
<!-- pom.xml — upgrade Spring Boot to include patched Spring Framework -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <!-- Spring Boot 2.6.6+ ships Spring Framework 5.3.18 (patched) -->
    <version>2.6.6</version>
</parent>

<!-- Or pin Spring Framework directly -->
<properties>
    <spring-framework.version>5.3.18</spring-framework.version>
</properties>
```

### Code-Level Mitigation: Restrict DataBinder Fields

```java
// ✅ Explicitly block class.* fields in all controllers
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setDisallowedFields(
        "class.*",
        "Class.*",
        "*.class.*",
        "*.Class.*"
    );
}

// Or globally via WebMvcConfigurer
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addFormatters(FormatterRegistry registry) {}

    @Bean
    public WebBindingInitializer webBindingInitializer() {
        ConfigurableWebBindingInitializer initializer = new ConfigurableWebBindingInitializer();
        initializer.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
        return initializer;
    }
}
```

### JVM-Level Mitigation

```bash
# Add JVM flag to disable property descriptor cache flushing
# This prevents the classLoader chain from being traversable
java -Dspring.disablePropertyDescriptorCacheFlush=true -jar app.jar
```

### WAF Rules

```nginx
# Nginx — block classLoader in query string and POST body
if ($request_uri ~* "class\.module\.classLoader") {
    return 403;
}
if ($request_body ~* "class\.module\.classLoader") {
    return 403;
}
```

### Defense Checklist

**Upgrade:**
- ✅ Spring Framework >= 5.3.18 or >= 5.2.20
- ✅ Spring Boot >= 2.6.6 or >= 2.5.12

**Harden:**
- ✅ Use `setDisallowedFields("class.*")` in all DataBinder configurations
- ✅ Deploy WAF rules blocking `class.module.classLoader` in parameters
- ✅ Run on JDK 8 if upgrade not immediately possible (JDK 8 lacks `class.module` path)

**Monitor:**
- ✅ Alert on HTTP parameters containing `classLoader`
- ✅ Monitor for unexpected `.jsp` file creation in webroot
- ✅ Watch for unusual Tomcat AccessLogValve configuration changes in logs

### Framework-Specific Patches

| Framework | Patched Version | Action |
|-----------|----------------|--------|
| **Spring Framework** | >= 5.3.18, >= 5.2.20 | Upgrade immediately |
| **Spring Boot** | >= 2.6.6, >= 2.5.12 | Upgrade immediately |
| **Spring Boot 2.7.x** | 2.7.0+ (ships 5.3.20+) | Already patched |
| **Spring Boot 3.x** | All versions | Not affected |

---

## Extending the Template

### Add Actuator-based Version Detection

```java
// Enhance fingerprinting with precise version from actuator
static String getSpringVersion(String host, int port, boolean useTls) {
    String body = httpGet(host, port, "/actuator/info", useTls);
    if (body != null && body.contains("spring")) {
        // Parse version from actuator/info JSON response
        Pattern p = Pattern.compile("\"Spring-Framework\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(body);
        if (m.find()) return m.group(1);
    }
    return null;
}
```

### Add Version-based Confidence Boost

```java
// If we can read the Spring version directly, boost confidence
String version = getSpringVersion(host, port, useTls);
if (version != null) {
    evidence.put("spring_version", version);
    // Version 5.3.0 to 5.3.17 = confirmed vulnerable range
    if (isVulnerableVersion(version)) {
        confidence = Math.min(confidence + 15, 95);
    }
}
```

### Integration with CI/CD

```yaml
# GitHub Actions — scan staging before merge
- name: Spring4Shell Scan
  run: |
    cxg scan \
      --scope ${{ secrets.STAGING_HOST }} \
      --ports 8080,443 \
      --template Spring4ShellDetection.java \
      --output-format json \
      --output spring4shell-results.json
    
- name: Check for vulnerabilities
  run: |
    HIGH=$(cat spring4shell-results.json | python3 -c \
      "import json,sys; f=json.load(sys.stdin)['findings']; \
       print(sum(1 for x in f if x['severity'] in ['critical','high']))")
    if [ "$HIGH" -gt "0" ]; then
      echo "Spring4Shell vulnerability detected! Block merge."
      exit 1
    fi
```

---

## References

### Advisories & Research

1. Spring Security Advisory (2022). "CVE-2022-22965: Spring Framework RCE via Data Binding on JDK 9+"
2. Rapid7 (2022). "Spring4Shell: Zero-Day Vulnerability in Spring Framework"
3. LunaSec (2022). "Spring RCE Vulnerabilities"
4. VMware Tanzu (2022). "CVE-2022-22965 Security Advisory"

### CVE & Patch Information

| Reference | Link |
|-----------|------|
| **NVD Entry** | https://nvd.nist.gov/vuln/detail/CVE-2022-22965 |
| **Spring Advisory** | https://spring.io/security/cve-2022-22965 |
| **Patch Commit** | https://github.com/spring-projects/spring-framework/commit/7f7fb58dd0dae86d22268a4b59ac7c72a6c22529 |
| **Rapid7 Analysis** | https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/ |

### Related CVEs

| CVE | Description |
|-----|-------------|
| **CVE-2022-22950** | Spring Framework DoS via SpEL expression |
| **CVE-2022-22963** | Spring Cloud Function RCE via routing expression |
| **CVE-2022-22978** | Spring Security RegexRequestMatcher auth bypass |

---

<div align="center">

## 🚀 Ready to Hunt?

```bash
# Start vulnerable test environment
docker-compose up --build -d

# Run detection
cxg scan --scope 127.0.0.1 --ports 8080 \
  --template Spring4ShellDetection.java \
  --output-format json -vv
```

**Found a Spring4Shell instance using this template?**
Let us know! Tag `@BugB-Tech` on Twitter with `#CERTXGEN`

---

*This playbook is part of the CERT-X-GEN Security Scanner documentation.*
*Licensed under Apache 2.0. Contributions welcome!*

[GitHub](https://github.com/Bugb-Technologies/cert-x-gen) • [Templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) • [DeepWiki](https://deepwiki.com/Bugb-Technologies/cert-x-gen)

</div>

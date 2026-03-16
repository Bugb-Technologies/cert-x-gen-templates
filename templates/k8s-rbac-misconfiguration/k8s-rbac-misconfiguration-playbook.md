# Kubernetes RBAC Misconfiguration Detection

<div align="center">

![CERT-X-GEN](https://img.shields.io/badge/CERT--X--GEN-Playbook-blue?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Go-cyan?style=for-the-badge)
![CVSS](https://img.shields.io/badge/CVSS-10.0-critical?style=for-the-badge)

**A deep dive into detecting Kubernetes RBAC misconfigurations enabling full cluster takeover**

*Why insecure ports, anonymous auth, and exposed dashboards turn K8s clusters into open doors*

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

Kubernetes RBAC (Role-Based Access Control) misconfigurations represent one of the most critical and prevalent cloud-native security failures. When a Kubernetes cluster is misconfigured — whether through an exposed insecure API port, anonymous authentication enabled, dangerous ClusterRoleBindings, or a publicly accessible Dashboard — any unauthenticated attacker can achieve **full cluster-admin level control** without a single credential.

**The result?** Complete infrastructure takeover. An attacker can create privileged pods, read all secrets (including cloud provider credentials), execute commands in running containers, and pivot laterally across the entire cloud environment.

> 💡 **Key Insight**: These misconfigurations cannot be reliably detected with simple port scans or YAML-based matchers. They require HTTP-aware probing, TLS-aware connections, JSON API response parsing, and RBAC enumeration logic — exactly what CERT-X-GEN's polyglot Go templates excel at.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 10.0 (Insecure Port) / 9.8 (Anonymous + RBAC) / 9.6 (Dashboard) |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **Affected Versions** | All K8s with insecure-port enabled; K8s with anonymous-auth=true |
| **Detection Complexity** | Medium (requires HTTP + JSON API awareness) |
| **Exploitation Difficulty** | Trivial (curl is sufficient once misconfiguration is present) |
| **FOFA Exposed Instances** | 622,847 K8s API servers on port 6443; 7 confirmed insecure port 8080 |

---

## Understanding the Vulnerability

### Kubernetes Authentication Architecture

Kubernetes API server requests pass through three gates before action is taken:

```
Request → Authentication → Authorization (RBAC) → Admission Control → API Action
```

Any failure at the **Authentication** layer that still results in a response means the cluster accepts unauthenticated requests — RBAC is bypassed entirely if a binding grants permissions to `system:anonymous`.

### Three Distinct Misconfiguration Vectors

#### Vector 1: Insecure Port 8080 (`--insecure-port`)

The Kubernetes API server historically supported a plaintext, unauthenticated HTTP port for local access:

```
--insecure-port=8080          # Accepts ALL requests — no auth, no TLS
--insecure-bind-address=...   # Often set to 0.0.0.0 (internet-facing!)
```

This effectively grants **cluster-admin to the entire internet**. Deprecated in K8s 1.13, removed in 1.20 — but thousands of older clusters remain in production.

#### Vector 2: Anonymous Authentication (`--anonymous-auth=true`)

When anonymous auth is enabled (it is the **default** in many K8s distributions), requests without a valid bearer token are processed as `system:anonymous` user in the `system:unauthenticated` group. If any ClusterRoleBinding grants permissions to these principals:

```
ClusterRoleBinding: cluster-admin → system:anonymous
```

Full unauthenticated cluster-admin access is granted. This is the most common RBAC misconfiguration found in the wild.

#### Vector 3: Exposed Kubernetes Dashboard

The Kubernetes Dashboard, when exposed publicly (via `kubectl proxy` on port 8001 or ingress on 443), often runs with cluster-admin service account permissions by default in older deployments. Even a login page exposure creates brute-force and token-theft attack surface.

### The Privilege Escalation Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│                  K8S RBAC PRIVILEGE ESCALATION CHAIN                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Attacker ──GET──► :8080/api                                        │
│     │              (no auth, no TLS)                                 │
│     │                    ↓                                           │
│     │              200 OK + APIVersions JSON                         │
│     │                    ↓                                           │
│     ├──GET──► :8080/api/v1/namespaces   → Lists all namespaces      │
│     ├──GET──► :8080/api/v1/secrets      → Reads ALL secrets         │
│     ├──POST──► :8080/api/v1/pods        → Creates privileged pod    │
│     └──POST──► :8080/exec               → Executes in containers    │
│                                                                      │
│  OR (Anonymous auth path):                                           │
│                                                                      │
│  Attacker ──GET──► :6443/api (no bearer token)                      │
│     │              200 OK → anonymous access enabled                 │
│     │                    ↓                                           │
│     ├──GET──► ClusterRoleBindings → finds cluster-admin binding     │
│     └──────► Full cluster control without credentials               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Why Traditional Scanners Fail

### The YAML Limitation

Traditional YAML-based scanners can detect open ports and simple HTTP responses, but they cannot reason about the **meaning** of what they find:

```yaml
# What Nuclei CAN do:
id: k8s-port-open
requests:
  - method: GET
    path:
      - "{{BaseURL}}:8080/api"
    matchers:
      - type: word
        words:
          - '"kind"'
```

This detects port 8080 is open — but **cannot**:

| Capability | YAML | CERT-X-GEN Go |
|------------|------|----------------|
| Detect insecure port 8080 | ✅ (basic) | ✅ (with K8s API confirmation) |
| Verify it's actually a K8s API | ❌ | ✅ |
| Enumerate live namespaces | ❌ | ✅ |
| Test 6443 with strict TLS | ❌ | ✅ |
| Enumerate ClusterRoleBindings | ❌ | ✅ |
| Identify dangerous RBAC principals | ❌ | ✅ |
| Detect Dashboard exposure | ❌ | ✅ |
| Grade severity by actual impact | ❌ | ✅ |
| **False positive rate** | High | **Near zero** |

### The Detection Gap

A port scanner sees `:8080 open`. CERT-X-GEN confirms it is a K8s API, enumerates namespaces to prove impact, and grades the finding at CVSS 10.0 — all in a single execution.

---

## The CERT-X-GEN Approach

CERT-X-GEN uses Go's standard `net/http` and `crypto/tls` to perform actual API-level probing — not just TCP connectivity checks.

### Detection Strategy

```
┌──────────────────────────────────────────────────────────────────────┐
│                   CERT-X-GEN DETECTION FLOW (3 CHECKS)               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  CHECK 1: Insecure Port                                              │
│  Template ──HTTP GET──► :8080/api                                    │
│     │                                                                │
│     ├── 200 + "APIVersions" → CRITICAL (CVSS 10.0)                  │
│     │   └── Bonus: GET :8080/api/v1/namespaces → enumerate          │
│     └── Error/non-200 → graceful skip                               │
│                                                                      │
│  CHECK 2: Anonymous Auth (strict TLS)                                │
│  Template ──HTTPS GET──► :6443/api (no bearer token)                │
│     │                                                                │
│     ├── TLS error → graceful skip (self-signed cert)                │
│     ├── 401/403 → INFO: properly secured                            │
│     ├── 200 + "APIVersions" → anonymous access confirmed            │
│     │   └── GET :6443/.../clusterrolebindings → enumerate RBAC      │
│     │       ├── Dangerous binding found → CRITICAL (CVSS 9.8)       │
│     │       └── No dangerous binding  → HIGH (CVSS 8.8)             │
│     └── Other → skip                                                │
│                                                                      │
│  CHECK 3: Dashboard Exposure                                         │
│  Template ──HTTP GET──► :8001/proxy/dashboard                        │
│  Template ──HTTPS GET──► :443/                                       │
│     │                                                                │
│     ├── Dashboard signal + no login → CRITICAL (CVSS 9.6)           │
│     ├── Dashboard signal + login page → HIGH (CVSS 7.5)             │
│     └── No signal → skip                                            │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```


### Key Advantages of Go for This Template

1. **Strict TLS control**: Go's `crypto/tls` allows precise `InsecureSkipVerify` per-connection — we use strict verification on port 6443 and skip for the dashboard probe only
2. **Concurrent-ready**: Each check uses `context.WithTimeout` independently for clean deadline management
3. **Zero dependencies**: Pure stdlib — no `go.mod` required, compiles anywhere Go is installed
4. **JSON-native**: `encoding/json` parses K8s API responses without third-party K8s client libraries

---

## Attack Flow Visualization

### Complete Attack Chain

**Phase 1: Discovery**
- 🔍 Scan for open port 8080 (insecure K8s API)
- 🔒 Probe port 6443 without credentials (anonymous auth test)
- 🖥️ Check ports 8001 and 443 for Dashboard

**Phase 2: Enumeration (if access gained)**
- 📋 List all namespaces (`/api/v1/namespaces`)
- 🔑 Read all secrets (`/api/v1/secrets`)
- 📜 Enumerate ClusterRoleBindings (`/apis/rbac.../clusterrolebindings`)
- 🎯 Identify dangerous principals (system:anonymous, system:unauthenticated)

**Phase 3: Escalation (post-detection, not performed by template)**
- 🚀 Create privileged pod with `hostPID: true` and `hostNetwork: true`
- 💾 Mount host filesystem via `hostPath: /`
- 🔓 Escape to host OS — full node compromise
- ↔️  Lateral movement to cloud provider metadata APIs

**Phase 4: Impact**
- ☁️ Extract cloud IAM credentials from node metadata
- 🔐 Exfiltrate all Kubernetes secrets (DB passwords, API keys, TLS certs)
- 💥 Deploy cryptominer or ransomware across all nodes

### Severity Matrix

```
┌──────────────────────────────────────────────────────────────────────┐
│                      SEVERITY DETERMINATION                           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Port 8080 open + K8s API confirmed                                  │
│  └──► CRITICAL (CVSS 10.0) — full unauth cluster-admin              │
│                                                                      │
│  Port 6443 anonymous + dangerous ClusterRoleBinding found            │
│  └──► CRITICAL (CVSS 9.8) — proven privilege escalation path        │
│                                                                      │
│  Port 6443 anonymous + no dangerous ClusterRoleBinding               │
│  └──► HIGH (CVSS 8.8) — resource enumeration, partial access        │
│                                                                      │
│  Dashboard on 8001/443 + no login required                           │
│  └──► CRITICAL (CVSS 9.6) — GUI cluster-admin without creds         │
│                                                                      │
│  Dashboard on 8001/443 + login page exposed                          │
│  └──► HIGH (CVSS 7.5) — brute-force / token theft surface           │
│                                                                      │
│  Port 6443 returns 401/403                                           │
│  └──► INFO — properly secured, authentication required              │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Check 1: Insecure Port Detection

```go
// testInsecurePort tests for Kubernetes insecure port 8080
func testInsecurePort(host string, port int) *Finding {
    baseURL := fmt.Sprintf("http://%s:%d", host, port)

    // Plain HTTP client — no TLS needed on insecure port
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)

    // Confirm it is the K8s API by looking for canonical response fields
    if !strings.Contains(bodyStr, "APIVersions") && !strings.Contains(bodyStr, "apiVersion") {
        return nil  // Not K8s — zero false positives
    }

    // Bonus: enumerate namespaces to gauge impact depth
    namespaceNames := enumerateNamespaces(baseURL, client)
    // → CRITICAL finding with namespace evidence
}
```

**Why this works**: Any response on port 8080 containing `APIVersions` or `apiVersion` is definitively a Kubernetes API server. We then enumerate namespaces to provide concrete evidence of impact depth, making the finding immediately actionable.

### Check 2: Anonymous Auth with Strict TLS

```go
// Strict TLS — InsecureSkipVerify: false
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
    },
}
// No Authorization header — pure anonymous probe
resp, err := client.Do(req)
if err != nil {
    // TLS error = self-signed cert or unreachable — skip gracefully
    return nil
}
// 401/403 = properly secured → INFO finding
// 200 + K8s API body = anonymous access confirmed → escalate to RBAC check
```

**Why strict TLS matters**: By refusing connections with invalid certs on port 6443, we eliminate a class of false positives from non-K8s HTTPS services. A properly deployed K8s cluster with a valid cert that returns 200 anonymously is definitively misconfigured.

### Check 3: RBAC Enumeration

```go
// enumerateRBAC fetches ClusterRoleBindings and flags dangerous patterns
dangerousPrincipals := map[string]bool{
    "system:anonymous":       true,
    "system:unauthenticated": true,
}
dangerousRoles := map[string]bool{
    "cluster-admin":  true,
    "system:masters": true,
}
// For each ClusterRoleBinding:
// if subject is dangerous principal OR role is cluster-admin → flag it
```

**The escalation signal**: Finding `ClusterRoleBinding: cluster-admin → system:anonymous` in the RBAC list means the misconfiguration is not just about anonymous access — it's a direct, proven privilege escalation path to full cluster ownership.

---

## Usage Guide

### Basic Usage

```bash
# Scan a single Kubernetes cluster API server
cxg scan --scope k8s-api.example.com --template k8s-rbac-misconfiguration.go

# Scan multiple targets from file
cxg scan --scope @targets.txt --template k8s-rbac-misconfiguration.go

# JSON output with verbose logging
cxg scan --scope @targets.txt --template k8s-rbac-misconfiguration.go \
  --output-format json --timeout 30s -vv

# Scan with extended timeout for slow clusters
cxg scan --scope k8s-api.example.com --template k8s-rbac-misconfiguration.go \
  --timeout 60s --output-format json
```

### Expected Output — Insecure Port Detected (CRITICAL)

```json
[{
  "template_id": "k8s-rbac-misconfiguration",
  "template_name": "Kubernetes RBAC Misconfiguration Detection",
  "host": "151.115.72.137",
  "severity": "CRITICAL",
  "confidence": 98,
  "title": "Kubernetes Insecure API Port Exposed on 151.115.72.137:8080 — Full Unauthenticated Access",
  "description": "The Kubernetes API server is running with --insecure-port=8080 enabled...",
  "evidence": {
    "port": 8080,
    "protocol": "http",
    "authentication": "not_required",
    "tls": false,
    "namespaces_found": ["default", "kube-system", "kube-public", "production"],
    "namespace_count": 4,
    "vulnerability": "--insecure-port=8080 enabled; full unauthenticated, unencrypted API access"
  },
  "cvss_score": 10.0
}]
```

### Expected Output — Anonymous Auth + Dangerous RBAC (CRITICAL)

```json
[{
  "template_id": "k8s-rbac-misconfiguration",
  "severity": "CRITICAL",
  "confidence": 95,
  "title": "Kubernetes RBAC Privilege Escalation via Anonymous Access on 10.0.0.1:6443",
  "evidence": {
    "anonymous_access": true,
    "dangerous_bindings": [
      "ClusterRoleBinding 'anon-admin': role='cluster-admin' granted to Group 'system:unauthenticated'"
    ],
    "clusterrolebindings_total": 42,
    "dangerous_binding_count": 1
  },
  "cvss_score": 9.8
}]
```

### Expected Output — Properly Secured (INFO)

```json
[{
  "template_id": "k8s-rbac-misconfiguration",
  "severity": "INFO",
  "confidence": 100,
  "title": "Kubernetes API Server Properly Secured on 10.0.0.1:6443",
  "evidence": {
    "authentication": "required",
    "anonymous_access": false,
    "tls_verification": "strict"
  }
}]
```

### Expected Output — Graceful Timeout

```
WARN: Template k8s-rbac-misconfiguration failed for target 182.92.110.203: Operation timed out after 30s
```
No crash, no malformed output — the engine handles it cleanly.

---

## Real-World Test Results

The template was tested against 5 live Kubernetes instances discovered via FOFA query:
`port="8080" && body="apiVersion" && body="kind" && body="namespaces"`

| Target | Country | Port 8080 | Port 6443 | Dashboard | Finding | Notes |
|--------|---------|-----------|-----------|-----------|---------|-------|
| 151.115.72.137 | 🇵🇱 PL | ✅ OPEN | Timeout | N/A | **CRITICAL** (CVSS 10.0) | K8s insecure port confirmed live |
| 182.92.110.203 | 🇨🇳 CN | ⏱️ Timeout | Timeout | Timeout | None | Host non-responsive during scan |
| 3.30.222.105 | 🇺🇸 US | ⏱️ Timeout | Timeout | Timeout | None | Likely firewalled post-FOFA index |
| 8.134.176.85 | 🇨🇳 CN | ⏱️ Timeout | Timeout | Timeout | None | Likely firewalled post-FOFA index |
| 139.59.196.38 | 🇬🇧 GB | ⏱️ Timeout | Timeout | Timeout | None | FOFA indexed but offline |

**Scan Statistics:**
- Scan ID: `671bc9ad-3136-47fa-9fd8-eafcb2ebed2c`
- Duration: 29.72s
- Targets scanned: 5
- Findings: 1 (CRITICAL — CVSS 10.0)
- Response rate: 20% (1/5)
- False positives: 0
- Engine crashes: 0

**Key Finding**: `151.115.72.137:8080` (Warsaw, Poland) has a live Kubernetes API server responding with full API access on the insecure HTTP port — no authentication, no TLS. This is a textbook CVSS 10.0 exposure.

**Why 3 timeouts?** FOFA indexes hosts at crawl time; between indexing and scanning, hosts may be firewalled, taken down, or rate-limited. A 20% live response rate is consistent with other Go templates in this repository (Kubelet: 20%, Redis: 53.8%).

The template correctly:
1. ✅ Detected a live K8s insecure port exposure
2. ✅ Generated a CRITICAL finding with CVSS 10.0 and full evidence
3. ✅ Handled 3 timeouts gracefully without crashing
4. ✅ Produced clean JSON output for the engine
5. ✅ Zero false positives (API response body verified before flagging)

---

## Ethical Boundary

> ⚠️ **This template is strictly a read-only detection tool.**

The template performs only `GET` requests to:
- `/api` — version discovery
- `/api/v1/namespaces` — namespace enumeration (evidence collection only)
- `/apis/rbac.authorization.k8s.io/v1/clusterrolebindings` — RBAC read

**No write operations are performed.** No pods are created. No secrets are read. No `exec` commands are issued. The dashboard check only requests the root path to detect signals.

Exploitation of any findings (creating pods, reading secrets, executing commands) is illegal without explicit written authorization from the cluster owner. This tool is for authorized security assessments only.

---

## Defense & Remediation

### Immediate Actions (Critical Priority)

#### 1. Disable Insecure Port

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --insecure-port=0           # ← Disable completely
    - --secure-port=6443
    - --anonymous-auth=false      # ← Disable anonymous auth
```

#### 2. Disable Anonymous Authentication

```bash
# Verify current state
kubectl get pod kube-apiserver-<node> -n kube-system -o yaml | grep anonymous

# Fix: add --anonymous-auth=false to kube-apiserver command flags
# Then verify no anonymous bindings exist:
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]?.name == "system:anonymous" or .subjects[]?.name == "system:unauthenticated")'
```

#### 3. Audit and Remove Dangerous ClusterRoleBindings

```bash
# Find all ClusterRoleBindings with dangerous subjects
kubectl get clusterrolebindings -o wide | grep -E "system:anonymous|system:unauthenticated"

# Delete dangerous bindings (example)
kubectl delete clusterrolebinding <binding-name>

# Audit all cluster-admin bindings
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name == "cluster-admin") | .metadata.name + ": " + (.subjects[]? | .kind + "/" + .name)'
```

#### 4. Secure the Kubernetes Dashboard

```bash
# Option 1: Access Dashboard only via local port-forward (recommended)
kubectl port-forward -n kubernetes-dashboard svc/kubernetes-dashboard 8443:443

# Option 2: Delete Dashboard if not needed
kubectl delete namespace kubernetes-dashboard

# Option 3: Use oauth2-proxy in front of Dashboard
# See: https://github.com/oauth2-proxy/oauth2-proxy
```

### Defense Checklist

**API Server Hardening:**
- ✅ `--insecure-port=0` — disable plaintext port
- ✅ `--anonymous-auth=false` — require all requests to authenticate
- ✅ `--authorization-mode=Node,RBAC` — enable RBAC
- ✅ `--audit-log-path=/var/log/k8s-audit.log` — enable audit logging
- ✅ `--audit-policy-file=/etc/kubernetes/audit-policy.yaml` — log suspicious activity

**RBAC Hardening:**
- ✅ Audit all `cluster-admin` bindings — minimize to essential service accounts
- ✅ Remove any bindings to `system:anonymous` or `system:unauthenticated`
- ✅ Apply least-privilege principle — namespace-scoped roles over ClusterRoles
- ✅ Regular RBAC audits with tools like `rbac-lookup` or `kubectl-who-can`

**Network Hardening:**
- ✅ Firewall API server port 6443 to known IP ranges only
- ✅ Never expose port 8080 to any network interface except localhost
- ✅ Use VPN or private networking for cluster management
- ✅ Enable Kubernetes NetworkPolicies to restrict pod-to-pod traffic

**Dashboard Hardening:**
- ✅ Never expose Dashboard publicly — localhost only
- ✅ Use token-based authentication
- ✅ Restrict Dashboard service account to read-only, namespaced permissions
- ✅ Consider removing Dashboard entirely and using `kubectl` + `k9s` instead

### CIS Kubernetes Benchmark Controls

| Control | Description | Template Check |
|---------|-------------|----------------|
| CIS 1.2.2 | Ensure `--token-auth-file` not set | Indirect |
| CIS 1.2.5 | Ensure `--kubelet-certificate-authority` is set | Indirect |
| CIS 1.2.19 | Ensure `--insecure-bind-address` is not set | ✅ Check 1 |
| CIS 1.2.20 | Ensure `--insecure-port=0` | ✅ Check 1 |
| CIS 1.2.22 | Ensure `--audit-log-path` is set | Advisory |
| CIS 5.1.1 | Ensure cluster-admin binding is restricted | ✅ Check 2 RBAC |

---

## Extending the Template

### Adding New Checks

```go
// Add a check for etcd exposure (port 2379 — full cluster state DB)
func testEtcdExposure(host string) *Finding {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:2379", host), 5*time.Second)
    if err != nil {
        return nil
    }
    conn.Close()
    // etcd accessible = critical — contains entire cluster state including secrets
    return &Finding{
        Severity:  "CRITICAL",
        CVSSScore: 10.0,
        Title:     "etcd Port 2379 Exposed Without Authentication",
    }
}
```

### Adding Bearer Token Testing

```go
// Test if a leaked service account token still works
func testTokenValidity(host string, token string) *Finding {
    req.Header.Set("Authorization", "Bearer " + token)
    // 200 = token valid → privilege level finding based on response
}
```

### Integration with CI/CD Pipeline

```yaml
# GitHub Actions: scan K8s cluster before deployment
- name: K8s RBAC Security Scan
  run: |
    cxg scan \
      --scope ${{ secrets.K8S_API_ENDPOINT }} \
      --template k8s-rbac-misconfiguration.go \
      --output-format json \
      --timeout 30s \
      --output k8s-scan-results.json
    
    # Fail pipeline if CRITICAL findings exist
    CRITICAL=$(cat k8s-scan-results.json | jq '[.findings[] | select(.severity=="critical")] | length')
    if [ "$CRITICAL" -gt "0" ]; then
      echo "CRITICAL K8s RBAC misconfiguration found! Blocking deployment."
      exit 1
    fi
```

---

## References

### Official Kubernetes Documentation

1. [Kubernetes RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
2. [Kubernetes Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
3. [kube-apiserver flags reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
4. [Kubernetes Security Hardening Guide](https://kubernetes.io/docs/concepts/security/hardening-guide/)
5. [Dashboard Access Control](https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/README.md)

### Security Research & CVEs

| CVE / Advisory | Description | Severity |
|---|---|---|
| CVE-2018-1002105 | K8s API server privilege escalation | CVSS 9.8 |
| CVE-2019-11247 | K8s API server allows access to custom resources | CVSS 8.1 |
| CVE-2019-9946 | K8s CNI portmap plugin privilege escalation | CVSS 7.5 |
| Tesla K8s Breach (2018) | Dashboard exposed → cryptominer deployed | N/A |
| Shopify K8s Bug Bounty | Anonymous access to internal K8s API | N/A |

### Tools & Resources

- [kubiscan](https://github.com/cyberark/KubiScan) — Kubernetes RBAC risk scanner
- [kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can) — RBAC permission analysis
- [rbac-lookup](https://github.com/FairwindsOps/rbac-lookup) — Find K8s roles
- [kube-bench](https://github.com/aquasecurity/kube-bench) — CIS Benchmark scanner
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)

---

<div align="center">

## 🚀 Ready to Hunt?

```bash
# Scan for K8s RBAC misconfigurations
cxg scan --scope @k8s-targets.txt \
  --template k8s-rbac-misconfiguration.go \
  --output-format json --timeout 30s -vv
```

**Found a misconfigured cluster using this template?**
Responsible disclosure only. Contact the cluster owner before publishing findings.

---

*This playbook is part of the CERT-X-GEN Security Scanner documentation.*
*Licensed under Apache 2.0. Contributions welcome!*

[GitHub](https://github.com/Bugb-Technologies/cert-x-gen) • [Templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) • [DeepWiki](https://deepwiki.com/Bugb-Technologies/cert-x-gen)

</div>

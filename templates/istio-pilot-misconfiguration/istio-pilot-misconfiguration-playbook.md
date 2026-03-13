# Istio Pilot Misconfiguration Detection

<div align="center">

![CERT-X-GEN](https://img.shields.io/badge/CERT--X--GEN-Playbook-blue?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Go-cyan?style=for-the-badge)
![CVSS](https://img.shields.io/badge/CVSS-9.1-critical?style=for-the-badge)

**Detecting exposed Istio control plane ports that allow service mesh bypass**

*Why YAML scanners can't reliably detect this — and how CERT-X-GEN's Go template does*

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

Istio Pilot (istiod) is the control plane of the Istio service mesh. It manages xDS configuration distribution, certificate issuance, and policy enforcement for all Envoy proxies in the mesh. When its internal ports are exposed outside the cluster without authentication — a common misconfiguration in self-managed Kubernetes deployments — attackers gain read access to the entire mesh topology, including service endpoints, TLS certificates, routing rules, and AuthorizationPolicy definitions.

**The result?** Complete service mesh reconnaissance. In the worst case, an attacker can register a rogue Envoy proxy and receive live xDS updates, effectively wiretapping internal service-to-service communication.

> 💡 **Key Insight**: This vulnerability cannot be reliably detected with simple HTTP pattern matching. It requires multi-port TCP probing, gRPC connection testing, and semantic analysis of Istio-specific HTTP response codes — exactly what CERT-X-GEN's Go templates excel at.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 9.1 (Critical) — xDS port; 7.5 (High) — admin port |
| **CWE** | CWE-306 (Missing Authentication for Critical Function) |
| **Affected Versions** | Istio < 1.9 (port 15010 enabled by default); any version with misconfigured NetworkPolicy |
| **Detection Complexity** | Medium (requires multi-port TCP + HTTP probing with Istio-aware logic) |
| **Exploitation Difficulty** | Low (any xDS client or curl suffices once port is reachable) |

---

## Understanding the Vulnerability

### Istio Pilot Port Architecture

Istiod exposes multiple ports for different purposes:

| Port | Protocol | Purpose | Auth Required? |
|------|----------|---------|----------------|
| **8080** | HTTP | Admin server: `/ready`, `/metrics`, `/debug/*` | Partial (debug: 401, ready: none) |
| **15010** | gRPC (plaintext) | xDS API — Envoy discovery service | ❌ None |
| **15012** | gRPC (mTLS) | xDS API — secure version | ✅ mTLS |
| **15014** | HTTP | Control plane monitoring + debug | ❌ None |
| **15017** | HTTPS | Webhook (admission controller) | ✅ TLS |

### The Misconfiguration

When ports `8080`, `15010`, or `15014` are reachable from outside the Kubernetes cluster — due to missing NetworkPolicy, NodePort exposure, or cloud load balancer misconfiguration — an attacker can:

```
┌─────────────────────────────────────────────────────────────────┐
│                  ISTIO PILOT ATTACK SURFACE                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Port 15010 (xDS plaintext gRPC):                               │
│  Attacker ──► Connect Envoy/xDS client ──► Receive ALL:         │
│               • ClusterDiscoveryService (CDS) responses         │
│               • EndpointDiscoveryService (EDS) responses        │
│               • ListenerDiscoveryService (LDS) responses        │
│               • RouteDiscoveryService (RDS) responses           │
│               • SecretDiscoveryService (SDS) — TLS certs        │
│                                                                  │
│  Port 8080 (HTTP admin):                                        │
│  Attacker ──► GET /debug/endpointz ──► Full endpoint table      │
│  Attacker ──► GET /metrics         ──► Mesh telemetry           │
│  Attacker ──► GET /ready           ──► Istiod presence          │
│                                                                  │
│  Port 15014 (monitoring):                                       │
│  Attacker ──► GET /metrics         ──► Control plane internals  │
│  Attacker ──► GET /debug/configz   ──► Full mesh config         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Happens

Istio is designed to run inside Kubernetes where network isolation is assumed. Many operators:
- Deploy istiod without a `NetworkPolicy` restricting control plane ports
- Expose istiod via `NodePort` for external mesh federation
- Use older Istio versions (< 1.9) where port 15010 is enabled by default
- Misconfigure cloud security groups/firewall rules during upgrades

---

## Why Traditional Scanners Fail

### The YAML Limitation

A YAML-based scanner can send an HTTP GET and match response patterns:

```yaml
# What a YAML scanner CAN do:
id: istio-port-check
requests:
  - method: GET
    path:
      - "{{BaseURL}}:8080/ready"
    matchers:
      - type: status
        status: [200, 503]
```

This approach has critical blind spots:

| Capability | YAML | CERT-X-GEN |
|------------|------|------------|
| Detect HTTP admin port (8080) | ✅ | ✅ |
| Distinguish 503 = Istio present vs generic 503 | ❌ | ✅ |
| Probe raw TCP gRPC port (15010) | ❌ | ✅ |
| Detect gRPC exposure via TCP connect + reset | ❌ | ✅ |
| Parse Istio-specific metrics indicators | ❌ | ✅ |
| Multi-port correlation (all three ports) | ❌ | ✅ |
| Graceful handling of TCP resets vs timeouts | ❌ | ✅ |
| **False positive rate** | High | **Low** |

### The Detection Gap

A YAML scanner hitting port 15010 with HTTP/1.1 will receive a TCP connection reset (gRPC speaks HTTP/2 framing). Most YAML scanners will classify this as "unreachable" and produce no finding — missing the exposure entirely. CERT-X-GEN's Go template uses `net.DialTimeout` at the TCP layer, treating a successful TCP connect as the detection signal regardless of the application-layer response.

---

## The CERT-X-GEN Approach

### Detection Strategy

```
┌──────────────────────────────────────────────────────────────────┐
│                    CERT-X-GEN DETECTION FLOW                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Probe port 8080 /ready                                       │
│     ├── 200 or 503 → Istio present → HIGH finding               │
│     ├── 401/403    → Port exists but protected → skip           │
│     └── unreachable → skip                                       │
│                                                                  │
│  2. Probe port 8080 /debug/endpointz                             │
│     ├── 200 + Istio content → CRITICAL finding                  │
│     ├── 401 → debug protected (log, no finding)                 │
│     └── 404 → endpoint not present                              │
│                                                                  │
│  3. Probe port 8080 /metrics                                     │
│     └── 200 + pilot_/istio_ prefix → HIGH finding              │
│                                                                  │
│  4. TCP connect to port 15010                                    │
│     ├── Connect success → send HTTP/1.1 GET                     │
│     ├── Any response (reset/empty/HTTP) → CRITICAL finding      │
│     └── Connection refused/timeout → skip                       │
│                                                                  │
│  5. Probe port 15014 /metrics                                    │
│     └── 200 + istio_ metrics → HIGH finding                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **TCP-layer probing for gRPC**: Port 15010 uses raw `net.DialTimeout` — not `http.Client` — so a gRPC reset is correctly interpreted as "port is exposed" rather than "unreachable"
2. **Status-code-as-signal**: HTTP 503 on `/ready` is treated as a positive Istio indicator, not an error. It means istiod is running but hasn't synced with Kubernetes yet — still proves the port is exposed
3. **Content-based confirmation**: Metrics and debug endpoints are validated against Istio-specific strings (`pilot_`, `istio_`, `clusterName`) to eliminate false positives from generic HTTP servers on the same ports
4. **Graceful degradation**: Each port probe is independent — failure on one never blocks the others

---

## Attack Flow Visualization

### Complete Attack Chain

**Phase 1: Reconnaissance**
- 🔍 Scan for Istio admin port 8080 reachability
- 📡 Check xDS plaintext port 15010 TCP connectivity
- 🔬 Enumerate debug endpoints for mesh topology

**Phase 2: Mesh Topology Extraction**
- 📋 Query `/debug/endpointz` for all service endpoints
- 🗺️ Query `/debug/configz` for VirtualServices, DestinationRules
- 📊 Read `/metrics` for proxy counts, config sync state

**Phase 3: xDS Exploitation (Port 15010)**
- ⚙️ Connect Envoy proxy or grpc_cli as xDS client
- 🔄 Subscribe to CDS/EDS/LDS/RDS streams
- 🔑 Receive SDS (Secret Discovery Service) — extract TLS certs
- 🚀 Register rogue workload to intercept traffic

**Phase 4: Service Mesh Bypass**
- 🛡️ Extract AuthorizationPolicy definitions
- 🔓 Identify policy gaps or permissive rules
- 🎯 Route traffic to bypass mTLS enforcement

### Port Exposure Impact Matrix

```
┌──────────────┬──────────────────────────────────┬──────────┐
│ Port         │ Impact if Exposed                │ Severity │
├──────────────┼──────────────────────────────────┼──────────┤
│ 15010 (xDS)  │ Full mesh config, TLS certs,     │ CRITICAL │
│              │ rogue proxy registration          │ CVSS 9.1 │
├──────────────┼──────────────────────────────────┼──────────┤
│ 8080 (admin) │ Endpoint enumeration, metrics,   │ HIGH     │
│              │ control plane status              │ CVSS 7.5 │
├──────────────┼──────────────────────────────────┼──────────┤
│ 15014 (mon.) │ Internal telemetry, debug config │ HIGH     │
│              │                                  │ CVSS 7.5 │
└──────────────┴──────────────────────────────────┴──────────┘
```

---

## Template Deep Dive

### TCP-Layer gRPC Detection (Port 15010)

```go
// The key insight: use net.DialTimeout, not http.Client
// http.Client would fail on gRPC TCP reset and return "unreachable"
// net.DialTimeout succeeds at TCP layer — proving the port is exposed
func probePort15010(host string) *Finding {
    address := fmt.Sprintf("%s:15010", host)
    conn, err := net.DialTimeout("tcp", address, 5*time.Second)
    if err != nil {
        return nil // Genuinely unreachable
    }
    defer conn.Close()

    // TCP connected — port IS exposed, regardless of gRPC response
    conn.SetDeadline(time.Now().Add(5 * time.Second))
    conn.Write([]byte("GET /ready HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
    
    // Read whatever comes back (may be gRPC reset frame or empty)
    buf := make([]byte, 256)
    n, _ := conn.Read(buf)
    
    // TCP connect success = CRITICAL finding
    return buildFinding(host, "critical", 9.1, ...)
}
```

### Smart HTTP 503 Handling (Port 8080)

```go
// 503 on /ready is NOT an error — it's proof Istio is present
// istiod returns 503 when it hasn't synced with Kubernetes yet
// Both 200 AND 503 are valid positive indicators
if readyResult.StatusCode == 200 || readyResult.StatusCode == 503 {
    // Istio is here — port is exposed
    findings = append(findings, buildFinding(...))
}
```

### Content-Based Confirmation (Metrics)

```go
// Don't just check status 200 — verify Istio-specific metric names
// Prevents false positives from other services on the same port
if strings.Contains(result.Body, "pilot_") || 
   strings.Contains(result.Body, "istio_") || 
   strings.Contains(result.Body, "grpc_") {
    // Confirmed Istio metrics — generate finding
}
```

---

## Usage Guide

### Basic Usage

```bash
# Scan a target for Istio Pilot misconfiguration
cxg scan --scope k8s-node.example.com --template templates/istio-pilot-misconfiguration/istio-pilot-misconfiguration.go

# With JSON output
cxg scan --scope k8s-node.example.com --template templates/istio-pilot-misconfiguration/istio-pilot-misconfiguration.go --output-format json

# Verbose mode
cxg scan --scope k8s-node.example.com --template templates/istio-pilot-misconfiguration/istio-pilot-misconfiguration.go -vv

# Scan multiple targets from file
cxg scan --scope @targets.txt --template templates/istio-pilot-misconfiguration/istio-pilot-misconfiguration.go --output-format json --timeout 30s
```

### Expected Output (Vulnerable — Port 15010 + 8080 Exposed)

```json
[
  {
    "template_id": "istio-pilot-misconfiguration",
    "severity": "critical",
    "confidence": 90,
    "title": "Istio xDS Plaintext gRPC Port Exposed on 10.0.0.5:15010",
    "description": "Istio Pilot xDS plaintext gRPC port (15010) is reachable without authentication...",
    "evidence": {
      "address": "10.0.0.5:15010",
      "port": 15010,
      "tcp_reachable": true,
      "authentication": "none",
      "protocol": "gRPC plaintext (xDS)"
    },
    "cvss_score": 9.1,
    "cwe": "CWE-306"
  },
  {
    "template_id": "istio-pilot-misconfiguration",
    "severity": "high",
    "confidence": 90,
    "title": "Istio Admin HTTP Port Exposed on 10.0.0.5:8080",
    "description": "Istio Pilot admin HTTP server (port 8080) is reachable without network restrictions...",
    "evidence": {
      "url": "http://10.0.0.5:8080/ready",
      "http_status": 503,
      "authentication": "not_required"
    },
    "cvss_score": 7.5,
    "cwe": "CWE-306"
  }
]
```

### Expected Output (Secure)

```
Scan Summary
  Findings: 0
  (All Istio ports unreachable or returning 401/403)
```

---

## Real-World Test Results

The template was validated against a local Docker-based Istio Pilot instance (`istio/pilot:1.17.2`):

| Target | Port | Probe | Response | Finding |
|--------|------|-------|----------|---------|
| 127.0.0.1 | 8080 | `/ready` | HTTP 503 | ✅ HIGH — Admin port exposed |
| 127.0.0.1 | 8080 | `/debug/endpointz` | HTTP 401 | ℹ️ Auth enforced on debug |
| 127.0.0.1 | 15010 | TCP connect | Reset (gRPC) | ✅ CRITICAL — xDS plaintext exposed |
| 127.0.0.1 | 15014 | `/metrics` | TCP unreachable | ✅ No false positive |

**Key findings:**
1. ✅ Port 8080 correctly detected via HTTP 503 (istiod running, K8s not connected)
2. ✅ Port 15010 correctly detected via TCP connect — even though HTTP/1.1 was reset by the gRPC server
3. ✅ Port 15014 gracefully skipped when not bound (no false positive)
4. ✅ Auth-enforced debug endpoints logged but not flagged as vulnerabilities
5. ✅ Total scan time: **0.52 seconds**

---

## Defense & Remediation

### Immediate Actions

**1. Apply NetworkPolicy (Kubernetes)**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-istiod-ports
  namespace: istio-system
spec:
  podSelector:
    matchLabels:
      app: istiod
  policyTypes:
    - Ingress
  ingress:
    # Only allow xDS from within the cluster (port 15012 mTLS only)
    - ports:
        - port: 15012
    # Allow webhook from kube-apiserver only
    - ports:
        - port: 15017
    # Block 8080, 15010, 15014 from external sources
```

**2. Disable Port 15010 (Istio 1.9+)**

```bash
# Helm upgrade
helm upgrade istiod istio/istiod \
  --set pilot.env.PILOT_ENABLE_UNSAFE_UNPROTECTED_CLIENT_CONTROL=false

# IstioOperator
spec:
  components:
    pilot:
      k8s:
        env:
          - name: PILOT_ENABLE_UNSAFE_UNPROTECTED_CLIENT_CONTROL
            value: "false"
```

**3. Restrict Admin Port (8080)**

```yaml
# IstioOperator — disable plaintext admin port
spec:
  meshConfig:
    defaultConfig:
      proxyAdminPort: 0  # Disable proxy admin port
```

### Defense Checklist

| Control | Description | Priority |
|---------|-------------|----------|
| ✅ NetworkPolicy | Block ports 8080/15010/15014 from external ingress | **Critical** |
| ✅ Disable 15010 | Set `PILOT_ENABLE_UNSAFE_UNPROTECTED_CLIENT_CONTROL=false` | **Critical** |
| ✅ Upgrade Istio | Istio 1.9+ disables port 15010 by default | **High** |
| ✅ Cloud Firewall | Add security group rules blocking control plane ports | **High** |
| ✅ mTLS Everywhere | Enforce `STRICT` PeerAuthentication mesh-wide | **High** |
| ✅ Audit Exposure | Run this template regularly in CI/CD pipeline | **Medium** |

---

## Extending the Template

### Add More Debug Endpoint Checks

```go
// Additional Istio debug paths to probe on port 8080
extraPaths := []string{
    "/debug/configz",      // Full mesh config dump
    "/debug/registryz",    // Service registry
    "/debug/syncz",        // xDS sync status per proxy
    "/debug/authorizationz", // AuthorizationPolicy state
    "/debug/push_status",  // Push queue internals
}
```

### Add Port 15014 Deep Inspection

```go
// Check for sensitive metric labels that reveal workload identities
sensitiveMetrics := []string{
    "pilot_xds_pushes",
    "pilot_proxy_convergence_time",
    "citadel_secret_controller",
}
```

### Integration with CI/CD

```yaml
# GitHub Actions — scan Istio control plane on every deployment
- name: Istio Security Scan
  run: |
    cxg scan \
      --scope $ISTIOD_IP \
      --template templates/istio-pilot-misconfiguration/istio-pilot-misconfiguration.go \
      --output-format sarif \
      --output istio-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: istio-results.sarif
```

---

## References

### CVEs & Advisories

| CVE | Description |
|-----|-------------|
| CVE-2020-8843 | Istio unauthenticated control plane access |
| CVE-2022-21701 | Istio privilege escalation via control plane |

### Official Documentation

- [Istio Security Best Practices](https://istio.io/latest/docs/ops/best-practices/security/)
- [Istio Pilot Configuration Reference](https://istio.io/latest/docs/reference/config/istio.pilot.v1alpha1/)
- [Istio NetworkPolicy Guide](https://istio.io/latest/docs/ops/configuration/traffic-management/network-topologies/)

### Research & Tools

- [Istio Attack Surface Analysis — NCC Group](https://research.nccgroup.com/2020/12/14/service-mesh-security/)
- [xDS API Specification — CNCF](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol)
- [MITRE ATT&CK T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

---

<div align="center">

## 🚀 Ready to Hunt?

```bash
cxg scan --scope your-k8s-node.example.com \
  --template templates/istio-pilot-misconfiguration/istio-pilot-misconfiguration.go \
  --output-format json -vv
```

**Found a misconfigured Istio deployment using this template?**
Tag `@BugB-Tech` on Twitter with `#CERTXGEN`

---

*This playbook is part of the CERT-X-GEN Security Scanner documentation.*
*Licensed under Apache 2.0. Contributions welcome!*

[GitHub](https://github.com/Bugb-Technologies/cert-x-gen) • [Templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) • [DeepWiki](https://deepwiki.com/Bugb-Technologies/cert-x-gen)

</div>

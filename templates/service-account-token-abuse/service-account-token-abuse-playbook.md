# Kubernetes Service Account Token Abuse

<div align="center">

![CERT-X-GEN](https://img.shields.io/badge/CERT--X--GEN-Playbook-blue?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Go-cyan?style=for-the-badge)
![CVSS](https://img.shields.io/badge/CVSS-9.6-critical?style=for-the-badge)
![CWE](https://img.shields.io/badge/CWE-522-orange?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-T1528-red?style=for-the-badge)

**How Kubernetes service account tokens become the skeleton key to full cluster compromise**

*Token extraction, lateral movement, and pivoting — detected before attackers can exploit them*

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

Kubernetes service account tokens are bearer credentials automatically mounted into every pod. When the Kubelet API or the Kubernetes API server is exposed without authentication, these tokens become trivially extractable — and once extracted, they can be used to authenticate to the API server with whatever permissions the service account holds, enabling full lateral movement across the cluster.

This template detects four distinct vectors that expose service account tokens: unauthenticated Secrets API access, exposed Kubelet `/pods` endpoints that reveal token mount paths, over-permissioned default service accounts with automounting enabled, and simulated token pivoting to measure blast radius.

> 💡 **Key Insight**: Service account token abuse is not a single CVE — it is a **misconfiguration chain**. Each link (anonymous Kubelet, open Secrets API, automount enabled, no RBAC scoping) is individually dangerous. CERT-X-GEN tests all four links simultaneously, something no YAML-based scanner can do.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 9.6 (Critical) |
| **CWE** | CWE-522 (Insufficiently Protected Credentials) |
| **MITRE ATT&CK** | T1528 — Steal Application Access Token |
| **Affected Versions** | Kubernetes all versions with default or misconfigured kubelet |
| **Detection Complexity** | High (requires multi-vector protocol testing) |
| **Exploitation Difficulty** | Low (once token is extracted) |

---

## Understanding the Vulnerability

### How Service Account Tokens Work

Every pod in Kubernetes receives a service account token automatically mounted at a predictable path:

```
/var/run/secrets/kubernetes.io/serviceaccount/
├── token        ← JWT bearer token (the crown jewel)
├── ca.crt       ← Cluster CA certificate
└── namespace    ← Pod's namespace name
```

This token is a signed JWT that authenticates the pod to the Kubernetes API server. Its permissions are governed by RBAC RoleBindings and ClusterRoleBindings.

### The Four Attack Vectors

```
┌───────────────────────────────────────────────────────────────────────┐
│               SERVICE ACCOUNT TOKEN ABUSE ATTACK CHAIN                │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  VECTOR 1: Unauthenticated Secrets API                                │
│  ─────────────────────────────────────                                │
│  GET /api/v1/secrets (no auth) → tokens exposed as base64 data       │
│  GET /api/v1/namespaces/default/secrets → same, scoped to namespace  │
│                         ↓                                             │
│  VECTOR 2: Kubelet /pods Endpoint (port 10250)                        │
│  ────────────────────────────────────────────                         │
│  GET https://node:10250/pods → reveals ALL token mount paths         │
│  Combined with /exec → read token directly from container filesystem │
│                         ↓                                             │
│  VECTOR 3: Default SA Automount Enabled                               │
│  ─────────────────────────────────────                                │
│  All pods inherit default SA token → compromise any pod = get token  │
│                         ↓                                             │
│  VECTOR 4: Token Pivoting                                             │
│  ────────────────────────                                             │
│  Extracted token → GET /api/v1/namespaces/kube-system/secrets        │
│  → Read cluster CA, etcd certs, admin credentials → FULL TAKEOVER    │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### Why This Is Catastrophic

The `default` service account in many misconfigured clusters — especially those following outdated tutorials — has been granted `cluster-admin` via a ClusterRoleBinding. A single misconfigured Kubelet port exposing one pod's token can therefore yield:

- Full read/write access to all secrets across all namespaces
- Ability to create privileged pods and escape to node
- Access to etcd credentials and cluster CA private key
- Ability to create new admin service accounts and backdoors

---

## Why Traditional Scanners Fail

### The YAML Limitation

Traditional YAML-based scanners can send HTTP requests and match patterns, but service account token abuse requires:

| Capability | YAML Scanner | CERT-X-GEN |
|------------|-------------|------------|
| Probe Kubelet port 10250 (HTTPS, self-signed cert) | ❌ | ✅ |
| Parse PodList JSON and extract volume mount paths | ❌ | ✅ |
| Identify service account token volumes across all pods | ❌ | ✅ |
| Probe K8s API server Secrets endpoint (multiple namespaces) | ❌ | ✅ |
| Decode base64 token data and detect JWT format | ❌ | ✅ |
| Re-use extracted token to test pivoting blast radius | ❌ | ✅ |
| Enumerate ServiceAccounts and check automount setting | ❌ | ✅ |
| **Confidence Level** | ~15% | **95–98%** |

### The Detection Gap

A YAML scanner sees an open port. CERT-X-GEN understands what that open port means for the entire cluster's credential security posture.

---

## The CERT-X-GEN Approach

The template executes four sequential checks, each building on the previous to paint a complete picture of the token exposure surface.

### Detection Strategy

```
┌──────────────────────────────────────────────────────────────────────┐
│                   CERT-X-GEN DETECTION FLOW                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Check 1: Secrets API                                                │
│  Scanner ──GET /api/v1/secrets (no auth)──► API Server :6443        │
│  200 OK? → Extract base64 tokens → CRITICAL finding                 │
│  401/403? → Properly secured → skip                                  │
│                          ↓                                           │
│  Check 2: Kubelet /pods                                              │
│  Scanner ──GET /pods (no auth)──► Kubelet :10250                    │
│  200 OK? → Parse PodList → count SA token mounts → CRITICAL         │
│  401/403? → Properly secured → skip                                  │
│                          ↓                                           │
│  Check 3: Service Account Automount                                  │
│  Scanner ──GET /api/v1/namespaces/default/serviceaccounts──►        │
│  200 OK? → Check automountServiceAccountToken field → HIGH          │
│  401/403? → Properly secured → skip                                  │
│                          ↓                                           │
│  Check 4: Token Pivoting                                             │
│  For each token extracted in Check 1:                                │
│  Scanner ──GET /api/v1/namespaces/kube-system/secrets──►            │
│  200 OK? → Pivot successful → CRITICAL (CVSS 10.0)                  │
│  401/403? → Token has limited scope → no finding                     │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Attack Flow Visualization

### Complete Attack Chain

**Phase 1: Initial Access**
- 🔍 Port scan reveals Kubelet 10250 or K8s API 6443 open
- 📡 Probe without authentication credentials
- ✅ Unauthenticated access confirmed

**Phase 2: Token Extraction**
- 📋 Enumerate pods via Kubelet `/pods` endpoint
- 🗂️ Identify pods with SA token volume mounts
- 🔑 Extract token from pod via `/exec` endpoint or Secrets API

**Phase 3: Lateral Movement**
- 🎯 Decode JWT to identify service account identity
- 🔐 Use token as Bearer credential against API server
- 📂 Read secrets across namespaces to find higher-value tokens

**Phase 4: Full Cluster Compromise**
- 💀 Access `kube-system` secrets (contains cluster admin creds)
- 🚀 Create privileged pod with host path mounts
- 🖥️ Escape to underlying node — full infrastructure compromise

### Token Anatomy

```
┌──────────────────────────────────────────────────────────────────────┐
│               SERVICE ACCOUNT JWT TOKEN STRUCTURE                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9                               │
│  └─── Header: {"alg":"RS256","kid":"<key-id>"}                       │
│                                                                      │
│  .eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50IiwK...              │
│   └─── Payload:                                                      │
│        {                                                             │
│          "iss": "kubernetes/serviceaccount",                         │
│          "kubernetes.io/serviceaccount/namespace": "default",        │
│          "kubernetes.io/serviceaccount/service-account.name": "...", │
│          "kubernetes.io/serviceaccount/service-account.uid": "...",  │
│          "sub": "system:serviceaccount:default:vuln-sa"  ← identity │
│        }                                                             │
│                                                                      │
│  .<signature>                                                        │
│   └─── Signed by cluster's service account signing key              │
│        Valid until token rotation or secret deletion                 │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Check 1: Unauthenticated Secrets API

```go
// Probe cluster-scoped and namespace-scoped secrets endpoints
namespacesToProbe := []string{"", "default", "kube-system", "kube-public"}

for _, ns := range namespacesToProbe {
    resp, body, err := get(ctx, client, endpoint, "") // no token = anonymous
    
    if resp.StatusCode == 200 {
        // Parse SecretList, filter for kubernetes.io/service-account-token type
        // Decode base64 token data to confirm JWT format (eyJ prefix)
        // Return CRITICAL finding with extracted token previews
    }
}
```

### Check 2: Kubelet /pods Token Path Mapping

```go
// Probe both /pods and /runningpods/ endpoints on port 10250
for _, pod := range podList.Items {
    for _, vm := range container.VolumeMounts {
        if strings.Contains(vm.MountPath, "serviceaccount") {
            // Record pod name, namespace, SA name, exact mount path
            // Each entry = one extractable token via /exec
        }
    }
}
```

### Check 4: Token Pivoting — Blast Radius Measurement

```go
// Ordered by sensitivity — stop at first accessible privileged endpoint
pivotEndpoints := []struct{ path, description string; cvss float64 }{
    {"/api/v1/namespaces/kube-system/secrets",              "kube-system secrets",     10.0},
    {"/api/v1/namespaces/kube-system/configmaps",           "kube-system configmaps",   8.5},
    {"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "RBAC privilege map",   8.0},
    {"/api/v1/nodes",                                       "node inventory",           7.5},
    {"/api/v1/namespaces",                                  "all namespaces",           7.0},
}

// CVSS score of the finding = highest accessible endpoint's score
// This gives a precise measure of the token's actual blast radius
```

---

## Usage Guide

### Basic Usage

```bash
# Scan a Kubernetes node for service account token abuse vectors
cxg scan --scope 10.0.0.1 --template templates/service-account-token-abuse/service-account-token-abuse.go

# Scan with JSON output and verbose logging
cxg scan --scope 10.0.0.1 --template templates/service-account-token-abuse/service-account-token-abuse.go --output-format json --timeout 30s -vv

# Scan multiple nodes from a targets file
cxg scan --scope @k8s-nodes.txt --template templates/service-account-token-abuse/service-account-token-abuse.go --output-format json --timeout 30s
```

### Direct Execution (for debugging)

```bash
# Run directly with Go for verbose stderr output
cd templates/service-account-token-abuse
go run service-account-token-abuse.go <target-ip>
```

### Expected Output (Kubelet Exposed — Vulnerable)

```json
[{
  "template_id": "service-account-token-abuse",
  "host": "172.19.0.2",
  "severity": "CRITICAL",
  "confidence": 95,
  "title": "Kubelet API Exposes Pod Service Account Token Mount Paths on 172.19.0.2:10250",
  "description": "The Kubelet API on port 10250 responds without authentication to /pods. 10 pods are enumerated, 6 of which have service account tokens automounted at predictable paths...",
  "evidence": {
    "kubelet_endpoint": "https://172.19.0.2:10250/pods",
    "http_status": 200,
    "total_pods": 10,
    "pods_with_sa_tokens": 6,
    "token_mount_details": [
      {
        "pod": "vuln-pod",
        "namespace": "default",
        "service_account": "vuln-sa",
        "token_mountpaths": ["nginx:/var/run/secrets/kubernetes.io/serviceaccount"]
      }
    ],
    "token_path_pattern": "/var/run/secrets/kubernetes.io/serviceaccount/token"
  },
  "cwe": "CWE-522",
  "cvss_score": 9.6
}]
```

### Expected Output (Fully Secured — No Findings)

```bash
[-] Secrets API: no unauthenticated access detected
[-] Kubelet: /pods not accessible without authentication
[-] SA check: no over-permissioned service accounts detected
[-] Token pivoting: no privileged endpoints accessible
[]
```

---

## Real-World Test Results

The template was tested against a deliberately misconfigured kind (Kubernetes-in-Docker) cluster running Kubernetes v1.29.2.

### Test Environment

| Component | Configuration |
|-----------|--------------|
| **Cluster** | kind v0.22.0, Kubernetes v1.29.2 |
| **API Server** | `--anonymous-auth=true`, `--authorization-mode=AlwaysAllow` |
| **Kubelet** | `anonymous: enabled: true`, `authorization.mode: AlwaysAllow` |
| **Test SA** | `vuln-sa` with `cluster-admin` ClusterRoleBinding |
| **Test Pod** | `vuln-pod` with `automountServiceAccountToken: true` |

### Scan Results

| Target | Check | Vector | Result | Finding |
|--------|-------|--------|--------|---------|
| 172.19.0.2 | 1 | Secrets API :6443 | 401 — properly secured | No finding ✅ |
| 172.19.0.2 | 2 | Kubelet /pods :10250 | **200 — EXPOSED** | **CRITICAL (CVSS 9.6)** 🔴 |
| 172.19.0.2 | 3 | SA Automount :6443 | 401 — properly secured | No finding ✅ |
| 172.19.0.2 | 4 | Token Pivoting :6443 | No tokens available | No finding ✅ |
| 127.0.0.1 | All | All vectors | 401 — properly secured | No finding ✅ |

### Key Findings

**Kubelet Exposure Detected:**
- 10 total pods enumerated without authentication
- 6 pods confirmed with service account tokens automounted at `/var/run/secrets/kubernetes.io/serviceaccount`
- `vuln-pod/default` running with `vuln-sa` (cluster-admin bound) token mounted
- An attacker with Kubelet `/exec` access could extract the token and gain full cluster-admin privileges

**Token Pivoting Validation (manual):**
```bash
# Confirmed token works against kube-system secrets
TOKEN=$(kubectl get secret vuln-sa-token -n default -o jsonpath='{.data.token}' | base64 -d)
curl -sk https://172.19.0.2:6443/api/v1/namespaces/kube-system/secrets \
  -H "Authorization: Bearer $TOKEN" | head -3
# → {"kind":"SecretList","apiVersion":"v1",...}  ← Full access confirmed
```

**Graceful Failure Handling:**
- All 401/403 responses correctly skipped with no false positives
- Connection failures on unreachable ports handled cleanly
- Empty `[]` returned when no findings present

---

## Defense & Remediation

### Kubelet Hardening

```yaml
# /var/lib/kubelet/config.yaml — Secure configuration
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false          # ← Disable anonymous access
  webhook:
    enabled: true           # ← Require token authentication
    cacheTTL: 2m
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook             # ← Use K8s RBAC for authorization
  webhook:
    cacheAuthorizedTTL: 5m
    cacheUnauthorizedTTL: 30s
```

### Service Account Hardening

```yaml
# Disable automounting on the default service account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: default
automountServiceAccountToken: false   # ← Opt-out of automounting
---
# For workloads that need API access: dedicated SA + scoped role
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: my-app
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: my-app
rules:
  - apiGroups: [""]
    resources: ["configmaps"]         # ← Only what the app needs
    verbs: ["get", "list"]
```

### Use Short-Lived Projected Tokens

```yaml
# Pod spec — use projected token with 1 hour expiry
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600   # ← 1 hour, not indefinite
              audience: my-app
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
```

### Defense Checklist

**Kubelet:**
- ✅ `--anonymous-auth=false`
- ✅ `--authorization-mode=Webhook`
- ✅ Firewall Kubelet ports (10250, 10255) from external access
- ✅ Use NodeRestriction admission plugin

**API Server:**
- ✅ `--anonymous-auth=false`
- ✅ `--authorization-mode=Node,RBAC`
- ✅ Enable secret encryption at rest (`--encryption-provider-config`)
- ✅ Audit logging for secret access

**Service Accounts:**
- ✅ `automountServiceAccountToken: false` on default SA in all namespaces
- ✅ Create dedicated per-workload service accounts
- ✅ Use projected tokens with short expiry (`expirationSeconds: 3600`)
- ✅ Never bind `cluster-admin` to workload service accounts
- ✅ Regularly audit: `kubectl get clusterrolebindings -o wide`

**Quick remediation commands:**
```bash
# Disable automount on default SA in all namespaces
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  kubectl patch serviceaccount default -n $ns \
    -p '{"automountServiceAccountToken": false}'
done

# Audit all SA token secrets
kubectl get secrets --all-namespaces \
  --field-selector type=kubernetes.io/service-account-token

# Find ClusterRoleBindings granting cluster-admin to SAs
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
```

---

## Extending the Template

### Add Kubelet /exec Token Extraction

```go
// Extend Check 2 to attempt actual token extraction via exec
execURL := fmt.Sprintf("https://%s:10250/exec/%s/%s/%s?command=cat&command=/var/run/secrets/kubernetes.io/serviceaccount/token&input=0&output=1&tty=0",
    host, pod.Metadata.Namespace, pod.Metadata.Name, container.Name)
// POST to execURL with websocket upgrade → receive token content
```

### Add IRSA / Workload Identity Detection

```go
// Detect AWS IRSA annotations (IAM role for SA)
if annotations["eks.amazonaws.com/role-arn"] != "" {
    // SA has AWS IAM permissions via token exchange
    // Elevated finding: cloud account access possible
}
```

### Integration with CI/CD

```yaml
# GitHub Actions — scan K8s cluster nodes after deployment
- name: Service Account Token Abuse Scan
  run: |
    for NODE_IP in ${{ secrets.K8S_NODE_IPS }}; do
      cxg scan \
        --scope $NODE_IP \
        --template templates/service-account-token-abuse/service-account-token-abuse.go \
        --output-format json \
        --timeout 30s \
        --output sa-token-results-$NODE_IP.json
    done
```

---

## References

### Standards & Frameworks

| Reference | Description |
|-----------|-------------|
| [MITRE T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Insufficiently Protected Credentials |
| [OWASP K8s Top 10 — K01](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K01-insecure-workload-configurations) | Insecure Workload Configurations |
| [NSA K8s Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) | Section 4: Pod Security |

### Kubernetes Documentation

- [Service Accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Kubelet Authentication & Authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Projected Volumes](https://kubernetes.io/docs/concepts/storage/projected-volumes/)

### Research & Advisories

- [CNCF — RBAC Least Privilege (2021)](https://www.cncf.io/blog/2021/08/20/kubernetes-rbac-least-privilege/)
- [CyberArk — Kubernetes Pentest Methodology](https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-1)
- [Trail of Bits — Kubernetes Security Review](https://github.com/trailofbits/audit-kubernetes)

---

<div align="center">

## 🚀 Ready to Hunt?

```bash
# Scan your Kubernetes nodes
cxg scan --scope <node-ip> \
  --template templates/service-account-token-abuse/service-account-token-abuse.go \
  --output-format json --timeout 30s -vv
```

**Found exposed service account tokens using this template?**
Tag `@BugB-Tech` on Twitter with `#CERTXGEN`

---

*This playbook is part of the CERT-X-GEN Security Scanner documentation.*
*Licensed under Apache 2.0. Contributions welcome!*

[GitHub](https://github.com/Bugb-Technologies/cert-x-gen) • [Templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) • [DeepWiki](https://deepwiki.com/Bugb-Technologies/cert-x-gen)

</div>

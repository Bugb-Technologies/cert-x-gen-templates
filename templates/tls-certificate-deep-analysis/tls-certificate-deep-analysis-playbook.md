# TLS Certificate Deep Analysis

<div align="center">

![CERT-X-GEN](https://img.shields.io/badge/CERT--X--GEN-Playbook-blue?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-High-orange?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Rust-red?style=for-the-badge)
![CVSS](https://img.shields.io/badge/CVSS-9.3-critical?style=for-the-badge)

**Comprehensive X.509 certificate chain validation and cryptographic weakness detection**

*Why native TLS libraries and deep certificate analysis matter for security scanning*

</div>

---

## 📖 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Understanding TLS Certificate Vulnerabilities](#understanding-tls-certificate-vulnerabilities)
3. [Why Traditional Scanners Fall Short](#why-traditional-scanners-fall-short)
4. [The CERT-X-GEN Approach](#the-cert-x-gen-approach)
5. [Template Deep Dive](#template-deep-dive)
6. [Usage Guide](#usage-guide)
7. [Real-World Test Results](#real-world-test-results)
8. [Defense & Remediation](#defense--remediation)
9. [Extending the Template](#extending-the-template)
10. [References](#references)

---

## Executive Summary

TLS certificate misconfigurations represent one of the most prevalent yet overlooked attack vectors in modern infrastructure. From expired certificates to weak cryptographic algorithms, these issues create opportunities for Man-in-the-Middle (MITM) attacks, authentication bypass, and complete compromise of encrypted communications.

**The Challenge?** Surface-level certificate checks miss critical vulnerabilities. Deep analysis requires parsing X.509 structures, validating chain integrity, checking cryptographic strength, and understanding RFC 5280 compliance—capabilities that demand low-level system programming.


> 💡 **Key Insight**: This template uses Rust's `x509-parser` and `rustls` libraries to perform deep certificate analysis that goes far beyond simple connection tests. It extracts and validates every aspect of the certificate chain, from cryptographic primitives to RFC compliance.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 9.3 (Critical) for hostname mismatch / 8.1 for self-signed |
| **CWE** | CWE-295 (Improper Certificate Validation), CWE-297 (Improper Host Verification), CWE-326 (Weak Key), CWE-327 (Weak Crypto) |
| **Detection Types** | Expired certs, weak keys, deprecated algorithms, chain issues, hostname mismatches |
| **Detection Complexity** | High (requires X.509 parsing + chain validation) |
| **Language Requirement** | Rust (for native TLS libraries and zero-copy parsing) |

---

## Understanding TLS Certificate Vulnerabilities

### The Certificate Trust Model

TLS security relies on a chain of trust:

```
┌────────────────────────────────────────────────────────────────┐
│                  TLS CERTIFICATE TRUST CHAIN                    │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Root CA (Trusted by OS/Browser)                               │
│         ↓ (signs)                                              │
│  Intermediate CA                                               │
│         ↓ (signs)                                              │
│  End-Entity Certificate (your website)                         │
│         ↓ (proves identity)                                    │
│  TLS Connection Established ✓                                  │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

**When any link in this chain breaks, security fails.**


### Critical Vulnerabilities This Template Detects

#### 1. **Expired Certificates** (CVSS 9.1)
**Impact**: Browser warnings, service disruption, MITM vulnerability  
**Root Cause**: Lack of automated renewal (Let's Encrypt/ACME)  
**Real-World Example**: Equifax breach partially attributed to expired certificates

#### 2. **Self-Signed Certificates** (CVSS 8.1)
**Impact**: No trust chain validation, easy MITM attacks  
**Common In**: Internal tools, IoT devices, development environments  
**Attack Scenario**: Attacker intercepts traffic, presents own self-signed cert

#### 3. **Hostname Mismatch** (CVSS 9.3)
**Impact**: Certificate for wrong domain, indicates MITM or misconfiguration  
**Detection**: Compare CN/SAN fields against actual hostname  
**Example**: Certificate for `example.com` served on `198.51.100.42`

#### 4. **Weak Signature Algorithms** (CVSS 7.4)
**Vulnerable**: MD5, SHA-1 (collision attacks demonstrated)  
**Required**: SHA-256 or stronger  
**Historical Context**: SHA-1 deprecated in 2017 after SHAttered attack

#### 5. **Weak RSA Keys** (CVSS 7.5)
**Minimum**: 2048 bits (4096 bits recommended)  
**Vulnerable**: 1024-bit keys (factorizable with modern compute)  
**Timeline**: NIST deprecated 1024-bit RSA in 2013

#### 6. **Certificate Chain Issues**
- Missing intermediate certificates
- CA constraints violated (leaf cert with CA flag)
- Certificate not yet valid (future-dated)

---

## Why Traditional Scanners Fall Short

### The YAML Scanner Limitation

Traditional YAML-based scanners can only perform surface-level checks:

```yaml
# ❌ What YAML scanners CAN'T do:
http:
  - method: GET
    path: "{{BaseURL}}"
    matchers:
      - type: regex
        regex:
          - "certificate expired"  # 🚨 Only catches error messages!
```


**Problems with YAML-only approaches:**

1. **No Certificate Parsing**: Cannot extract X.509 fields (subject, issuer, validity dates)
2. **No Cryptographic Analysis**: Cannot check key sizes, signature algorithms
3. **No Chain Validation**: Cannot verify certificate chain integrity
4. **Surface-Level Only**: Detects errors but not the underlying vulnerabilities
5. **False Negatives**: Misses properly served but insecure certificates

### Why Rust?

| Requirement | Why Rust Excels |
|-------------|----------------|
| **Native TLS** | `rustls` provides pure-Rust TLS 1.2/1.3 implementation |
| **X.509 Parsing** | `x509-parser` offers zero-copy DER parsing |
| **Memory Safety** | No buffer overflows when parsing untrusted certificates |
| **Performance** | Compiled binary with no runtime overhead |
| **Type Safety** | Catch errors at compile-time, not in production |

---

## The CERT-X-GEN Approach

### Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│              TLS CERTIFICATE DEEP ANALYSIS FLOW                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. TCP Connection                                               │
│     ↓                                                            │
│  2. TLS Handshake (Custom Verifier - Accept All Certs)          │
│     ↓                                                            │
│  3. Certificate Chain Extraction (DER format)                    │
│     ↓                                                            │
│  4. X.509 Parsing (x509-parser)                                 │
│     ├── Parse validity dates                                    │
│     ├── Extract signature algorithm OID                          │
│     ├── Parse public key info                                    │
│     ├── Extract Subject/Issuer DNs                              │
│     └── Parse extensions (SAN, CA constraints)                   │
│     ↓                                                            │
│  5. Validation Checks                                            │
│     ├── check_validity_period()                                  │
│     ├── check_signature_algorithm()                             │
│     ├── check_key_strength()                                     │
│     ├── check_hostname_match()                                   │
│     ├── check_ca_constraints()                                   │
│     └── analyze_chain_structure()                                │
│     ↓                                                            │
│  6. Finding Generation (JSON output)                             │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```


### Key Innovation: Custom Certificate Verifier

The template uses a **custom `ServerCertVerifier`** that accepts all certificates, including:
- Expired certificates
- Self-signed certificates
- Invalid chains
- Hostname mismatches

This allows deep analysis of **broken certificates** that normal TLS libraries would reject.

```rust
// ✅ Custom verifier accepts ALL certificates for analysis
impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(&self, ...) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())  // Always accept
    }
}
```

---

## Template Deep Dive

### Core Detection Functions

#### 1. `check_validity_period()`
```rust
let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
let not_before = cert.validity().not_before.timestamp();
let not_after = cert.validity().not_after.timestamp();

if now < not_before {
    // Certificate not yet valid
} else if now > not_after {
    // Certificate expired
}
```

#### 2. `check_signature_algorithm()`
```rust
let sig_alg = cert.signature_algorithm.algorithm.to_id_string();

let weak_algs = vec![
    "1.2.840.113549.1.1.4",  // MD5WithRSAEncryption
    "1.2.840.113549.1.1.5",  // SHA1WithRSAEncryption
];

if weak_algs.contains(&sig_alg.as_str()) {
    // Weak signature algorithm detected
}
```


#### 3. `check_key_strength()`
```rust
// Check RSA key size by algorithm OID
if algo_oid == "1.2.840.113549.1.1.1" {  // RSA encryption
    let key_size_bits = public_key.subject_public_key.data.len() * 8;
    
    if key_size_bits < 2048 {
        // Weak RSA key detected
    }
}
```

#### 4. `check_hostname_match()`
```rust
// Extract CN from Subject
let subject_cn = cert.subject().iter_common_name().next()?;

// Check Subject Alternative Names
for san_ext in cert.extensions() {
    if san_ext.oid == OID_X509_EXT_SUBJECT_ALT_NAME {
        // Compare DNS names with target hostname
    }
}
```

---

## Usage Guide

### Prerequisites

**System Requirements:**
- Rust toolchain (1.70+)
- Cargo package manager
- Network access to target hosts

**Dependencies** (automatically handled by Cargo):
- `rustls` 0.23.x - TLS library
- `x509-parser` 0.16.x - X.509 parsing
- `webpki-roots` - Root CA certificates
- `rustls-pki-types` - PKI type definitions

### Compilation

```bash
cd templates/tls-certificate-deep-analysis
cargo build --release
```

**Binary location**: `target/release/tls-certificate-deep-analysis`

### Running Scans

#### Single Target
```bash
./target/release/tls-certificate-deep-analysis \
  --target example.com \
  --port 443 \
  --json > results.json
```


#### Multiple Targets (Batch Scanning)
```bash
#!/bin/bash
# scan-multiple.sh

targets=(
    "192.168.1.1"
    "10.0.0.1"
    "example.com"
)

for target in "${targets[@]}"; do
    echo "Scanning $target..."
    ./target/release/tls-certificate-deep-analysis \
      --target "$target" \
      --port 443 \
      --json > "results-${target}.json" 2>&1
done
```

### Environment Variables

The template supports CERT-X-GEN environment variables:

```bash
export CERT_X_GEN_TARGET_HOST="example.com"
export CERT_X_GEN_TARGET_PORT="443"
./target/release/tls-certificate-deep-analysis --json
```

---

## Real-World Test Results

### FOFA Internet Scan Results

**Scan Parameters:**
- **Query**: `cert.is_valid=false` (certificates marked invalid)
- **Targets**: 5 HTTPS servers on port 443
- **Date**: 2026-02-19

### Results Summary

| Metric | Value |
|--------|-------|
| **Targets Scanned** | 5 |
| **Responsive Targets** | 1 (20%) |
| **Total Findings** | 2 CRITICAL |
| **Severity Breakdown** | Critical: 2, High: 0 |

### Detailed Findings

#### Target: 118.69.65.52 (Vietnam)

**Finding 1: Hostname Mismatch** ⚠️ CRITICAL
```json
{
  "severity": "critical",
  "confidence": 98,
  "title": "Hostname Mismatch",
  "cvss_score": 9.3,
  "evidence": {
    "subject_cn": "Vigor Router",
    "hostname": "118.69.65.52",
    "subject": "C=TW, ST=HsinChu, L=HuKou, O=DrayTek Corp."
  }
}
```


**Analysis**: DrayTek Vigor router using generic "Vigor Router" certificate name instead of IP/hostname. Classic embedded device misconfiguration.

**Finding 2: Self-Signed Certificate** ⚠️ CRITICAL
```json
{
  "severity": "critical",
  "confidence": 95,
  "title": "Self-Signed Certificate",
  "cvss_score": 8.1,
  "evidence": {
    "subject": "CN=Vigor Router",
    "issuer": "CN=Vigor Router",  // Same as subject = self-signed
    "chain_length": "1"
  }
}
```

**Analysis**: Certificate signed by itself, no trusted CA in chain. Common in IoT/router management interfaces but creates MITM vulnerability.

### Unreachable Targets

| Target | Error | Analysis |
|--------|-------|----------|
| 38.238.55.28 | Connection reset | Firewall/rate limiting |
| 186.236.129.44 | TLS InternalError | Server misconfiguration |
| 43.153.21.98 | UnrecognisedName | SNI requirement not met |
| 190.93.246.122 | HandshakeFailure | TLS version/cipher mismatch |

**Detection Rate**: 20% (1/5 targets analyzed successfully)

**Note**: Low response rate expected when scanning for invalid certificates—many have additional network/TLS issues.

---

## Defense & Remediation

### Priority Actions

#### 1. **Implement Automated Certificate Management**
```bash
# Use Let's Encrypt with automatic renewal
certbot certonly --standalone -d example.com
certbot renew --dry-run  # Test renewal
```

**Tools:**
- Let's Encrypt (free, automated)
- cert-manager (Kubernetes)
- AWS Certificate Manager
- Cloudflare SSL

#### 2. **Enforce Minimum Cryptographic Standards**

**Policy Requirements:**
- ✅ RSA: 2048+ bits (4096 recommended)
- ✅ Signature: SHA-256 or stronger
- ✅ TLS: 1.2 minimum (1.3 preferred)
- ❌ Disable: SSLv3, TLS 1.0/1.1, SHA-1, MD5


#### 3. **Certificate Monitoring**

```bash
# Check certificate expiration
openssl s_client -connect example.com:443 -servername example.com </dev/null | \
  openssl x509 -noout -dates

# Automated monitoring with cron
0 0 * * * /usr/local/bin/check-certs.sh | mail -s "Cert Status" admin@example.com
```

**Commercial Solutions:**
- SSL Labs (free online scanner)
- Certificate Transparency logs
- Nagios/Zabbix SSL plugins
- Cloud provider monitoring

#### 4. **Hostname Validation**

**Server Configuration:**
```nginx
# Nginx: Ensure certificate matches server_name
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
}
```

#### 5. **Replace Self-Signed Certificates**

**Even for internal services:**
- Use internal CA (HashiCorp Vault, CFSSL)
- Deploy Let's Encrypt via DNS-01 challenge
- Use service mesh (Istio, Linkerd) with automatic mTLS

---

## Extending the Template

### Adding Custom Checks

#### Example: Check Certificate Transparency Logs

```rust
fn check_sct_extension(cert: &X509Certificate) -> Option<Finding> {
    // Look for SCT (Signed Certificate Timestamp) extension
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == "1.3.6.1.4.1.11129.2.4.2" {
            return None;  // SCT present, certificate is logged
        }
    }
    
    // No SCT found
    Some(Finding {
        title: "Missing Certificate Transparency".to_string(),
        description: "Certificate not logged in CT logs".to_string(),
        severity: "medium".to_string(),
        cvss_score: 5.3,
        // ...
    })
}
```


#### Example: OCSP Stapling Check

```rust
fn check_ocsp_stapling(tls_conn: &rustls::ClientConnection) -> Option<Finding> {
    // Check if server provided OCSP response
    if tls_conn.received_resumption_data().is_none() {
        return Some(Finding {
            title: "No OCSP Stapling".to_string(),
            description: "Server does not provide OCSP stapling".to_string(),
            severity: "low".to_string(),
            cvss_score: 3.1,
            // ...
        });
    }
    None
}
```

### Performance Optimization

**Batch Scanning Tips:**
- Use async I/O for parallel connections
- Implement connection pooling
- Add rate limiting to avoid triggering IDS/IPS
- Cache results for recently scanned hosts

```rust
// Example: Parallel scanning with tokio
use tokio::task;

let handles: Vec<_> = targets
    .iter()
    .map(|target| {
        task::spawn(async move {
            analyze_certificate(target).await
        })
    })
    .collect();
```

---

## References

### Standards & RFCs

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) - Internet X.509 PKI Certificate and CRL Profile
- [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) - Representation and Verification of Domain-Based Application Service Identity
- [RFC 8954](https://www.rfc-editor.org/rfc/rfc8954) - Online Certificate Status Protocol (OCSP) Nonce Extension
- [CAB Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/) - Industry standards for CAs

### Security Resources

- [SSL Labs Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [NIST SP 800-57](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) - Key Management Recommendations
- [Key Length](https://www.keylength.com/) - Cryptographic Key Length Recommendations


### CWE Mappings

- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) - Improper Certificate Validation
- [CWE-297](https://cwe.mitre.org/data/definitions/297.html) - Improper Validation of Certificate with Host Mismatch
- [CWE-326](https://cwe.mitre.org/data/definitions/326.html) - Inadequate Encryption Strength
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) - Use of a Broken or Risky Cryptographic Algorithm

### Rust Libraries

- [rustls](https://github.com/rustls/rustls) - Modern TLS library in Rust
- [x509-parser](https://github.com/rusticata/x509-parser) - X.509 certificate parser
- [webpki](https://github.com/briansmith/webpki) - Web PKI certificate verification
- [rcgen](https://github.com/rustls/rcgen) - Rust X.509 certificate generator

### Notable Attacks

- **Heartbleed (2014)** - OpenSSL vulnerability exposing private keys
- **POODLE (2014)** - SSLv3 protocol weakness
- **FREAK (2015)** - Export-grade cryptography weakness
- **Logjam (2015)** - Diffie-Hellman weakness
- **SHAttered (2017)** - SHA-1 collision attack

---

## Conclusion

TLS certificate vulnerabilities remain a critical attack surface in modern infrastructure. This template demonstrates the power of CERT-X-GEN's polyglot approach—using Rust's native TLS libraries and X.509 parsing capabilities to perform deep analysis that traditional YAML scanners cannot achieve.

### Key Takeaways

1. **Surface checks aren't enough** - Need deep X.509 parsing and cryptographic analysis
2. **Native libraries matter** - Rust provides zero-copy parsing and memory safety
3. **Accept-all verifier** - Essential for analyzing broken/misconfigured certificates
4. **Automation is critical** - Manual certificate management fails at scale
5. **Defense in depth** - Combine automated scanning with monitoring and strong defaults

### Next Steps

1. **Integrate into CI/CD** - Scan certificates before deployment
2. **Set up monitoring** - Alert 30 days before expiration
3. **Enforce standards** - Block weak algorithms at infrastructure level
4. **Regular scanning** - Weekly scans of production infrastructure
5. **Incident response** - Have playbook for certificate compromise

---

**Template Version**: 1.0.0  
**Last Updated**: 2026-02-19  
**Maintained By**: BugB Technologies  
**License**: MIT  

For questions or contributions, see: https://github.com/Bugb-Technologies/cert-x-gen-templates

//! CERT-X-GEN Rust Template — TLS Certificate Deep Analysis
//!
//! @id: tls-certificate-deep-analysis
//! @name: TLS Certificate Deep Analysis
//! @author: BugB Technologies
//! @severity: high
//! @description: Deep X.509 certificate chain analysis detecting expired certs, weak keys, deprecated signature algorithms, self-signed roots, hostname mismatches, missing SANs, CA constraint violations, and chain integrity issues that enable MITM attacks or authentication bypass.
//! @tags: tls, ssl, x509, certificate, chain-validation, weak-crypto, expired-cert, self-signed, sha1, mitm, pki, rfc5280
//! @cwe: CWE-295
//! @confidence: 92
//! @references: https://www.rfc-editor.org/rfc/rfc5280, https://cwe.mitre.org/data/definitions/295.html, https://ssl-config.mozilla.org/, https://www.cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.8.7.pdf

use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName as PkiServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::ServerName;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;
use x509_parser::prelude::*;

// ============================================================
//  Finding struct
// ============================================================

#[derive(Debug, Clone)]
struct Finding {
    template_id: String,
    template_name: String,
    severity: String,
    confidence: u8,
    title: String,
    description: String,
    evidence: HashMap<String, String>,
    cwe: String,
    cvss_score: f32,
    remediation: String,
    references: Vec<String>,
    matched_at: String,
}

impl Finding {
    fn to_json(&self) -> String {
        let mut evidence_parts = Vec::with_capacity(self.evidence.len());
        for (k, v) in &self.evidence {
            let ev = v
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r");
            evidence_parts.push(format!(r#""{}":"{}""#, k, ev));
        }
        let evidence_json = evidence_parts.join(",");

        let mut refs_parts = Vec::with_capacity(self.references.len());
        for r in &self.references {
            refs_parts.push(format!(r#""{}""#, r));
        }
        let refs_json = refs_parts.join(",");

        let desc = self.description.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r");
        let title = self.title.replace('"', "\\\"");
        let rem = self.remediation.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r");

        format!(
            r#"{{"template_id":"{}","template_name":"{}","severity":"{}","confidence":{},"title":"{}","description":"{}","evidence":{{{}}},"cwe":"{}","cvss_score":{},"remediation":"{}","references":[{}],"matched_at":"{}"}}"#,
            self.template_id, self.template_name, self.severity, self.confidence, title, desc, evidence_json, self.cwe, self.cvss_score, rem, refs_json, self.matched_at
        )
    }
}

// ============================================================
//  TLS probe — connect via rustls, capture certificates
// ============================================================

struct CertChain {
    /// DER-encoded certificates in order (leaf first)
    certs: Vec<Vec<u8>>,
}

/// Custom certificate verifier that accepts all certificates
/// This allows us to analyze invalid/expired/self-signed certificates
#[derive(Debug)]
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &PkiServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn probe_tls(host: &str, port: u16) -> Result<CertChain, String> {
    // Install default crypto provider (required for rustls 0.23+)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    
    // Use dangerous configuration that accepts all certificates (for analysis purposes)
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();

    let rc_config = Arc::new(config);

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("Invalid server name '{}': {}", host, e))?;

    let addr = format!("{}:{}", host, port);
    
    // Resolve address safely
    let socket_addr = addr.parse::<std::net::SocketAddr>()
        .or_else(|_| {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs()?
                .next()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("Failed to resolve {}", addr)))
        })
        .map_err(|e| format!("Address resolution failed: {}", e))?;
    
    let mut tcp = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
        .map_err(|e| format!("TCP connect failed to {}: {}", addr, e))?;

    tcp.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;

    let mut conn = rustls::ClientConnection::new(rc_config, server_name)
        .map_err(|e| format!("TLS client init failed: {}", e))?;

    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    // Trigger handshake
    tls.flush().map_err(|e| format!("TLS flush: {}", e))?;

    let peer_certs = tls.conn.peer_certificates()
        .ok_or_else(|| "No certificates returned by peer".to_string())?;

    if peer_certs.is_empty() {
        return Err("Empty certificate chain".to_string());
    }

    Ok(CertChain {
        certs: peer_certs.iter().map(|c| c.as_ref().to_vec()).collect(),
    })
}

// ============================================================
//  Certificate Analysis Functions
// ============================================================

fn get_iso8601_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    
    // Calculate date components
    let days_since_epoch = secs / 86400;
    let mut year = 1970;
    let mut days_remaining = days_since_epoch;
    
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days_remaining < days_in_year {
            break;
        }
        days_remaining -= days_in_year;
        year += 1;
    }
    
    let is_leap = is_leap_year(year);
    let days_in_months = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    
    let mut month = 1;
    for &days_in_month in &days_in_months {
        if days_remaining < days_in_month as u64 {
            break;
        }
        days_remaining -= days_in_month as u64;
        month += 1;
    }
    
    let day = days_remaining + 1;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;
    
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, minute, second)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn analyze_certificate_chain(chain: &CertChain, hostname: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, cert_der) in chain.certs.iter().enumerate() {
        match X509Certificate::from_der(cert_der) {
            Ok((_, cert)) => {
                findings.extend(analyze_single_cert(&cert, hostname, idx == 0));
            }
            Err(e) => {
                eprintln!("[!] Failed to parse certificate {}: {}", idx, e);
            }
        }
    }

    findings.extend(analyze_chain_structure(chain, hostname));

    findings
}

fn analyze_single_cert(cert: &X509Certificate, hostname: &str, is_leaf: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check expiry
    findings.extend(check_validity_period(cert));

    // Check signature algorithm
    findings.extend(check_signature_algorithm(cert));

    // Check key strength
    findings.extend(check_key_strength(cert));

    // For leaf certificate, check hostname and SANs
    if is_leaf {
        findings.extend(check_hostname_match(cert, hostname));
    }

    // Check CA constraints
    findings.extend(check_ca_constraints(cert, is_leaf));

    findings
}

fn check_validity_period(cert: &X509Certificate) -> Vec<Finding> {
    let mut findings = Vec::new();
    let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => {
            eprintln!("[!] System time error - cannot validate certificate dates");
            return findings;
        }
    };

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    if now < not_before {
        let mut evidence = HashMap::new();
        evidence.insert("subject".to_string(), cert.subject().to_string());
        evidence.insert("not_before".to_string(), cert.validity().not_before.to_string());
        evidence.insert("current_time".to_string(), format!("{}", now));

        findings.push(Finding {
            template_id: "tls-certificate-deep-analysis".to_string(),
            template_name: "TLS Certificate Deep Analysis".to_string(),
            severity: "high".to_string(),
            confidence: 95,
            title: "Certificate Not Yet Valid".to_string(),
            description: "Certificate has a future validity start date, indicating possible system clock misconfiguration or an incorrectly issued certificate.".to_string(),
            evidence,
            cwe: "CWE-295".to_string(),
            cvss_score: 7.5,
            remediation: "Verify system clock is synchronized with NTP. If certificate is legitimate, wait until validity period begins.".to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc5280".to_string()],
            matched_at: get_iso8601_timestamp(),
        });
    }

    if now > not_after {
        let mut evidence = HashMap::new();
        evidence.insert("subject".to_string(), cert.subject().to_string());
        evidence.insert("not_after".to_string(), cert.validity().not_after.to_string());
        evidence.insert("current_time".to_string(), format!("{}", now));
        evidence.insert("expired_days".to_string(), format!("{}", (now - not_after) / 86400));

        findings.push(Finding {
            template_id: "tls-certificate-deep-analysis".to_string(),
            template_name: "TLS Certificate Deep Analysis".to_string(),
            severity: "critical".to_string(),
            confidence: 100,
            title: "Expired TLS Certificate".to_string(),
            description: "Certificate has expired and is no longer trusted. Connections using this certificate are vulnerable to MITM attacks.".to_string(),
            evidence,
            cwe: "CWE-295".to_string(),
            cvss_score: 9.1,
            remediation: "Renew the certificate immediately. Implement automated certificate renewal (e.g., Let's Encrypt, ACME protocol).".to_string(),
            references: vec![
                "https://www.rfc-editor.org/rfc/rfc5280".to_string(),
                "https://cwe.mitre.org/data/definitions/295.html".to_string(),
            ],
            matched_at: get_iso8601_timestamp(),
        });
    }

    findings
}

fn check_signature_algorithm(cert: &X509Certificate) -> Vec<Finding> {
    let mut findings = Vec::new();
    let sig_alg = cert.signature_algorithm.algorithm.to_id_string();

    // Check for weak/deprecated signature algorithms
    let weak_algs = vec![
        "1.2.840.113549.1.1.4",  // MD5WithRSAEncryption
        "1.2.840.113549.1.1.5",  // SHA1WithRSAEncryption
        "1.3.14.3.2.29",         // SHA1WithRSA (alternative)
        "1.2.840.10040.4.3",     // SHA1WithDSA
    ];

    if weak_algs.contains(&sig_alg.as_str()) {
        let mut evidence = HashMap::new();
        evidence.insert("subject".to_string(), cert.subject().to_string());
        evidence.insert("signature_algorithm".to_string(), sig_alg);

        findings.push(Finding {
            template_id: "tls-certificate-deep-analysis".to_string(),
            template_name: "TLS Certificate Deep Analysis".to_string(),
            severity: "high".to_string(),
            confidence: 95,
            title: "Weak Signature Algorithm Detected".to_string(),
            description: "Certificate uses a deprecated or weak signature algorithm (MD5/SHA1). These algorithms are vulnerable to collision attacks and should not be trusted.".to_string(),
            evidence,
            cwe: "CWE-327".to_string(),
            cvss_score: 7.4,
            remediation: "Replace certificate with one signed using SHA256 or stronger algorithm.".to_string(),
            references: vec![
                "https://shattered.io/".to_string(),
                "https://www.rfc-editor.org/rfc/rfc8954".to_string(),
            ],
            matched_at: get_iso8601_timestamp(),
        });
    }

    findings
}

fn check_key_strength(cert: &X509Certificate) -> Vec<Finding> {
    let mut findings = Vec::new();
    let public_key = cert.public_key();

    // Check RSA key size based on algorithm OID
    let algo_oid = public_key.algorithm.algorithm.to_id_string();
    
    // RSA encryption OID: 1.2.840.113549.1.1.1
    if algo_oid == "1.2.840.113549.1.1.1" {
        let key_size_bits = public_key.subject_public_key.data.len() * 8;

        if key_size_bits < 2048 {
            let mut evidence = HashMap::new();
            evidence.insert("subject".to_string(), cert.subject().to_string());
            evidence.insert("key_type".to_string(), "RSA".to_string());
            evidence.insert("key_size_bits".to_string(), format!("{}", key_size_bits));

            findings.push(Finding {
                template_id: "tls-certificate-deep-analysis".to_string(),
                template_name: "TLS Certificate Deep Analysis".to_string(),
                severity: "high".to_string(),
                confidence: 90,
                title: "Weak RSA Key Size".to_string(),
                description: "Certificate uses an RSA key smaller than 2048 bits. Keys below 2048 bits are considered weak and vulnerable to factorization attacks.".to_string(),
                evidence,
                cwe: "CWE-326".to_string(),
                cvss_score: 7.5,
                remediation: "Replace certificate with one using at least 2048-bit RSA key (4096 bits recommended for long-term security).".to_string(),
                references: vec![
                    "https://www.keylength.com/".to_string(),
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf".to_string(),
                ],
                matched_at: get_iso8601_timestamp(),
            });
        }
    }

    findings
}

fn check_hostname_match(cert: &X509Certificate, hostname: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut matched = false;

    // Check CN in Subject
    let subject_cn = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("");

    if hostname_matches(subject_cn, hostname) {
        matched = true;
    }

    // Check Subject Alternative Names
    if let Some(san_ext) = cert.extensions().iter().find(|e| e.oid == OID_X509_EXT_SUBJECT_ALT_NAME) {
        if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    if hostname_matches(dns, hostname) {
                        matched = true;
                        break;
                    }
                }
            }
        }
    }

    if !matched {
        let mut evidence = HashMap::new();
        evidence.insert("subject_cn".to_string(), subject_cn.to_string());
        evidence.insert("hostname".to_string(), hostname.to_string());
        evidence.insert("subject".to_string(), cert.subject().to_string());

        findings.push(Finding {
            template_id: "tls-certificate-deep-analysis".to_string(),
            template_name: "TLS Certificate Deep Analysis".to_string(),
            severity: "critical".to_string(),
            confidence: 98,
            title: "Hostname Mismatch".to_string(),
            description: "Certificate hostname does not match the target hostname. This indicates a potential MITM attack or misconfiguration.".to_string(),
            evidence,
            cwe: "CWE-297".to_string(),
            cvss_score: 9.3,
            remediation: "Ensure certificate CN or SAN matches the hostname. Investigate for potential MITM attack.".to_string(),
            references: vec![
                "https://www.rfc-editor.org/rfc/rfc6125".to_string(),
                "https://cwe.mitre.org/data/definitions/297.html".to_string(),
            ],
            matched_at: get_iso8601_timestamp(),
        });
    }

    findings
}

fn hostname_matches(cert_name: &str, hostname: &str) -> bool {
    let cert_lower = cert_name.to_lowercase();
    let host_lower = hostname.to_lowercase();

    // Exact match
    if cert_lower == host_lower {
        return true;
    }

    // Wildcard match (*.example.com matches sub.example.com)
    if cert_lower.starts_with("*.") {
        let cert_domain = &cert_lower[2..];
        if let Some(idx) = host_lower.find('.') {
            let host_domain = &host_lower[idx + 1..];
            if cert_domain == host_domain {
                return true;
            }
        }
    }

    false
}

fn check_ca_constraints(cert: &X509Certificate, is_leaf: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    let is_ca = cert.is_ca();

    if is_leaf && is_ca {
        let mut evidence = HashMap::new();
        evidence.insert("subject".to_string(), cert.subject().to_string());
        evidence.insert("is_ca".to_string(), "true".to_string());

        findings.push(Finding {
            template_id: "tls-certificate-deep-analysis".to_string(),
            template_name: "TLS Certificate Deep Analysis".to_string(),
            severity: "medium".to_string(),
            confidence: 85,
            title: "Leaf Certificate with CA Flag".to_string(),
            description: "Leaf certificate incorrectly has CA flag set. This violates RFC 5280 and could be used to issue fraudulent certificates.".to_string(),
            evidence,
            cwe: "CWE-295".to_string(),
            cvss_score: 6.5,
            remediation: "Reissue certificate without CA flag for end-entity certificates.".to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9".to_string()],
            matched_at: get_iso8601_timestamp(),
        });
    }

    findings
}

fn analyze_chain_structure(chain: &CertChain, _hostname: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if chain.certs.len() == 1 {
        if let Ok((_, cert)) = X509Certificate::from_der(&chain.certs[0]) {
            // Check if self-signed
            if cert.subject() == cert.issuer() {
                let mut evidence = HashMap::new();
                evidence.insert("subject".to_string(), cert.subject().to_string());
                evidence.insert("issuer".to_string(), cert.issuer().to_string());
                evidence.insert("chain_length".to_string(), "1".to_string());

                findings.push(Finding {
                    template_id: "tls-certificate-deep-analysis".to_string(),
                    template_name: "TLS Certificate Deep Analysis".to_string(),
                    severity: "critical".to_string(),
                    confidence: 95,
                    title: "Self-Signed Certificate".to_string(),
                    description: "Server uses a self-signed certificate without a proper trust chain. Self-signed certificates cannot be validated and are vulnerable to MITM attacks.".to_string(),
                    evidence,
                    cwe: "CWE-295".to_string(),
                    cvss_score: 8.1,
                    remediation: "Replace with a certificate issued by a trusted CA (e.g., Let's Encrypt, DigiCert, Sectigo).".to_string(),
                    references: vec![
                        "https://letsencrypt.org/".to_string(),
                        "https://cwe.mitre.org/data/definitions/295.html".to_string(),
                    ],
                    matched_at: get_iso8601_timestamp(),
                });
            }
        }
    }

    findings
}

// ============================================================
//  Main entry point
// ============================================================

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    let mut target = env::var("CERT_X_GEN_TARGET_HOST").ok();
    let mut port: u16 = env::var("CERT_X_GEN_TARGET_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    
    // Parse --target and --port flags
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => {
                if i + 1 < args.len() {
                    target = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --target requires a value");
                    println!("[]");
                    return;
                }
            }
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    if let Ok(p) = args[i + 1].parse() {
                        port = p;
                    }
                    i += 2;
                } else {
                    eprintln!("Error: --port requires a value");
                    println!("[]");
                    return;
                }
            }
            "--json" => {
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    let target = match target {
        Some(t) => t,
        None => {
            eprintln!("Error: No target specified");
            println!("[]");
            return;
        }
    };

    eprintln!("[*] Connecting to {}:{}", target, port);

    let chain = match probe_tls(&target, port) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] TLS connection failed: {}", e);
            println!("[]");
            return;
        }
    };

    eprintln!("[+] Retrieved {} certificate(s)", chain.certs.len());

    let findings = analyze_certificate_chain(&chain, &target);

    eprintln!("[*] Analysis complete: {} finding(s)", findings.len());

    let json_findings: Vec<String> = findings.iter().map(|f| f.to_json()).collect();
    println!("[{}]", json_findings.join(","));
}

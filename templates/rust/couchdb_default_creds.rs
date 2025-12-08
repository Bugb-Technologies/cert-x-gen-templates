//! CERT-X-GEN CouchDB Default Credentials Detection Template
//!
//! Template Metadata:
//!   ID: couchdb-default-credentials
//!   Name: CouchDB Default Credentials Detection
//!   Author: CERT-X-GEN Security Team
//!   Severity: critical
//!   Description: Detects CouchDB instances using default administrative credentials or running
//!                in Party Mode (no authentication), allowing unauthorized database access and
//!                manipulation. Tests common default credentials and authentication bypass.
//!   Tags: couchdb, database, default-credentials, nosql, authentication, party-mode
//!   Language: rust
//!   CWE: CWE-798 (Use of Hard-coded Credentials)
//!   References:
//!     - https://cwe.mitre.org/data/definitions/798.html
//!     - https://docs.couchdb.org/en/stable/intro/security.html
//!     - https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password

use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

pub const TEMPLATE_ID: &str = "couchdb-default-credentials";
pub const TEMPLATE_NAME: &str = "CouchDB Default Credentials Detection";
pub const SEVERITY: &str = "critical";
pub const CONFIDENCE: u8 = 95;

#[derive(Debug, Serialize, Deserialize)]
pub struct CouchDBInfo {
    pub couchdb: String,
    pub version: String,
    pub git_sha: Option<String>,
    pub uuid: Option<String>,
    pub features: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: Value,
    pub remediation: String,
    pub cwe: String,
    pub cvss_score: f32,
}

pub struct CouchDBTemplate {
    client: reqwest::Client,
    credentials: Vec<(&'static str, &'static str)>,
}

impl CouchDBTemplate {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build HTTP client");
        
        // Common default/weak credentials
        let credentials = vec![
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "couchdb"),
            ("couchdb", "couchdb"),
            ("administrator", "password"),
            ("", ""),  // No auth (Party Mode)
        ];
        
        Self { client, credentials }
    }
    
    pub async fn execute(&self, target: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test common CouchDB ports
        for port in &[5984, 6984] {
            let scheme = if *port == 6984 { "https" } else { "http" };
            let base_url = format!("{}://{}:{}", scheme, target, port);
            
            // Test 1: Check if Party Mode is enabled (no auth required)
            if let Some(finding) = self.test_party_mode(&base_url).await {
                findings.push(finding);
                // In Party Mode, no need to test credentials
                continue;
            }
            
            // Test 2: Try default/weak credentials
            for (username, password) in &self.credentials {
                if let Some(mut cred_findings) = self.test_credentials(&base_url, username, password).await {
                    findings.append(&mut cred_findings);
                    break; // Stop after first successful auth
                }
            }
        }
        
        findings
    }
    
    async fn test_party_mode(&self, base_url: &str) -> Option<Finding> {
        // In Party Mode, anyone can access /_all_dbs without authentication
        let url = format!("{}/_all_dbs", base_url);
        
        match self.client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(text) = response.text().await {
                    if text.starts_with('[') {
                        // Successfully listed databases without auth
                        let db_count = text.matches(',').count() + 1;
                        
                        return Some(Finding {
                            severity: "critical".to_string(),
                            title: "CouchDB Party Mode Enabled (No Authentication)".to_string(),
                            description: format!(
                                "CouchDB is running in Party Mode - no authentication required. {} databases accessible.",
                                db_count
                            ),
                            evidence: serde_json::json!({
                                "party_mode": true,
                                "endpoint": url,
                                "database_count": db_count,
                                "authentication_required": false
                            }),
                            remediation: get_remediation(),
                            cwe: "CWE-306".to_string(),
                            cvss_score: 10.0,
                        });
                    }
                }
            }
            _ => {}
        }
        
        None
    }
    
    async fn test_credentials(&self, base_url: &str, username: &str, password: &str) -> Option<Vec<Finding>> {
        let url = format!("{}/_session", base_url);
        
        // Try to authenticate
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "name": username,
                "password": password
            }))
            .send()
            .await;
        
        if let Ok(resp) = response {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    if text.contains("\"ok\":true") {
                        return Some(self.enumerate_with_credentials(base_url, username, password).await);
                    }
                }
            }
        }
        
        // Also try Basic Auth
        let info_url = format!("{}/", base_url);
        let response = self.client
            .get(&info_url)
            .basic_auth(username, Some(password))
            .send()
            .await;
        
        if let Ok(resp) = response {
            if resp.status().is_success() {
                if let Ok(info) = resp.json::<CouchDBInfo>().await {
                    return Some(self.enumerate_with_credentials(base_url, username, password).await);
                }
            }
        }
        
        None
    }
    
    async fn enumerate_with_credentials(&self, base_url: &str, username: &str, password: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Main finding: credentials work
        findings.push(Finding {
            severity: "critical".to_string(),
            title: format!("CouchDB Default/Weak Credentials: {}:{}", username, password),
            description: format!("Successfully authenticated to CouchDB with credentials {}:{}", username, password),
            evidence: serde_json::json!({
                "username": username,
                "password": password,
                "endpoint": base_url,
            }),
            remediation: get_remediation(),
            cwe: "CWE-798".to_string(),
            cvss_score: 9.8,
        });
        
        // Enumerate databases
        if let Ok(databases) = self.list_databases(base_url, username, password).await {
            findings.push(Finding {
                severity: "high".to_string(),
                title: "CouchDB Database Enumeration".to_string(),
                description: format!("Successfully enumerated {} databases", databases.len()),
                evidence: serde_json::json!({
                    "database_count": databases.len(),
                    "databases": databases
                }),
                remediation: get_remediation(),
                cwe: "CWE-798".to_string(),
                cvss_score: 7.5,
            });
        }
        
        // Check for sensitive databases
        self.check_sensitive_databases(base_url, username, password, &mut findings).await;
        
        // Try to get admin info
        if let Ok(users) = self.list_users(base_url, username, password).await {
            findings.push(Finding {
                severity: "high".to_string(),
                title: "CouchDB User Enumeration".to_string(),
                description: format!("Successfully enumerated {} users", users.len()),
                evidence: serde_json::json!({
                    "user_count": users.len(),
                    "users": users
                }),
                remediation: get_remediation(),
                cwe: "CWE-798".to_string(),
                cvss_score: 7.5,
            });
        }
        
        findings
    }
    
    async fn list_databases(&self, base_url: &str, username: &str, password: &str) -> Result<Vec<String>, ()> {
        let url = format!("{}/_all_dbs", base_url);
        
        match self.client
            .get(&url)
            .basic_auth(username, Some(password))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(dbs) = resp.json::<Vec<String>>().await {
                    return Ok(dbs);
                }
            }
            _ => {}
        }
        
        Err(())
    }
    
    async fn check_sensitive_databases(&self, base_url: &str, username: &str, password: &str, findings: &mut Vec<Finding>) {
        let sensitive_dbs = vec!["_users", "_replicator", "admin", "passwords", "secrets", "credentials"];
        
        for db_name in sensitive_dbs {
            let url = format!("{}/{}", base_url, db_name);
            
            if let Ok(resp) = self.client
                .get(&url)
                .basic_auth(username, Some(password))
                .send()
                .await
            {
                if resp.status().is_success() {
                    findings.push(Finding {
                        severity: "critical".to_string(),
                        title: format!("Sensitive Database Accessible: {}", db_name),
                        description: format!("Sensitive database '{}' is accessible", db_name),
                        evidence: serde_json::json!({
                            "database": db_name,
                            "accessible": true
                        }),
                        remediation: get_remediation(),
                        cwe: "CWE-798".to_string(),
                        cvss_score: 9.1,
                    });
                }
            }
        }
    }
    
    async fn list_users(&self, base_url: &str, username: &str, password: &str) -> Result<Vec<String>, ()> {
        let url = format!("{}/_users/_all_docs", base_url);
        
        match self.client
            .get(&url)
            .basic_auth(username, Some(password))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(json) = resp.json::<Value>().await {
                    if let Some(rows) = json["rows"].as_array() {
                        let users: Vec<String> = rows.iter()
                            .filter_map(|row| row["id"].as_str().map(String::from))
                            .collect();
                        return Ok(users);
                    }
                }
            }
            _ => {}
        }
        
        Err(())
    }
}

fn get_remediation() -> String {
    r#"
1. Disable Party Mode - require authentication:
   [chttpd]
   require_valid_user = true

2. Change admin password immediately:
   curl -X PUT http://admin:oldpass@localhost:5984/_node/_local/_config/admins/admin -d '"newpassword"'

3. Create admin user with strong password:
   curl -X PUT http://localhost:5984/_node/_local/_config/admins/newadmin -d '"strongpassword"'

4. Enable HTTPS/TLS:
   [ssl]
   enable = true
   cert_file = /path/to/cert.pem
   key_file = /path/to/key.pem

5. Bind to localhost only (if local use):
   [chttpd]
   bind_address = 127.0.0.1

6. Use proper authentication:
   - JWT tokens
   - OAuth
   - Proxy authentication

7. Implement database-level permissions
8. Enable audit logging
9. Regular security audits
10. Keep CouchDB updated
"#.to_string()
}

#[derive(Serialize)]
pub struct TemplateMetadata {
    pub id: String,
    pub name: String,
    pub author: String,
    pub severity: String,
    pub language: String,
    pub tags: Vec<String>,
    pub confidence: u8,
}

pub fn get_metadata() -> TemplateMetadata {
    TemplateMetadata {
        id: TEMPLATE_ID.to_string(),
        name: TEMPLATE_NAME.to_string(),
        author: "CERT-X-GEN Security Team".to_string(),
        severity: SEVERITY.to_string(),
        language: "rust".to_string(),
        tags: vec!["couchdb".to_string(), "default-credentials".to_string(), "database".to_string()],
        confidence: CONFIDENCE,
    }
}

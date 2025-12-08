//! CERT-X-GEN Elasticsearch Unauthenticated Access Detection Template
//!
//! Template Metadata:
//!   ID: elasticsearch-unauthenticated
//!   Name: Elasticsearch Unauthenticated Access Detection
//!   Author: CERT-X-GEN Security Team
//!   Severity: critical
//!   Description: Detects Elasticsearch clusters accessible without authentication, exposing
//!                indexed data, cluster configuration, and allowing unauthorized operations.
//!                Tests for open cluster API, index enumeration, and data access.
//!   Tags: elasticsearch, search-engine, authentication, nosql, data-exposure, cluster
//!   Language: rust
//!   CWE: CWE-306 (Missing Authentication for Critical Function)
//!   References:
//!     - https://cwe.mitre.org/data/definitions/306.html
//!     - https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html
//!     - https://owasp.org/www-community/vulnerabilities/Broken_Authentication

use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// Template metadata
pub const TEMPLATE_ID: &str = "elasticsearch-unauthenticated-access";
pub const TEMPLATE_NAME: &str = "Elasticsearch Unauthenticated Access Detection";
pub const SEVERITY: &str = "critical";
pub const CONFIDENCE: u8 = 95;

/// Elasticsearch cluster information
#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterInfo {
    pub name: String,
    pub cluster_name: String,
    pub cluster_uuid: String,
    pub version: ElasticsearchVersion,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ElasticsearchVersion {
    pub number: String,
    pub build_flavor: String,
    pub build_type: String,
}

/// Finding structure
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

/// Elasticsearch template executor
pub struct ElasticsearchTemplate {
    client: reqwest::Client,
}

impl ElasticsearchTemplate {
    /// Create new template instance
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build HTTP client");
        
        Self { client }
    }
    
    /// Execute template against target
    pub async fn execute(&self, target: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test standard Elasticsearch ports
        let ports = vec![9200, 9201];
        
        for port in ports {
            let base_url = format!("http://{}:{}", target, port);
            
            // Test 1: Check cluster info (root endpoint)
            if let Some(finding) = self.test_cluster_info(&base_url).await {
                findings.push(finding);
            }
            
            // Test 2: List indices
            if let Some(finding) = self.test_list_indices(&base_url).await {
                findings.push(finding);
            }
            
            // Test 3: Check cluster health
            if let Some(finding) = self.test_cluster_health(&base_url).await {
                findings.push(finding);
            }
            
            // Test 4: Try to read data
            if let Some(finding) = self.test_data_access(&base_url).await {
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Test cluster information endpoint
    async fn test_cluster_info(&self, base_url: &str) -> Option<Finding> {
        let url = format!("{}/", base_url);
        
        match self.client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(text) = response.text().await {
                    if text.contains("cluster_name") && text.contains("version") {
                        // Try to parse as JSON
                        if let Ok(info) = serde_json::from_str::<ClusterInfo>(&text) {
                            return Some(Finding {
                                severity: "critical".to_string(),
                                title: "Elasticsearch Unauthenticated Access".to_string(),
                                description: format!(
                                    "Elasticsearch cluster '{}' (v{}) is accessible without authentication",
                                    info.cluster_name, info.version.number
                                ),
                                evidence: serde_json::json!({
                                    "cluster_name": info.cluster_name,
                                    "cluster_uuid": info.cluster_uuid,
                                    "version": info.version.number,
                                    "endpoint": url
                                }),
                                remediation: get_remediation(),
                                cwe: "CWE-306".to_string(),
                                cvss_score: 9.8,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        
        None
    }
    
    /// Test index listing
    async fn test_list_indices(&self, base_url: &str) -> Option<Finding> {
        let url = format!("{}/_cat/indices?v", base_url);
        
        match self.client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(text) = response.text().await {
                    if text.contains("health") && text.contains("index") {
                        // Count indices
                        let index_count = text.lines().skip(1).count();
                        
                        return Some(Finding {
                            severity: "high".to_string(),
                            title: "Elasticsearch Index Enumeration".to_string(),
                            description: format!("Successfully enumerated {} indices", index_count),
                            evidence: serde_json::json!({
                                "index_count": index_count,
                                "indices_sample": text.lines().take(10).collect::<Vec<_>>()
                            }),
                            remediation: get_remediation(),
                            cwe: "CWE-306".to_string(),
                            cvss_score: 7.5,
                        });
                    }
                }
            }
            _ => {}
        }
        
        None
    }
    
    /// Test cluster health endpoint
    async fn test_cluster_health(&self, base_url: &str) -> Option<Finding> {
        let url = format!("{}/_cluster/health", base_url);
        
        match self.client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(text) = response.text().await {
                    if let Ok(health) = serde_json::from_str::<Value>(&text) {
                        return Some(Finding {
                            severity: "medium".to_string(),
                            title: "Elasticsearch Cluster Health Exposed".to_string(),
                            description: "Cluster health information accessible without authentication".to_string(),
                            evidence: health,
                            remediation: get_remediation(),
                            cwe: "CWE-306".to_string(),
                            cvss_score: 5.3,
                        });
                    }
                }
            }
            _ => {}
        }
        
        None
    }
    
    /// Test data access
    async fn test_data_access(&self, base_url: &str) -> Option<Finding> {
        // Try to search all indices
        let url = format!("{}/_search?size=1", base_url);
        
        match self.client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(text) = response.text().await {
                    if text.contains("hits") && text.contains("total") {
                        return Some(Finding {
                            severity: "critical".to_string(),
                            title: "Elasticsearch Data Access Without Authentication".to_string(),
                            description: "Successfully queried data from Elasticsearch without credentials".to_string(),
                            evidence: serde_json::json!({
                                "search_endpoint": url,
                                "data_accessible": true
                            }),
                            remediation: get_remediation(),
                            cwe: "CWE-306".to_string(),
                            cvss_score: 9.8,
                        });
                    }
                }
            }
            _ => {}
        }
        
        None
    }
}

/// Get remediation steps
fn get_remediation() -> String {
    r#"
1. Enable X-Pack security (Elasticsearch 6.8+):
   xpack.security.enabled: true
   
2. Configure authentication in elasticsearch.yml:
   xpack.security.authc:
     realms:
       native:
         native1:
           order: 0

3. Create admin user:
   bin/elasticsearch-users useradd admin -p strong_password -r superuser

4. Enable TLS/SSL:
   xpack.security.transport.ssl.enabled: true
   xpack.security.http.ssl.enabled: true

5. Bind to localhost only:
   network.host: 127.0.0.1

6. Use firewall rules to restrict access
7. Enable audit logging
8. Regularly update Elasticsearch to latest version
"#.to_string()
}

// Template metadata for CERT-X-GEN engine
#[derive(Serialize)]
pub struct TemplateMetadata {
    pub id: String,
    pub name: String,
    pub author: String,
    pub severity: String,
    pub language: String,
    pub tags: Vec<String>,
    pub confidence: u8,
    pub references: Vec<String>,
}

pub fn get_metadata() -> TemplateMetadata {
    TemplateMetadata {
        id: TEMPLATE_ID.to_string(),
        name: TEMPLATE_NAME.to_string(),
        author: "CERT-X-GEN Security Team".to_string(),
        severity: SEVERITY.to_string(),
        language: "rust".to_string(),
        tags: vec![
            "elasticsearch".to_string(),
            "unauthenticated".to_string(),
            "database".to_string(),
            "search-engine".to_string(),
        ],
        confidence: CONFIDENCE,
        references: vec![
            "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html".to_string(),
            "https://cwe.mitre.org/data/definitions/306.html".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_template_creation() {
        let template = ElasticsearchTemplate::new();
        assert!(true); // Template created successfully
    }
}

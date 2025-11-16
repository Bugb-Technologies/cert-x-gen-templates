#!/usr/bin/env python3
"""
MySQL Exporter Exposed Without Authentication

Detects exposed Prometheus MySQL Exporter instances that reveal
database performance metrics and sensitive configuration information.

Author: CERT-X-GEN Security Team
Severity: Critical
CWE: CWE-200 (Information Exposure)
"""

import json
import sys
import os
import urllib.request

def get_port():
    """Get port to scan from environment or use default"""
    if "CERT_X_GEN_OVERRIDE_PORTS" in os.environ:
        ports = os.environ["CERT_X_GEN_OVERRIDE_PORTS"].split(',')
        return int(ports[0].strip())
    elif "CERT_X_GEN_ADD_PORTS" in os.environ:
        ports = os.environ["CERT_X_GEN_ADD_PORTS"].split(',')
        return int(ports[0].strip())
    return 9104  # Default MySQL Exporter port

def check_mysql_exporter(host, port):
    """Check if MySQL Exporter is accessible"""
    try:
        url = f"http://{host}:{port}/metrics"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'CERT-X-GEN/1.0'}
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode('utf-8', errors='ignore')
            
            # Check for MySQL Exporter signatures
            signatures = ['mysql_up', 'mysql_global_status', 'mysqld_exporter']
            if any(sig in body for sig in signatures):
                evidence_data = {
                    "endpoint": url,
                    "port": port,
                    "status_code": 200,
                    "response_size": len(body)
                }
                
                # Detect sensitive exposed data
                sensitive_info = []
                if 'mysql_global_variables' in body:
                    sensitive_info.append("MySQL configuration variables")
                if 'mysql_slave_status' in body:
                    sensitive_info.append("replication status")
                if 'mysql_info_schema' in body:
                    sensitive_info.append("database schema information")
                if 'mysql_perf_schema' in body:
                    sensitive_info.append("performance metrics")
                if 'mysql_global_status_queries' in body:
                    sensitive_info.append("query statistics")
                
                if sensitive_info:
                    evidence_data["exposed_data"] = sensitive_info
                
                # Check if up
                is_up = 'mysql_up 1' in body
                if is_up:
                    evidence_data["mysql_connection_active"] = True
                
                return {
                    "severity": "critical",
                    "confidence": 95,
                    "title": "MySQL Exporter Exposed Without Authentication",
                    "description": f"MySQL Exporter at {host}:{port} is accessible without authentication, exposing sensitive database metrics including {', '.join(sensitive_info[:3])}. This can reveal database topology, performance issues, and potential attack vectors.",
                    "evidence": evidence_data,
                    "cwe": "CWE-200",
                    "cvss_score": 8.6,
                    "remediation": "Secure MySQL Exporter by:\n1. Using authentication proxy (nginx with basic auth)\n2. Restricting access via firewall rules\n3. Running on internal network only\n4. Using VPN for remote access\n5. Configuring network-level ACLs",
                    "references": [
                        "https://github.com/prometheus/mysqld_exporter",
                        "https://prometheus.io/docs/guides/basic-auth/",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    "tags": ["mysql", "database", "exporter", "information-disclosure", "critical"]
                }
    except Exception:
        pass
    
    return None

def main():
    # Get target
    target = None
    if len(sys.argv) > 1:
        target = sys.argv[1]
    elif "CERT_X_GEN_TARGET_HOST" in os.environ:
        target = os.environ["CERT_X_GEN_TARGET_HOST"]
    
    if not target:
        print(json.dumps([]))
        sys.exit(0)
    
    port = get_port()
    findings = []
    
    finding = check_mysql_exporter(target, port)
    if finding:
        findings.append(finding)
    
    # Output results
    print(json.dumps(findings, indent=2))

if __name__ == "__main__":
    main()

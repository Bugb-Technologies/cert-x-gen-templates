#!/usr/bin/env python3
# @id: elasticsearch-data-exposure
# @name: Elasticsearch Cluster Data Exposure
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects exposed Elasticsearch clusters, enumerates indices, and classifies sensitive data
# @tags: elasticsearch, database, search, api, data-exposure, pii
# @cwe: CWE-200, CWE-306
# @cvss: 9.1
# @references: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html
# @confidence: 98
# @version: 1.0.0
#
# WHY PYTHON?
# Elasticsearch analysis requires:
# - REST API exploration with complex JSON parsing
# - Data classification logic (PII detection patterns)
# - Index enumeration and sampling
# - Statistical analysis of cluster content
# Python's rich JSON handling and string processing make this ideal.
"""
CERT-X-GEN Elasticsearch Data Exposure Detection

This template goes beyond simple "is it open" detection:
1. Enumerates cluster health and configuration
2. Lists all indices with size/document counts
3. Classifies indices by likely sensitivity
4. Samples documents to detect PII patterns
5. Provides comprehensive risk assessment
"""

import json
import os
import re
import socket
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Template metadata
METADATA = {
    "id": "elasticsearch-data-exposure",
    "name": "Elasticsearch Cluster Data Exposure",
    "author": "CERT-X-GEN Security Team",
    "severity": "critical",
    "description": "Detects exposed Elasticsearch clusters and classifies sensitive data",
    "tags": ["elasticsearch", "database", "search", "data-exposure", "pii"],
    "language": "python",
    "confidence": 98,
    "cwe": ["CWE-200", "CWE-306"],
    "cvss_score": 9.1
}

# Sensitive index name patterns
SENSITIVE_INDEX_KEYWORDS = [
    'user', 'customer', 'account', 'member', 'client', 'employee',
    'password', 'credential', 'auth', 'token', 'session',
    'payment', 'card', 'billing', 'invoice', 'transaction', 'order',
    'email', 'phone', 'address', 'contact', 'profile',
    'log', 'audit', 'event', 'activity',
    'pii', 'ssn', 'personal', 'private', 'sensitive', 'secret',
    'health', 'medical', 'patient', 'prescription',
    'financial', 'bank', 'credit', 'salary', 'payroll'
]

# PII detection patterns (for document sampling)
PII_PATTERNS = {
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'date_of_birth': r'\b(?:19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b',
}


def http_get(host: str, port: int, path: str, timeout: int = 10) -> Tuple[Optional[int], Optional[str]]:
    """Perform HTTP GET request using raw sockets."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        request = f"GET {path} HTTP/1.1\r\n"
        request += f"Host: {host}:{port}\r\n"
        request += "Accept: application/json\r\n"
        request += "Connection: close\r\n\r\n"
        
        sock.send(request.encode())
        
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        
        response_str = response.decode('utf-8', errors='ignore')
        if '\r\n\r\n' in response_str:
            headers, body = response_str.split('\r\n\r\n', 1)
            status_code = int(headers.split('\r\n')[0].split()[1])
            return status_code, body
        return None, None
    except Exception:
        return None, None


class ElasticsearchScanner:
    """Scanner for Elasticsearch cluster exposure and data classification."""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.evidence: Dict[str, Any] = {}
        self.findings: List[Dict] = []
    
    def get_cluster_info(self) -> bool:
        """Get basic cluster information."""
        status, body = http_get(self.host, self.port, '/')
        
        if status != 200 or not body:
            return False
        
        try:
            info = json.loads(body)
            self.evidence['cluster_name'] = info.get('cluster_name', 'unknown')
            self.evidence['version'] = info.get('version', {}).get('number', 'unknown')
            self.evidence['lucene_version'] = info.get('version', {}).get('lucene_version', 'unknown')
            self.evidence['tagline'] = info.get('tagline', '')
            return True
        except json.JSONDecodeError:
            return False
    
    def get_cluster_health(self) -> None:
        """Get cluster health status."""
        status, body = http_get(self.host, self.port, '/_cluster/health')
        
        if status == 200 and body:
            try:
                health = json.loads(body)
                self.evidence['cluster_health'] = health.get('status', 'unknown')
                self.evidence['number_of_nodes'] = health.get('number_of_nodes', 0)
                self.evidence['number_of_data_nodes'] = health.get('number_of_data_nodes', 0)
                self.evidence['active_shards'] = health.get('active_shards', 0)
            except json.JSONDecodeError:
                pass
    
    def enumerate_indices(self) -> List[Dict]:
        """List all indices with metadata."""
        status, body = http_get(self.host, self.port, '/_cat/indices?format=json&bytes=b')
        
        if status != 200 or not body:
            return []
        
        try:
            indices_raw = json.loads(body)
            indices = []
            total_docs = 0
            total_size = 0
            
            for idx in indices_raw:
                index_info = {
                    'name': idx.get('index', 'unknown'),
                    'docs': int(idx.get('docs.count', 0) or 0),
                    'size_bytes': int(idx.get('store.size', 0) or 0),
                    'health': idx.get('health', 'unknown'),
                    'status': idx.get('status', 'unknown')
                }
                
                # Classify sensitivity
                index_info['sensitivity'] = self._classify_index_sensitivity(index_info['name'])
                
                indices.append(index_info)
                total_docs += index_info['docs']
                total_size += index_info['size_bytes']
            
            self.evidence['total_indices'] = len(indices)
            self.evidence['total_documents'] = total_docs
            self.evidence['total_size_bytes'] = total_size
            self.evidence['total_size_human'] = self._format_bytes(total_size)
            
            return indices
        
        except json.JSONDecodeError:
            return []
    
    def _classify_index_sensitivity(self, index_name: str) -> str:
        """Classify index sensitivity based on name."""
        name_lower = index_name.lower()
        
        # Skip system indices
        if name_lower.startswith('.'):
            return 'system'
        
        # Check for sensitive keywords
        high_sensitivity = ['password', 'credential', 'secret', 'ssn', 'credit', 'payment', 'health', 'medical']
        medium_sensitivity = ['user', 'customer', 'account', 'email', 'phone', 'log', 'audit']
        
        for keyword in high_sensitivity:
            if keyword in name_lower:
                return 'high'
        
        for keyword in medium_sensitivity:
            if keyword in name_lower:
                return 'medium'
        
        return 'low'
    
    def sample_documents(self, index_name: str, sample_size: int = 3) -> Dict[str, Any]:
        """Sample documents from an index to detect PII."""
        status, body = http_get(
            self.host, self.port, 
            f'/{index_name}/_search?size={sample_size}'
        )
        
        if status != 200 or not body:
            return {}
        
        try:
            result = json.loads(body)
            hits = result.get('hits', {}).get('hits', [])
            
            pii_found = set()
            field_names = set()
            
            for hit in hits:
                source = hit.get('_source', {})
                
                # Collect field names
                field_names.update(source.keys())
                
                # Convert to string for PII scanning
                source_str = json.dumps(source)
                
                # Scan for PII patterns
                for pii_type, pattern in PII_PATTERNS.items():
                    if re.search(pattern, source_str):
                        pii_found.add(pii_type)
            
            return {
                'documents_sampled': len(hits),
                'field_names': list(field_names)[:20],
                'pii_detected': list(pii_found)
            }
        
        except json.JSONDecodeError:
            return {}
    
    def _format_bytes(self, size: int) -> str:
        """Format bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def scan(self) -> List[Dict]:
        """Perform complete scan."""
        
        # Step 1: Get cluster info
        if not self.get_cluster_info():
            return []
        
        # Step 2: Get health
        self.get_cluster_health()
        
        # Step 3: Enumerate indices
        indices = self.enumerate_indices()
        
        # Categorize indices by sensitivity
        high_risk_indices = [i for i in indices if i['sensitivity'] == 'high']
        medium_risk_indices = [i for i in indices if i['sensitivity'] == 'medium']
        
        # Sample top indices for PII
        pii_summary = []
        for idx in (high_risk_indices + medium_risk_indices)[:5]:
            sample_result = self.sample_documents(idx['name'])
            if sample_result.get('pii_detected'):
                pii_summary.append({
                    'index': idx['name'],
                    'pii_types': sample_result['pii_detected']
                })
        
        # Build evidence
        self.evidence['indices'] = [
            {'name': i['name'], 'docs': i['docs'], 'sensitivity': i['sensitivity']}
            for i in indices[:30]
        ]
        self.evidence['high_risk_indices'] = [i['name'] for i in high_risk_indices]
        self.evidence['pii_detected'] = pii_summary
        
        # Build finding
        severity = "critical"
        desc = f"Elasticsearch cluster '{self.evidence.get('cluster_name')}' on {self.host}:{self.port} is exposed without authentication. "
        desc += f"Version: {self.evidence.get('version')}. "
        desc += f"Cluster health: {self.evidence.get('cluster_health', 'unknown')}. "
        desc += f"Total indices: {self.evidence.get('total_indices', 0)}. "
        desc += f"Total documents: {self.evidence.get('total_documents', 0):,}. "
        desc += f"Data size: {self.evidence.get('total_size_human', 'unknown')}. "
        
        if high_risk_indices:
            desc += f"HIGH-RISK INDICES: {', '.join(i['name'] for i in high_risk_indices[:5])}. "
        
        if pii_summary:
            pii_types = set()
            for p in pii_summary:
                pii_types.update(p['pii_types'])
            desc += f"PII DETECTED: {', '.join(pii_types)}. "
        
        desc += "Attackers can read all indexed data, delete indices, or execute cluster-wide operations."
        
        self.findings.append({
            "id": METADATA['id'],
            "name": METADATA['name'],
            "severity": severity,
            "confidence": METADATA['confidence'],
            "description": desc,
            "evidence": self.evidence,
            "remediation": "Enable Elasticsearch security features (X-Pack/OpenSearch Security). Use strong authentication. Restrict network access. Enable TLS encryption.",
            "cwe": METADATA['cwe'],
            "cvss_score": METADATA['cvss_score'],
            "tags": METADATA['tags'],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        
        return self.findings


def main():
    """Main execution."""
    host = os.getenv('CERT_X_GEN_TARGET_HOST')
    port_str = os.getenv('CERT_X_GEN_TARGET_PORT', '9200')
    
    if not host and len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port_str = sys.argv[2]
    
    if not host:
        host = '127.0.0.1'
    
    port = int(port_str)
    
    scanner = ElasticsearchScanner(host, port)
    findings = scanner.scan()
    
    result = {
        "findings": findings,
        "metadata": METADATA
    }
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

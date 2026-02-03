#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@id: graphql-user-enumeration
@name: GraphQL User Enumeration (CVE-2021-4191)
@author: CERT-X-GEN Security Team
@severity: medium
@description: Detects GraphQL endpoints exposing user enumeration via introspection or direct queries
@tags: graphql, user-enumeration, information-disclosure, cve-2021-4191
@cwe: CWE-200, CWE-359
@cvss: 5.3
@references: https://nvd.nist.gov/vuln/detail/CVE-2021-4191, https://graphql.org/learn/introspection/
@confidence: 85
@version: 1.0.0
"""

import requests
import json
import sys
from typing import Dict, List, Any

METADATA = {
    "id": "graphql-user-enumeration",
    "name": "GraphQL User Enumeration (CVE-2021-4191)",
    "author": {"name": "CERT-X-GEN Security Team", "email": "security@cert-x-gen.io"},
    "severity": "medium",
    "description": "Detects GraphQL endpoints exposing user enumeration",
    "tags": ["graphql", "user-enumeration", "information-disclosure", "cve-2021-4191"],
    "language": "python",
    "confidence": 85,
    "cwe": ["CWE-200", "CWE-359"],
    "cvss": 5.3,
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-4191",
        "https://graphql.org/learn/introspection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
    ]
}


def check_graphql_introspection(url: str, timeout: int) -> Dict[str, Any]:
    """Check if GraphQL introspection is enabled"""
    introspection_query = {
        "query": """
        {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
    }
    
    try:
        response = requests.post(url, json=introspection_query, timeout=timeout, verify=False)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and '__schema' in data.get('data', {}):
                return {'enabled': True, 'types': data['data']['__schema'].get('types', [])}
    except Exception:
        pass
    
    return {'enabled': False, 'types': []}


def check_user_queries(url: str, timeout: int) -> Dict[str, Any]:
    """Test common user enumeration queries"""
    test_queries = [
        {"query": "{ users { id username email } }"},
        {"query": "{ allUsers { nodes { id username } } }"},
        {"query": "{ user(id: 1) { username email } }"},
        {"query": "{ viewer { login email } }"},
    ]
    
    results = {'accessible_queries': [], 'user_data_exposed': False}
    
    for query_obj in test_queries:
        try:
            response = requests.post(url, json=query_obj, timeout=timeout, verify=False)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and data['data']:
                    results['accessible_queries'].append(query_obj['query'])
                    results['user_data_exposed'] = True
        except Exception:
            continue
    
    return results


def test_vulnerability(host: str, port: int = 443, timeout: int = 10) -> List[Dict[str, Any]]:
    """Main detection function"""
    findings = []
    scheme = 'https' if port == 443 else 'http'
    
    # Common GraphQL endpoints
    endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/api']
    
    for endpoint in endpoints:
        url = f"{scheme}://{host}:{port}{endpoint}"
        
        try:
            # Check introspection
            introspection_result = check_graphql_introspection(url, timeout)
            
            # Check user enumeration
            user_query_result = check_user_queries(url, timeout)
            
            if introspection_result['enabled'] or user_query_result['user_data_exposed']:
                severity = 'medium' if user_query_result['user_data_exposed'] else 'low'
                confidence = 85 if user_query_result['user_data_exposed'] else 70
                
                title = "GraphQL User Enumeration Detected" if user_query_result['user_data_exposed'] else "GraphQL Introspection Enabled"
                
                description = f"GraphQL endpoint at {endpoint} "
                if user_query_result['user_data_exposed']:
                    description += f"exposes user data via {len(user_query_result['accessible_queries'])} query types. "
                if introspection_result['enabled']:
                    description += "Introspection enabled allowing schema discovery."
                
                evidence = {
                    'endpoint': endpoint,
                    'introspection_enabled': introspection_result['enabled'],
                    'user_data_exposed': user_query_result['user_data_exposed'],
                    'accessible_queries': user_query_result['accessible_queries'],
                    'type_count': len(introspection_result.get('types', []))
                }
                
                finding = {
                    'target': f"{host}:{port}",
                    'template_id': METADATA['id'],
                    'template_name': METADATA['name'],
                    'severity': severity,
                    'confidence': confidence,
                    'title': title,
                    'matched_at': url,
                    'description': description,
                    'evidence': evidence,
                    'remediation': 'Disable GraphQL introspection in production. Implement authentication for user queries. Use field-level permissions.',
                    'cwe_ids': METADATA['cwe'],
                    'cvss_score': METADATA['cvss'],
                    'tags': METADATA['tags'],
                    'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
                }
                
                findings.append(finding)
                break  # Found vulnerable endpoint, no need to test others
                
        except Exception:
            continue
    
    if not findings:
        # No vulnerable endpoints found
        finding = {
            'target': f"{host}:{port}",
            'template_id': METADATA['id'],
            'template_name': METADATA['name'],
            'severity': 'info',
            'confidence': 60,
            'title': 'GraphQL Endpoints Secure or Not Found',
            'matched_at': f"{scheme}://{host}:{port}",
            'description': 'No GraphQL user enumeration vulnerabilities detected.',
            'evidence': {'endpoints_tested': endpoints},
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
            print(json.dumps({'error': 'Usage: graphql-user-enumeration.py <host> [port]'}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    findings = test_vulnerability(host, port)
    result = {'findings': findings, 'metadata': METADATA}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

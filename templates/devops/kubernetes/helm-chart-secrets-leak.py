#!/usr/bin/env python3
"""
@id: helm-chart-secrets-leak
@name: Helm Chart Secrets Leak Detection
@author: CERT-X-GEN Security Team
@severity: high
@description: Detects exposed secrets in Helm chart values.yaml files
@tags: kubernetes, helm, secrets, credentials, devops
@cwe: CWE-798, CWE-200
@cvss: 7.5
@references: https://helm.sh/docs/chart_best_practices/values/
@confidence: 90
@version: 1.0.0
"""

import requests
import json
import sys
import re
from typing import List, Dict, Any

METADATA = {
    "id": "helm-chart-secrets-leak",
    "name": "Helm Chart Secrets Leak Detection",
    "author": {"name": "CERT-X-GEN Security Team", "email": "security@cert-x-gen.io"},
    "severity": "high",
    "description": "Detects exposed secrets in Helm values.yaml",
    "tags": ["kubernetes", "helm", "secrets", "credentials", "devops"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-798", "CWE-200"],
    "cvss": 7.5,
    "references": ["https://helm.sh/docs/chart_best_practices/values/"]
}

SECRET_PATTERNS = {
    'password': r'password:\s*["\']?([^\s"\']{8,})["\']?',
    'api_key': r'(?:api[_-]?key|apikey):\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
    'token': r'token:\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
    'secret': r'secret:\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
}


def check_helm_files(base_url: str, timeout: int) -> Dict[str, Any]:
    """Check for exposed Helm chart files"""
    
    helm_paths = [
        'values.yaml',
        'values.yml',
        'chart/values.yaml',
        'helm/values.yaml',
        'charts/values.yaml',
    ]
    
    results = {'exposed_files': [], 'secrets_found': [], 'total_secrets': 0}
    
    for path in helm_paths:
        try:
            url = f"{base_url}/{path}"
            response = requests.get(url, timeout=timeout, verify=False)
            
            if response.status_code == 200:
                content = response.text
                results['exposed_files'].append(path)
                
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        results['secrets_found'].append({
                            'file': path,
                            'type': secret_type,
                            'value_preview': match[:15] + '...' if len(match) > 15 else match
                        })
                        results['total_secrets'] += 1
        except Exception:
            continue
    
    return results


def test_vulnerability(host: str, port: int = 443, timeout: int = 10) -> List[Dict[str, Any]]:
    """Main detection function"""
    findings = []
    scheme = 'https' if port == 443 else 'http'
    base_url = f"{scheme}://{host}:{port}"
    
    try:
        results = check_helm_files(base_url, timeout)
        
        if results['total_secrets'] > 0:
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'high',
                'confidence': 90,
                'title': f"Helm Chart Secrets Exposed ({results['total_secrets']} secrets)",
                'matched_at': base_url,
                'description': f"Found {results['total_secrets']} exposed secrets in Helm chart files.",
                'evidence': {
                    'exposed_files': results['exposed_files'],
                    'secrets_found': results['secrets_found'][:5]
                },
                'remediation': 'Use Kubernetes Secrets or sealed-secrets. Remove hardcoded credentials from values.yaml.',
                'cwe_ids': METADATA['cwe'],
                'cvss_score': METADATA['cvss'],
                'tags': METADATA['tags'],
                'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
            }
        elif results['exposed_files']:
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'medium',
                'confidence': 80,
                'title': 'Helm Chart Files Exposed',
                'matched_at': base_url,
                'description': f"Found {len(results['exposed_files'])} exposed Helm files without obvious secrets.",
                'evidence': {'exposed_files': results['exposed_files']},
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
                'title': 'No Helm Chart Exposure Detected',
                'matched_at': base_url,
                'description': 'No exposed Helm chart files detected.',
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
            'title': 'Helm Chart Detection Failed',
            'matched_at': base_url,
            'description': f'Failed to check Helm charts: {str(e)}',
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
        port = int(os.getenv('CERT_X_GEN_TARGET_PORT', '443'))
        if not host:
            print(json.dumps({'error': 'CERT_X_GEN_TARGET_HOST not set'}))
            sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({'error': 'Usage: helm-chart-secrets-leak.py <host> [port]'}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    findings = test_vulnerability(host, port)
    print(json.dumps({'findings': findings, 'metadata': METADATA}, indent=2))


if __name__ == '__main__':
    main()

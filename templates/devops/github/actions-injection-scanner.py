#!/usr/bin/env python3
"""
@id: actions-injection-scanner
@name: GitHub Actions Injection Scanner
@author: CERT-X-GEN Security Team
@severity: high
@description: Detects script injection vulnerabilities in GitHub Actions workflows
@tags: github-actions, injection, ci-cd, code-execution
@cwe: CWE-94
@cvss: 8.8
@references: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
@confidence: 90
@version: 1.0.0
"""

import requests
import json
import sys
import re
from typing import List, Dict, Any

METADATA = {
    "id": "actions-injection-scanner",
    "name": "GitHub Actions Injection Scanner",
    "author": {"name": "CERT-X-GEN Security Team", "email": "security@cert-x-gen.io"},
    "severity": "high",
    "description": "Detects script injection in GitHub Actions workflows",
    "tags": ["github-actions", "injection", "ci-cd", "code-execution"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-94"],
    "cvss": 8.8,
    "references": [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
        "https://securitylab.github.com/research/github-actions-untrusted-input/"
    ]
}

INJECTION_PATTERNS = [
    r'\$\{\{\s*github\.event\.(issue|pull_request|comment)\.', 
    r'\$\{\{\s*github\.head_ref\s*\}\}',
    r'run:\s*.*\$\{\{',
]


def check_workflow_files(base_url: str, timeout: int) -> Dict[str, Any]:
    """Check GitHub Actions workflow files for injection vulnerabilities"""
    
    workflow_paths = [
        '.github/workflows/ci.yml',
        '.github/workflows/main.yml',
        '.github/workflows/test.yml',
        '.github/workflows/build.yml',
        '.github/workflows/deploy.yml',
    ]
    
    results = {'vulnerable_files': [], 'total_issues': 0}
    
    for path in workflow_paths:
        try:
            url = f"{base_url}/{path}"
            response = requests.get(url, timeout=timeout, verify=False)
            
            if response.status_code == 200:
                content = response.text
                
                for pattern in INJECTION_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        results['vulnerable_files'].append({
                            'file': path,
                            'pattern_matched': pattern,
                            'risk': 'Untrusted input in run command'
                        })
                        results['total_issues'] += 1
        except Exception:
            continue
    
    return results


def test_vulnerability(host: str, port: int = 443, timeout: int = 10) -> List[Dict[str, Any]]:
    """Main detection function"""
    findings = []
    scheme = 'https' if port == 443 else 'http'
    base_url = f"{scheme}://{host}:{port}"
    
    try:
        results = check_workflow_files(base_url, timeout)
        
        if results['total_issues'] > 0:
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'high',
                'confidence': 90,
                'title': f"GitHub Actions Injection Detected ({results['total_issues']} issues)",
                'matched_at': base_url,
                'description': f"Found {results['total_issues']} potential injection vulnerabilities in GitHub Actions workflows.",
                'evidence': {'vulnerable_files': results['vulnerable_files']},
                'remediation': 'Use environment variables for untrusted input. Avoid direct interpolation of github.event data.',
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
                'title': 'No GitHub Actions Injection Detected',
                'matched_at': base_url,
                'description': 'No injection vulnerabilities found in GitHub Actions workflows.',
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
            'title': 'Actions Injection Detection Failed',
            'matched_at': base_url,
            'description': f'Failed to check workflows: {str(e)}',
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
            print(json.dumps({'error': 'Usage: actions-injection-scanner.py <host> [port]'}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    findings = test_vulnerability(host, port)
    print(json.dumps({'findings': findings, 'metadata': METADATA}, indent=2))


if __name__ == '__main__':
    main()

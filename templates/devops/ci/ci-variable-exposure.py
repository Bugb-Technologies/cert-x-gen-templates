#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@id: ci-variable-exposure
@name: CI/CD Variable Exposure Detection
@author: CERT-X-GEN Security Team
@severity: critical
@description: Detects exposed secrets and sensitive variables in CI/CD pipeline configurations
@tags: ci-cd, secrets, credentials, gitlab-ci, github-actions, environment-variables
@cwe: CWE-798, CWE-200
@cvss: 9.1
@references: https://docs.gitlab.com/ee/ci/variables/, https://docs.github.com/en/actions/security-guides/encrypted-secrets
@confidence: 95
@version: 1.0.0
"""

import requests
import json
import sys
import re
from typing import Dict, List, Any

METADATA = {
    "id": "ci-variable-exposure",
    "name": "CI/CD Variable Exposure Detection",
    "author": {"name": "CERT-X-GEN Security Team", "email": "security@cert-x-gen.io"},
    "severity": "critical",
    "description": "Detects exposed secrets in CI/CD configurations",
    "tags": ["ci-cd", "secrets", "credentials", "gitlab-ci", "github-actions", "environment-variables"],
    "language": "python",
    "confidence": 95,
    "cwe": ["CWE-798", "CWE-200"],
    "cvss": 9.1,
    "references": [
        "https://docs.gitlab.com/ee/ci/variables/",
        "https://docs.github.com/en/actions/security-guides/encrypted-secrets",
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
    ]
}

# Patterns for detecting secrets
SECRET_PATTERNS = {
    'api_key': r'(?i)(api[_-]?key|apikey|api[_-]?token)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
    'aws_key': r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret)[\s:=]+["\']?([A-Z0-9]{20,})["\']?',
    'private_key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'password': r'(?i)(password|passwd|pwd)[\s:=]+["\']?([^\s"\']{8,})["\']?',
    'token': r'(?i)(token|bearer|auth)[\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
    'database_url': r'(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)[\s:=]+["\']?([^\s"\']+)["\']?',
    'generic_secret': r'(?i)(secret|credential)[\s:=]+["\']?([a-zA-Z0-9_\-]{16,})["\']?',
}


def check_ci_files(base_url: str, timeout: int) -> Dict[str, Any]:
    """Check for exposed CI/CD configuration files"""
    
    ci_files = [
        '.gitlab-ci.yml',
        '.github/workflows/main.yml',
        '.github/workflows/ci.yml', 
        '.github/workflows/deploy.yml',
        'bitbucket-pipelines.yml',
        '.circleci/config.yml',
        '.travis.yml',
        'azure-pipelines.yml',
        'Jenkinsfile',
    ]
    
    results = {
        'exposed_files': [],
        'secrets_found': [],
        'total_secrets': 0
    }
    
    for ci_file in ci_files:
        try:
            url = f"{base_url}/{ci_file}"
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                content = response.text
                results['exposed_files'].append(ci_file)
                
                # Scan for secrets
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        for match in matches:
                            secret_value = match[1] if isinstance(match, tuple) else match
                            results['secrets_found'].append({
                                'file': ci_file,
                                'type': secret_type,
                                'pattern_matched': True,
                                'line_preview': secret_value[:20] + '...' if len(secret_value) > 20 else secret_value
                            })
                            results['total_secrets'] += 1
        except Exception:
            continue
    
    return results


def check_env_files(base_url: str, timeout: int) -> Dict[str, Any]:
    """Check for exposed environment variable files"""
    
    env_files = [
        '.env',
        '.env.local',
        '.env.production',
        '.env.development',
        'config.yml',
        'config.json',
        'secrets.yml',
    ]
    
    results = {
        'exposed_files': [],
        'secrets_found': [],
        'total_secrets': 0
    }
    
    for env_file in env_files:
        try:
            url = f"{base_url}/{env_file}"
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                content = response.text
                results['exposed_files'].append(env_file)
                
                # Scan for secrets
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        for match in matches:
                            secret_value = match[1] if isinstance(match, tuple) else match
                            results['secrets_found'].append({
                                'file': env_file,
                                'type': secret_type,
                                'pattern_matched': True
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
        # Check CI files
        ci_results = check_ci_files(base_url, timeout)
        
        # Check env files
        env_results = check_env_files(base_url, timeout)
        
        total_secrets = ci_results['total_secrets'] + env_results['total_secrets']
        total_files = len(ci_results['exposed_files']) + len(env_results['exposed_files'])
        
        if total_secrets > 0:
            # Secrets found - CRITICAL
            severity = 'critical'
            confidence = 95
            title = f"CI/CD Secrets Exposure Detected ({total_secrets} secrets in {total_files} files)"
            
            description = f"Found {total_secrets} exposed secrets across {total_files} configuration files. "
            description += f"CI files exposed: {len(ci_results['exposed_files'])}, "
            description += f"Environment files exposed: {len(env_results['exposed_files'])}. "
            description += "This exposes credentials that could lead to system compromise."
            
            all_secrets = ci_results['secrets_found'] + env_results['secrets_found']
            secret_types = list(set([s['type'] for s in all_secrets]))
            
            evidence = {
                'total_secrets_found': total_secrets,
                'total_files_exposed': total_files,
                'ci_files_exposed': ci_results['exposed_files'],
                'env_files_exposed': env_results['exposed_files'],
                'secret_types_found': secret_types,
                'sample_secrets': all_secrets[:5]  # Show first 5 for evidence
            }
            
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': severity,
                'confidence': confidence,
                'title': title,
                'matched_at': base_url,
                'description': description,
                'evidence': evidence,
                'remediation': 'Remove hardcoded secrets from CI files. Use encrypted secrets/variables. Implement secret scanning in CI pipeline. Rotate all exposed credentials immediately.',
                'cwe_ids': METADATA['cwe'],
                'cvss_score': METADATA['cvss'],
                'tags': METADATA['tags'],
                'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
            }
            
        elif total_files > 0:
            # Files exposed but no secrets detected - HIGH
            severity = 'high'
            confidence = 80
            title = f"CI/CD Configuration Files Exposed ({total_files} files)"
            
            description = f"Found {total_files} exposed CI/CD configuration files without obvious secrets. "
            description += "This reveals pipeline structure and may contain sensitive information."
            
            evidence = {
                'total_files_exposed': total_files,
                'ci_files_exposed': ci_results['exposed_files'],
                'env_files_exposed': env_results['exposed_files'],
                'secrets_detected': False
            }
            
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': severity,
                'confidence': confidence,
                'title': title,
                'matched_at': base_url,
                'description': description,
                'evidence': evidence,
                'remediation': 'Restrict access to CI configuration files. Review exposed files for sensitive data.',
                'tags': METADATA['tags'],
                'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
            }
            
        else:
            # No exposure detected - INFO
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'info',
                'confidence': 70,
                'title': 'No CI/CD Configuration Exposure Detected',
                'matched_at': base_url,
                'description': 'No exposed CI/CD configuration files or secrets detected.',
                'evidence': {'files_checked': 16},
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
            'title': 'CI/CD Exposure Detection Failed',
            'matched_at': base_url,
            'description': f'Failed to check for CI/CD exposure: {str(e)}',
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
            print(json.dumps({'error': 'Usage: ci-variable-exposure.py <host> [port]'}))
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

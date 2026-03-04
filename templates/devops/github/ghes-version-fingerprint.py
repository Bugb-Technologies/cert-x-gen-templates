#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@id: ghes-version-fingerprint
@name: GitHub Enterprise Server Version Fingerprint
@author: CERT-X-GEN Security Team
@severity: info
@description: Fingerprints GHES instances to identify exact version for CVE mapping
@tags: github-enterprise, ghes, fingerprint, version-detection, reconnaissance
@cwe: CWE-200
@cvss: 0.0
@references: https://docs.github.com/en/enterprise-server, https://github.com/github/enterprise-releases
@confidence: 90
@version: 1.0.0
"""

import requests
import json
import sys
import re
from urllib.parse import urljoin
from typing import Dict, List, Optional, Any

# Metadata
METADATA = {
    "id": "ghes-version-fingerprint",
    "name": "GitHub Enterprise Server Version Fingerprint",
    "author": {
        "name": "CERT-X-GEN Security Team",
        "email": "security@cert-x-gen.io"
    },
    "severity": "info",
    "description": "Fingerprints GHES instances to identify exact version for CVE mapping",
    "tags": ["github-enterprise", "ghes", "fingerprint", "version-detection", "reconnaissance"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-200"],
    "cvss": 0.0,
    "references": [
        "https://docs.github.com/en/enterprise-server",
        "https://github.com/github/enterprise-releases",
        "https://enterprise.github.com/releases"
    ]
}


class GHESFingerprinter:
    """GitHub Enterprise Server version fingerprinting engine"""
    
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.version_info = {
            'version': None,
            'build': None,
            'detection_methods': []
        }
    
    def fingerprint(self) -> Dict[str, Any]:
        """Run all fingerprinting methods"""
        self._check_meta_endpoint()
        self._check_headers()
        self._check_login_page()
        self._check_setup_page()
        
        return self.version_info
    
    def _check_meta_endpoint(self):
        """Check /api/v3/meta endpoint"""
        try:
            url = urljoin(self.base_url, '/api/v3/meta')
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                data = response.json()
                if 'installed_version' in data:
                    self.version_info['version'] = data['installed_version']
                    self.version_info['detection_methods'].append('api_meta_endpoint')
                    return True
        except Exception:
            pass
        return False
    
    def _check_headers(self):
        """Check HTTP headers for version info"""
        try:
            response = self.session.get(self.base_url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Check for X-GitHub-Enterprise-Version header
            if 'X-GitHub-Enterprise-Version' in response.headers:
                version = response.headers['X-GitHub-Enterprise-Version']
                if not self.version_info['version']:
                    self.version_info['version'] = version
                    self.version_info['detection_methods'].append('http_header')
                return True
                
        except Exception:
            pass
        return False
    
    def _check_login_page(self):
        """Parse login page for version in footer/meta"""
        try:
            url = urljoin(self.base_url, '/login')
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                html = response.text
                
                # Look for version patterns
                patterns = [
                    r'GitHub Enterprise Server ([\d.]+)',
                    r'enterprise/([\d.]+)',
                    r'data-version="([^"]+)"',
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        if not self.version_info['version']:
                            self.version_info['version'] = version
                            self.version_info['detection_methods'].append('login_page')
                        return True
        except Exception:
            pass
        return False
    
    def _check_setup_page(self):
        """Check /setup endpoint (first-time setup)"""
        try:
            url = urljoin(self.base_url, '/setup/start')
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                html = response.text
                
                match = re.search(r'GitHub Enterprise ([\d.]+)', html)
                if match:
                    version = match.group(1)
                    if not self.version_info['version']:
                        self.version_info['version'] = version
                        self.version_info['detection_methods'].append('setup_page')
                    return True
        except Exception:
            pass
        return False


def test_vulnerability(host: str, port: int = 443, timeout: int = 10) -> List[Dict[str, Any]]:
    """Main detection function"""
    findings = []
    
    scheme = 'https' if port == 443 else 'http'
    base_url = f"{scheme}://{host}:{port}"
    
    fingerprinter = GHESFingerprinter(base_url, timeout)
    
    try:
        version_info = fingerprinter.fingerprint()
        
        if version_info['version']:
            title = f"GHES Version Detected: {version_info['version']}"
            description = f"GitHub Enterprise Server identified with version {version_info['version']}. "
            description += f"Detection methods: {', '.join(version_info['detection_methods'])}"
            
            evidence = {
                'version': version_info['version'],
                'build': version_info['build'],
                'detection_methods': version_info['detection_methods'],
                'base_url': base_url
            }
            
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'info',
                'confidence': 90,
                'title': title,
                'matched_at': base_url,
                'description': description,
                'evidence': evidence,
                'tags': METADATA['tags'],
                'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
            }
            
        else:
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'info',
                'confidence': 50,
                'title': 'GHES Instance Detected (Version Unknown)',
                'matched_at': base_url,
                'description': 'GitHub Enterprise Server detected but version could not be determined.',
                'evidence': {
                    'version': None,
                    'detection_methods_attempted': ['api_meta', 'http_header', 'login_page', 'setup_page'],
                    'base_url': base_url
                },
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
            'title': 'GHES Version Detection Failed',
            'matched_at': base_url,
            'description': f'Failed to fingerprint GHES instance: {str(e)}',
            'evidence': {
                'error': str(e),
                'base_url': base_url
            },
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
            print(json.dumps({'error': 'Usage: ghes-version-fingerprint.py <host> [port]'}))
            sys.exit(1)
        
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    findings = test_vulnerability(host, port, timeout=10)
    
    result = {
        'findings': findings,
        'metadata': METADATA
    }
    
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

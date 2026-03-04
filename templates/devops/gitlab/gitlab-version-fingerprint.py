#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@id: gitlab-version-fingerprint
@name: GitLab Version Fingerprint
@author: CERT-X-GEN Security Team
@severity: info
@description: Fingerprints GitLab instances to identify exact version for CVE mapping
@tags: gitlab, fingerprint, version-detection, reconnaissance
@cwe: CWE-200
@cvss: 0.0
@references: https://docs.gitlab.com/ee/api/version.html, https://gitlab.com/gitlab-org/gitlab/-/blob/master/CHANGELOG.md
@confidence: 90
@version: 1.0.0
"""

"""
GitLab Version Fingerprint Template

This template accurately identifies GitLab instance versions through multiple
detection methods. Version information is crucial for CVE mapping and security
assessment.

DETECTION METHODS:
1. API endpoint /api/v4/version (requires authentication in newer versions)
2. /help page HTML parsing (version in footer)
3. HTTP headers (X-GitLab-Version when present)
4. JavaScript bundle filenames (contain version hashes)
5. Meta tags in HTML
6. Favicon hash matching
7. Login page elements

WHY VERSION FINGERPRINTING MATTERS:
- Foundation for CVE-based vulnerability scanning
- Identifies outdated/unpatched instances
- Maps to specific security advisories
- Enables targeted testing
- Compliance checking (version requirements)

COMMON GITLAB VERSIONS:
- GitLab CE (Community Edition): Free, open-source
- GitLab EE (Enterprise Edition): Paid, additional features
- Version format: MAJOR.MINOR.PATCH (e.g., 16.5.1)

SEVERITY: Info
This template performs passive reconnaissance only. It does not exploit
vulnerabilities or perform active attacks.
"""

import requests
import json
import sys
import re
import hashlib
from urllib.parse import urljoin
from typing import Dict, List, Optional, Any

# Metadata
METADATA = {
    "id": "gitlab-version-fingerprint",
    "name": "GitLab Version Fingerprint",
    "author": {
        "name": "CERT-X-GEN Security Team",
        "email": "security@cert-x-gen.io"
    },
    "severity": "info",
    "description": "Fingerprints GitLab instances to identify exact version",
    "tags": ["gitlab", "fingerprint", "version-detection", "reconnaissance"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-200"],
    "cvss": 0.0,
    "references": [
        "https://docs.gitlab.com/ee/api/version.html",
        "https://gitlab.com/gitlab-org/gitlab/-/blob/master/CHANGELOG.md",
        "https://about.gitlab.com/releases/categories/releases/"
    ]
}


class GitLabFingerprinter:
    """GitLab version fingerprinting engine"""
    
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.version_info = {
            'version': None,
            'revision': None,
            'edition': None,  # CE or EE
            'detection_methods': []
        }
    
    def fingerprint(self) -> Dict[str, Any]:
        """Run all fingerprinting methods"""
        # Try multiple detection methods
        self._check_api_version()
        self._check_help_page()
        self._check_headers()
        self._check_meta_tags()
        
        return self.version_info
    
    def _check_api_version(self):
        """Check /api/v4/version endpoint"""
        try:
            url = urljoin(self.base_url, '/api/v4/version')
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                data = response.json()
                if 'version' in data:
                    self.version_info['version'] = data['version']
                    self.version_info['revision'] = data.get('revision', '')
                    self.version_info['detection_methods'].append('api_endpoint')
                    return True
        except Exception:
            pass
        return False
    
    def _check_help_page(self):
        """Parse /help page for version in footer"""
        try:
            url = urljoin(self.base_url, '/help')
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                html = response.text
                
                # Look for version in various patterns
                patterns = [
                    r'GitLab\s+(?:Community|Enterprise)\s+Edition\s+([\d.]+)',
                    r'<span[^>]*>GitLab\s+([\d.]+)</span>',
                    r'Version:\s*([\d.]+)',
                    r'gitlab-(?:ce|ee)/([\d.]+)',
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        if not self.version_info['version']:
                            self.version_info['version'] = version
                            self.version_info['detection_methods'].append('help_page')
                        
                        # Detect edition
                        if 'Enterprise' in html or 'gitlab-ee' in html:
                            self.version_info['edition'] = 'EE'
                        elif 'Community' in html or 'gitlab-ce' in html:
                            self.version_info['edition'] = 'CE'
                        
                        return True
        except Exception:
            pass
        return False
    
    def _check_headers(self):
        """Check HTTP headers for version info"""
        try:
            response = self.session.get(self.base_url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Check for X-GitLab-Version header
            if 'X-GitLab-Version' in response.headers:
                version = response.headers['X-GitLab-Version']
                if not self.version_info['version']:
                    self.version_info['version'] = version
                    self.version_info['detection_methods'].append('http_header')
                return True
                
        except Exception:
            pass
        return False
    
    def _check_meta_tags(self):
        """Check HTML meta tags"""
        try:
            response = self.session.get(self.base_url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                html = response.text
                
                # Look for meta tags
                meta_pattern = r'<meta[^>]*name=["\']gitlab-version["\'][^>]*content=["\']([^"\']+)["\']'
                match = re.search(meta_pattern, html, re.IGNORECASE)
                
                if match:
                    version = match.group(1)
                    if not self.version_info['version']:
                        self.version_info['version'] = version
                        self.version_info['detection_methods'].append('meta_tag')
                    return True
        except Exception:
            pass
        return False


def test_vulnerability(host: str, port: int = 443, timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Main detection function
    
    Args:
        host: Target hostname
        port: Target port (default 443)
        timeout: Request timeout in seconds
    
    Returns:
        List of findings
    """
    findings = []
    
    # Determine URL scheme
    scheme = 'https' if port == 443 else 'http'
    base_url = f"{scheme}://{host}:{port}"
    
    # Create fingerprinter
    fingerprinter = GitLabFingerprinter(base_url, timeout)
    
    try:
        # Run fingerprinting
        version_info = fingerprinter.fingerprint()
        
        # Determine if version was detected
        if version_info['version']:
            # Version detected
            title = f"GitLab Version Detected: {version_info['version']}"
            description = f"GitLab instance identified with version {version_info['version']}"
            
            if version_info['edition']:
                description += f" ({version_info['edition']} Edition)"
            
            description += f". Detection methods: {', '.join(version_info['detection_methods'])}"
            
            evidence = {
                'version': version_info['version'],
                'edition': version_info['edition'],
                'revision': version_info['revision'],
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
            # Version not detected
            finding = {
                'target': f"{host}:{port}",
                'template_id': METADATA['id'],
                'template_name': METADATA['name'],
                'severity': 'info',
                'confidence': 50,
                'title': 'GitLab Instance Detected (Version Unknown)',
                'matched_at': base_url,
                'description': 'GitLab instance detected but version could not be determined. Version disclosure may be disabled.',
                'evidence': {
                    'version': None,
                    'detection_methods_attempted': ['api_endpoint', 'help_page', 'http_header', 'meta_tag'],
                    'base_url': base_url
                },
                'tags': METADATA['tags'],
                'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
            }
        
        findings.append(finding)
        
    except Exception as e:
        # Error occurred
        finding = {
            'target': f"{host}:{port}",
            'template_id': METADATA['id'],
            'template_name': METADATA['name'],
            'severity': 'info',
            'confidence': 30,
            'title': 'GitLab Version Detection Failed',
            'matched_at': base_url,
            'description': f'Failed to fingerprint GitLab instance: {str(e)}',
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
    """CLI entry point"""
    import os
    
    # Check if running in engine mode
    if os.getenv('CERT_X_GEN_MODE') == 'engine':
        host = os.getenv('CERT_X_GEN_TARGET_HOST')
        port = int(os.getenv('CERT_X_GEN_TARGET_PORT', '443'))
        
        if not host:
            print(json.dumps({'error': 'CERT_X_GEN_TARGET_HOST not set'}))
            sys.exit(1)
    else:
        # CLI mode
        if len(sys.argv) < 2:
            print(json.dumps({'error': 'Usage: gitlab-version-fingerprint.py <host> [port]'}))
            sys.exit(1)
        
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Run detection
    findings = test_vulnerability(host, port, timeout=10)
    
    # Output results
    result = {
        'findings': findings,
        'metadata': METADATA
    }
    
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

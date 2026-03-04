#!/usr/bin/env python3
"""
Template: SAML SSO Bypass GitLab
Purpose: Detects GitLab SAML authentication bypass vulnerability
Severity: HIGH
CVE: CVE-2024-4985 (CVSS 10.0 - Critical)
CWE: CWE-287 (Improper Authentication)

Description:
Detects GitLab instances vulnerable to CVE-2024-4985, where attackers can
bypass SAML SSO authentication and gain unauthorized access with admin privileges.
This affects GitLab CE/EE versions 16.9.0 to 16.9.6, 16.10.0 to 16.10.5,
16.11.0 to 16.11.2, 17.0.0 to 17.0.1.

Vulnerability Details:
- SAML authentication bypass in GitLab
- Allows unauthorized admin access
- Affects SAML-enabled instances
- Critical impact on authentication flow

Detection Method:
- Fingerprints GitLab version via multiple methods
- Checks version against vulnerable ranges
- Detects SAML SSO configuration
- Non-invasive version-based detection

Author: CERT-X-GEN Team
Date: 2026-02-02
"""

import sys
import json
import re
import requests
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime
from packaging import version

class SAMLSSOBypassGitLab:
    def __init__(self, target: str, port: int = 443):
        """Initialize scanner with target."""
        self.target = target.rstrip('/')
        self.port = port
        self.base_url = f"https://{target}" if not target.startswith('http') else target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CERT-X-GEN Security Scanner/1.0'
        })
        self.timeout = 10
        
        # Vulnerable version ranges for CVE-2024-4985
        self.vulnerable_ranges = [
            ('16.9.0', '16.9.6'),
            ('16.10.0', '16.10.5'),
            ('16.11.0', '16.11.2'),
            ('17.0.0', '17.0.1')
        ]
    
    def scan(self) -> Dict[str, Any]:
        """Main scanning logic."""
        result = {
            "template": "saml-sso-bypass-gitlab",
            "target": self.target,
            "port": self.port,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "findings": [],
            "metadata": {
                "gitlab_detected": False,
                "version": None,
                "vulnerable": False,
                "saml_enabled": None
            }
        }
        
        try:
            # Step 1: Detect if target is GitLab
            is_gitlab, detected_version = self._detect_gitlab()
            result["metadata"]["gitlab_detected"] = is_gitlab
            result["metadata"]["version"] = detected_version
            
            if not is_gitlab:
                result["findings"].append({
                    "severity": "info",
                    "confidence": 100,
                    "title": "Not a GitLab Instance",
                    "description": f"Target {self.target} is not a GitLab instance",
                    "remediation": "This scanner is designed for GitLab instances only"
                })
                return result
            
            # Step 2: Check if version is vulnerable
            if detected_version:
                is_vulnerable = self._check_vulnerable_version(detected_version)
                result["metadata"]["vulnerable"] = is_vulnerable
                
                # Step 3: Check if SAML is enabled (optional)
                saml_enabled = self._check_saml_enabled()
                result["metadata"]["saml_enabled"] = saml_enabled
                
                if is_vulnerable:
                    severity = "critical" if saml_enabled else "high"
                    confidence = 95 if saml_enabled else 85
                    
                    description = (
                        f"GitLab version {detected_version} is vulnerable to CVE-2024-4985 "
                        f"(SAML SSO authentication bypass). "
                    )
                    
                    if saml_enabled:
                        description += (
                            f"SAML authentication is ENABLED on this instance, making it "
                            f"actively vulnerable. Attackers can bypass SAML SSO and gain "
                            f"unauthorized admin access. CVSS Score: 10.0 (Critical)"
                        )
                    else:
                        description += (
                            f"SAML status could not be determined. If SAML is enabled, "
                            f"this instance is critically vulnerable to authentication bypass."
                        )
                    
                    result["findings"].append({
                        "severity": severity,
                        "confidence": confidence,
                        "title": "GitLab SAML SSO Authentication Bypass (CVE-2024-4985)",
                        "description": description,
                        "cwe": "CWE-287",
                        "cve": "CVE-2024-4985",
                        "remediation": (
                            f"Immediately upgrade GitLab to:\n"
                            f"- Version 17.0.2 or later (for 17.0.x)\n"
                            f"- Version 16.11.3 or later (for 16.11.x)\n"
                            f"- Version 16.10.6 or later (for 16.10.x)\n"
                            f"- Version 16.9.7 or later (for 16.9.x)\n\n"
                            f"Additional steps:\n"
                            f"1. Review SAML configuration for unauthorized access\n"
                            f"2. Audit user accounts for suspicious admin privileges\n"
                            f"3. Check authentication logs for bypass attempts"
                        ),
                        "references": [
                            "https://about.gitlab.com/releases/2024/05/30/patch-release-gitlab-17-0-2-released/",
                            "https://nvd.nist.gov/vuln/detail/CVE-2024-4985",
                            "https://gitlab.com/gitlab-org/gitlab/-/issues/458742"
                        ]
                    })
                else:
                    result["findings"].append({
                        "severity": "info",
                        "confidence": 90,
                        "title": "GitLab Version Not Vulnerable",
                        "description": f"GitLab version {detected_version} is not vulnerable to CVE-2024-4985",
                        "remediation": "Continue following GitLab security best practices"
                    })
            else:
                result["findings"].append({
                    "severity": "info",
                    "confidence": 60,
                    "title": "GitLab Detected - Version Unknown",
                    "description": "GitLab instance detected but version could not be determined",
                    "remediation": "Manually verify GitLab version against CVE-2024-4985 vulnerable ranges"
                })
        
        except Exception as e:
            result["findings"].append({
                "severity": "info",
                "confidence": 50,
                "title": "Scan Error",
                "description": f"Error during scan: {str(e)}",
                "remediation": "Check target accessibility and permissions"
            })
        
        return result
    
    def _detect_gitlab(self) -> Tuple[bool, Optional[str]]:
        """Detect if target is GitLab and attempt to get version."""
        
        # Method 1: Check /api/v4/version endpoint
        try:
            response = self.session.get(
                f"{self.base_url}/api/v4/version",
                timeout=self.timeout,
                verify=False
            )
            if response.status_code == 200:
                data = response.json()
                if 'version' in data:
                    return True, data['version']
        except:
            pass
        
        # Method 2: Check headers for X-GitLab-Feature-Category
        try:
            response = self.session.get(
                f"{self.base_url}",
                timeout=self.timeout,
                verify=False
            )
            if 'X-GitLab-Feature-Category' in response.headers:
                # Try to extract version from meta tags
                version_match = re.search(r'content="GitLab Community Edition (\d+\.\d+\.\d+)"', response.text)
                if not version_match:
                    version_match = re.search(r'content="GitLab Enterprise Edition (\d+\.\d+\.\d+)"', response.text)
                if not version_match:
                    version_match = re.search(r'"version":"(\d+\.\d+\.\d+)"', response.text)
                
                if version_match:
                    return True, version_match.group(1)
                return True, None
        except:
            pass
        
        # Method 3: Check for GitLab-specific paths
        gitlab_paths = [
            '/users/sign_in',
            '/explore',
            '/help'
        ]
        
        for path in gitlab_paths:
            try:
                response = self.session.get(
                    f"{self.base_url}{path}",
                    timeout=self.timeout,
                    verify=False
                )
                if 'gitlab' in response.text.lower():
                    # Try version from HTML
                    version_match = re.search(r'GitLab.*?(\d+\.\d+\.\d+)', response.text)
                    if version_match:
                        return True, version_match.group(1)
                    return True, None
            except:
                continue
        
        return False, None
    
    def _check_vulnerable_version(self, detected_version: str) -> bool:
        """Check if detected version is in vulnerable ranges."""
        try:
            current_version = version.parse(detected_version)
            
            for min_ver, max_ver in self.vulnerable_ranges:
                min_version = version.parse(min_ver)
                max_version = version.parse(max_ver)
                
                if min_version <= current_version <= max_version:
                    return True
            
            return False
        except:
            return False
    
    def _check_saml_enabled(self) -> Optional[bool]:
        """
        Check if SAML authentication is enabled.
        Non-invasive detection.
        """
        try:
            # Check sign-in page for SAML provider
            response = self.session.get(
                f"{self.base_url}/users/sign_in",
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                # Look for SAML-related elements
                if any(indicator in response.text.lower() for indicator in [
                    'saml',
                    'single sign-on',
                    'sso',
                    'oauth_saml'
                ]):
                    return True
                return False
            
            return None
        except:
            return None

def main():
    """Main entry point for template."""
    if len(sys.argv) != 3:
        print("Usage: saml-sso-bypass-gitlab.py <target> <port>", file=sys.stderr)
        sys.exit(1)
    
    target = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Error: Port must be an integer", file=sys.stderr)
        sys.exit(1)
    
    scanner = SAMLSSOBypassGitLab(target, port)
    result = scanner.scan()
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# @id: ghes-version-fingerprint
# @name: GitHub Enterprise Server Version Fingerprint
# @severity: info
# @description: Identifies GitHub Enterprise Server version for CVE mapping and vulnerability assessment
# @tags: github,ghes,github-enterprise,version,fingerprint,recon,informational
# @cwe: CWE-200
# @author: BugB Technologies
# @reference: https://docs.github.com/en/enterprise-server/rest/meta/meta

import os
import sys
import json
import socket
import ssl
import re
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime

def get_target():
    """Extract target host and port from environment variables"""
    host = os.environ.get('CERT_X_GEN_TARGET_HOST')
    port = os.environ.get('CERT_X_GEN_TARGET_PORT', '80')
    
    if not host:
        return None, None
    
    return host, int(port)

def create_ssl_context():
    """Create SSL context that doesn't verify certificates"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def check_meta_endpoint(base_url, timeout=5):
    """Check GHES version via /api/v3/meta endpoint"""
    try:
        api_url = f"{base_url}/api/v3/meta"
        req = Request(api_url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        req.add_header('Accept', 'application/vnd.github+json')
        
        ctx = create_ssl_context()
        with urlopen(req, timeout=timeout, context=ctx) as response:
            data = json.loads(response.read().decode('utf-8'))
            installed_version = data.get('installed_version')
            if installed_version:
                return installed_version, 'meta_api'
    except (HTTPError, URLError, json.JSONDecodeError, socket.timeout):
        pass
    
    return None, None

def check_headers(base_url, timeout=5):
    """Check GHES version from HTTP response headers"""
    try:
        # Try multiple endpoints that are likely to return the header
        endpoints = ['/api/v3/', '/api/v3/zen', '/']
        ctx = create_ssl_context()
        
        for endpoint in endpoints:
            try:
                req = Request(f"{base_url}{endpoint}")
                req.add_header('User-Agent', 'Mozilla/5.0')
                
                with urlopen(req, timeout=timeout, context=ctx) as response:
                    headers = response.info()
                    
                    # Check X-GitHub-Enterprise-Version header
                    if 'X-GitHub-Enterprise-Version' in headers:
                        version_header = headers['X-GitHub-Enterprise-Version']
                        # Extract version from format: enterprise-server@3.10.0
                        version_match = re.search(r'enterprise-server@([0-9.]+)', version_header)
                        if version_match:
                            return version_match.group(1), 'header'
                        return version_header, 'header'
                    
            except (HTTPError, URLError, socket.timeout):
                continue
                    
    except Exception:
        pass
    
    return None, None

def check_html_indicators(base_url, timeout=5):
    """Check for GHES indicators in HTML content"""
    try:
        req = Request(f"{base_url}/login")
        req.add_header('User-Agent', 'Mozilla/5.0')
        ctx = create_ssl_context()
        
        with urlopen(req, timeout=timeout, context=ctx) as response:
            html = response.read().decode('utf-8', errors='ignore')
            
            # Look for GHES-specific patterns in HTML
            ghes_patterns = [
                r'<meta\s+name=["\']?github-keyboard-shortcuts-preference-cookie-name["\']?',
                r'data-github-version=["\']([^"\']+)["\']',
                r'window\.github_version\s*=\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in ghes_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match and len(match.groups()) > 0:
                    return match.group(1), 'html'
                elif match:
                    # Pattern matched but didn't capture version - at least we know it's GHES
                    return "unknown", 'html_indicator'
                    
    except (HTTPError, URLError, socket.timeout):
        pass
    
    return None, None

def detect_ghes_version(host, port):
    """
    Main detection logic for GHES version fingerprinting
    Returns: (version_string, detection_method, protocol) or (None, None, None)
    """
    # Try both HTTP and HTTPS
    protocols = ['https', 'http'] if port in [443, 8443, 9443] else ['http', 'https']
    
    for protocol in protocols:
        base_url = f"{protocol}://{host}:{port}"
        
        # Method 1: /api/v3/meta endpoint (most reliable)
        version, method = check_meta_endpoint(base_url)
        if version:
            return version, method, protocol
        
        # Method 2: HTTP headers
        version, method = check_headers(base_url)
        if version:
            return version, method, protocol
        
        # Method 3: HTML indicators
        version, method = check_html_indicators(base_url)
        if version:
            return version, method, protocol
    
    return None, None, None

def main():
    """Main execution function"""
    findings = []
    
    # Get target from environment
    host, port = get_target()
    
    if not host:
        print(json.dumps({"findings": []}))
        return
    
    # Detect GHES version
    version, method, protocol = detect_ghes_version(host, port)
    
    if version:
        finding = {
            "template_id": "ghes-version-fingerprint",
            "template_name": "GitHub Enterprise Server Version Fingerprint",
            "id": "ghes-version-fingerprint",
            "severity": "info",
            "name": "GitHub Enterprise Server Version Detected",
            "host": host,
            "port": port,
            "protocol": protocol,
            "version": version,
            "detection_method": method,
            "matched_at": datetime.utcnow().isoformat() + "Z",
            "description": f"GitHub Enterprise Server version {version} detected via {method}",
            "recommendation": "Ensure GHES is updated to the latest version to avoid known vulnerabilities. Check GitHub's security advisories for version-specific vulnerabilities."
        }
        findings.append(finding)
    
    # Output JSON
    print(json.dumps({"findings": findings}, indent=2))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Graceful error handling - return empty findings
        print(json.dumps({"findings": []}))
        sys.exit(0)

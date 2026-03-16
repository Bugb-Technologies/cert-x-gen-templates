#!/usr/bin/env python3
# @id: gitlab-version-fingerprint
# @name: GitLab Version Fingerprint
# @severity: info
# @description: Identifies GitLab version for CVE mapping and vulnerability assessment
# @tags: gitlab,version,fingerprint,recon,informational
# @author: BugB Technologies
# @reference: https://docs.gitlab.com/ee/api/version.html

import os
import sys
import json
import socket
import re
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

def get_target():
    """Extract target host and port from environment variables"""
    host = os.environ.get('CERT_X_GEN_TARGET_HOST')
    port = os.environ.get('CERT_X_GEN_TARGET_PORT', '80')
    
    if not host:
        return None, None
    
    return host, int(port)

def check_version_api(base_url, timeout=5):
    """Check GitLab version via API endpoint"""
    try:
        api_url = f"{base_url}/api/v4/version"
        req = Request(api_url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        with urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get('version'), 'api'
    except (HTTPError, URLError, json.JSONDecodeError, socket.timeout):
        return None, None

def check_headers(base_url, timeout=5):
    """Check GitLab version from HTTP headers"""
    try:
        req = Request(base_url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        with urlopen(req, timeout=timeout) as response:
            headers = response.info()
            
            # Check X-GitLab-Version header
            if 'X-GitLab-Version' in headers:
                return headers['X-GitLab-Version'], 'header'
            
            # Check Server header for GitLab
            server = headers.get('Server', '')
            if 'gitlab' in server.lower():
                # Try to extract version from Server header
                version_match = re.search(r'(\d+\.\d+\.\d+)', server)
                if version_match:
                    return version_match.group(1), 'header'
                    
    except (HTTPError, URLError, socket.timeout):
        pass
    
    return None, None

def check_html_meta(base_url, timeout=5):
    """Check GitLab version from HTML meta tags"""
    try:
        req = Request(f"{base_url}/users/sign_in")
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        with urlopen(req, timeout=timeout) as response:
            html = response.read().decode('utf-8', errors='ignore')
            
            # Look for meta tags with version info
            meta_patterns = [
                r'<meta\s+name=["\']?version["\']?\s+content=["\']?([^"\']+)["\']?',
                r'data-version=["\']?([^"\']+)["\']?',
                r'gitlab-version["\']:\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in meta_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    return match.group(1), 'html'
            
            # Look for version in JavaScript files references
            js_match = re.search(r'gitlab\.(?:[\w-]+\.)?js\?v=(\d+\.\d+\.\d+)', html)
            if js_match:
                return js_match.group(1), 'html'
                
    except (HTTPError, URLError, socket.timeout):
        pass
    
    return None, None

def detect_gitlab_version(host, port):
    """
    Main detection logic for GitLab version fingerprinting
    Returns: (version_string, detection_method) or (None, None)
    """
    # Try both HTTP and HTTPS
    protocols = ['https', 'http'] if port in [443, 8443, 9443] else ['http', 'https']
    
    for protocol in protocols:
        base_url = f"{protocol}://{host}:{port}"
        
        # Method 1: API endpoint (most reliable)
        version, method = check_version_api(base_url)
        if version:
            return version, method, protocol
        
        # Method 2: HTTP headers
        version, method = check_headers(base_url)
        if version:
            return version, method, protocol
        
        # Method 3: HTML meta tags
        version, method = check_html_meta(base_url)
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
    
    # Detect GitLab version
    version, method, protocol = detect_gitlab_version(host, port)
    
    if version:
        finding = {
            "id": "gitlab-version-fingerprint",
            "severity": "info",
            "name": "GitLab Version Detected",
            "host": host,
            "port": port,
            "protocol": protocol,
            "version": version,
            "detection_method": method,
            "description": f"GitLab version {version} detected via {method}",
            "recommendation": "Ensure GitLab is updated to the latest version to avoid known vulnerabilities"
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

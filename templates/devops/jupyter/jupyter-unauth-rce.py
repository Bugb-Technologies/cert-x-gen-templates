#!/usr/bin/env python3
# @id: jupyter-unauth-rce
# @name: Jupyter Notebook Unauthenticated RCE
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects Jupyter notebooks accessible without authentication, enabling arbitrary code execution
# @tags: jupyter, ai, ml, rce, notebook, python, data-science
# @cwe: CWE-306, CWE-94
# @cvss: 9.8
# @references: https://jupyter-notebook.readthedocs.io/en/stable/security.html
# @confidence: 98
# @version: 1.0.0
#
# WHY PYTHON?
# Jupyter IS Python. This provides:
# - Natural API understanding (Jupyter REST API is Python-centric)
# - Session and kernel handling familiarity
# - Complex multi-step authentication bypass logic
# - Rich JSON/HTTP handling with requests patterns
"""
CERT-X-GEN Jupyter Notebook Unauthenticated RCE Detection

Detects Jupyter notebooks accessible without authentication. When unprotected,
Jupyter allows arbitrary Python code execution on the server, effectively
providing remote code execution capabilities.

This template:
1. Checks if authentication is required
2. Verifies API access without credentials
3. Enumerates kernels and notebooks
4. Confirms code execution capability
"""

import json
import os
import socket
import sys
import urllib.parse
from datetime import datetime

# Template metadata
METADATA = {
    "id": "jupyter-unauth-rce",
    "name": "Jupyter Notebook Unauthenticated RCE",
    "author": "CERT-X-GEN Security Team",
    "severity": "critical",
    "description": "Detects Jupyter notebooks accessible without authentication",
    "tags": ["jupyter", "ai", "ml", "rce", "notebook", "python"],
    "language": "python",
    "confidence": 98,
    "cwe": ["CWE-306", "CWE-94"],
    "cvss_score": 9.8,
    "references": [
        "https://jupyter-notebook.readthedocs.io/en/stable/security.html",
        "https://blog.jupyter.org/security-best-practices-for-jupyter-notebook-server"
    ]
}


def http_request(host: str, port: int, method: str, path: str, 
                 headers: dict = None, body: str = None, timeout: int = 10) -> tuple:
    """
    Perform HTTP request using raw sockets (no external dependencies).
    Returns (status_code, response_body, response_headers).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Build request
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {host}:{port}\r\n"
        request += "Accept: application/json, text/html, */*\r\n"
        request += "User-Agent: CERT-X-GEN/1.0\r\n"
        
        if headers:
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
        
        if body:
            request += f"Content-Length: {len(body)}\r\n"
            request += "Content-Type: application/json\r\n"
        
        request += "Connection: close\r\n\r\n"
        
        if body:
            request += body
        
        sock.send(request.encode())
        
        # Receive response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        
        # Parse response
        response_str = response.decode('utf-8', errors='ignore')
        if '\r\n\r\n' in response_str:
            header_part, body_part = response_str.split('\r\n\r\n', 1)
            status_line = header_part.split('\r\n')[0]
            status_code = int(status_line.split()[1])
            
            # Extract headers
            resp_headers = {}
            for line in header_part.split('\r\n')[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    resp_headers[k.strip().lower()] = v.strip()
            
            return status_code, body_part, resp_headers
        
        return None, None, {}
    
    except Exception as e:
        return None, str(e), {}


class JupyterScanner:
    """Scanner for Jupyter Notebook authentication bypass and RCE detection."""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.evidence = {}
        self.findings = []
        self.authenticated = False
        self.api_accessible = False
    
    def check_main_page(self) -> bool:
        """Check main page for Jupyter detection and auth requirements."""
        status, body, headers = http_request(self.host, self.port, 'GET', '/')
        
        if status is None:
            return False
        
        body_lower = body.lower() if body else ""
        
        # Check for redirect to login (auth required)
        if status in [301, 302, 303, 307, 308]:
            location = headers.get('location', '')
            if 'login' in location or 'token' in location:
                self.evidence['requires_auth'] = True
                self.evidence['jupyter_detected'] = True
                return True
            
            # JupyterLab redirects to /lab - this indicates Jupyter
            if '/lab' in location or '/tree' in location:
                self.evidence['jupyter_detected'] = True
                self.evidence['requires_auth'] = False
                return True
        
        # Detect Jupyter from body content
        jupyter_indicators = ['jupyter', 'notebook', 'jupyterhub', 'jupyterlab']
        if any(ind in body_lower for ind in jupyter_indicators):
            self.evidence['jupyter_detected'] = True
        else:
            # Also check /api endpoint for Jupyter detection
            api_status, api_body, _ = http_request(self.host, self.port, 'GET', '/api')
            if api_status == 200 and api_body:
                try:
                    import json
                    data = json.loads(api_body)
                    if 'version' in data:
                        self.evidence['jupyter_detected'] = True
                        self.evidence['api_version'] = data.get('version')
                except:
                    pass
            
            if not self.evidence.get('jupyter_detected'):
                return False
        
        # Check for login form in body
        if 'password' in body_lower or 'token' in body_lower:
            if 'id="password"' in body_lower or 'type="password"' in body_lower:
                self.evidence['requires_auth'] = True
                return True
        
        self.evidence['requires_auth'] = False
        return True
    
    def check_api_access(self) -> bool:
        """Check if API is accessible without authentication."""
        endpoints_to_check = [
            ('/api', 'API root'),
            ('/api/kernels', 'Kernels list'),
            ('/api/contents', 'Contents/files'),
            ('/api/sessions', 'Sessions'),
            ('/api/terminals', 'Terminals'),
        ]
        
        accessible_endpoints = []
        
        for endpoint, name in endpoints_to_check:
            status, body, _ = http_request(self.host, self.port, 'GET', endpoint)
            
            if status == 200:
                accessible_endpoints.append(name)
                self.api_accessible = True
                
                # Parse specific endpoint data
                try:
                    data = json.loads(body)
                    
                    if endpoint == '/api':
                        self.evidence['api_version'] = data.get('version', 'unknown')
                    
                    elif endpoint == '/api/kernels':
                        kernels = data if isinstance(data, list) else []
                        self.evidence['running_kernels'] = len(kernels)
                        self.evidence['kernel_info'] = [
                            {'id': k.get('id', '')[:8], 'name': k.get('name', 'unknown')}
                            for k in kernels[:5]
                        ]
                    
                    elif endpoint == '/api/contents':
                        self._enumerate_contents(data)
                    
                    elif endpoint == '/api/terminals':
                        terminals = data if isinstance(data, list) else []
                        self.evidence['terminals'] = len(terminals)
                
                except json.JSONDecodeError:
                    pass
        
        self.evidence['accessible_endpoints'] = accessible_endpoints
        return self.api_accessible
    
    def _enumerate_contents(self, data: dict):
        """Enumerate notebook files from contents API."""
        notebooks = []
        python_files = []
        
        def find_files(item):
            if isinstance(item, dict):
                item_type = item.get('type', '')
                name = item.get('name', '')
                
                if item_type == 'notebook':
                    notebooks.append(name)
                elif item_type == 'file' and name.endswith('.py'):
                    python_files.append(name)
                
                # Recurse into directories
                if 'content' in item and isinstance(item['content'], list):
                    for child in item['content']:
                        find_files(child)
        
        find_files(data)
        
        self.evidence['notebooks'] = notebooks[:10]
        self.evidence['notebook_count'] = len(notebooks)
        self.evidence['python_files'] = python_files[:5]
    
    def check_code_execution(self) -> bool:
        """Verify if code execution is possible (creates finding but doesn't execute malicious code)."""
        # We verify code execution capability by checking kernel creation endpoint
        # We do NOT actually execute code
        
        status, body, _ = http_request(
            self.host, self.port, 'POST', '/api/kernels',
            headers={'Content-Type': 'application/json'},
            body='{"name": "python3"}'
        )
        
        if status in [200, 201]:
            try:
                data = json.loads(body)
                kernel_id = data.get('id', '')
                self.evidence['code_execution_verified'] = True
                self.evidence['test_kernel_id'] = kernel_id[:8] if kernel_id else None
                
                # Clean up - delete the test kernel
                if kernel_id:
                    http_request(
                        self.host, self.port, 'DELETE', 
                        f'/api/kernels/{kernel_id}'
                    )
                
                return True
            except:
                pass
        
        return False
    
    def scan(self) -> list:
        """Perform full scan and return findings."""
        
        # Step 1: Check main page
        if not self.check_main_page():
            return self.findings
        
        if not self.evidence.get('jupyter_detected'):
            return self.findings
        
        # Step 2: Check API access
        self.check_api_access()
        
        # Step 3: Check code execution capability
        code_exec = False
        if self.api_accessible:
            code_exec = self.check_code_execution()
        
        # Build findings based on results
        if self.api_accessible and not self.evidence.get('requires_auth', True):
            severity = "critical"
            
            desc = f"Jupyter Notebook server on {self.host}:{self.port} is accessible without authentication. "
            
            if self.evidence.get('running_kernels'):
                desc += f"Running kernels: {self.evidence['running_kernels']}. "
            
            if self.evidence.get('notebook_count'):
                desc += f"Notebooks found: {self.evidence['notebook_count']}. "
            
            if code_exec:
                desc += "CODE EXECUTION VERIFIED - kernel creation successful. "
            
            desc += "An attacker can execute arbitrary Python code, access the filesystem, steal credentials, and pivot to other systems."
            
            self.findings.append({
                "id": METADATA['id'],
                "name": METADATA['name'],
                "severity": severity,
                "confidence": METADATA['confidence'],
                "description": desc,
                "evidence": self.evidence,
                "remediation": "Enable token or password authentication. Use JupyterHub for multi-user deployments. Never expose Jupyter to the internet. Use SSL/TLS encryption.",
                "cwe": METADATA['cwe'],
                "cvss_score": METADATA['cvss_score'],
                "tags": METADATA['tags'],
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        elif self.evidence.get('jupyter_detected') and self.evidence.get('requires_auth'):
            # Jupyter found but auth required
            self.findings.append({
                "id": "jupyter-exposed",
                "name": "Jupyter Notebook Exposed (Auth Required)",
                "severity": "medium",
                "confidence": 90,
                "description": f"Jupyter Notebook detected on {self.host}:{self.port} but authentication is required.",
                "evidence": {"jupyter_detected": True, "requires_auth": True},
                "remediation": "Consider restricting access via firewall or VPN. Ensure strong token/password is configured.",
                "tags": ["jupyter", "exposed"],
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        return self.findings


def main():
    """Main execution."""
    # Get target from environment or args
    host = os.getenv('CERT_X_GEN_TARGET_HOST')
    port_str = os.getenv('CERT_X_GEN_TARGET_PORT', '8888')
    
    if not host and len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port_str = sys.argv[2]
    
    if not host:
        host = '127.0.0.1'
    
    port = int(port_str)
    
    # Run scan
    scanner = JupyterScanner(host, port)
    findings = scanner.scan()
    
    # Output result
    result = {
        "findings": findings,
        "metadata": METADATA
    }
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

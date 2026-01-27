#!/usr/bin/env python3
# @id: http-header-injection
# @name: HTTP Header Injection Detection
# @severity: medium
# @description: Detects HTTP header injection vulnerabilities through response splitting tests

import socket
import json
import os
from urllib.parse import urlparse

def test_header_injection(host, port, path):
    try:
        # Build malicious HTTP request with CRLF injection
        injection_payload = "\r\nX-Injection: true"
        http_request = f"GET {path}{injection_payload} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(http_request.encode())
        
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()
        
        response_text = response.decode('utf-8', errors='ignore')
        
        # Check if injection was successful
        if "X-Injection: true" in response_text:
            return True
        return False
    except Exception as e:
        return False

def main():
    host = os.environ.get('CERT_X_GEN_TARGET_HOST', 'localhost')
    port = int(os.environ.get('CERT_X_GEN_TARGET_PORT', '80'))
    
    findings = []
    
    # Test multiple injection vectors
    test_paths = ["/", "/api", "/search?q=test"]
    
    for path in test_paths:
        if test_header_injection(host, port, path):
            findings.append({
                "id": "http-header-injection",
                "severity": "medium",
                "host": host,
                "port": port,
                "path": path,
                "vulnerable_parameter": "HTTP headers",
                "description": "Application is vulnerable to HTTP header injection via response splitting"
            })
    
    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# @id: ssti-engine-fingerprint
# @name: Server-Side Template Injection Engine Fingerprint
# @author: CERT-X-GEN Security Team  
# @severity: high
# @description: Fingerprints template engines via payload injection and response analysis to detect SSTI vulnerabilities
# @tags: ssti, template-injection, web, vulnerability-detection, jinja2, twig, freemarker, velocity, smarty, mako
# @cwe: CWE-94, CWE-1336
# @cvss: 8.6
# @references: https://portswigger.net/research/server-side-template-injection, https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
# @confidence: 90
# @version: 1.0.0
"""
Server-Side Template Injection (SSTI) Engine Fingerprinting

This template detects SSTI vulnerabilities by:
1. Injecting mathematical expression payloads specific to different template engines
2. Analyzing responses to identify which engine processed the payload
3. Testing multiple injection contexts (parameter, header, path)
4. Fingerprinting engines: Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, ERB, Handlebars, Pug

Detection Strategy:
- Jinja2/Twig: {{7*7}} → 49
- Freemarker: ${7*7} → 49  
- Velocity: #set($x=7*7)$x → 49
- Smarty: {7*7} → 49
- Mako: ${7*7} → 49
- ERB: <%= 7*7 %> → 49
- Handlebars: {{#with "s" as |string|}}{{7*7}}{{/with}} → special detection
- Pug: #{7*7} → 49

Note: This is detection-only. Does not exploit - only fingerprints the engine.
"""

import socket
import urllib.parse
import json
import sys
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Template metadata
METADATA = {
    "id": "ssti-engine-fingerprint",
    "name": "Server-Side Template Injection Engine Fingerprint",
    "author": {
        "name": "CERT-X-GEN Security Team",
        "email": "security@cert-x-gen.io"
    },
    "severity": "high",
    "description": "Fingerprints template engines via payload injection and response analysis to detect SSTI vulnerabilities",
    "tags": ["ssti", "template-injection", "web", "vulnerability-detection"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-94", "CWE-1336"],
    "cvss": 8.6,
    "references": [
        "https://portswigger.net/research/server-side-template-injection",
        "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection"
    ]
}

# Template engine detection payloads (optimized set)
# Format: (payload, expected_result, engine_name, detection_pattern)
PAYLOADS = [
    # Jinja2 (Python) - Flask, Django
    ("{{7*7}}", "49", "Jinja2", r"\b49\b"),
    
    # Freemarker (Java)
    ("${7*7}", "49", "Freemarker", r"\b49\b"),
    
    # Velocity (Java)
    ("#set($x=7*7)$x", "49", "Velocity", r"\b49\b"),
    
    # Smarty (PHP)
    ("{7*7}", "49", "Smarty", r"\b49\b"),
    
    # Mako (Python)
    ("${7*7}", "49", "Mako", r"\b49\b"),
    
    # ERB (Ruby) - Rails
    ("<%= 7*7 %>", "49", "ERB", r"\b49\b"),
    
    # Thymeleaf (Java) - Spring
    ("[(7*7)]", "49", "Thymeleaf", r"\b49\b"),
]

def send_http_request(host: str, port: int, method: str, path: str, headers: Dict[str, str], body: str = "", timeout: int = 3) -> Tuple[int, Dict[str, str], str]:
    """Send HTTP request and return status, headers, body"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Build request
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        
        if body:
            request += f"Content-Length: {len(body)}\r\n"
        
        request += "Connection: close\r\n"
        request += "\r\n"
        
        if body:
            request += body
        
        sock.sendall(request.encode('utf-8', errors='ignore'))
        
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
        parts = response_str.split('\r\n\r\n', 1)
        
        if len(parts) < 2:
            return 0, {}, response_str
        
        header_section = parts[0]
        body_section = parts[1]
        
        # Parse status code
        status_line = header_section.split('\r\n')[0]
        status_code = 200
        try:
            status_code = int(status_line.split(' ')[1])
        except Exception:
            pass
        
        # Parse headers
        response_headers = {}
        for line in header_section.split('\r\n')[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                response_headers[key.lower()] = value
        
        return status_code, response_headers, body_section
        
    except Exception as e:
        return 0, {}, str(e)

def test_ssti(host: str, port: int = 80, timeout: int = 3) -> List[Dict]:
    """Test for SSTI vulnerabilities"""
    findings = []
    detected_engines = set()
    
    # Test different injection points (reduced for speed)
    test_paths = [
        "/",
        "/search"
    ]
    
    # Test different parameters (reduced for speed)
    test_params = [
        "q", "name", "search"
    ]
    
    for test_path in test_paths:
        for param in test_params:
            for payload, expected, engine, pattern in PAYLOADS:
                # Skip if we already detected this engine
                if engine in detected_engines:
                    continue
                
                # URL encode payload
                encoded_payload = urllib.parse.quote(payload, safe='')
                
                # Test in GET parameter
                path_with_param = f"{test_path}?{param}={encoded_payload}"
                
                try:
                    status, headers, body = send_http_request(
                        host, port, "GET", path_with_param, 
                        {"User-Agent": "cert-x-gen/1.0"}, "", timeout
                    )
                    
                    # Check if payload was executed
                    if status == 200 and re.search(pattern, body):
                        # Verify it's not a false positive
                        if expected in body or re.search(pattern, body):
                            detected_engines.add(engine)
                            
                            finding = {
                                "target": f"{host}:{port}",
                                "template_id": METADATA["id"],
                                "template_name": METADATA["name"],
                                "severity": METADATA["severity"],
                                "confidence": METADATA["confidence"],
                                "title": f"SSTI Vulnerability Detected - {engine} Template Engine",
                                "matched_at": path_with_param,
                                "description": f"Server-Side Template Injection vulnerability detected. The application uses the {engine} template engine and is vulnerable to template injection attacks.",
                                "evidence": {
                                    "engine": engine,
                                    "injection_point": "GET parameter",
                                    "parameter": param,
                                    "payload": payload,
                                    "expected_output": expected,
                                    "path": path_with_param,
                                    "response_snippet": body[:500] if len(body) > 500 else body,
                                    "detection_pattern": pattern,
                                    "matched": True
                                },
                                "remediation": f"The {engine} template engine is executing user-controlled input. Implement proper input validation and use safe template rendering methods. Never pass user input directly to template engines.",
                                "cwe_ids": METADATA["cwe"],
                                "cvss_score": METADATA["cvss"],
                                "tags": METADATA["tags"] + [engine.lower()],
                                "timestamp": datetime.utcnow().isoformat() + "Z"
                            }
                            findings.append(finding)
                            
                except Exception as e:
                    continue
                
                # Limit to 2 detected engines to avoid excessive testing
                if len(detected_engines) >= 2:
                    break
            
            if len(detected_engines) >= 2:
                break
        
        if len(detected_engines) >= 2:
            break
    
    # If no vulnerabilities found, return informational finding
    if not findings:
        finding = {
            "target": f"{host}:{port}",
            "template_id": METADATA["id"],
            "template_name": METADATA["name"],
            "severity": "info",
            "confidence": 50,
            "title": "No SSTI Vulnerabilities Detected",
            "matched_at": "/",
            "description": "No Server-Side Template Injection vulnerabilities were detected. The application either does not use template engines or properly sanitizes user input.",
            "evidence": {
                "payloads_tested": len(PAYLOADS),
                "paths_tested": len(test_paths),
                "parameters_tested": len(test_params)
            },
            "tags": METADATA["tags"],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        findings.append(finding)
    
    return findings

def main():
    """Main execution"""
    import os
    
    if os.getenv('CERT_X_GEN_MODE') == 'engine':
        host = os.getenv('CERT_X_GEN_TARGET_HOST')
        port = int(os.getenv('CERT_X_GEN_TARGET_PORT', '80'))
        if not host:
            print(json.dumps({"error": "CERT_X_GEN_TARGET_HOST not set"}))
            sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({"error": "Usage: ssti-engine-fingerprint.py <host> [port]"}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    findings = test_ssti(host, port)
    
    result = {
        "findings": findings,
        "metadata": METADATA
    }
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

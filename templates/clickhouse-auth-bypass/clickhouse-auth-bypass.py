#!/usr/bin/env python3
# @id: clickhouse-auth-bypass
# @name: ClickHouse Authentication Bypass
# @severity: high
# @description: Detects ClickHouse HTTP interface exposed without authentication, allowing unauthorized database access
# @tags: clickhouse,database,authentication,bypass,http,misconfiguration,unauthorized-access
# @cwe: CWE-306
# @author: BugB Technologies
# @reference: https://clickhouse.com/docs/interfaces/http, https://clickhouse.com/docs/guides/sre/user-management/users-and-roles

import os
import sys
import json
import socket
import ssl
import re
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime

def get_target():
    """Extract target host and port from environment variables"""
    host = os.environ.get('CERT_X_GEN_TARGET_HOST')
    port = os.environ.get('CERT_X_GEN_TARGET_PORT', '8123')
    
    if not host:
        return None, None
    
    return host, int(port)

def create_ssl_context():
    """Create SSL context that doesn't verify certificates"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def test_unauthenticated_query(base_url, query, timeout=5):
    """
    Test if query executes without authentication
    Returns: (success, status_code, response_data, headers)
    """
    try:
        # URL encode the query
        encoded_query = quote(query)
        test_url = f"{base_url}/?query={encoded_query}"
        
        req = Request(test_url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        req.add_header('Accept', '*/*')
        
        ctx = create_ssl_context()
        with urlopen(req, timeout=timeout, context=ctx) as response:
            status_code = response.getcode()
            headers = dict(response.info())
            response_data = response.read().decode('utf-8', errors='ignore')
            
            # Check for successful query execution
            if status_code == 200 and response_data:
                return True, status_code, response_data, headers
            
    except HTTPError as e:
        # Capture error details
        status_code = e.code
        headers = dict(e.headers) if hasattr(e, 'headers') else {}
        response_data = e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else str(e)
        
        # Check for authentication errors (indicates security is enabled)
        if status_code == 401:
            return False, status_code, response_data, headers
        elif status_code == 516 or 'Authentication failed' in response_data:
            return False, status_code, response_data, headers
            
    except (URLError, socket.timeout, Exception):
        pass
    
    return False, None, None, {}

def detect_clickhouse_service(base_url, timeout=5):
    """
    Detect if ClickHouse HTTP interface is present
    Returns: (is_clickhouse, version, server_name)
    """
    try:
        # Ping endpoint
        req = Request(f"{base_url}/ping")
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        ctx = create_ssl_context()
        with urlopen(req, timeout=timeout, context=ctx) as response:
            headers = dict(response.info())
            response_data = response.read().decode('utf-8', errors='ignore')
            
            # Check for ClickHouse indicators
            server_header = headers.get('Server', '')
            display_name = headers.get('X-ClickHouse-Server-Display-Name', '')
            
            if 'ClickHouse' in server_header or 'X-ClickHouse' in str(headers) or response_data.strip() == 'Ok.':
                # Extract version from headers
                summary = headers.get('X-ClickHouse-Summary', '')
                version = "unknown"
                
                # Try to get version from server header
                version_match = re.search(r'ClickHouse/([0-9.]+)', server_header)
                if version_match:
                    version = version_match.group(1)
                
                return True, version, display_name or "ClickHouse"
                
    except (HTTPError, URLError, socket.timeout):
        pass
    
    return False, None, None

def test_data_access(base_url, timeout=5):
    """
    Test if we can access system tables (more conclusive proof of bypass)
    Returns: (success, table_count, error_message)
    """
    try:
        # Query system.tables to enumerate accessible tables
        query = "SELECT count() FROM system.tables"
        encoded_query = quote(query)
        test_url = f"{base_url}/?query={encoded_query}"
        
        req = Request(test_url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        ctx = create_ssl_context()
        with urlopen(req, timeout=timeout, context=ctx) as response:
            if response.getcode() == 200:
                data = response.read().decode('utf-8', errors='ignore')
                try:
                    table_count = int(data.strip())
                    return True, table_count, None
                except ValueError:
                    return True, 0, None
                    
    except HTTPError as e:
        error_msg = e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else str(e)
        return False, 0, error_msg
    except Exception:
        pass
    
    return False, 0, None

def detect_auth_bypass(host, port):
    """
    Main detection logic for ClickHouse authentication bypass
    Returns: finding dictionary or None
    """
    # Try both HTTP and HTTPS
    protocols = ['https', 'http'] if port in [443, 8443, 9443] else ['http', 'https']
    
    for protocol in protocols:
        base_url = f"{protocol}://{host}:{port}"
        
        # Step 1: Detect ClickHouse service
        is_clickhouse, version, server_name = detect_clickhouse_service(base_url)
        
        if not is_clickhouse:
            continue
        
        # Step 2: Test basic query without authentication
        query_test = test_unauthenticated_query(base_url, "SELECT 1")
        success, status_code, response_data, headers = query_test
        
        if not success:
            # Authentication is enabled - not vulnerable
            continue
        
        # Step 3: Test system table access (confirms full data access)
        data_access, table_count, error_msg = test_data_access(base_url)
        
        # Build finding
        evidence = {
            "url": base_url,
            "protocol": protocol,
            "clickhouse_version": version,
            "server_name": server_name,
            "test_query": "SELECT 1",
            "test_response": response_data[:200] if response_data else None,
            "status_code": status_code,
            "headers": {k: v for k, v in headers.items() if 'ClickHouse' in k or k == 'Server'},
            "system_table_access": data_access,
            "accessible_tables": table_count if data_access else 0
        }
        
        severity = "high" if data_access else "medium"
        
        description = (
            f"ClickHouse HTTP interface on {host}:{port} allows unauthenticated access. "
            f"Queries execute without credentials, exposing database operations. "
        )
        
        if data_access:
            description += f"System tables accessible - {table_count} tables enumerated."
        else:
            description += "Basic queries execute but system table access not confirmed."
        
        recommendation = """
1. Configure authentication for the default user in /etc/clickhouse-server/users.xml
2. Set a strong password: <password>your_secure_password</password>
3. Restrict network access: <networks><ip>::1</ip><ip>127.0.0.1/8</ip></networks>
4. Consider using X.509 certificate authentication for production
5. Enable SSL/TLS on port 8443 and disable insecure port 8123
6. Review ClickHouse security best practices: https://clickhouse.com/docs/guides/sre/user-management/
"""
        
        finding = {
            "template_id": "clickhouse-auth-bypass",
            "template_name": "ClickHouse Authentication Bypass",
            "id": "clickhouse-auth-bypass",
            "severity": severity,
            "name": "ClickHouse HTTP Interface Authentication Bypass",
            "host": host,
            "port": port,
            "protocol": protocol,
            "matched_at": datetime.utcnow().isoformat() + "Z",
            "description": description,
            "evidence": evidence,
            "cwe": "CWE-306",
            "cvss_score": 8.6 if data_access else 7.5,
            "recommendation": recommendation,
            "references": [
                "https://clickhouse.com/docs/interfaces/http",
                "https://clickhouse.com/docs/guides/sre/user-management/users-and-roles",
                "https://clickhouse.com/docs/operations/security"
            ]
        }
        
        return finding
    
    return None

def main():
    """Main execution function"""
    findings = []
    
    # Get target from environment
    host, port = get_target()
    
    if not host:
        print(json.dumps({"findings": []}))
        return
    
    # Detect authentication bypass
    finding = detect_auth_bypass(host, port)
    
    if finding:
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

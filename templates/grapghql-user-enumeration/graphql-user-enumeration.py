#!/usr/bin/env python3
# @id: graphql-user-enumeration
# @name: GraphQL User Enumeration Detection
# @severity: critical
# @description: Detects unauthenticated user enumeration in GraphQL endpoints (CVE-2021-4191). Tests for exposed user queries that return PII without authentication.
# @tags: graphql,user-enumeration,cve-2021-4191,authentication-bypass,information-disclosure,pii
# @cwe: CWE-200,CWE-359,CWE-863
# @author: BugB Technologies
# @cvss: 7.5
# @reference: https://nvd.nist.gov/vuln/detail/CVE-2021-4191,https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/

import os
import sys
import json
import socket
import ssl
import re
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

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

def test_graphql_endpoint(url: str, timeout: int = 10) -> Tuple[bool, Optional[Dict]]:
    """
    Test if a URL is a valid GraphQL endpoint
    Returns: (is_graphql, response_data)
    """
    # Simple introspection query to test GraphQL
    test_query = {
        "query": "{ __typename }"
    }
    
    try:
        req = Request(url, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        data = json.dumps(test_query).encode('utf-8')
        
        # Only use SSL context for HTTPS
        if url.startswith('https'):
            ctx = create_ssl_context()
            response = urlopen(req, data=data, timeout=timeout, context=ctx)
        else:
            response = urlopen(req, data=data, timeout=timeout)
        
        with response as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            
            # Valid GraphQL response should have 'data' field
            if 'data' in resp_data or 'errors' in resp_data:
                return True, resp_data
                
    except (HTTPError, URLError, json.JSONDecodeError, socket.timeout, Exception):
        pass
    
    return False, None

def get_introspection_schema(url: str, timeout: int = 15) -> Optional[Dict]:
    """
    Retrieve GraphQL schema via introspection query
    """
    introspection_query = {
        "query": """
        {
          __schema {
            queryType {
              name
              fields {
                name
                description
                type {
                  name
                  kind
                  ofType {
                    name
                    kind
                  }
                }
                args {
                  name
                  type {
                    name
                    kind
                  }
                }
              }
            }
          }
        }
        """
    }
    
    try:
        req = Request(url, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        data = json.dumps(introspection_query).encode('utf-8')
        
        # Only use SSL context for HTTPS
        if url.startswith('https'):
            ctx = create_ssl_context()
            response = urlopen(req, data=data, timeout=timeout, context=ctx)
        else:
            response = urlopen(req, data=data, timeout=timeout)
        
        with response as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            
            
            if 'data' in resp_data and '__schema' in resp_data['data']:
                return resp_data['data']['__schema']
                
    except (HTTPError, URLError, json.JSONDecodeError, socket.timeout, Exception) as e:
        pass
    
    return None

def find_user_queries(schema: Dict) -> List[Dict[str, Any]]:
    """
    Identify user-related queries from GraphQL schema
    """
    user_keywords = ['user', 'member', 'account', 'profile', 'person', 'people', 'customer']
    list_indicators = ['all', 'list', 'get', 'find', 'search', 'query']
    
    user_queries = []
    
    if not schema or 'queryType' not in schema:
        return user_queries
    
    query_type = schema['queryType']
    if not query_type or 'fields' not in query_type:
        return user_queries
    
    fields = query_type['fields'] or []
    
    for field in fields:
        field_name = field.get('name', '').lower()
        field_desc = (field.get('description') or '').lower()
        
        # Check if field name contains user-related keywords
        is_user_related = any(keyword in field_name for keyword in user_keywords)
        is_list_query = any(indicator in field_name for indicator in list_indicators)
        
        # Check return type for list/array
        field_type = field.get('type', {})
        is_list_type = field_type.get('kind') == 'LIST'
        
        # Also check nested ofType for LIST
        if not is_list_type and field_type.get('ofType'):
            is_list_type = field_type['ofType'].get('kind') == 'LIST'
        
        if is_user_related and (is_list_query or is_list_type):
            user_queries.append({
                'name': field.get('name'),
                'description': field.get('description'),
                'args': field.get('args', []),
                'type': field_type
            })
    
    return user_queries

def test_user_enumeration(url: str, query_name: str, timeout: int = 15) -> Tuple[bool, Optional[Dict], Optional[List]]:
    """
    Test if a user query returns unauthenticated data
    Returns: (vulnerable, response_data, user_data)
    """
    # Build GraphQL query - request common fields only
    # Using minimal fields to avoid field errors
    test_query = {
        "query": f"{{ {query_name} {{ id username email firstName lastName }} }}"
    }
    
    
    try:
        req = Request(url, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'Mozilla/5.0')
        # Explicitly NO authentication headers
        
        data = json.dumps(test_query).encode('utf-8')
        
        # Only use SSL context for HTTPS
        if url.startswith('https'):
            ctx = create_ssl_context()
            response = urlopen(req, data=data, timeout=timeout, context=ctx)
        else:
            response = urlopen(req, data=data, timeout=timeout)
        
        with response as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            
            
            # Check if we got user data back
            if 'data' in resp_data and resp_data['data']:
                query_result = resp_data['data'].get(query_name)
                
                
                if query_result and isinstance(query_result, list) and len(query_result) > 0:
                    # Successfully enumerated users!
                    return True, resp_data, query_result
                elif query_result and isinstance(query_result, dict):
                    # Single user returned (still concerning)
                    return True, resp_data, [query_result]
            
            # Check for authentication errors (expected behavior)
            if 'errors' in resp_data:
                errors = resp_data['errors']
                error_messages = [err.get('message', '').lower() for err in errors]
                
                # If errors mention auth, that's good (not vulnerable)
                auth_keywords = ['unauthorized', 'unauthenticated', 'forbidden', 'permission', 'auth']
                if any(any(keyword in msg for keyword in auth_keywords) for msg in error_messages):
                    return False, resp_data, None
            
    except (HTTPError, URLError, json.JSONDecodeError, socket.timeout, Exception) as e:
        pass
    
    return False, None, None

def analyze_user_data(users: List[Dict]) -> Dict[str, Any]:
    """
    Analyze the exposed user data to determine PII exposure level
    """
    pii_fields = {
        'high_risk': ['email', 'phone', 'phoneNumber', 'ssn', 'socialSecurityNumber', 'dateOfBirth'],
        'medium_risk': ['firstName', 'lastName', 'name', 'fullName', 'address'],
        'low_risk': ['username', 'login', 'id', 'userId']
    }
    
    exposed_fields = set()
    sample_user = users[0] if users else {}
    
    for field in sample_user.keys():
        exposed_fields.add(field)
    
    # Determine risk level
    high_risk_exposed = any(field in exposed_fields for field in pii_fields['high_risk'])
    medium_risk_exposed = any(field in exposed_fields for field in pii_fields['medium_risk'])
    
    if high_risk_exposed:
        risk_level = 'critical'
    elif medium_risk_exposed:
        risk_level = 'high'
    else:
        risk_level = 'medium'
    
    return {
        'total_users': len(users),
        'exposed_fields': list(exposed_fields),
        'risk_level': risk_level,
        'sample_user': sample_user
    }

def detect_graphql_user_enumeration(host: str, port: int) -> List[Dict[str, Any]]:
    """
    Main detection logic for GraphQL user enumeration
    """
    findings = []
    
    # Determine protocol
    protocol = 'https' if port in [443, 8443, 9443] else 'http'
    base_url = f"{protocol}://{host}:{port}"
    
    # Debug output
    
    # Common GraphQL endpoint paths
    graphql_paths = [
        '/graphql',
        '/api/graphql',
        '/v1/graphql',
        '/query',
        '/api',
        '/api/v1/graphql',
        '/graphql/v1',
        '/gql'
    ]
    
    for path in graphql_paths:
        url = urljoin(base_url, path)
        
        
        # Step 1: Verify it's a GraphQL endpoint
        is_graphql, _ = test_graphql_endpoint(url)
        
        
        if not is_graphql:
            continue
        
        
        # Step 2: Get schema via introspection
        schema = get_introspection_schema(url)
        
        
        if not schema:
            # GraphQL exists but introspection disabled
            finding = {
                "template_id": "graphql-user-enumeration",
                "template_name": "GraphQL User Enumeration Detection",
                "id": f"graphql-introspection-disabled-{host}-{port}-{path.replace('/', '_')}",
                "severity": "info",
                "name": "GraphQL Endpoint Detected (Introspection Disabled)",
                "host": host,
                "port": port,
                "protocol": protocol,
                "path": path,
                "url": url,
                "matched_at": datetime.utcnow().isoformat() + "Z",
                "description": f"GraphQL endpoint found at {url} but introspection is disabled. Cannot automatically test for user enumeration.",
                "recommendation": "Manually test this GraphQL endpoint for user enumeration vulnerabilities. Introspection being disabled is a security best practice."
            }
            findings.append(finding)
            continue
        
        # Step 3: Find user-related queries
        user_queries = find_user_queries(schema)
        
        
        if not user_queries:
            # No obvious user queries found
            finding = {
                "template_id": "graphql-user-enumeration",
                "template_name": "GraphQL User Enumeration Detection",
                "id": f"graphql-no-user-queries-{host}-{port}-{path.replace('/', '_')}",
                "severity": "info",
                "name": "GraphQL Endpoint Detected (No User Queries Found)",
                "host": host,
                "port": port,
                "protocol": protocol,
                "path": path,
                "url": url,
                "matched_at": datetime.utcnow().isoformat() + "Z",
                "description": f"GraphQL endpoint found at {url}. Introspection enabled but no obvious user enumeration queries detected in schema.",
                "recommendation": "Review the GraphQL schema manually for any queries that might expose user data. Consider disabling introspection in production."
            }
            findings.append(finding)
            continue
        
        # Step 4: Test each user query for unauthenticated access
        for query in user_queries:
            query_name = query['name']
            vulnerable, response, user_data = test_user_enumeration(url, query_name)
            
            
            if vulnerable and user_data:
                # VULNERABILITY CONFIRMED
                analysis = analyze_user_data(user_data)
                
                finding = {
                    "template_id": "graphql-user-enumeration",
                    "template_name": "GraphQL User Enumeration Detection",
                    "id": f"graphql-user-enum-{host}-{port}-{path.replace('/', '_')}-{query_name}",
                    "severity": analysis['risk_level'],
                    "name": f"Unauthenticated User Enumeration via GraphQL ({query_name})",
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "path": path,
                    "url": url,
                    "query_name": query_name,
                    "matched_at": datetime.utcnow().isoformat() + "Z",
                    "cve": "CVE-2021-4191",
                    "description": f"GraphQL query '{query_name}' at {url} returns {analysis['total_users']} user record(s) without authentication. Exposed fields: {', '.join(analysis['exposed_fields'])}",
                    "evidence": {
                        "total_users_exposed": analysis['total_users'],
                        "exposed_fields": analysis['exposed_fields'],
                        "sample_user": analysis['sample_user'],
                        "query_tested": query_name
                    },
                    "recommendation": f"""
1. Implement authentication and authorization checks on the '{query_name}' GraphQL query
2. Ensure all user queries require valid authentication tokens
3. Apply field-level authorization to restrict PII access
4. Disable GraphQL introspection in production environments
5. Implement rate limiting on GraphQL endpoints
6. Log and monitor all GraphQL user enumeration attempts
                    """,
                    "references": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-4191",
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
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
    
    # Detect GraphQL user enumeration
    findings = detect_graphql_user_enumeration(host, port)
    
    # Output JSON
    print(json.dumps({"findings": findings}, indent=2))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Graceful error handling - return empty findings
        print(json.dumps({"findings": []}), file=sys.stderr)
        sys.exit(0)

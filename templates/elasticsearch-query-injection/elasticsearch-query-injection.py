#!/usr/bin/env python3
# @id: elasticsearch-query-injection
# @name: Elasticsearch Query DSL Injection Detector
# @severity: high
# @description: Detects Elasticsearch Query DSL injection vulnerabilities through boolean-based injection, script field injection, and aggregation parameter manipulation testing
# @tags: elasticsearch,injection,dsl,query-injection,script-injection,nosql
# @cwe: CWE-943
# @author: BugB Technologies
# @reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html, https://owasp.org/www-community/attacks/NoSQL_Injection

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
    port = os.environ.get('CERT_X_GEN_TARGET_PORT', '9200')
    
    if not host:
        return None, None
    
    return host, int(port)

def create_ssl_context():
    """Create SSL context that doesn't verify certificates"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def detect_elasticsearch_service(host, port, timeout=5):
    """
    Detect if Elasticsearch service is running and fingerprint version
    Returns: (is_elasticsearch, version, cluster_info)
    """
    protocols = ['http', 'https'] if port in [80, 443, 8080, 8443, 9200, 9243] else ['https', 'http']
    
    for protocol in protocols:
        try:
            # Try root endpoint
            url = f"{protocol}://{host}:{port}/"
            req = Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            req.add_header('Accept', 'application/json')
            
            ctx = create_ssl_context()
            with urlopen(req, timeout=timeout, context=ctx) as response:
                data = response.read().decode('utf-8')
                info = json.loads(data)
                
                # Check if it's Elasticsearch
                if 'tagline' in info and 'You Know, for Search' in info.get('tagline', ''):
                    version = info.get('version', {})
                    return True, version.get('number', 'unknown'), {
                        'name': info.get('name'),
                        'cluster_name': info.get('cluster_name'),
                        'version': version,
                        'protocol': protocol
                    }
        
        except (HTTPError, URLError, json.JSONDecodeError, socket.timeout):
            continue
        except Exception:
            continue
    
    return False, None, None

def test_cluster_api_injection(host, port, protocol, timeout=5):
    """
    Test for injection in cluster APIs
    Returns: list of vulnerabilities found
    """
    vulnerabilities = []
    base_url = f"{protocol}://{host}:{port}"
    
    # Test _cluster/health with injection
    injection_endpoints = [
        '/_cluster/health?wait_for_status=yellow&timeout=1s',
        '/_nodes',
        '/_cat/indices',
        '/_cat/shards'
    ]
    
    for endpoint in injection_endpoints:
        try:
            url = f"{base_url}{endpoint}"
            req = Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            ctx = create_ssl_context()
            with urlopen(req, timeout=timeout, context=ctx) as response:
                status_code = response.getcode()
                data = response.read().decode('utf-8')
                
                if status_code == 200 and len(data) > 0:
                    # Successful access to sensitive API
                    vuln = {
                        'type': 'Exposed Elasticsearch API',
                        'endpoint': endpoint,
                        'status_code': status_code,
                        'data_sample': data[:200]
                    }
                    vulnerabilities.append(vuln)
        
        except (HTTPError, URLError, socket.timeout):
            continue
        except Exception:
            continue
    
    return vulnerabilities


def test_query_dsl_injection(host, port, protocol, timeout=5):
    """
    Test for Query DSL injection vulnerabilities
    Tests boolean-based injection in search queries
    Returns: list of vulnerabilities found
    """
    vulnerabilities = []
    base_url = f"{protocol}://{host}:{port}"
    
    # Injection payloads for Query DSL
    injection_payloads = [
        # Boolean match_all injection
        {
            "query": {
                "bool": {
                    "must": [
                        {"match_all": {}}
                    ]
                }
            }
        },
        # Script query injection (if scripts enabled)
        {
            "query": {
                "script": {
                    "script": {
                        "source": "true",
                        "lang": "painless"
                    }
                }
            }
        },
        # Range query injection
        {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-1d/d",
                        "lt": "now/d"
                    }
                }
            }
        }
    ]
    
    # Test against common indices
    test_indices = ['_all', '*', 'logs-*', 'test']
    
    for index in test_indices:
        search_url = f"{base_url}/{index}/_search"
        
        for payload in injection_payloads:
            try:
                json_payload = json.dumps(payload)
                req = Request(search_url, data=json_payload.encode('utf-8'), method='POST')
                req.add_header('Content-Type', 'application/json')
                req.add_header('User-Agent', 'Mozilla/5.0')
                
                ctx = create_ssl_context()
                with urlopen(req, timeout=timeout, context=ctx) as response:
                    status_code = response.getcode()
                    data = response.read().decode('utf-8')
                    
                    if status_code == 200:
                        try:
                            result = json.loads(data)
                            hits = result.get('hits', {}).get('hits', [])
                            
                            if hits or result.get('hits', {}).get('total', {}).get('value', 0) > 0:
                                vuln = {
                                    'type': 'Query DSL Injection',
                                    'index': index,
                                    'payload': payload,
                                    'status_code': status_code,
                                    'hits_returned': len(hits),
                                    'total_hits': result.get('hits', {}).get('total', {}).get('value', 0)
                                }
                                vulnerabilities.append(vuln)
                                break  # Found vulnerability on this index
                        
                        except json.JSONDecodeError:
                            pass
            
            except (HTTPError, URLError, socket.timeout):
                continue
            except Exception:
                continue
    
    return vulnerabilities

def test_script_field_injection(host, port, protocol, timeout=5):
    """
    Test for script field injection in search queries
    Returns: list of vulnerabilities found
    """
    vulnerabilities = []
    base_url = f"{protocol}://{host}:{port}"
    
    # Script field injection payload
    script_payload = {
        "query": {"match_all": {}},
        "script_fields": {
            "test_field": {
                "script": {
                    "source": "1+1",
                    "lang": "painless"
                }
            }
        },
        "size": 1
    }
    
    test_indices = ['_all', '*']
    
    for index in test_indices:
        try:
            search_url = f"{base_url}/{index}/_search"
            json_payload = json.dumps(script_payload)
            req = Request(search_url, data=json_payload.encode('utf-8'), method='POST')
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            ctx = create_ssl_context()
            with urlopen(req, timeout=timeout, context=ctx) as response:
                status_code = response.getcode()
                data = response.read().decode('utf-8')
                
                if status_code == 200:
                    try:
                        result = json.loads(data)
                        hits = result.get('hits', {}).get('hits', [])
                        
                        # Check if script executed
                        if hits:
                            for hit in hits:
                                if 'fields' in hit and 'test_field' in hit['fields']:
                                    vuln = {
                                        'type': 'Script Field Injection',
                                        'index': index,
                                        'payload': script_payload,
                                        'status_code': status_code,
                                        'script_result': hit['fields']['test_field']
                                    }
                                    vulnerabilities.append(vuln)
                                    return vulnerabilities  # Critical finding
                    
                    except json.JSONDecodeError:
                        pass
        
        except (HTTPError, URLError, socket.timeout):
            continue
        except Exception:
            continue
    
    return vulnerabilities


def test_aggregation_injection(host, port, protocol, timeout=5):
    """
    Test for aggregation parameter injection
    Returns: list of vulnerabilities found
    """
    vulnerabilities = []
    base_url = f"{protocol}://{host}:{port}"
    
    # Aggregation injection payload
    agg_payload = {
        "size": 0,
        "aggs": {
            "test_agg": {
                "terms": {
                    "field": "_index",
                    "size": 100
                }
            }
        }
    }
    
    try:
        search_url = f"{base_url}/_all/_search"
        json_payload = json.dumps(agg_payload)
        req = Request(search_url, data=json_payload.encode('utf-8'), method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        ctx = create_ssl_context()
        with urlopen(req, timeout=timeout, context=ctx) as response:
            status_code = response.getcode()
            data = response.read().decode('utf-8')
            
            if status_code == 200:
                try:
                    result = json.loads(data)
                    aggs = result.get('aggregations', {}).get('test_agg', {})
                    buckets = aggs.get('buckets', [])
                    
                    if buckets:
                        vuln = {
                            'type': 'Aggregation Injection',
                            'payload': agg_payload,
                            'status_code': status_code,
                            'indices_exposed': [b['key'] for b in buckets[:10]]
                        }
                        vulnerabilities.append(vuln)
                
                except json.JSONDecodeError:
                    pass
    
    except (HTTPError, URLError, socket.timeout):
        pass
    except Exception:
        pass
    
    return vulnerabilities

def test_search_template_injection(host, port, protocol, timeout=5):
    """
    Test for search template parameter injection
    Returns: list of vulnerabilities found
    """
    vulnerabilities = []
    base_url = f"{protocol}://{host}:{port}"
    
    # Search template injection payload
    template_payload = {
        "source": {
            "query": {
                "match": {
                    "{{field}}": "{{value}}"
                }
            }
        },
        "params": {
            "field": "_id",
            "value": "1"
        }
    }
    
    try:
        template_url = f"{base_url}/_search/template"
        json_payload = json.dumps(template_payload)
        req = Request(template_url, data=json_payload.encode('utf-8'), method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        ctx = create_ssl_context()
        with urlopen(req, timeout=timeout, context=ctx) as response:
            status_code = response.getcode()
            data = response.read().decode('utf-8')
            
            if status_code == 200:
                try:
                    result = json.loads(data)
                    if 'hits' in result:
                        vuln = {
                            'type': 'Search Template Injection',
                            'payload': template_payload,
                            'status_code': status_code
                        }
                        vulnerabilities.append(vuln)
                
                except json.JSONDecodeError:
                    pass
    
    except (HTTPError, URLError, socket.timeout):
        pass
    except Exception:
        pass
    
    return vulnerabilities

def detect_injection_vulnerabilities(host, port):
    """
    Main detection logic for Elasticsearch Query DSL injection
    Returns: list of findings
    """
    findings = []
    
    # Step 1: Detect Elasticsearch service
    is_elasticsearch, version, cluster_info = detect_elasticsearch_service(host, port)
    
    if not is_elasticsearch:
        return []
    
    protocol = cluster_info.get('protocol', 'http')
    
    # Step 2: Test various injection vectors
    api_vulns = test_cluster_api_injection(host, port, protocol)
    query_vulns = test_query_dsl_injection(host, port, protocol)
    script_vulns = test_script_field_injection(host, port, protocol)
    agg_vulns = test_aggregation_injection(host, port, protocol)
    template_vulns = test_search_template_injection(host, port, protocol)
    
    all_vulns = api_vulns + query_vulns + script_vulns + agg_vulns + template_vulns
    
    # Build findings
    if all_vulns or is_elasticsearch:
        # Determine severity based on vulnerabilities found
        if script_vulns:
            severity = "critical"  # Script execution is critical
        elif query_vulns or template_vulns:
            severity = "high"  # Query injection is high
        elif agg_vulns or api_vulns:
            severity = "medium"  # Information disclosure
        else:
            severity = "info"  # Just service detected
        
        description = f"Elasticsearch service detected on {host}:{port}"
        if version:
            description += f" (version {version}). "
        else:
            description += ". "
        
        if script_vulns:
            description += f"CRITICAL: Script field injection vulnerability detected - Painless script execution is enabled. "
        
        if query_vulns:
            description += f"Found {len(query_vulns)} Query DSL injection vulnerabilities. "
        
        if template_vulns:
            description += f"Found {len(template_vulns)} search template injection vulnerabilities. "
        
        if agg_vulns:
            description += f"Found {len(agg_vulns)} aggregation injection vulnerabilities exposing sensitive data. "
        
        if api_vulns:
            description += f"Found {len(api_vulns)} exposed Elasticsearch API endpoints. "
        
        evidence = {
            "host": host,
            "port": port,
            "elasticsearch_detected": True,
            "version": version,
            "cluster_info": cluster_info,
            "script_injections": script_vulns[:2] if script_vulns else [],
            "query_injections": query_vulns[:2] if query_vulns else [],
            "template_injections": template_vulns[:2] if template_vulns else [],
            "aggregation_injections": agg_vulns[:2] if agg_vulns else [],
            "api_exposures": api_vulns[:2] if api_vulns else [],
            "total_vulnerabilities": len(all_vulns)
        }
        
        recommendation = """
1. IMMEDIATE ACTIONS:
   - Disable dynamic scripting if not required: script.disable_dynamic: true
   - Enable script sandboxing for Painless scripts
   - Implement strict input validation and sanitization
   - Use Elasticsearch query builders instead of string concatenation
   - Enable authentication and authorization (X-Pack Security/Elastic Stack Security)

2. QUERY DSL SECURITY:
   - Validate and sanitize all user inputs before query construction
   - Use parameterized queries through official Elasticsearch client libraries
   - Implement allowlists for query parameters and fields
   - Reject queries containing script blocks from untrusted sources
   - Use Query String Query carefully - prefer Match Query for user input

3. SCRIPT SECURITY:
   - Disable inline scripting: script.inline: false
   - Use stored scripts with predefined templates only
   - Restrict script.painless.regex.enabled if regex not needed
   - Monitor script execution via slow log

4. ACCESS CONTROL:
   - Enable Elasticsearch Security features (formerly X-Pack)
   - Implement role-based access control (RBAC)
   - Use API keys with minimal required permissions
   - Restrict network access - bind to localhost if possible
   - Use firewall rules to limit access to port 9200/9300

5. AGGREGATION SECURITY:
   - Limit aggregation bucket sizes: search.max_buckets
   - Set circuit breakers to prevent resource exhaustion
   - Monitor aggregation query patterns

6. MONITORING AND AUDITING:
   - Enable audit logging for all query operations
   - Monitor for unusual query patterns and script execution
   - Set up alerts for failed authentication attempts
   - Regular security assessments and penetration testing

7. GENERAL SECURITY:
   - Keep Elasticsearch updated to latest stable version
   - Use TLS/SSL for all communications
   - Implement rate limiting to prevent DoS
   - Regular backup and disaster recovery testing
   - Follow Elasticsearch security best practices documentation

OWASP NoSQL Injection Prevention:
- Input validation and type checking
- Use official client libraries with built-in protections
- Implement least privilege principle
- Regular security audits and code reviews
"""
        
        # Calculate CVSS score
        cvss_score = 9.8 if script_vulns else (8.1 if query_vulns or template_vulns else (6.5 if agg_vulns else 5.0))
        
        finding = {
            "template_id": "elasticsearch-query-injection",
            "template_name": "Elasticsearch Query DSL Injection Detector",
            "id": "elasticsearch-query-injection",
            "severity": severity,
            "name": "Elasticsearch Query DSL Injection Vulnerability",
            "host": host,
            "port": port,
            "matched_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "description": description,
            "evidence": evidence,
            "cwe": "CWE-943",
            "cvss_score": cvss_score,
            "recommendation": recommendation,
            "references": [
                "https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html",
                "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html",
                "https://owasp.org/www-community/attacks/NoSQL_Injection",
                "https://cwe.mitre.org/data/definitions/943.html",
                "https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting-security.html",
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
    
    # Detect Elasticsearch Query DSL injection vulnerabilities
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

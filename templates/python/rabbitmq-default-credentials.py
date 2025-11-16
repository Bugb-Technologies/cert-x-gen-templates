#!/usr/bin/env python3
"""
RabbitMQ Default Credentials Detection

Tests for default credentials (guest:guest) on RabbitMQ instances.
Also tests for weak/common passwords on admin account.

Author: CERT-X-GEN Security Team
Severity: Critical
CWE: CWE-798 (Use of Hard-coded Credentials)
"""

import requests
import json
from typing import List, Dict, Any
from requests.auth import HTTPBasicAuth
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RabbitMQDefaultCredsTemplate:
    """Template for detecting RabbitMQ default/weak credentials"""
    
    def __init__(self):
        self.id = "rabbitmq-default-credentials"
        self.name = "RabbitMQ Default Credentials Detection"
        self.severity = "critical"
        self.tags = ["rabbitmq", "default-credentials", "authentication", "cwe-798"]
        self.confidence = 95
        self.ports = [15672, 15671, 5672]  # Management UI, AMQPS, AMQP
        
        # Default and common credentials to test
        self.credentials = [
            ("guest", "guest"),         # Default RabbitMQ
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "rabbitmq"),
            ("rabbitmq", "rabbitmq"),
            ("user", "user"),
            ("test", "test"),
        ]
    
    def execute(self, target: str) -> List[Dict[str, Any]]:
        """
        Execute template against target
        
        Args:
            target: Target hostname or IP
            
        Returns:
            List of findings
        """
        findings = []
        
        # Test Management API (HTTP)
        for port in [15672, 15671]:
            scheme = "https" if port == 15671 else "http"
            findings.extend(self._test_management_api(target, port, scheme))
        
        # Test AMQP protocol
        findings.extend(self._test_amqp_protocol(target))
        
        return findings
    
    def _test_management_api(self, target: str, port: int, scheme: str) -> List[Dict[str, Any]]:
        """Test RabbitMQ Management API with default credentials"""
        findings = []
        base_url = f"{scheme}://{target}:{port}"
        
        for username, password in self.credentials:
            try:
                # Test authentication on /api/whoami endpoint
                url = f"{base_url}/api/whoami"
                response = requests.get(
                    url,
                    auth=HTTPBasicAuth(username, password),
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Authentication successful
                    user_info = response.json()
                    
                    findings.append({
                        "severity": "critical",
                        "title": f"RabbitMQ Default/Weak Credentials: {username}:{password}",
                        "description": f"RabbitMQ Management API accessible with credentials {username}:{password}",
                        "evidence": {
                            "username": username,
                            "password": password,
                            "endpoint": url,
                            "user_info": user_info,
                            "tags": user_info.get("tags", [])
                        },
                        "remediation": self._get_remediation(),
                        "cwe": "CWE-798",
                        "cvss_score": 9.8
                    })
                    
                    # Try to enumerate more info
                    overview = self._get_cluster_overview(base_url, username, password)
                    if overview:
                        findings.append({
                            "severity": "high",
                            "title": "RabbitMQ Cluster Information Exposed",
                            "description": "Successfully retrieved cluster configuration",
                            "evidence": {
                                "rabbitmq_version": overview.get("rabbitmq_version"),
                                "cluster_name": overview.get("cluster_name"),
                                "node": overview.get("node"),
                                "erlang_version": overview.get("erlang_version")
                            }
                        })
                    
                    # Try to list vhosts
                    vhosts = self._list_vhosts(base_url, username, password)
                    if vhosts:
                        findings.append({
                            "severity": "high",
                            "title": "RabbitMQ Virtual Hosts Enumeration",
                            "description": f"Successfully enumerated {len(vhosts)} virtual hosts",
                            "evidence": {
                                "vhosts": [v.get("name") for v in vhosts]
                            }
                        })
                    
                    # Try to list queues
                    queues = self._list_queues(base_url, username, password)
                    if queues:
                        findings.append({
                            "severity": "high",
                            "title": "RabbitMQ Queues Enumeration",
                            "description": f"Successfully enumerated {len(queues)} queues",
                            "evidence": {
                                "queue_count": len(queues),
                                "queue_names": [q.get("name") for q in queues[:10]]
                            }
                        })
                    
                    # Only test first working credentials
                    break
                    
            except requests.exceptions.RequestException:
                # Connection failed, try next port
                continue
        
        return findings
    
    def _get_cluster_overview(self, base_url: str, username: str, password: str) -> Dict:
        """Get RabbitMQ cluster overview"""
        try:
            response = requests.get(
                f"{base_url}/api/overview",
                auth=HTTPBasicAuth(username, password),
                timeout=5,
                verify=False
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}
    
    def _list_vhosts(self, base_url: str, username: str, password: str) -> List[Dict]:
        """List virtual hosts"""
        try:
            response = requests.get(
                f"{base_url}/api/vhosts",
                auth=HTTPBasicAuth(username, password),
                timeout=5,
                verify=False
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return []
    
    def _list_queues(self, base_url: str, username: str, password: str) -> List[Dict]:
        """List queues"""
        try:
            response = requests.get(
                f"{base_url}/api/queues",
                auth=HTTPBasicAuth(username, password),
                timeout=5,
                verify=False
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return []
    
    def _test_amqp_protocol(self, target: str) -> List[Dict[str, Any]]:
        """Test AMQP protocol with default credentials"""
        findings = []
        
        try:
            # Try to connect using pika library if available
            import pika
            
            for username, password in self.credentials:
                try:
                    credentials = pika.PlainCredentials(username, password)
                    parameters = pika.ConnectionParameters(
                        host=target,
                        port=5672,
                        credentials=credentials,
                        connection_attempts=1,
                        socket_timeout=3
                    )
                    
                    connection = pika.BlockingConnection(parameters)
                    
                    findings.append({
                        "severity": "critical",
                        "title": f"RabbitMQ AMQP Authentication with {username}:{password}",
                        "description": "Successfully authenticated to AMQP protocol",
                        "evidence": {
                            "username": username,
                            "password": password,
                            "protocol": "AMQP",
                            "port": 5672
                        },
                        "remediation": self._get_remediation(),
                        "cwe": "CWE-798",
                        "cvss_score": 9.8
                    })
                    
                    connection.close()
                    break
                    
                except:
                    continue
                    
        except ImportError:
            # pika not available, skip AMQP test
            pass
        except Exception as e:
            pass
        
        return findings
    
    def _get_remediation(self) -> str:
        """Get remediation steps"""
        return """
1. Change default credentials immediately:
   rabbitmqctl change_password guest NEW_STRONG_PASSWORD
   
2. Delete guest user if not needed:
   rabbitmqctl delete_user guest

3. Create new admin user with strong password:
   rabbitmqctl add_user admin STRONG_PASSWORD
   rabbitmqctl set_user_tags admin administrator
   rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

4. Disable guest user remote access (rabbitmq.config):
   {rabbit, [{loopback_users, [<<"guest">>]}]}

5. Enable TLS/SSL for Management API:
   management.ssl.port = 15671
   management.ssl.cacertfile = /path/to/ca_certificate.pem
   management.ssl.certfile = /path/to/server_certificate.pem
   management.ssl.keyfile = /path/to/server_key.pem

6. Use strong authentication mechanisms:
   - LDAP integration
   - OAuth 2.0
   - X.509 certificates

7. Implement network segmentation
8. Enable audit logging
9. Regular security audits
10. Keep RabbitMQ updated to latest version
"""

# Template metadata
TEMPLATE_METADATA = {
    "id": "rabbitmq-default-credentials",
    "name": "RabbitMQ Default Credentials Detection",
    "author": "CERT-X-GEN Security Team",
    "severity": "critical",
    "language": "python",
    "tags": ["rabbitmq", "default-credentials", "weak-password", "authentication"],
    "confidence": 95,
    "references": [
        "https://www.rabbitmq.com/access-control.html",
        "https://www.rabbitmq.com/management.html",
        "https://cwe.mitre.org/data/definitions/798.html"
    ]
}

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python rabbitmq-default-credentials.py <target>")
        sys.exit(1)
    
    template = RabbitMQDefaultCredsTemplate()
    findings = template.execute(sys.argv[1])
    
    print(json.dumps(findings, indent=2))
    print(f"\n[+] Total findings: {len(findings)}")

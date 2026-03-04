#!/usr/bin/env python3
# CERT-X-GEN Kafka Unauthenticated Access Detection Template
#
# @id: kafka-unauthenticated-access
# @name: Kafka Unauthenticated Access Detection
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects unauthenticated access to Apache Kafka brokers on port 9092. Kafka without proper authentication allows unauthorized clients to connect and manipulate topics, messages, and cluster configurations.
# @tags: kafka, authentication, message-broker, unauthenticated-access, critical
# @cwe: CWE-287
# @confidence: 95
# @references: https://cwe.mitre.org/data/definitions/287.html, https://kafka.apache.org/documentation/#security
#
# Usage:
#   python3 kafka-unauthenticated-access.py <target> [--port 9092] [--json]
#   python3 kafka-unauthenticated-access.py example.com --port 9092 --json
#
# When run by CERT-X-GEN engine, environment variables are set:
#   CERT_X_GEN_TARGET_HOST - Target host/IP
#   CERT_X_GEN_TARGET_PORT - Target port (default 9092)
#   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
#

import json
import sys
import os
import argparse
import socket
import struct
from typing import List, Dict, Any
from enum import Enum

# Kafka protocol constants
class KafkaApiVersion(Enum):
    """Kafka API versions"""
    METADATA_REQUEST = 3
    APIVERSION_REQUEST = 18

class CertXGenTemplate:
    """Base class for CERT-X-GEN Python templates"""
    
    def __init__(self):
        self.id = "kafka-unauthenticated-access"
        self.name = "Kafka Unauthenticated Access Detection"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "critical"
        self.tags = ["kafka", "authentication", "message-broker"]
        self.confidence = 95
        self.cwe = "CWE-287"
        self.target = None
        self.context = {}
    
    def execute(self, target: str, port: int = 9092) -> List[Dict[str, Any]]:
        """
        Main execution method for the template.
        
        Args:
            target: Target host/IP address
            port: Target port (default: 9092 for Kafka)
            
        Returns:
            List of findings in CERT-X-GEN format
        """
        findings = []
        
        try:
            # Test unauthenticated Kafka access
            if self.test_kafka_access(target, port):
                # Get Kafka metadata to confirm access
                metadata = self.get_kafka_metadata(target, port)
                
                finding = self.create_finding(
                    title="Unauthenticated Kafka Access Detected",
                    description=f"Kafka broker on {target}:{port} allows unauthenticated access without SASL/TLS authentication. This allows unauthorized clients to connect and manipulate topics, messages, and cluster configuration.",
                    evidence={
                        "host": target,
                        "port": port,
                        "protocol": "Kafka",
                        "metadata": metadata
                    },
                    severity="critical",
                    remediation=self.get_remediation()
                )
                findings.append(finding)
        
        except Exception as e:
            print(f"Error during scan: {e}", file=sys.stderr)
        
        return findings
    
    def test_kafka_access(self, host: str, port: int) -> bool:
        """
        Test if Kafka broker accepts unauthenticated connections
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send Kafka API Version request (simplest probe)
            api_version_request = self.build_api_version_request()
            sock.send(api_version_request)
            
            # Try to receive response
            response = sock.recv(1024)
            sock.close()
            
            if response and len(response) > 0:
                return True
            
        except (socket.timeout, socket.error, ConnectionRefusedError):
            pass
        
        return False
    
    def get_kafka_metadata(self, host: str, port: int) -> Dict[str, Any]:
        """
        Get Kafka cluster metadata without authentication
        """
        metadata = {
            "accessible": False,
            "brokers": [],
            "topics": []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send Metadata request
            metadata_request = self.build_metadata_request()
            sock.send(metadata_request)
            
            response = sock.recv(4096)
            sock.close()
            
            if response:
                metadata["accessible"] = True
                # Parse basic response structure
                metadata["response_length"] = len(response)
                metadata["response_hex"] = response[:32].hex()  # First 32 bytes
            
        except Exception:
            pass
        
        return metadata
    
    def build_api_version_request(self) -> bytes:
        """
        Build Kafka API Version Request (no authentication needed)
        """
        # API Version Request format:
        # int32 size (will be calculated)
        # int16 api_key (18 for ApiVersion)
        # int16 api_version (1 for v1)
        # int32 correlation_id
        # string client_id
        
        api_key = 18  # ApiVersion
        api_version = 1
        correlation_id = 1
        client_id = b"cert-x-gen"
        
        # Build request body
        body = struct.pack(">H", api_key)  # api_key
        body += struct.pack(">H", api_version)  # api_version
        body += struct.pack(">I", correlation_id)  # correlation_id
        body += struct.pack(">H", len(client_id))  # client_id length
        body += client_id
        
        # Add size header
        request = struct.pack(">I", len(body)) + body
        
        return request
    
    def build_metadata_request(self) -> bytes:
        """
        Build Kafka Metadata Request (no authentication needed)
        """
        api_key = 3  # Metadata
        api_version = 9
        correlation_id = 1
        client_id = b"cert-x-gen"
        
        # Build request body
        body = struct.pack(">H", api_key)
        body += struct.pack(">H", api_version)
        body += struct.pack(">I", correlation_id)
        body += struct.pack(">H", len(client_id))
        body += client_id
        body += struct.pack(">I", 0)  # topics array size (0 = all topics)
        
        # Add size header
        request = struct.pack(">I", len(body)) + body
        
        return request
    
    def create_finding(
        self,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        severity: str = None,
        remediation: str = None
    ) -> Dict[str, Any]:
        """
        Create a finding in CERT-X-GEN format
        """
        return {
            "template_id": self.id,
            "severity": severity or self.severity,
            "confidence": self.confidence,
            "title": title,
            "description": description,
            "evidence": evidence,
            "cwe": self.cwe,
            "cvss_score": self.calculate_cvss_score(severity or self.severity),
            "remediation": remediation or self.get_remediation(),
            "references": self.get_references()
        }
    
    def calculate_cvss_score(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        scores = {
            "critical": 9.8,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 0.0
        }
        return scores.get(severity.lower(), 5.0)
    
    def get_remediation(self) -> str:
        """
        Get remediation steps for Kafka unauthenticated access
        """
        return """
1. Enable SASL/SCRAM authentication on all Kafka brokers
2. Configure TLS/SSL for broker-to-broker and client-to-broker communication
3. Implement ACLs (Access Control Lists) to restrict client permissions
4. Set advertised.listeners to use only authenticated endpoints
5. Configure broker security.inter.broker.protocol.version
6. Restrict network access to Kafka brokers using firewalls
7. Enable Kafka audit logging to monitor access attempts
8. Use Kafka Authorizer to enforce authorization policies
9. Regularly rotate credentials and update security configurations
10. Monitor for unauthorized connection attempts
"""
    
    def get_references(self) -> List[str]:
        """
        Get references for Kafka security
        """
        return [
            "https://kafka.apache.org/documentation/#security",
            "https://kafka.apache.org/documentation/#sasl",
            "https://cwe.mitre.org/data/definitions/287.html",
            "https://owasp.org/www-project-top-ten/"
        ]
    
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description=self.name,
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        parser.add_argument(
            "target",
            nargs="?",
            help="Target host or IP address"
        )
        
        parser.add_argument(
            "--target",
            dest="target_flag",
            help="Target host (alternative)"
        )
        
        parser.add_argument(
            "--port",
            type=int,
            default=9092,
            help="Target port (default: 9092)"
        )
        
        parser.add_argument(
            "--json",
            action="store_true",
            help="Output findings as JSON"
        )
        
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Verbose output"
        )
        
        return parser.parse_args()
    
    def run(self):
        """Main entry point for the template"""
        args = self.parse_arguments()
        
        # Get target from arguments or environment
        target = args.target or args.target_flag
        if not target and "CERT_X_GEN_TARGET_HOST" in os.environ:
            target = os.environ["CERT_X_GEN_TARGET_HOST"]
        
        if not target:
            print("Error: No target specified", file=sys.stderr)
            sys.exit(1)
        
        # Get port
        port = args.port
        if "CERT_X_GEN_TARGET_PORT" in os.environ:
            port = int(os.environ["CERT_X_GEN_TARGET_PORT"])
        
        # Get context from environment
        if "CERT_X_GEN_CONTEXT" in os.environ:
            try:
                self.context = json.loads(os.environ["CERT_X_GEN_CONTEXT"])
            except json.JSONDecodeError:
                pass
        
        # Execute the template
        findings = self.execute(target, port)
        
        # Output results
        if args.json or os.environ.get("CERT_X_GEN_MODE") == "engine":
            # JSON output for CERT-X-GEN engine integration
            print(json.dumps(findings, indent=2))
        else:
            # Human-readable output
            if findings:
                print(f"\n[+] Found {len(findings)} issue(s):\n")
                for finding in findings:
                    print(f"[{finding['severity'].upper()}] {finding['title']}")
                    print(f"    {finding['description']}")
                    if args.verbose:
                        print(f"    Evidence: {json.dumps(finding['evidence'], indent=8)}")
                    print()
            else:
                print("\n[-] No issues found")

class KafkaUnauthenticatedAccessTemplate(CertXGenTemplate):
    """
    Kafka Unauthenticated Access Detection Template
    
    Detects if a Kafka broker on port 9092 allows unauthenticated connections
    """
    
    def __init__(self):
        super().__init__()
        self.id = "kafka-unauthenticated-access"
        self.name = "Kafka Unauthenticated Access Detection"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "critical"
        self.tags = ["kafka", "authentication", "message-broker", "critical"]
        self.confidence = 95
        self.cwe = "CWE-287"

if __name__ == "__main__":
    template = KafkaUnauthenticatedAccessTemplate()
    template.run()

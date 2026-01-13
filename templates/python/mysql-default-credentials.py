#!/usr/bin/env python3
# @id: mysql-default-credentials
# @name: MySQL Default/Weak Credentials Detection
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects MySQL servers accessible with default, weak, or empty credentials
# @tags: mysql, database, credentials, authentication, brute-force
# @cwe: CWE-798
# @cvss: 9.8
# @references: https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html
# @confidence: 98
# @version: 1.0.0
#
# WHY PYTHON?
# MySQL credential testing requires:
# - MySQL protocol handshake (capability negotiation)
# - Password hashing (mysql_native_password / caching_sha2_password)
# - Database enumeration on success
# - This is a DATABASE PROTOCOL - YAML cannot authenticate
#
# WHAT IT DOES:
# 1. Connects to MySQL server
# 2. Performs MySQL handshake
# 3. Attempts login with common default credentials
# 4. On success, enumerates databases and tables
# 5. Reports exposure level
"""
CERT-X-GEN MySQL Default Credentials Detection

This template demonstrates database protocol intelligence - something
impossible in YAML-based scanners. It uses pymysql to attempt
authentication with default/weak credentials.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Tuple

# Template metadata
METADATA = {
    "id": "mysql-default-credentials",
    "name": "MySQL Default/Weak Credentials Detection",
    "author": "CERT-X-GEN Security Team",
    "severity": "critical",
    "description": "Detects MySQL servers with default or weak credentials",
    "tags": ["mysql", "database", "credentials", "authentication"],
    "language": "python",
    "confidence": 98,
    "cwe": ["CWE-798", "CWE-521"],
    "cvss_score": 9.8,
    "references": [
        "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html"
    ]
}

# Default credentials to try
DEFAULT_CREDS = [
    ("root", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "mysql"),
    ("root", "admin"),
    ("root", "123456"),
    ("root", "toor"),
    ("mysql", ""),
    ("mysql", "mysql"),
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("test", "test"),
    ("guest", "guest"),
]


class MySQLScanner:
    """MySQL Default Credentials Scanner."""
    
    def __init__(self, host: str, port: int = 3306):
        self.host = host
        self.port = port
        self.evidence = {}
        self.findings = []
        self.timeout = 10
        self.successful_creds = None
    
    def _try_connect(self, user: str, password: str) -> Tuple[bool, Any]:
        """Attempt MySQL connection with given credentials."""
        try:
            import pymysql
            
            conn = pymysql.connect(
                host=self.host,
                port=self.port,
                user=user,
                password=password,
                connect_timeout=self.timeout,
                read_timeout=self.timeout
            )
            return True, conn
        except ImportError:
            # Fallback to socket-based check if pymysql not available
            return self._try_connect_socket(user, password)
        except Exception as e:
            error_str = str(e).lower()
            # Check for specific error types
            if "access denied" in error_str:
                return False, "access_denied"
            elif "unknown database" in error_str:
                return False, "unknown_db"
            elif "connection refused" in error_str:
                return False, "refused"
            elif "timed out" in error_str:
                return False, "timeout"
            return False, str(e)
    
    def _try_connect_socket(self, user: str, password: str) -> Tuple[bool, Any]:
        """Fallback socket-based MySQL handshake check."""
        import socket
        import struct
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Read initial handshake packet
            data = sock.recv(4096)
            if len(data) < 4:
                sock.close()
                return False, "no_handshake"
            
            # Parse packet length and sequence
            packet_len = struct.unpack('<I', data[:3] + b'\x00')[0]
            
            # Check if it's a MySQL server (protocol version should be 10)
            if len(data) > 4 and data[4] == 10:
                # Extract server version
                null_pos = data.find(b'\x00', 5)
                if null_pos != -1:
                    version = data[5:null_pos].decode('utf-8', errors='ignore')
                    self.evidence['server_version'] = version
            
            sock.close()
            # Socket check can only verify server is MySQL, not auth
            return False, "socket_only"
            
        except Exception as e:
            return False, str(e)
    
    def _enumerate_databases(self, conn) -> List[str]:
        """Enumerate databases on successful connection."""
        databases = []
        try:
            cursor = conn.cursor()
            cursor.execute("SHOW DATABASES")
            for row in cursor.fetchall():
                databases.append(row[0])
            cursor.close()
        except Exception:
            pass
        return databases
    
    def _get_user_privileges(self, conn) -> str:
        """Get current user privileges."""
        try:
            cursor = conn.cursor()
            cursor.execute("SHOW GRANTS")
            grants = []
            for row in cursor.fetchall():
                grants.append(row[0])
            cursor.close()
            return "; ".join(grants[:3])  # First 3 grants
        except Exception:
            return "unknown"
    
    def _get_server_info(self, conn) -> Dict[str, str]:
        """Get MySQL server information."""
        info = {}
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION(), USER(), DATABASE()")
            row = cursor.fetchone()
            if row:
                info['version'] = row[0]
                info['current_user'] = row[1]
                info['current_db'] = row[2]
            cursor.close()
        except Exception:
            pass
        return info


    def scan(self) -> List[Dict[str, Any]]:
        """Perform credential scan and return findings."""
        
        self.evidence['target'] = f"{self.host}:{self.port}"
        self.evidence['credentials_tested'] = len(DEFAULT_CREDS)
        
        # Try each credential pair
        for user, password in DEFAULT_CREDS:
            success, result = self._try_connect(user, password)
            
            if success:
                self.successful_creds = (user, password)
                self.evidence['username'] = user
                self.evidence['password'] = password if password else "(empty)"
                self.evidence['auth_success'] = True
                
                # Enumerate on successful connection
                conn = result
                
                # Get server info
                server_info = self._get_server_info(conn)
                self.evidence.update(server_info)
                
                # Get databases
                databases = self._enumerate_databases(conn)
                self.evidence['databases'] = databases
                self.evidence['database_count'] = len(databases)
                
                # Check for sensitive databases
                sensitive_dbs = [db for db in databases if db.lower() in 
                               ['mysql', 'information_schema', 'performance_schema', 'sys']]
                self.evidence['system_databases'] = sensitive_dbs
                
                # Get privileges
                privileges = self._get_user_privileges(conn)
                self.evidence['privileges'] = privileges
                
                conn.close()
                break
            
            elif result == "refused":
                self.evidence['error'] = 'Connection refused'
                break
            elif result == "timeout":
                self.evidence['error'] = 'Connection timeout'
                break
        
        # Generate finding if credentials worked
        if self.successful_creds:
            user, password = self.successful_creds
            
            desc = f"MySQL server at {self.host}:{self.port} allows login with "
            if password:
                desc += f"default credentials ({user}/{password}). "
            else:
                desc += f"empty password for user '{user}'. "
            
            if self.evidence.get('version'):
                desc += f"Server version: {self.evidence['version']}. "
            
            if self.evidence.get('databases'):
                desc += f"Found {self.evidence['database_count']} databases. "
            
            desc += "Default credentials allow full database access including data exfiltration, "
            desc += "modification, and potential privilege escalation."
            
            self.findings.append({
                "id": METADATA['id'],
                "name": METADATA['name'],
                "severity": "critical",
                "confidence": METADATA['confidence'],
                "title": f"MySQL Default Credentials on {self.host}:{self.port}",
                "description": desc,
                "evidence": self.evidence,
                "remediation": "Change default MySQL passwords immediately. "
                              "Remove or disable default accounts. "
                              "Implement strong password policies. "
                              "Restrict network access to MySQL port.",
                "cwe": METADATA['cwe'],
                "cvss_score": METADATA['cvss_score'],
                "tags": METADATA['tags'],
                "matched_at": f"{self.host}:{self.port}",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        return self.findings


def main():
    """Main execution."""
    host = os.getenv('CERT_X_GEN_TARGET_HOST')
    port_str = os.getenv('CERT_X_GEN_TARGET_PORT', '3306')
    
    if not host and len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port_str = sys.argv[2]
    
    if not host:
        host = '127.0.0.1'
    
    port = int(port_str)
    
    scanner = MySQLScanner(host, port)
    findings = scanner.scan()
    
    result = {
        "findings": findings,
        "metadata": METADATA
    }
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Template: PostgreSQL Extension RCE
Purpose: Detects PostgreSQL instances vulnerable to extension-based code execution
Severity: CRITICAL
CWE: CWE-94 (Improper Control of Generation of Code)
Related: CVE-2019-9193 (PostgreSQL COPY FROM PROGRAM RCE)

Description:
Detects PostgreSQL instances vulnerable to remote code execution through
dangerous extensions and features like PL/pgSQL, COPY FROM PROGRAM,
and untrusted procedural languages. Focuses on misconfigurations that
allow arbitrary code execution.

Vulnerability Vectors:
1. Unauthenticated PostgreSQL access
2. Weak/default credentials (postgres/postgres)
3. Enabled dangerous extensions (plpgsql, plpythonu, plperlu)
4. COPY FROM PROGRAM command availability
5. CREATE EXTENSION privileges

Detection Method:
- Tests PostgreSQL connectivity on default port 5432
- Attempts authentication with common credentials
- Enumerates installed extensions
- Checks for dangerous procedural languages
- Tests COPY FROM PROGRAM availability (non-invasive)
- Verifies CREATE EXTENSION permissions

Author: CERT-X-GEN Team
Date: 2026-02-02
"""

import sys
import json
import socket
from typing import Dict, List, Any, Optional
from datetime import datetime

# Try to import psycopg2, provide fallback
try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

class PostgreSQLExtensionRCE:
    def __init__(self, target: str, port: int = 5432):
        """Initialize scanner with target."""
        self.target = target
        self.port = port
        self.timeout = 10
        
        # Common credentials to test
        self.credentials = [
            ('postgres', 'postgres'),
            ('postgres', ''),
            ('postgres', 'password'),
            ('postgres', 'admin'),
            ('admin', 'admin')
        ]
        
        # Dangerous extensions that enable RCE
        self.dangerous_extensions = [
            'plpgsql',      # PL/pgSQL - can execute system commands
            'plpythonu',    # Untrusted Python
            'plperlu',      # Untrusted Perl
            'plsh',         # Shell extension
            'plv8'          # JavaScript - can be dangerous
        ]
    
    def scan(self) -> Dict[str, Any]:
        """Main scanning logic."""
        result = {
            "template": "postgresql-extension-rce",
            "target": self.target,
            "port": self.port,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "findings": [],
            "metadata": {
                "postgresql_detected": False,
                "authenticated": False,
                "version": None,
                "dangerous_extensions": [],
                "rce_possible": False
            }
        }
        
        if not HAS_PSYCOPG2:
            result["findings"].append({
                "severity": "info",
                "confidence": 100,
                "title": "Missing Dependency",
                "description": "psycopg2 module not installed. Run: pip install psycopg2-binary",
                "remediation": "Install psycopg2-binary to enable PostgreSQL scanning"
            })
            return result
        
        try:
            # Step 1: Check if PostgreSQL is accessible
            accessible = self._check_postgresql_accessible()
            
            if not accessible:
                result["findings"].append({
                    "severity": "info",
                    "confidence": 100,
                    "title": "PostgreSQL Not Accessible",
                    "description": f"PostgreSQL not accessible on {self.target}:{self.port}",
                    "remediation": "Verify target is running PostgreSQL"
                })
                return result
            
            result["metadata"]["postgresql_detected"] = True
            
            # Step 2: Try to authenticate
            conn, username, password = self._try_authenticate()
            
            if not conn:
                result["findings"].append({
                    "severity": "info",
                    "confidence": 90,
                    "title": "PostgreSQL Detected - Authentication Required",
                    "description": f"PostgreSQL is running but authentication failed with common credentials",
                    "remediation": "PostgreSQL requires valid credentials for further testing"
                })
                return result
            
            result["metadata"]["authenticated"] = True
            
            try:
                # Step 3: Get version
                version = self._get_version(conn)
                result["metadata"]["version"] = version
                
                # Step 4: Check for dangerous extensions
                dangerous_exts = self._check_dangerous_extensions(conn)
                result["metadata"]["dangerous_extensions"] = dangerous_exts
                
                # Step 5: Check privileges
                can_create_extension = self._check_create_extension_privilege(conn)
                can_copy_program = self._check_copy_program_privilege(conn)
                
                # Determine severity
                if dangerous_exts or can_copy_program:
                    result["metadata"]["rce_possible"] = True
                    
                    severity = "critical"
                    confidence = 95
                    
                    vuln_details = []
                    if username == 'postgres' and password in ['postgres', '', 'password', 'admin']:
                        vuln_details.append(f"Weak credentials: {username}/{password or '(empty)'}")
                    
                    if dangerous_exts:
                        vuln_details.append(f"Dangerous extensions installed: {', '.join(dangerous_exts)}")
                    
                    if can_copy_program:
                        vuln_details.append("COPY FROM PROGRAM command available")
                    
                    if can_create_extension:
                        vuln_details.append("CREATE EXTENSION privilege granted")
                    
                    result["findings"].append({
                        "severity": severity,
                        "confidence": confidence,
                        "title": "PostgreSQL RCE via Extensions/Commands",
                        "description": (
                            f"PostgreSQL instance is vulnerable to remote code execution. "
                            f"Vulnerabilities: {'; '.join(vuln_details)}. "
                            f"Attackers can execute arbitrary system commands through PL/pgSQL "
                            f"functions or COPY FROM PROGRAM."
                        ),
                        "cwe": "CWE-94",
                        "remediation": (
                            "1. Change default PostgreSQL credentials immediately\n"
                            "2. Disable untrusted procedural languages (plpythonu, plperlu)\n"
                            "3. Restrict COPY FROM PROGRAM to superusers only\n"
                            "4. Review and restrict CREATE EXTENSION privileges\n"
                            "5. Use pg_hba.conf to restrict network access\n"
                            "6. Enable SSL/TLS for PostgreSQL connections\n"
                            "7. Audit installed extensions and remove unnecessary ones"
                        ),
                        "references": [
                            "https://www.postgresql.org/docs/current/sql-createextension.html",
                            "https://www.postgresql.org/docs/current/sql-copy.html",
                            "https://nvd.nist.gov/vuln/detail/CVE-2019-9193"
                        ]
                    })
                else:
                    result["findings"].append({
                        "severity": "medium",
                        "confidence": 80,
                        "title": "PostgreSQL Accessible with Weak Credentials",
                        "description": (
                            f"PostgreSQL accessible with credentials {username}/{password or '(empty)'}. "
                            f"No immediate RCE vectors detected, but weak credentials pose security risk."
                        ),
                        "remediation": "Change PostgreSQL credentials and restrict network access"
                    })
            
            finally:
                conn.close()
        
        except Exception as e:
            result["findings"].append({
                "severity": "info",
                "confidence": 50,
                "title": "Scan Error",
                "description": f"Error during scan: {str(e)}",
                "remediation": "Check target accessibility and permissions"
            })
        
        return result
    
    def _check_postgresql_accessible(self) -> bool:
        """Check if PostgreSQL port is accessible."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _try_authenticate(self) -> tuple:
        """Try to authenticate with common credentials."""
        for username, password in self.credentials:
            try:
                conn = psycopg2.connect(
                    host=self.target,
                    port=self.port,
                    user=username,
                    password=password,
                    database='postgres',
                    connect_timeout=self.timeout
                )
                return conn, username, password
            except psycopg2.OperationalError:
                continue
            except Exception:
                continue
        
        return None, None, None
    
    def _get_version(self, conn) -> Optional[str]:
        """Get PostgreSQL version."""
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT version();")
            version = cursor.fetchone()[0]
            cursor.close()
            return version
        except:
            return None
    
    def _check_dangerous_extensions(self, conn) -> List[str]:
        """Check for dangerous extensions installed."""
        dangerous_found = []
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT extname FROM pg_extension;")
            installed_extensions = [row[0] for row in cursor.fetchall()]
            cursor.close()
            
            for ext in self.dangerous_extensions:
                if ext in installed_extensions:
                    dangerous_found.append(ext)
        except:
            pass
        
        return dangerous_found
    
    def _check_create_extension_privilege(self, conn) -> bool:
        """Check if current user can create extensions."""
        try:
            cursor = conn.cursor()
            # Check if user is superuser
            cursor.execute("SELECT usesuper FROM pg_user WHERE usename = current_user;")
            is_superuser = cursor.fetchone()[0]
            cursor.close()
            return is_superuser
        except:
            return False
    
    def _check_copy_program_privilege(self, conn) -> bool:
        """Check if COPY FROM PROGRAM is available (requires superuser)."""
        try:
            cursor = conn.cursor()
            # Check if user is superuser (required for COPY FROM PROGRAM)
            cursor.execute("SELECT usesuper FROM pg_user WHERE usename = current_user;")
            is_superuser = cursor.fetchone()[0]
            cursor.close()
            return is_superuser
        except:
            return False

def main():
    """Main entry point for template."""
    if len(sys.argv) != 3:
        print("Usage: postgresql-extension-rce.py <target> <port>", file=sys.stderr)
        sys.exit(1)
    
    target = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Error: Port must be an integer", file=sys.stderr)
        sys.exit(1)
    
    scanner = PostgreSQLExtensionRCE(target, port)
    result = scanner.scan()
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# @id: ftp-anonymous-access
# @name: FTP Anonymous Access Detection
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects FTP servers allowing anonymous login, which can expose sensitive files
# @tags: ftp, anonymous, file-access, network, credentials
# @cwe: CWE-284
# @cvss: 7.5
# @references: https://www.rfc-editor.org/rfc/rfc959, https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
# @confidence: 95
# @version: 1.0.0
#
# WHY PYTHON?
# FTP Anonymous Access detection requires:
# - Multi-step stateful protocol conversation (USER → PASS → PWD → LIST)
# - Response code parsing and branching logic
# - Directory listing and file enumeration
# - This is IMPOSSIBLE in YAML - requires actual conversation handling
#
# WHAT IT DOES:
# 1. Connects to FTP server
# 2. Attempts login with anonymous/guest credentials
# 3. Lists accessible directories and files
# 4. Reports exposure level and sample files
"""
CERT-X-GEN FTP Anonymous Access Detection

This template demonstrates stateful protocol intelligence for FTP.
It performs a full FTP conversation to determine if anonymous login
is allowed and what files are accessible.
"""

import json
import os
import socket
import sys
from datetime import datetime
from typing import Dict, List, Any, Tuple

# Template metadata
METADATA = {
    "id": "ftp-anonymous-access",
    "name": "FTP Anonymous Access Detection",
    "author": "CERT-X-GEN Security Team",
    "severity": "high",
    "description": "Detects FTP servers allowing anonymous login",
    "tags": ["ftp", "anonymous", "file-access", "network", "credentials"],
    "language": "python",
    "confidence": 95,
    "cwe": ["CWE-284"],
    "cvss_score": 7.5,
    "references": [
        "https://www.rfc-editor.org/rfc/rfc959",
        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
    ]
}


class FTPScanner:
    """FTP Anonymous Access Scanner with stateful protocol handling."""
    
    def __init__(self, host: str, port: int = 21):
        self.host = host
        self.port = port
        self.sock = None
        self.evidence = {}
        self.findings = []
        self.banner = None
        self.timeout = 10
        self.logged_in = False
        
        # Anonymous credentials to try
        self.anon_users = ['anonymous', 'ftp', 'guest']
        self.anon_passwords = ['anonymous@', 'ftp@', 'guest@', '']
    
    def connect(self) -> bool:
        """Establish connection to FTP server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            
            # Read banner (220 response)
            response = self._recv()
            if response and response.startswith('220'):
                self.banner = response.strip()
                self.evidence['banner'] = self.banner
                return True
            return False
        except Exception as e:
            self.evidence['connection_error'] = str(e)
            return False
    
    def _send(self, command: str) -> None:
        """Send FTP command."""
        self.sock.send((command + "\r\n").encode())
    
    def _recv(self) -> str:
        """Receive FTP response (handles multi-line)."""
        response = ""
        try:
            while True:
                data = self.sock.recv(4096).decode('utf-8', errors='ignore')
                response += data
                if not data:
                    break
                # Check for end of response
                lines = response.strip().split('\r\n')
                if lines:
                    last_line = lines[-1]
                    # Response complete if line starts with 3 digits and space
                    if len(last_line) >= 4 and last_line[:3].isdigit() and last_line[3] == ' ':
                        break
        except socket.timeout:
            pass
        return response
    
    def _get_code(self, response: str) -> int:
        """Extract response code from FTP response."""
        if response and len(response) >= 3:
            try:
                return int(response[:3])
            except ValueError:
                pass
        return 0
    
    def login_anonymous(self) -> Tuple[bool, str, str]:
        """
        Attempt anonymous login with various credential combinations.
        Returns: (success, username_used, response)
        """
        for user in self.anon_users:
            for passwd in self.anon_passwords:
                # Send USER command
                self._send(f"USER {user}")
                user_response = self._recv()
                user_code = self._get_code(user_response)
                
                # 230 = logged in immediately (no password needed)
                if user_code == 230:
                    self.logged_in = True
                    self.evidence['login_user'] = user
                    self.evidence['login_type'] = 'no_password'
                    return True, user, user_response
                
                # 331 = password required
                if user_code == 331:
                    self._send(f"PASS {passwd}")
                    pass_response = self._recv()
                    pass_code = self._get_code(pass_response)
                    
                    # 230 = logged in successfully
                    if pass_code == 230:
                        self.logged_in = True
                        self.evidence['login_user'] = user
                        self.evidence['login_pass'] = passwd or '(empty)'
                        self.evidence['login_type'] = 'anonymous'
                        return True, user, pass_response
                
                # 530 = login failed, try next
                # Reset connection for next attempt
                try:
                    self._send("RSET")
                    self._recv()
                except Exception:
                    pass
        
        return False, '', ''

    def get_pwd(self) -> str:
        """Get current working directory."""
        if not self.logged_in:
            return ""
        try:
            self._send("PWD")
            response = self._recv()
            # Extract path from response like: 257 "/" is current directory
            if '257' in response:
                start = response.find('"')
                end = response.find('"', start + 1)
                if start != -1 and end != -1:
                    return response[start+1:end]
        except Exception:
            pass
        return "/"
    
    def list_files(self, path: str = ".") -> List[str]:
        """List files in directory using NLST (simpler than LIST)."""
        files = []
        if not self.logged_in:
            return files
        
        try:
            # Use PASV mode for data connection
            self._send("PASV")
            pasv_response = self._recv()
            
            if '227' not in pasv_response:
                return files
            
            # Parse PASV response to get data port
            # Format: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
            start = pasv_response.find('(')
            end = pasv_response.find(')')
            if start == -1 or end == -1:
                return files
            
            parts = pasv_response[start+1:end].split(',')
            if len(parts) != 6:
                return files
            
            data_host = '.'.join(parts[:4])
            data_port = int(parts[4]) * 256 + int(parts[5])
            
            # Connect to data port
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.settimeout(5)
            data_sock.connect((data_host, data_port))
            
            # Send NLST command
            self._send(f"NLST {path}")
            list_response = self._recv()
            
            if self._get_code(list_response) in [125, 150]:
                # Receive file listing
                data = b''
                while True:
                    try:
                        chunk = data_sock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    except Exception:
                        break
                
                data_sock.close()
                
                # Read completion response
                self._recv()
                
                # Parse file list
                files = [f.strip() for f in data.decode('utf-8', errors='ignore').split('\n') if f.strip()]
            
            data_sock.close()
            
        except Exception as e:
            self.evidence['list_error'] = str(e)
        
        return files[:50]  # Limit to 50 files
    
    def quit(self) -> None:
        """Close FTP session properly."""
        try:
            self._send("QUIT")
            self._recv()
            self.sock.close()
        except Exception:
            pass
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform full scan and return findings."""
        
        # Step 1: Connect
        if not self.connect():
            return self.findings
        
        # Step 2: Attempt anonymous login
        login_ok, username, response = self.login_anonymous()
        
        if login_ok:
            # Step 3: Get current directory
            cwd = self.get_pwd()
            self.evidence['current_directory'] = cwd
            
            # Step 4: List files
            files = self.list_files()
            self.evidence['files'] = files
            self.evidence['file_count'] = len(files)
            
            # Build description
            desc = f"FTP server at {self.host}:{self.port} allows anonymous login. "
            desc += f"Logged in as '{username}'. "
            
            if self.banner:
                desc += f"Banner: {self.banner[:80]}. "
            
            if files:
                desc += f"Found {len(files)} files/directories accessible. "
                sample = ', '.join(files[:5])
                desc += f"Sample: {sample}. "
            
            desc += "Anonymous FTP access can expose sensitive files and allow unauthorized uploads."
            
            # Determine severity based on what's accessible
            severity = "high"
            if any(f for f in files if any(s in f.lower() for s in ['passwd', 'shadow', 'config', 'backup', '.sql', '.key', '.pem'])):
                severity = "critical"
            
            self.findings.append({
                "id": METADATA['id'],
                "name": METADATA['name'],
                "severity": severity,
                "confidence": METADATA['confidence'],
                "title": f"FTP Anonymous Access on {self.host}:{self.port}",
                "description": desc,
                "evidence": self.evidence,
                "remediation": "Disable anonymous FTP access unless absolutely required. "
                              "If anonymous access is needed, restrict to read-only and limit to non-sensitive directories. "
                              "Use SFTP/FTPS with proper authentication instead.",
                "cwe": METADATA['cwe'],
                "cvss_score": METADATA['cvss_score'],
                "tags": METADATA['tags'],
                "matched_at": f"{self.host}:{self.port}",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        # Cleanup
        self.quit()
        
        return self.findings


def main():
    """Main execution."""
    host = os.getenv('CERT_X_GEN_TARGET_HOST')
    port_str = os.getenv('CERT_X_GEN_TARGET_PORT', '21')
    
    if not host and len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port_str = sys.argv[2]
    
    if not host:
        host = '127.0.0.1'
    
    port = int(port_str)
    
    scanner = FTPScanner(host, port)
    findings = scanner.scan()
    
    result = {
        "findings": findings,
        "metadata": METADATA
    }
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

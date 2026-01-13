#!/usr/bin/env python3
# @id: smtp-open-relay
# @name: SMTP Open Relay Detection
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects SMTP servers configured as open relays, allowing unauthorized email relay
# @tags: smtp, email, relay, network, mail-server
# @cwe: CWE-284
# @cvss: 7.5
# @references: https://www.rfc-editor.org/rfc/rfc5321, https://owasp.org/www-community/vulnerabilities/Mail_Relay
# @confidence: 95
# @version: 1.0.0
#
# WHY PYTHON?
# SMTP Open Relay detection requires:
# - Multi-step stateful protocol conversation (HELO → MAIL FROM → RCPT TO → DATA)
# - Branching logic based on server responses (250 vs 550)
# - Understanding of SMTP response codes and extensions
# - This is IMPOSSIBLE in YAML - requires actual conversation handling
#
# WHAT IT DOES:
# 1. Connects to SMTP server
# 2. Performs EHLO/HELO handshake
# 3. Attempts relay by sending MAIL FROM with external domain
# 4. Attempts RCPT TO with external domain
# 5. Analyzes responses to determine if relay is allowed
# 6. Does NOT actually send email (safe check)
"""
CERT-X-GEN SMTP Open Relay Detection

This template demonstrates stateful protocol intelligence - something
impossible in YAML-based scanners. It performs a full SMTP conversation
to determine if a mail server will relay email for unauthorized senders.
"""

import json
import os
import socket
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Template metadata
METADATA = {
    "id": "smtp-open-relay",
    "name": "SMTP Open Relay Detection",
    "author": "CERT-X-GEN Security Team",
    "severity": "high",
    "description": "Detects SMTP servers configured as open relays",
    "tags": ["smtp", "email", "relay", "network", "mail-server"],
    "language": "python",
    "confidence": 95,
    "cwe": ["CWE-284"],
    "cvss_score": 7.5,
    "references": [
        "https://www.rfc-editor.org/rfc/rfc5321",
        "https://owasp.org/www-community/vulnerabilities/Mail_Relay"
    ]
}


class SMTPScanner:
    """SMTP Open Relay Scanner with stateful protocol handling."""
    
    def __init__(self, host: str, port: int = 25):
        self.host = host
        self.port = port
        self.sock = None
        self.evidence = {}
        self.findings = []
        self.banner = None
        self.extensions = []
        self.timeout = 10
        
        # Test domains - we use invalid TLDs to ensure no actual delivery
        self.test_sender = "test@relay-check.invalid"
        self.test_recipient = "test@external-domain.invalid"
    
    def connect(self) -> bool:
        """Establish connection to SMTP server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            
            # Read banner
            response = self._recv()
            if response and response.startswith('220'):
                self.banner = response
                self.evidence['banner'] = response.strip()
                return True
            return False
        except Exception as e:
            self.evidence['connection_error'] = str(e)
            return False
    
    def _send(self, command: str) -> None:
        """Send SMTP command."""
        self.sock.send((command + "\r\n").encode())
    
    def _recv(self) -> str:
        """Receive SMTP response (handles multi-line)."""
        response = ""
        try:
            while True:
                data = self.sock.recv(4096).decode('utf-8', errors='ignore')
                response += data
                # Check if response is complete (ends with \r\n and code followed by space)
                if not data or (len(response) >= 4 and response[-2:] == '\r\n'):
                    # Check for multi-line response (code followed by -)
                    lines = response.strip().split('\r\n')
                    if lines:
                        last_line = lines[-1]
                        if len(last_line) >= 4 and last_line[3] == ' ':
                            break
                        elif len(last_line) >= 4 and last_line[3] == '-':
                            continue
                    break
        except socket.timeout:
            pass
        return response
    
    def ehlo(self) -> Tuple[bool, str]:
        """Send EHLO and parse extensions."""
        self._send(f"EHLO relay-test.invalid")
        response = self._recv()
        
        if response.startswith('250'):
            # Parse extensions from multi-line response
            lines = response.strip().split('\r\n')
            for line in lines[1:]:
                if len(line) > 4:
                    ext = line[4:].strip()
                    self.extensions.append(ext)
            self.evidence['ehlo_response'] = response.strip()
            self.evidence['extensions'] = self.extensions[:10]  # First 10
            return True, response
        return False, response
    
    def helo(self) -> Tuple[bool, str]:
        """Fallback to HELO if EHLO fails."""
        self._send(f"HELO relay-test.invalid")
        response = self._recv()
        
        if response.startswith('250'):
            self.evidence['helo_response'] = response.strip()
            return True, response
        return False, response


    def mail_from(self, sender: str = None) -> Tuple[bool, str, int]:
        """
        Send MAIL FROM command.
        Returns: (accepted, response, code)
        """
        sender = sender or self.test_sender
        self._send(f"MAIL FROM:<{sender}>")
        response = self._recv()
        
        code = int(response[:3]) if response and len(response) >= 3 else 0
        accepted = code == 250
        
        self.evidence['mail_from_sender'] = sender
        self.evidence['mail_from_response'] = response.strip()
        self.evidence['mail_from_code'] = code
        
        return accepted, response, code
    
    def rcpt_to(self, recipient: str = None) -> Tuple[bool, str, int]:
        """
        Send RCPT TO command - this is the key relay test.
        Returns: (accepted, response, code)
        """
        recipient = recipient or self.test_recipient
        self._send(f"RCPT TO:<{recipient}>")
        response = self._recv()
        
        code = int(response[:3]) if response and len(response) >= 3 else 0
        # 250 = accepted, 251 = will forward, both indicate relay
        accepted = code in [250, 251]
        
        self.evidence['rcpt_to_recipient'] = recipient
        self.evidence['rcpt_to_response'] = response.strip()
        self.evidence['rcpt_to_code'] = code
        
        return accepted, response, code
    
    def rset(self) -> None:
        """Reset the session (cleanup)."""
        try:
            self._send("RSET")
            self._recv()
        except Exception:
            pass
    
    def quit(self) -> None:
        """Close SMTP session properly."""
        try:
            self._send("QUIT")
            self._recv()
            self.sock.close()
        except Exception:
            pass
    
    def test_relay(self) -> bool:
        """
        Perform the full open relay test.
        
        Returns True if relay is allowed (vulnerability found).
        """
        # Step 1: Connect
        if not self.connect():
            return False
        
        # Step 2: EHLO/HELO handshake
        ehlo_ok, _ = self.ehlo()
        if not ehlo_ok:
            helo_ok, _ = self.helo()
            if not helo_ok:
                self.quit()
                return False
        
        # Step 3: MAIL FROM with external sender
        mail_ok, mail_resp, mail_code = self.mail_from()
        if not mail_ok:
            self.evidence['relay_blocked_at'] = 'MAIL FROM'
            self.quit()
            return False
        
        # Step 4: RCPT TO with external recipient - THE KEY TEST
        rcpt_ok, rcpt_resp, rcpt_code = self.rcpt_to()
        
        # Reset and cleanup
        self.rset()
        self.quit()
        
        if rcpt_ok:
            self.evidence['open_relay'] = True
            self.evidence['relay_type'] = 'full'
            return True
        else:
            self.evidence['open_relay'] = False
            self.evidence['relay_blocked_at'] = 'RCPT TO'
            self.evidence['rejection_code'] = rcpt_code
            return False


    def scan(self) -> List[Dict[str, Any]]:
        """Perform full scan and return findings."""
        
        is_open_relay = self.test_relay()
        
        if is_open_relay:
            desc = f"SMTP server at {self.host}:{self.port} is configured as an OPEN RELAY. "
            desc += "The server accepted a message from an external sender to an external recipient. "
            
            if self.banner:
                desc += f"Banner: {self.banner[:100]}. "
            
            if self.extensions:
                desc += f"Extensions: {', '.join(self.extensions[:5])}. "
            
            desc += "Open relays can be abused for spam, phishing campaigns, and bypassing email security controls."
            
            self.findings.append({
                "id": METADATA['id'],
                "name": METADATA['name'],
                "severity": "high",
                "confidence": METADATA['confidence'],
                "title": f"SMTP Open Relay Detected on {self.host}:{self.port}",
                "description": desc,
                "evidence": self.evidence,
                "remediation": "Configure SMTP server to require authentication for relay. "
                              "Restrict relay to authorized IP ranges or authenticated users only. "
                              "Enable SPF, DKIM, and DMARC policies.",
                "cwe": METADATA['cwe'],
                "cvss_score": METADATA['cvss_score'],
                "tags": METADATA['tags'],
                "matched_at": f"{self.host}:{self.port}",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        elif self.evidence.get('banner'):
            # SMTP server found but not open relay - info finding
            desc = f"SMTP server detected at {self.host}:{self.port} but relay is properly restricted. "
            if self.evidence.get('relay_blocked_at'):
                desc += f"Relay blocked at: {self.evidence['relay_blocked_at']}. "
            
            self.findings.append({
                "id": "smtp-server-detected",
                "name": "SMTP Server Detected (Relay Restricted)",
                "severity": "info",
                "confidence": 90,
                "title": f"SMTP Server on {self.host}:{self.port}",
                "description": desc,
                "evidence": {
                    "banner": self.evidence.get('banner'),
                    "relay_blocked_at": self.evidence.get('relay_blocked_at'),
                    "rejection_code": self.evidence.get('rejection_code')
                },
                "matched_at": f"{self.host}:{self.port}",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        return self.findings


def main():
    """Main execution."""
    # Get target from environment or args
    host = os.getenv('CERT_X_GEN_TARGET_HOST')
    port_str = os.getenv('CERT_X_GEN_TARGET_PORT', '25')
    
    if not host and len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port_str = sys.argv[2]
    
    if not host:
        host = '127.0.0.1'
    
    port = int(port_str)
    
    # Run scan
    scanner = SMTPScanner(host, port)
    findings = scanner.scan()
    
    # Output result
    result = {
        "findings": findings,
        "metadata": METADATA
    }
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# @id: dns-zone-transfer
# @name: DNS Zone Transfer (AXFR) Detection
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects DNS servers allowing unauthorized zone transfers (AXFR), which can expose all DNS records
# @tags: dns, axfr, zone-transfer, network, reconnaissance
# @cwe: CWE-200
# @cvss: 7.5
# @references: https://www.rfc-editor.org/rfc/rfc5936, https://owasp.org/www-community/attacks/Domain_Hijacking
# @confidence: 98
# @version: 1.0.0
#
# WHY PYTHON?
# DNS Zone Transfer detection requires:
# - Constructing DNS AXFR query packets
# - Parsing DNS wire format responses
# - Handling multi-message zone data
# - This is a classic network security check - YAML cannot do this
#
# WHAT IT DOES:
# 1. Constructs DNS AXFR request for target domain
# 2. Sends request to DNS server
# 3. Parses response to extract zone records
# 4. Reports all leaked hostnames and records
"""
CERT-X-GEN DNS Zone Transfer (AXFR) Detection

This template detects misconfigured DNS servers that allow zone transfers
to unauthorized clients, potentially exposing the entire DNS zone including
internal hostnames, mail servers, and infrastructure details.
"""

import json
import os
import socket
import struct
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Template metadata
METADATA = {
    "id": "dns-zone-transfer",
    "name": "DNS Zone Transfer (AXFR) Detection",
    "author": "CERT-X-GEN Security Team",
    "severity": "high",
    "description": "Detects DNS servers allowing unauthorized zone transfers",
    "tags": ["dns", "axfr", "zone-transfer", "network", "reconnaissance"],
    "language": "python",
    "confidence": 98,
    "cwe": ["CWE-200"],
    "cvss_score": 7.5,
    "references": [
        "https://www.rfc-editor.org/rfc/rfc5936",
        "https://owasp.org/www-community/attacks/Domain_Hijacking"
    ]
}


class DNSZoneTransferScanner:
    """DNS Zone Transfer (AXFR) Scanner."""
    
    # DNS record types
    RECORD_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
        15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 252: 'AXFR'
    }
    
    def __init__(self, host: str, port: int = 53, domain: str = None):
        self.host = host
        self.port = port
        self.domain = domain or self._guess_domain(host)
        self.evidence = {}
        self.findings = []
        self.records = []
        self.timeout = 10
    
    def _guess_domain(self, host: str) -> str:
        """Try to determine domain from host if not provided."""
        # If it looks like an IP, we need a domain
        try:
            socket.inet_aton(host)
            return "example.com"  # Default for testing
        except:
            # It's likely a hostname
            parts = host.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return host
    
    def _encode_domain(self, domain: str) -> bytes:
        """Encode domain name in DNS wire format."""
        result = b''
        for label in domain.split('.'):
            result += bytes([len(label)]) + label.encode()
        result += b'\x00'
        return result
    
    def _decode_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Decode DNS name from wire format with compression support."""
        labels = []
        original_offset = offset
        jumped = False
        
        while True:
            if offset >= len(data):
                break
            
            length = data[offset]
            
            if length == 0:
                offset += 1
                break
            
            # Check for compression pointer (top 2 bits set)
            if (length & 0xC0) == 0xC0:
                if not jumped:
                    original_offset = offset + 2
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                offset = pointer
                jumped = True
                continue
            
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode('utf-8', errors='ignore'))
            offset += length
        
        return '.'.join(labels), original_offset if jumped else offset
    
    def _build_axfr_query(self) -> bytes:
        """Build DNS AXFR query packet."""
        # Transaction ID
        transaction_id = struct.pack('>H', 0x1234)
        
        # Flags: Standard query
        flags = struct.pack('>H', 0x0000)
        
        # Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
        counts = struct.pack('>HHHH', 1, 0, 0, 0)
        
        # Question section
        qname = self._encode_domain(self.domain)
        qtype = struct.pack('>H', 252)  # AXFR
        qclass = struct.pack('>H', 1)   # IN
        
        return transaction_id + flags + counts + qname + qtype + qclass


    def _parse_response(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse DNS response and extract records."""
        records = []
        
        if len(data) < 12:
            return records
        
        # Parse header
        answer_count = struct.unpack('>H', data[6:8])[0]
        
        # Skip header and question section
        offset = 12
        
        # Skip question
        while offset < len(data) and data[offset] != 0:
            if (data[offset] & 0xC0) == 0xC0:
                offset += 2
                break
            offset += data[offset] + 1
        else:
            offset += 1
        offset += 4  # Skip QTYPE and QCLASS
        
        # Parse answer records
        for _ in range(min(answer_count, 100)):  # Limit records
            if offset >= len(data):
                break
            
            try:
                name, offset = self._decode_name(data, offset)
                
                if offset + 10 > len(data):
                    break
                
                rtype = struct.unpack('>H', data[offset:offset+2])[0]
                rclass = struct.unpack('>H', data[offset+2:offset+4])[0]
                ttl = struct.unpack('>I', data[offset+4:offset+8])[0]
                rdlength = struct.unpack('>H', data[offset+8:offset+10])[0]
                offset += 10
                
                rdata_raw = data[offset:offset+rdlength]
                offset += rdlength
                
                # Parse rdata based on type
                rdata = self._parse_rdata(rtype, rdata_raw, data)
                
                record = {
                    'name': name,
                    'type': self.RECORD_TYPES.get(rtype, str(rtype)),
                    'ttl': ttl,
                    'data': rdata
                }
                records.append(record)
                
            except Exception:
                break
        
        return records
    
    def _parse_rdata(self, rtype: int, rdata: bytes, full_data: bytes) -> str:
        """Parse record data based on type."""
        try:
            if rtype == 1:  # A
                return '.'.join(str(b) for b in rdata)
            elif rtype == 28:  # AAAA
                return ':'.join(f'{rdata[i]:02x}{rdata[i+1]:02x}' for i in range(0, 16, 2))
            elif rtype in [2, 5, 12]:  # NS, CNAME, PTR
                name, _ = self._decode_name(rdata, 0)
                return name
            elif rtype == 15:  # MX
                pref = struct.unpack('>H', rdata[:2])[0]
                name, _ = self._decode_name(rdata, 2)
                return f"{pref} {name}"
            elif rtype == 16:  # TXT
                return rdata[1:rdata[0]+1].decode('utf-8', errors='ignore')
            elif rtype == 6:  # SOA
                return "SOA record"
            else:
                return rdata.hex()
        except Exception:
            return rdata.hex() if rdata else ""


    def test_zone_transfer(self) -> bool:
        """Attempt zone transfer and return True if successful."""
        try:
            # AXFR uses TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Build and send AXFR query (TCP needs length prefix)
            query = self._build_axfr_query()
            length_prefix = struct.pack('>H', len(query))
            sock.send(length_prefix + query)
            
            # Receive response
            all_records = []
            
            while True:
                # Read length prefix
                length_data = sock.recv(2)
                if len(length_data) < 2:
                    break
                
                msg_length = struct.unpack('>H', length_data)[0]
                
                # Read message
                data = b''
                while len(data) < msg_length:
                    chunk = sock.recv(msg_length - len(data))
                    if not chunk:
                        break
                    data += chunk
                
                if len(data) < 12:
                    break
                
                # Check for error response
                rcode = data[3] & 0x0F
                if rcode != 0:
                    self.evidence['rcode'] = rcode
                    self.evidence['error'] = 'Transfer refused' if rcode == 5 else f'Error code {rcode}'
                    break
                
                # Parse records
                records = self._parse_response(data)
                all_records.extend(records)
                
                # Check if this is the last message (ends with SOA)
                if records and records[-1]['type'] == 'SOA' and len(all_records) > 1:
                    break
                
                # Safety limit
                if len(all_records) > 500:
                    break
            
            sock.close()
            
            self.records = all_records
            self.evidence['record_count'] = len(all_records)
            
            return len(all_records) > 0
            
        except socket.timeout:
            self.evidence['error'] = 'Connection timeout'
            return False
        except ConnectionRefusedError:
            self.evidence['error'] = 'Connection refused'
            return False
        except Exception as e:
            self.evidence['error'] = str(e)
            return False
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform zone transfer scan and return findings."""
        
        self.evidence['target_domain'] = self.domain
        self.evidence['dns_server'] = f"{self.host}:{self.port}"
        
        transfer_successful = self.test_zone_transfer()
        
        if transfer_successful and self.records:
            # Extract interesting records
            hostnames = []
            a_records = []
            mx_records = []
            ns_records = []
            
            for rec in self.records:
                if rec['name'] and rec['name'] not in hostnames:
                    hostnames.append(rec['name'])
                if rec['type'] == 'A':
                    a_records.append(f"{rec['name']} -> {rec['data']}")
                elif rec['type'] == 'MX':
                    mx_records.append(rec['data'])
                elif rec['type'] == 'NS':
                    ns_records.append(rec['data'])
            
            self.evidence['hostnames'] = hostnames[:20]
            self.evidence['a_records'] = a_records[:10]
            self.evidence['mx_records'] = mx_records[:5]
            self.evidence['ns_records'] = ns_records[:5]
            
            desc = f"DNS server {self.host}:{self.port} allows zone transfer for domain '{self.domain}'. "
            desc += f"Retrieved {len(self.records)} DNS records exposing {len(hostnames)} unique hostnames. "
            
            if a_records:
                desc += f"Sample A records: {', '.join(a_records[:3])}. "
            
            desc += "Zone transfers expose internal infrastructure, hostnames, and can aid reconnaissance attacks."
            
            self.findings.append({
                "id": METADATA['id'],
                "name": METADATA['name'],
                "severity": "high",
                "confidence": METADATA['confidence'],
                "title": f"DNS Zone Transfer Allowed on {self.host}",
                "description": desc,
                "evidence": self.evidence,
                "remediation": "Restrict zone transfers to authorized secondary DNS servers only. "
                              "Configure 'allow-transfer' ACLs in BIND or equivalent settings. "
                              "Use TSIG keys for authenticated transfers.",
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
    port_str = os.getenv('CERT_X_GEN_TARGET_PORT', '53')
    domain = os.getenv('CERT_X_GEN_DNS_DOMAIN')
    
    if not host and len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port_str = sys.argv[2]
    if len(sys.argv) > 3:
        domain = sys.argv[3]
    
    if not host:
        host = '127.0.0.1'
    
    port = int(port_str)
    
    scanner = DNSZoneTransferScanner(host, port, domain)
    findings = scanner.scan()
    
    result = {
        "findings": findings,
        "metadata": METADATA
    }
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

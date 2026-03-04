#!/usr/bin/env python3
# @id: nbns-name-query-probe
# @name: NBNS Name Query Probe
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Sends a NetBIOS Name Service query and checks for a valid response
# @tags: network, nbns, udp, recon
# @cwe: CWE-200
# @confidence: 85
# @references: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network

import argparse
import json
import os
import socket
import struct
import sys
from typing import Any, Dict, List, Optional


def build_nbns_query(query_id: int = 0x1337) -> bytes:
    # NBNS query for wildcard name "*" (encoded as 32 bytes of 'A' / 'B' nibble encoding).
    header = struct.pack("!HHHHHH", query_id, 0x0000, 1, 0, 0, 0)
    # Encoded name for * (0x2A) followed by padding, per RFC 1002 encoding.
    encoded = "CK" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 32 chars after 'CK'
    qname = b"\x20" + encoded.encode("ascii") + b"\x00"
    question = qname + struct.pack("!HH", 0x0021, 0x0001)  # NBSTAT, IN
    return header + question


def parse_nbns_response(data: bytes, query_id: int) -> bool:
    if len(data) < 12:
        return False
    resp_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if resp_id != query_id:
        return False
    if (flags & 0x8000) == 0:
        return False
    if ancount < 1:
        return False
    if qdcount < 1:
        return False
    return True


def send_nbns_query(host: str, port: int, timeout: float = 3.0) -> Optional[bytes]:
    query_id = 0x1337
    payload = build_nbns_query(query_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(2048)
        if parse_nbns_response(data, query_id):
            return data
    except socket.error:
        return None
    finally:
        sock.close()
    return None


def create_finding(template_id: str, title: str, description: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template_id": template_id,
        "severity": "info",
        "confidence": 85,
        "title": title,
        "description": description,
        "evidence": evidence,
        "cwe": "CWE-200",
        "cvss_score": 0.0,
        "remediation": "Restrict NetBIOS Name Service to trusted networks where possible.",
        "references": [
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NBNS Name Query Probe")
    parser.add_argument("target", nargs="?", help="Target host or IP address")
    parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
    parser.add_argument("--port", type=int, default=137, help="Target port (default: 137)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target = args.target or args.target_flag or os.environ.get("CERT_X_GEN_TARGET_HOST")
    if not target:
        print("Error: No target specified", file=sys.stderr)
        sys.exit(1)

    port = int(os.environ.get("CERT_X_GEN_TARGET_PORT", args.port))

    findings: List[Dict[str, Any]] = []
    response = send_nbns_query(target, port)
    if response is not None:
        findings.append(
            create_finding(
                template_id="nbns-name-query-probe",
                title="NBNS Response Detected",
                description=f"Target {target}:{port} responded to an NBNS name query.",
                evidence={"target": target, "port": port, "response_len": len(response)},
            )
        )

    if args.json or os.environ.get("CERT_X_GEN_MODE") == "engine":
        print(json.dumps(findings, indent=2))
    else:
        if findings:
            print(f"\n[+] Found {len(findings)} issue(s):\n")
            for finding in findings:
                print(f"[{finding['severity'].upper()}] {finding['title']}")
                print(f"    {finding['description']}")
                if args.verbose:
                    print(f"    Evidence: {finding['evidence']}")
                print()
        else:
            print("\n[-] No issues found")


if __name__ == "__main__":
    main()

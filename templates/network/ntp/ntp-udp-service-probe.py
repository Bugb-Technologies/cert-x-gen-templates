#!/usr/bin/env python3
# @id: ntp-udp-service-probe
# @name: NTP UDP Service Probe
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Sends a minimal NTP client request over UDP and checks for a valid response
# @tags: network, ntp, udp, recon
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


def build_ntp_request() -> bytes:
    # LI=0, VN=3, Mode=3 (client)
    return b"\x1b" + b"\x00" * 47


def parse_ntp_response(data: bytes) -> bool:
    if len(data) < 48:
        return False
    first_byte = data[0]
    mode = first_byte & 0x7
    stratum = data[1]
    if mode != 4:
        return False
    if stratum > 15:
        return False
    return True


def send_ntp_probe(host: str, port: int, timeout: float = 3.0) -> Optional[bytes]:
    payload = build_ntp_request()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(2048)
        if parse_ntp_response(data):
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
        "remediation": "Restrict NTP exposure to trusted sources and apply rate limiting.",
        "references": [
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NTP UDP Service Probe")
    parser.add_argument("target", nargs="?", help="Target host or IP address")
    parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
    parser.add_argument("--port", type=int, default=123, help="Target port (default: 123)")
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
    response = send_ntp_probe(target, port)
    if response is not None:
        findings.append(
            create_finding(
                template_id="ntp-udp-service-probe",
                title="NTP Service Responded (UDP)",
                description=f"Target {target}:{port} responded to an NTP client request over UDP.",
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

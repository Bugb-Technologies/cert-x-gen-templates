#!/usr/bin/env python3
# @id: dhcpv6-solicit-response
# @name: DHCPv6 Solicit Response Probe
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Sends a DHCPv6 Solicit and checks for an Advertise/Reply response
# @tags: network, dhcpv6, udp, recon
# @cwe: CWE-200
# @confidence: 80
# @references: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/dhcpv6

import argparse
import json
import os
import socket
import sys
from typing import Any, Dict, List, Optional

DHCPV6_CLIENT_PORT = 546
DHCPV6_SERVER_PORT = 547


def build_solicit(xid: bytes) -> bytes:
    # DHCPv6 Solicit (1) with a minimal Client Identifier option.
    # Option: Client Identifier (1) with DUID-LLT (1) and placeholder data.
    # This is minimal and intended for service presence detection only.
    duid = b"\x00\x01" + b"\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00\x00\x00"
    option = b"\x00\x01" + len(duid).to_bytes(2, "big") + duid
    return b"\x01" + xid + option


def parse_message_type(data: bytes) -> Optional[int]:
    if len(data) < 4:
        return None
    return data[0]


def send_solicit(host: str, port: int, timeout: float = 3.0) -> Optional[bytes]:
    xid = b"\x00\x01\x02"
    payload = build_solicit(xid)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(4096)
        msg_type = parse_message_type(data)
        if msg_type in (2, 7):
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
        "confidence": 80,
        "title": title,
        "description": description,
        "evidence": evidence,
        "cwe": "CWE-200",
        "cvss_score": 0.0,
        "remediation": "Restrict DHCPv6 services to trusted networks and monitor for rogue servers.",
        "references": [
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/dhcpv6"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DHCPv6 Solicit Response Probe")
    parser.add_argument("target", nargs="?", help="Target host or IPv6 address")
    parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
    parser.add_argument("--port", type=int, default=DHCPV6_SERVER_PORT, help="Target port (default: 547)")
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
    response = send_solicit(target, port)
    if response is not None:
        findings.append(
            create_finding(
                template_id="dhcpv6-solicit-response",
                title="DHCPv6 Service Responded",
                description=f"Target {target}:{port} responded to a DHCPv6 Solicit message.",
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

#!/usr/bin/env python3
# @id: mdns-service-discovery-probe
# @name: mDNS Service Discovery Probe
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Sends an mDNS service discovery query and checks for a valid response
# @tags: network, mdns, udp, recon
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


def build_mdns_query(query_name: str, query_id: int = 0x0000) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0000, 1, 0, 0, 0)
    labels = query_name.split(".")
    qname = b"".join(len(label).to_bytes(1, "big") + label.encode("ascii") for label in labels)
    qname += b"\x00"
    question = qname + struct.pack("!HH", 12, 1)  # PTR, IN
    return header + question


def parse_mdns_response(data: bytes) -> bool:
    if len(data) < 12:
        return False
    _, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if (flags & 0x8000) == 0:
        return False
    if (ancount + nscount + arcount) < 1:
        return False
    if qdcount < 1:
        return False
    return True


def send_mdns_query(host: str, port: int, timeout: float = 3.0) -> Optional[bytes]:
    payload = build_mdns_query("_services._dns-sd._udp.local")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(4096)
        if parse_mdns_response(data):
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
        "remediation": "Restrict mDNS to trusted networks and disable it where unnecessary.",
        "references": [
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mDNS Service Discovery Probe")
    parser.add_argument("target", nargs="?", help="Target host or IP address")
    parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
    parser.add_argument("--port", type=int, default=5353, help="Target port (default: 5353)")
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
    response = send_mdns_query(target, port)
    if response is not None:
        findings.append(
            create_finding(
                template_id="mdns-service-discovery-probe",
                title="mDNS Service Discovery Response",
                description=f"Target {target}:{port} responded to an mDNS service discovery query.",
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

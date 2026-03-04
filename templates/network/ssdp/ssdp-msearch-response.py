#!/usr/bin/env python3
# @id: ssdp-msearch-response
# @name: SSDP M-SEARCH Response Probe
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Sends an SSDP M-SEARCH request and checks for device responses
# @tags: network, ssdp, udp, recon
# @cwe: CWE-200
# @confidence: 85
# @references: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network

import argparse
import json
import os
import socket
import sys
from typing import Any, Dict, List, Optional


def build_msearch(host: str, port: int) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}:{port}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT: cert-x-gen/1.0\r\n\r\n"
    ).encode("ascii")


def parse_ssdp_response(data: bytes) -> bool:
    text = data.decode("utf-8", errors="ignore").lower()
    return "http/1.1 200" in text and ("st:" in text or "usn:" in text)


def send_msearch(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    payload = build_msearch(host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(4096)
        if parse_ssdp_response(data):
            return data.decode("utf-8", errors="ignore")
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
        "remediation": "Restrict SSDP/UPnP exposure to trusted networks or disable it.",
        "references": [
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SSDP M-SEARCH Response Probe")
    parser.add_argument("target", nargs="?", help="Target host or IP address")
    parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
    parser.add_argument("--port", type=int, default=1900, help="Target port (default: 1900)")
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
    response = send_msearch(target, port)
    if response is not None:
        findings.append(
            create_finding(
                template_id="ssdp-msearch-response",
                title="SSDP Device Response",
                description=f"Target {target}:{port} responded to an SSDP M-SEARCH request.",
                evidence={"target": target, "port": port, "response_snippet": response[:500]},
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

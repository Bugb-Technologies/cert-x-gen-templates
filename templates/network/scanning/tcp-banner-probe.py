#!/usr/bin/env python3
# @id: tcp-banner-probe
# @name: TCP Banner Probe
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Connects to a TCP port, sends a minimal probe, and captures any banner
# @tags: network, tcp, banner, recon
# @cwe: CWE-200
# @confidence: 85
# @references: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network

import argparse
import json
import os
import socket
import sys
from typing import Any, Dict, List


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
        "remediation": "Avoid exposing unnecessary services and suppress verbose banners when possible.",
        "references": [
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TCP Banner Probe")
    parser.add_argument("target", nargs="?", help="Target host or IP address")
    parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
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
    banner = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, port))
        try:
            sock.sendall(b"\r\n")
        except socket.error:
            pass
        try:
            banner = sock.recv(2048).decode("utf-8", errors="ignore")
        except socket.timeout:
            banner = ""
    except socket.error as exc:
        print(f"Socket error: {exc}", file=sys.stderr)
    finally:
        sock.close()

    if banner:
        findings.append(
            create_finding(
                template_id="tcp-banner-probe",
                title="TCP Service Banner Detected",
                description=f"Target {target}:{port} returned a service banner.",
                evidence={"target": target, "port": port, "banner": banner[:500]},
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

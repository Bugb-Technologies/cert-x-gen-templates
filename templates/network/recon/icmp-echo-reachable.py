#!/usr/bin/env python3
# @id: icmp-echo-reachable
# @name: ICMP Echo Reachability
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Detects whether a target responds to ICMP echo requests (ping)
# @tags: network, recon, icmp, availability
# @cwe: CWE-200
# @confidence: 75
# @references: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network

import argparse
import json
import os
import platform
import subprocess
import sys
from typing import Any, Dict, List, Optional


def run_ping(host: str, timeout_sec: int = 2) -> Optional[str]:
    system = platform.system().lower()
    if system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec * 1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), host]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec + 2,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

    if result.returncode == 0:
        return result.stdout.strip()

    return None


def create_finding(template_id: str, title: str, description: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template_id": template_id,
        "severity": "info",
        "confidence": 75,
        "title": title,
        "description": description,
        "evidence": evidence,
        "cwe": "CWE-200",
        "cvss_score": 0.0,
        "remediation": "Consider limiting ICMP exposure where appropriate and monitoring ICMP traffic.",
        "references": [
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ICMP Echo Reachability")
    parser.add_argument("target", nargs="?", help="Target host or IP address")
    parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
    parser.add_argument("--port", type=int, default=80, help="Unused port (required by CLI contract)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target = args.target or args.target_flag or os.environ.get("CERT_X_GEN_TARGET_HOST")
    if not target:
        print("Error: No target specified", file=sys.stderr)
        sys.exit(1)

    findings: List[Dict[str, Any]] = []
    output = run_ping(target)

    if output is not None:
        findings.append(
            create_finding(
                template_id="icmp-echo-reachable",
                title="ICMP Echo Response Detected",
                description=f"Target {target} responded to an ICMP echo request.",
                evidence={"ping_output": output[:1000]},
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

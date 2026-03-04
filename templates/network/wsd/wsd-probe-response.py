#!/usr/bin/env python3
# @id: wsd-probe-response
# @name: WSD Probe Response
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Sends a WS-Discovery probe and checks for a valid response
# @tags: network, wsd, udp, recon
# @cwe: CWE-200
# @confidence: 85
# @references: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network

import argparse
import json
import os
import socket
import sys
import uuid
from typing import Any, Dict, List, Optional


def build_probe(message_id: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{message_id}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>
""".encode("utf-8")


def parse_probe_response(data: bytes) -> bool:
    text = data.decode("utf-8", errors="ignore").lower()
    return "probe" in text and "discovery" in text


def send_probe(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    message_id = str(uuid.uuid4())
    payload = build_probe(message_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(8192)
        if parse_probe_response(data):
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
        "remediation": "Restrict WS-Discovery to trusted networks and disable it if not needed.",
        "references": [
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WSD Probe Response")
    parser.add_argument("target", nargs="?", help="Target host or IP address")
    parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
    parser.add_argument("--port", type=int, default=3702, help="Target port (default: 3702)")
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
    response = send_probe(target, port)
    if response is not None:
        findings.append(
            create_finding(
                template_id="wsd-probe-response",
                title="WSD Probe Response Detected",
                description=f"Target {target}:{port} responded to a WS-Discovery probe.",
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

#!/usr/bin/env python3
# @id: cursor-mcpoison-config-risk
# @name: Cursor MCP Config Command Risk (MCPoison)
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects potentially dangerous MCP command configurations in Cursor .cursor mcp.json files (MCPoison risk)
# @tags: cursor, mcp, mcpoison, ide, rce, config, cve-2025-54136
# @cwe: CWE-829
# @confidence: 70
# @references: https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/

import json
import sys
import os
from typing import List, Dict, Any

# Common command interpreters that indicate higher risk if present in MCP configs
SUSPICIOUS_COMMANDS = {
    "cmd.exe",
    "powershell",
    "pwsh",
    "bash",
    "sh",
    "zsh",
    "python",
    "python3",
    "node",
}

SUSPICIOUS_ARGS = {
    "/c",
    "-c",
    "-Command",
    "-EncodedCommand",
}

MCP_PATHS = [
    ".cursor/mcp.json",
    ".cursor/rules/mcp.json",
]


class CertXGenTemplate:
    def __init__(self):
        self.id = "cursor-mcpoison-config-risk"
        self.name = "Cursor MCP Config Command Risk (MCPoison)"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "high"
        self.tags = ["cursor", "mcp", "mcpoison", "ide", "rce", "config", "cve-2025-54136"]
        self.confidence = 70
        self.cwe = "CWE-829"
        self.target = None
        self.context = {}

    def execute(self, target: str, port: int = 0) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if not target:
            return findings

        base_path = target
        if not os.path.exists(base_path):
            return findings

        if os.path.isfile(base_path):
            base_dir = os.path.dirname(base_path)
        else:
            base_dir = base_path

        for rel_path in MCP_PATHS:
            mcp_file = os.path.join(base_dir, rel_path)
            if not os.path.isfile(mcp_file):
                continue

            try:
                with open(mcp_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Error reading {mcp_file}: {exc}", file=sys.stderr)
                continue

            mcp_servers = data.get("mcpServers", {})
            if not isinstance(mcp_servers, dict):
                continue

            for name, cfg in mcp_servers.items():
                if not isinstance(cfg, dict):
                    continue
                command = str(cfg.get("command", "")).strip()
                args = cfg.get("args", [])
                if not isinstance(args, list):
                    args = [str(args)]

                cmd_lower = command.lower()
                suspicious_cmd = cmd_lower in SUSPICIOUS_COMMANDS
                suspicious_args = any(str(a) in SUSPICIOUS_ARGS for a in args)

                if suspicious_cmd or suspicious_args:
                    evidence = {
                        "file": mcp_file,
                        "server": name,
                        "command": command,
                        "args": args,
                    }
                    findings.append(
                        self.create_finding(
                            title="Potential MCPoison Risky Command Configuration",
                            description=(
                                "Cursor MCP configuration includes a command or arguments commonly used to "
                                "execute arbitrary shell actions. In Cursor versions vulnerable to MCPoison "
                                "(CVE-2025-54136), command/args changes may execute without re-approval."
                            ),
                            evidence=evidence,
                        )
                    )

        return findings

    def create_finding(self, title: str, description: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "template_id": self.id,
            "template_name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": title,
            "description": description,
            "matched_at": evidence.get("file", "unknown"),
            "evidence": evidence,
            "cwe": self.cwe,
            "cvss_score": 7.5,
            "remediation": self.get_remediation(),
            "references": self.get_references(),
        }

    def get_remediation(self) -> str:
        return (
            "1. Upgrade Cursor to version 1.3 or later.\n"
            "2. Treat .cursor/mcp.json as code: require reviews and CI checks.\n"
            "3. Avoid untrusted MCP configurations; prefer signed or centrally managed configs.\n"
            "4. Monitor for unexpected changes in MCP command/args settings.\n"
        )

    def get_references(self) -> List[str]:
        return [
            "https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/",
        ]

    def parse_arguments(self):
        import argparse

        parser = argparse.ArgumentParser(
            description=self.name,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("target", nargs="?", help="Target path (repository root)")
        parser.add_argument("--target", dest="target_flag", help="Target path (alternative)")
        parser.add_argument("--json", action="store_true", help="Output findings as JSON")
        return parser.parse_args()

    def run(self):
        args = self.parse_arguments()
        target = args.target or args.target_flag
        if not target and "CERT_X_GEN_TARGET_HOST" in os.environ:
            target = os.environ["CERT_X_GEN_TARGET_HOST"]

        if not target:
            print("[]")
            sys.exit(0)

        findings = self.execute(target, 0)
        if args.json or os.environ.get("CERT_X_GEN_MODE") == "engine":
            print(json.dumps(findings, indent=2))
        else:
            print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    template = CertXGenTemplate()
    template.run()

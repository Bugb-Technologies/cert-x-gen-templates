#!/usr/bin/env python3
# @id: copilot-yolo-autoapprove-enabled
# @name: GitHub Copilot YOLO Mode Enabled (Static Scan)
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects VS Code settings that enable Copilot YOLO mode (chat.tools.autoApprove=true)
# @tags: ai, copilot, vscode, prompt-injection, yolo, autoapprove, rce, static-scan
# @cwe: CWE-306
# @confidence: 70
# @references: https://blog.trailofbits.com/2025/08/06/prompt-injection-engineering-for-attackers-exploiting-github-copilot/

import json
import os
import re
import sys
from typing import Dict, List, Any

EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
}

SETTINGS_FILE_NAMES = {
    "settings.json",
}

WORKSPACE_SUFFIX = ".code-workspace"

AUTOAPPROVE_REGEX = re.compile(r"\"chat\.tools\.autoApprove\"\s*:\s*true", re.IGNORECASE)


def should_skip_dir(dirname: str) -> bool:
    return dirname in EXCLUDE_DIRS


def iter_candidate_files(root: str) -> List[str]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        for filename in filenames:
            if filename in SETTINGS_FILE_NAMES or filename.endswith(WORKSPACE_SUFFIX):
                files.append(os.path.join(dirpath, filename))
    return files


def scan_file(path: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as exc:
        sys.stderr.write(f"Error reading {path}: {exc}\n")
        return findings

    for idx, line in enumerate(lines, start=1):
        if AUTOAPPROVE_REGEX.search(line):
            findings.append(
                {
                    "file": path,
                    "line": idx,
                    "snippet": line.strip(),
                }
            )
    return findings


class CertXGenTemplate:
    def __init__(self):
        self.id = "copilot-yolo-autoapprove-enabled"
        self.name = "GitHub Copilot YOLO Mode Enabled (Static Scan)"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "high"
        self.tags = ["ai", "copilot", "vscode", "prompt-injection", "yolo", "autoapprove", "rce", "static-scan"]
        self.confidence = 70
        self.cwe = "CWE-306"

    def execute(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not target or not os.path.exists(target):
            return findings

        root = target if os.path.isdir(target) else os.path.dirname(target)
        for path in iter_candidate_files(root):
            for result in scan_file(path):
                findings.append(
                    self.create_finding(
                        title="Copilot YOLO Mode Enabled",
                        description=(
                            "VS Code settings enable chat.tools.autoApprove=true, allowing Copilot to execute "
                            "tool calls without user approval. This increases prompt-injection risk and can lead "
                            "to local command execution."
                        ),
                        evidence={
                            "file": result["file"],
                            "line": result["line"],
                            "snippet": result["snippet"],
                        },
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
            "cvss_score": 8.0,
            "remediation": self.get_remediation(),
            "references": self.get_references(),
        }

    def get_remediation(self) -> str:
        return (
            "1. Remove chat.tools.autoApprove or set it to false in VS Code settings.\n"
            "2. Restrict Copilot tool execution to explicit user approvals.\n"
            "3. Review repositories for prompt-injection payloads in docs and issues.\n"
            "4. Apply least-privilege workspace settings for AI agents.\n"
        )

    def get_references(self) -> List[str]:
        return [
            "https://blog.trailofbits.com/2025/08/06/prompt-injection-engineering-for-attackers-exploiting-github-copilot/",
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

        findings = self.execute(target)
        if args.json or os.environ.get("CERT_X_GEN_MODE") == "engine":
            print(json.dumps(findings, indent=2))
        else:
            print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    template = CertXGenTemplate()
    template.run()

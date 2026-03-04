#!/usr/bin/env python3
# @id: claude-code-sed-bypass-usage
# @name: Claude Code sed DSL Bypass Indicators (Static Scan)
# @author: CERT-X-GEN Security Team
# @severity: medium
# @description: Detects sed usage patterns that can write/read arbitrary files (CVE-2025-64755 context)
# @tags: ai, claude-code, sed, command-validation, rce, static-scan, cve-2025-64755
# @cwe: CWE-94
# @confidence: 60
# @references: https://specterops.io/blog/2025/11/21/an-evening-with-claude-code/

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

CODE_EXTENSIONS = {
    ".sh",
    ".bash",
    ".zsh",
    ".command",
    ".txt",
    ".md",
}

# Heuristic patterns for sed commands that can write/read files without whitespace
RULES = [
    {
        "id": "sed_write_no_space",
        "severity": "medium",
        "pattern": re.compile(r"\bsed\b[^\n]*\b[0-9,]*w/[^\s'\"]+", re.IGNORECASE),
        "title": "sed write (w) without whitespace",
        "description": "sed can write to arbitrary files using the w command without whitespace (e.g., 1,1w/path).",
    },
    {
        "id": "sed_read_no_space",
        "severity": "medium",
        "pattern": re.compile(r"\bsed\b[^\n]*\br/[^\s'\"]+", re.IGNORECASE),
        "title": "sed read (r) without whitespace",
        "description": "sed can read arbitrary files using the r command without whitespace (e.g., r/path).",
    },
    {
        "id": "sed_exec_token",
        "severity": "high",
        "pattern": re.compile(r"\bsed\b[^\n]*\b[eE]\b", re.IGNORECASE),
        "title": "sed execution token (e/E)",
        "description": "GNU/BSD sed can execute shell commands using the e/E command token.",
    },
]


def should_skip_dir(dirname: str) -> bool:
    return dirname in EXCLUDE_DIRS


def iter_files(root: str) -> List[str]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in CODE_EXTENSIONS:
                files.append(os.path.join(dirpath, filename))
    return files


def scan_file(path: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as exc:
        print(f"Error reading {path}: {exc}", file=sys.stderr)
        return findings

    for idx, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append(
                    {
                        "rule_id": rule["id"],
                        "file": path,
                        "line": idx,
                        "snippet": line.strip(),
                        "severity": rule["severity"],
                        "title": rule["title"],
                        "description": rule["description"],
                    }
                )
    return findings


class CertXGenTemplate:
    def __init__(self):
        self.id = "claude-code-sed-bypass-usage"
        self.name = "Claude Code sed DSL Bypass Indicators (Static Scan)"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "medium"
        self.tags = ["ai", "claude-code", "sed", "command-validation", "rce", "static-scan", "cve-2025-64755"]
        self.confidence = 60
        self.cwe = "CWE-94"

    def execute(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not target or not os.path.exists(target):
            return findings

        root = target if os.path.isdir(target) else os.path.dirname(target)
        for path in iter_files(root):
            for result in scan_file(path):
                findings.append(
                    self.create_finding(
                        title=result["title"],
                        description=result["description"],
                        evidence={
                            "file": result["file"],
                            "line": result["line"],
                            "snippet": result["snippet"],
                            "rule_id": result["rule_id"],
                        },
                        severity=result["severity"],
                    )
                )
        return findings

    def create_finding(
        self,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        severity: str,
    ) -> Dict[str, Any]:
        return {
            "template_id": self.id,
            "template_name": self.name,
            "severity": severity,
            "confidence": self.confidence,
            "title": title,
            "description": description,
            "matched_at": evidence.get("file", "unknown"),
            "evidence": evidence,
            "cwe": self.cwe,
            "cvss_score": 5.5,
            "remediation": self.get_remediation(),
            "references": self.get_references(),
        }

    def get_remediation(self) -> str:
        return (
            "1. Treat LLM tool policies as untrusted; require explicit user approval.\n"
            "2. Avoid allowing sed write/read/execute forms in allowlists.\n"
            "3. Harden CLI validation and audit command usage in logs.\n"
            "4. Upgrade to patched Claude Code versions if applicable.\n"
        )

    def get_references(self) -> List[str]:
        return [
            "https://specterops.io/blog/2025/11/21/an-evening-with-claude-code/",
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

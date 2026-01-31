#!/usr/bin/env python3
# @id: pytorch-unsafe-load-usage
# @name: PyTorch Unsafe torch.load Usage (Static Scan)
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects PyTorch torch.load calls that may deserialize untrusted data (missing weights_only=True)
# @tags: ai, ml, pytorch, torch, deserialization, rce, static-scan
# @cwe: CWE-502
# @confidence: 70
# @references: https://pytorch.org/docs/stable/notes/serialization.html#security

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
    ".py",
    ".pyi",
    ".ipynb",
}

RULES = [
    {
        "id": "torch_load_weights_only_false",
        "severity": "high",
        "pattern": re.compile(r"\btorch\.load\s*\([^\n]*weights_only\s*=\s*False", re.IGNORECASE),
        "title": "torch.load with weights_only=False",
        "description": "torch.load with weights_only=False can execute pickle payloads. Use weights_only=True or safe loaders for untrusted models.",
    },
    {
        "id": "torch_load_missing_weights_only",
        "severity": "medium",
        "pattern": re.compile(r"\btorch\.load\s*\(", re.IGNORECASE),
        "title": "torch.load without weights_only",
        "description": "torch.load without weights_only=True can deserialize pickle objects. Review for untrusted model sources.",
        "suppress_if": re.compile(r"\bweights_only\s*=\s*True", re.IGNORECASE),
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
                if "suppress_if" in rule and rule["suppress_if"].search(line):
                    continue
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
        self.id = "pytorch-unsafe-load-usage"
        self.name = "PyTorch Unsafe torch.load Usage (Static Scan)"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "high"
        self.tags = ["ai", "ml", "pytorch", "torch", "deserialization", "rce", "static-scan"]
        self.confidence = 70
        self.cwe = "CWE-502"

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
            "cvss_score": 7.5,
            "remediation": self.get_remediation(),
            "references": self.get_references(),
        }

    def get_remediation(self) -> str:
        return (
            "1. Avoid deserializing untrusted PyTorch checkpoints.\n"
            "2. Prefer torch.load(..., weights_only=True).\n"
            "3. Use safe formats (e.g., safetensors, ONNX) for untrusted models.\n"
            "4. Verify model provenance and signatures before loading.\n"
        )

    def get_references(self) -> List[str]:
        return [
            "https://pytorch.org/docs/stable/notes/serialization.html#security",
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

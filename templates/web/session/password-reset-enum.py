#!/usr/bin/env python3
#
# @id: password-reset-enum
# @name: Password Reset User Enumeration via Response Differences
# @author: BugB Security Team
# @severity: medium
# @description: Tests whether the password reset flow leaks valid email addresses through differing HTTP status codes, response bodies, response times, or error messages between existing and non-existing accounts.
# @tags: user-enumeration,password-reset,information-disclosure,owasp-a02,timing-attack,account-oracle
# @cwe: CWE-204
# @cvss: 5.3
# @confidence: 80
# @version: 1.0.0
# @references: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account,https://cwe.mitre.org/data/definitions/204.html
# @context_vars: login_url:required
# @vuln_class: info_disclosure
# @hypothesis_tags: user-enumeration, password-reset, information-disclosure, account-oracle, timing-side-channel
# @batch_group: auth-context
# @auto_probe: true
#

import json
import os
import statistics
import time
import requests
import urllib3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEMPLATE_ID   = "password-reset-enum"
TEMPLATE_NAME = "Password Reset User Enumeration via Response Differences"

# Dummy addresses: one very likely to exist, one guaranteed random
CANARY_EXIST    = "admin@juice-sh.op"      # common Juice Shop admin
CANARY_NONEXIST = "zzz_nonexistent_xq7k@example-cxg-test.invalid"

RESET_PATH_PROBES = [
    "/api/Users/reset-password",
    "/rest/user/reset-password",
    "/api/v1/auth/forgot-password",
    "/api/forgot-password",
    "/auth/reset",
    "/account/forgot",
    "/users/password/reset",
    "/api/auth/reset",
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def get_target() -> Tuple[Optional[str], int]:
    host = os.environ.get("CERT_X_GEN_TARGET_HOST")
    port = int(os.environ.get("CERT_X_GEN_TARGET_PORT", "80"))
    return host, port

def get_context() -> Dict[str, Any]:
    raw = os.environ.get("CERT_X_GEN_CONTEXT", "{}")
    try:
        return json.loads(raw)
    except Exception:
        return {}

def build_base_url(host: str, port: int) -> str:
    scheme = "https" if port == 443 else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"

def missing_context_finding(host: str, missing: List[str]) -> Dict[str, Any]:
    return {
        "template_id": TEMPLATE_ID,
        "template_name": TEMPLATE_NAME,
        "host": host,
        "matched_at": host,
        "severity": "info",
        "confidence": 100,
        "title": f"Template requires context: {', '.join(missing)} missing",
        "description": (
            f"{TEMPLATE_NAME} needs the login/reset URL to probe. "
            "Re-run with: --context '{\"login_url\":\"/rest/user/login\"}'"
        ),
        "evidence": {"missing_vars": missing},
        "cwe": "CWE-204",
        "cvss_score": 0.0,
        "remediation": "Provide login_url via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── HTTP helpers ───────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.verify = False
HEADERS = {"User-Agent": "CXG-Enum-Scanner/1.0", "Content-Type": "application/json",
           "Accept": "application/json"}

def discover_reset_endpoint(base_url: str, login_url: str) -> Optional[str]:
    """Derive reset endpoint from login_url, or probe common paths."""
    # Try to swap 'login' → 'reset-password' in the supplied login_url
    for candidate in (
        login_url.replace("login", "reset-password"),
        login_url.replace("login", "forgot-password"),
        login_url.replace("login", "forgot"),
    ):
        if candidate != login_url:
            url = candidate if candidate.startswith("http") else base_url + candidate
            try:
                r = SESSION.post(url, json={"email": "probe@test.com"},
                                 headers=HEADERS, timeout=5)
                if r.status_code not in (404, 405):
                    return candidate
            except Exception:
                pass

    # Probe wordlist
    for path in RESET_PATH_PROBES:
        url = base_url + path
        try:
            r = SESSION.post(url, json={"email": "probe@test.com"},
                             headers=HEADERS, timeout=5)
            if r.status_code not in (404, 405):
                return path
        except Exception:
            pass

    return None

def timed_reset_request(url: str, email: str, base_url: str) -> Tuple[Optional[int], str, float]:
    """Returns (status_code, body_text, elapsed_seconds)."""
    full = url if url.startswith("http") else base_url + url
    payloads = [{"email": email}, {"Email": email}, {"username": email}]
    for payload in payloads:
        try:
            t0 = time.monotonic()
            r = SESSION.post(full, json=payload, headers=HEADERS, timeout=10)
            elapsed = time.monotonic() - t0
            return r.status_code, r.text, elapsed
        except Exception:
            pass
    return None, "", 0.0

# ── Core test ─────────────────────────────────────────────────────────────────

def test_reset_enum(
    reset_url: str,
    base_url: str,
    host: str,
    known_email: str,
) -> List[Dict[str, Any]]:
    findings = []

    exist_results    = [timed_reset_request(reset_url, known_email, base_url)      for _ in range(2)]
    nonexist_results = [timed_reset_request(reset_url, CANARY_NONEXIST, base_url)  for _ in range(2)]

    exist_codes    = [r[0] for r in exist_results    if r[0] is not None]
    nonexist_codes = [r[0] for r in nonexist_results if r[0] is not None]

    if not exist_codes or not nonexist_codes:
        return findings

    exist_body    = exist_results[0][1].lower()
    nonexist_body = nonexist_results[0][1].lower()

    exist_times    = [r[2] for r in exist_results    if r[2] > 0]
    nonexist_times = [r[2] for r in nonexist_results if r[2] > 0]

    full_url = reset_url if reset_url.startswith("http") else base_url + reset_url

    # Check 1: different HTTP status codes
    if set(exist_codes) != set(nonexist_codes):
        findings.append({
            "template_id": TEMPLATE_ID,
            "template_name": TEMPLATE_NAME,
            "host": host,
            "matched_at": full_url,
            "severity": "medium",
            "confidence": 88,
            "title": "Password reset leaks account existence via HTTP status code",
            "description": (
                f"Reset endpoint returns different status codes for known vs unknown emails. "
                f"Known email: {exist_codes}, Unknown email: {nonexist_codes}. "
                "An attacker can enumerate valid accounts by submitting email addresses."
            ),
            "evidence": {
                "reset_url": full_url,
                "existing_email": known_email,
                "existing_status_codes": exist_codes,
                "nonexistent_status_codes": nonexist_codes,
                "technique": "status_code_difference",
            },
            "cwe": "CWE-204",
            "cvss_score": 5.3,
            "remediation": (
                "Always return the same HTTP status code (200) regardless of whether the "
                "email exists. Use a generic message like 'If this email is registered, "
                "you will receive a reset link.'"
            ),
            "references": [
                "https://cwe.mitre.org/data/definitions/204.html",
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # Check 2: different response bodies
    body_leak_phrases = [
        "email not found", "no account", "not registered",
        "user does not exist", "invalid email", "not exist",
        "account not found", "no user",
    ]
    body_leaks = [p for p in body_leak_phrases if p in nonexist_body and p not in exist_body]
    if body_leaks:
        findings.append({
            "template_id": TEMPLATE_ID,
            "template_name": TEMPLATE_NAME,
            "host": host,
            "matched_at": full_url,
            "severity": "medium",
            "confidence": 85,
            "title": "Password reset leaks account existence via response body",
            "description": (
                f"Reset endpoint returns a user-specific error for unknown emails. "
                f"Leaked phrases: {body_leaks}. "
                "An attacker can enumerate valid accounts by comparing response messages."
            ),
            "evidence": {
                "reset_url": full_url,
                "leaked_phrases": body_leaks,
                "nonexistent_body_preview": nonexist_body[:200],
                "technique": "body_difference",
            },
            "cwe": "CWE-204",
            "cvss_score": 5.3,
            "remediation": (
                "Return a generic, identical response body for all reset requests regardless "
                "of whether the account exists."
            ),
            "references": ["https://cwe.mitre.org/data/definitions/204.html"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # Check 3: timing side-channel (>300ms difference, consistent across samples)
    if exist_times and nonexist_times:
        avg_exist    = statistics.mean(exist_times)
        avg_nonexist = statistics.mean(nonexist_times)
        diff = abs(avg_exist - avg_nonexist)
        if diff > 0.35:
            findings.append({
                "template_id": TEMPLATE_ID,
                "template_name": TEMPLATE_NAME,
                "host": host,
                "matched_at": full_url,
                "severity": "low",
                "confidence": 65,
                "title": "Password reset timing side-channel may leak account existence",
                "description": (
                    f"Average response time for known email ({avg_exist:.2f}s) differs "
                    f"from unknown email ({avg_nonexist:.2f}s) by {diff:.2f}s. "
                    "This timing difference may allow statistical enumeration."
                ),
                "evidence": {
                    "reset_url": full_url,
                    "avg_exist_seconds": round(avg_exist, 3),
                    "avg_nonexist_seconds": round(avg_nonexist, 3),
                    "difference_seconds": round(diff, 3),
                    "technique": "timing_difference",
                },
                "cwe": "CWE-204",
                "cvss_score": 3.7,
                "remediation": (
                    "Use constant-time lookup or artificial delay to equalise response times "
                    "regardless of account existence."
                ),
                "references": ["https://cwe.mitre.org/data/definitions/204.html"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    return findings

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    host, port = get_target()
    if not host:
        print(json.dumps({"findings": []}))
        return

    ctx = get_context()
    base_url = build_base_url(host, port)

    login_url = ctx.get("login_url")
    if not login_url:
        print(json.dumps({"findings": [missing_context_finding(host, ["login_url"])]}))
        return

    # Auto-probe: derive reset endpoint from login_url
    reset_url = ctx.get("reset_url") or discover_reset_endpoint(base_url, login_url)
    if not reset_url:
        print(json.dumps({"findings": []}))
        return

    known_email = ctx.get("email") or CANARY_EXIST

    findings = test_reset_enum(reset_url, base_url, host, known_email)
    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

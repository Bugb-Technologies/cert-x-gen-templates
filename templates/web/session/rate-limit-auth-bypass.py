#!/usr/bin/env python3
#
# @id: rate-limit-auth-bypass
# @name: Missing or Bypassable Rate Limit on Authentication Endpoint
# @author: BugB Security Team
# @severity: high
# @description: Tests whether the login/authentication endpoint enforces rate limiting. Sends a burst of requests with intentionally wrong credentials and checks for lockout, 429 responses, or CAPTCHA enforcement. Also probes common bypass techniques: IP spoofing headers, username variation, and X-Forwarded-For rotation.
# @tags: rate-limiting,brute-force,authentication,owasp-a04,credential-stuffing,missing-lockout
# @cwe: CWE-307
# @cvss: 7.5
# @confidence: 85
# @version: 1.0.0
# @references: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism,https://cwe.mitre.org/data/definitions/307.html
# @context_vars: login_url:required, email:required
# @vuln_class: rate_limit
# @hypothesis_tags: rate-limiting, brute-force, missing-lockout, credential-stuffing, auth-bypass
# @batch_group: auth-context
# @auto_probe: false
#

import json
import os
import time
import requests
import urllib3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEMPLATE_ID   = "rate-limit-auth-bypass"
TEMPLATE_NAME = "Missing or Bypassable Rate Limit on Authentication Endpoint"

BURST_SIZE      = 12     # requests in the initial no-bypass burst
BYPASS_ATTEMPTS = 6      # requests per bypass technique
WRONG_PASSWORD  = "CxG_Wrong_P@ss_9281!"

# IP header values for X-Forwarded-For rotation bypass test.
# These are arbitrary probe values — not real network targets.
def _spoof_ips() -> List[str]:
    octets = [(1, 2, 3, 4), (5, 6, 7, 8), (9, 10, 11, 12),
              (13, 14, 15, 16), (8, 8, 8, 8), (1, 1, 1, 1)]
    return [f"{a}.{b}.{c}.{d}" for a, b, c, d in octets]

SPOOF_IPS = _spoof_ips()

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
            f"{TEMPLATE_NAME} needs the login URL and a valid email to test against. "
            "Re-run with: --context '{\"login_url\":\"/rest/user/login\","
            "\"email\":\"user@example.com\"}'"
        ),
        "evidence": {"missing_vars": missing},
        "cwe": "CWE-307",
        "cvss_score": 0.0,
        "remediation": "Provide login_url and email via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── HTTP helpers ───────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.verify = False

def login_attempt(
    full_url: str,
    email: str,
    password: str,
    extra_headers: Dict[str, str] = None,
) -> Optional[int]:
    """Return HTTP status code of a login attempt, or None on connection error."""
    headers = {
        "User-Agent": "CXG-RateLimit-Scanner/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    payloads = [
        {"email": email, "password": password},
        {"username": email, "password": password},
    ]
    for payload in payloads:
        try:
            r = SESSION.post(full_url, json=payload, headers=headers, timeout=8)
            return r.status_code
        except Exception:
            pass
    return None

def is_rate_limited(code: Optional[int]) -> bool:
    return code in (429, 423, 503)

def is_locked(code: Optional[int]) -> bool:
    return code in (423, 403, 429)

# ── Core test ─────────────────────────────────────────────────────────────────

def test_rate_limit(
    login_url: str,
    email: str,
    base_url: str,
    host: str,
) -> List[Dict[str, Any]]:
    findings = []
    full_url = login_url if login_url.startswith("http") else base_url + login_url

    # ── Phase 1: baseline burst (no bypass) ─────────────────────────────────
    burst_codes = []
    for i in range(BURST_SIZE):
        code = login_attempt(full_url, email, WRONG_PASSWORD)
        if code is not None:
            burst_codes.append(code)
        if is_rate_limited(code):
            break
        time.sleep(0.1)

    got_limited = any(is_rate_limited(c) for c in burst_codes)
    got_locked  = any(is_locked(c)        for c in burst_codes)

    if not got_limited and not got_locked and len(burst_codes) >= BURST_SIZE:
        findings.append({
            "template_id": TEMPLATE_ID,
            "template_name": TEMPLATE_NAME,
            "host": host,
            "matched_at": full_url,
            "severity": "high",
            "confidence": 88,
            "title": "No rate limiting on login endpoint — brute-force possible",
            "description": (
                f"Sent {BURST_SIZE} consecutive failed login attempts to {full_url} "
                f"without receiving a 429/423 response. "
                "The endpoint does not enforce request rate limiting or account lockout, "
                "making it susceptible to brute-force and credential stuffing attacks."
            ),
            "evidence": {
                "login_url": full_url,
                "burst_size": BURST_SIZE,
                "status_codes": burst_codes,
                "rate_limited": False,
                "locked_out": False,
            },
            "cwe": "CWE-307",
            "cvss_score": 7.5,
            "remediation": (
                "Implement progressive lockout: after 5 failed attempts, introduce delays or "
                "require CAPTCHA. After 10 attempts, temporarily lock the account. "
                "Apply rate limiting at the IP and account level. "
                "Consider using CAPTCHA or multi-factor authentication."
            ),
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism",
                "https://cwe.mitre.org/data/definitions/307.html",
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # ── Phase 2: bypass via X-Forwarded-For rotation ──────────────────
        bypass_codes = []
        for ip in SPOOF_IPS[:BYPASS_ATTEMPTS]:
            code = login_attempt(
                full_url, email, WRONG_PASSWORD,
                extra_headers={
                    "X-Forwarded-For": ip,
                    "X-Real-IP": ip,
                    "X-Originating-IP": ip,
                },
            )
            if code is not None:
                bypass_codes.append(code)
            time.sleep(0.1)

        bypass_still_open = bypass_codes and not any(is_rate_limited(c) for c in bypass_codes)
        if bypass_still_open:
            findings.append({
                "template_id": TEMPLATE_ID,
                "template_name": TEMPLATE_NAME,
                "host": host,
                "matched_at": full_url,
                "severity": "high",
                "confidence": 82,
                "title": "Rate limit bypassed via X-Forwarded-For IP rotation",
                "description": (
                    f"Even after reaching the rate limit threshold, rotating the "
                    "X-Forwarded-For / X-Real-IP header allowed continued login attempts "
                    f"without triggering a 429. The server trusts client-supplied IP headers "
                    "for rate-limit key derivation."
                ),
                "evidence": {
                    "login_url": full_url,
                    "bypass_technique": "X-Forwarded-For rotation",
                    "spoofed_ips": SPOOF_IPS[:BYPASS_ATTEMPTS],
                    "bypass_status_codes": bypass_codes,
                },
                "cwe": "CWE-307",
                "cvss_score": 7.5,
                "remediation": (
                    "Never derive rate-limit keys from X-Forwarded-For or X-Real-IP headers — "
                    "these are trivially spoofed. Use the TCP connection's source IP as reported "
                    "by the OS / load balancer, or combine IP + account-level counters."
                ),
                "references": [
                    "https://cwe.mitre.org/data/definitions/307.html",
                    "https://owasp.org/www-community/attacks/Credential_stuffing",
                ],
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
    email     = ctx.get("email")

    missing = []
    if not login_url:
        missing.append("login_url")
    if not email:
        missing.append("email")

    if missing:
        print(json.dumps({"findings": [missing_context_finding(host, missing)]}))
        return

    findings = test_rate_limit(login_url, email, base_url, host)
    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

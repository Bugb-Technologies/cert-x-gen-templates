#!/usr/bin/env python3
#
# @id: session-fixation-check
# @name: Session Fixation — Token Unchanged After Login
# @author: BugB Security Team
# @severity: high
# @description: Tests for session fixation by comparing the session token before and after authentication. If the pre-auth token remains valid post-login, an attacker who pre-seeds that token can hijack the authenticated session.
# @tags: session-fixation,session-management,authentication,owasp-a07,token-reuse
# @cwe: CWE-384
# @cvss: 7.5
# @confidence: 82
# @version: 1.0.0
# @references: https://owasp.org/www-community/attacks/Session_fixation,https://cwe.mitre.org/data/definitions/384.html
# @context_vars: login_url:required, email:required, password:required
# @vuln_class: session_mgmt
# @hypothesis_tags: session-fixation, session-management, token-reuse, broken-authentication
# @batch_group: auth-context
# @auto_probe: false
#

import json
import os
import requests
import urllib3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEMPLATE_ID   = "session-fixation-check"
TEMPLATE_NAME = "Session Fixation — Token Unchanged After Login"

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
            f"{TEMPLATE_NAME} needs login credentials and the login endpoint. "
            "Re-run with: --context '{\"login_url\":\"/rest/user/login\","
            "\"email\":\"user@example.com\",\"password\":\"pass\"}'"
        ),
        "evidence": {"missing_vars": missing},
        "cwe": "CWE-384",
        "cvss_score": 0.0,
        "remediation": "Provide login_url, email, and password via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── Session helpers ────────────────────────────────────────────────────────────

def extract_session_tokens(resp: requests.Response) -> Dict[str, str]:
    """Extract cookies and any token from response headers/body."""
    tokens = {}
    for name, value in resp.cookies.items():
        tokens[f"cookie:{name}"] = value
    # Check Authorization/token in JSON body
    try:
        body = resp.json()
        for key in ("token", "accessToken", "access_token", "sessionToken", "sid"):
            if key in body:
                tokens[f"body:{key}"] = str(body[key])
            # Nested under 'data' or 'authentication'
            for wrapper in ("data", "authentication", "session"):
                if wrapper in body and isinstance(body[wrapper], dict):
                    if key in body[wrapper]:
                        tokens[f"body:{wrapper}.{key}"] = str(body[wrapper][key])
    except Exception:
        pass
    return tokens

def login(login_url: str, email: str, password: str, base_url: str) -> Optional[Tuple[requests.Response, requests.Session]]:
    """Attempt login, return (response, session) or None."""
    full_url = login_url if login_url.startswith("http") else base_url + login_url
    sess = requests.Session()
    sess.verify = False

    payloads = [
        {"email": email, "password": password},
        {"username": email, "password": password},
        {"user": email, "pass": password},
    ]
    for payload in payloads:
        try:
            r = sess.post(
                full_url,
                json=payload,
                headers={"User-Agent": "CXG-Session-Scanner/1.0",
                         "Content-Type": "application/json",
                         "Accept": "application/json"},
                timeout=8,
                allow_redirects=True,
            )
            if r.status_code in (200, 201):
                return r, sess
        except Exception:
            pass

    # Try form-encoded
    for payload in payloads:
        try:
            r = sess.post(
                full_url,
                data=payload,
                headers={"User-Agent": "CXG-Session-Scanner/1.0",
                         "Accept": "application/json"},
                timeout=8,
                allow_redirects=True,
            )
            if r.status_code in (200, 201):
                return r, sess
        except Exception:
            pass

    return None

# ── Core test ─────────────────────────────────────────────────────────────────

def test_session_fixation(
    login_url: str,
    email: str,
    password: str,
    base_url: str,
    host: str,
) -> List[Dict[str, Any]]:
    findings = []

    # Session 1: pre-login — collect any tokens set before auth
    pre_session = requests.Session()
    pre_session.verify = False
    login_full = login_url if login_url.startswith("http") else base_url + login_url

    try:
        pre_resp = pre_session.get(
            login_full.replace("/login", "").replace("/rest/user", "") or base_url,
            timeout=6,
        )
        pre_tokens = {name: val for name, val in pre_session.cookies.items()}
    except Exception:
        pre_tokens = {}

    # Session 2: actual login
    result = login(login_url, email, password, base_url)
    if not result:
        return findings

    login_resp, post_session = result
    post_tokens = extract_session_tokens(login_resp)
    post_cookies = {name: val for name, val in post_session.cookies.items()}

    # Check 1: did any pre-login cookie survive unchanged into post-login?
    for name, pre_val in pre_tokens.items():
        post_val = post_cookies.get(name)
        if post_val and post_val == pre_val:
            findings.append({
                "template_id": TEMPLATE_ID,
                "template_name": TEMPLATE_NAME,
                "host": host,
                "matched_at": login_full,
                "severity": "high",
                "confidence": 88,
                "title": f"Session Fixation: cookie '{name}' unchanged after login",
                "description": (
                    f"Cookie '{name}' had value '{pre_val[:30]}…' before login and retained "
                    f"the same value after successful authentication. "
                    "An attacker who pre-seeds this cookie value can hijack the authenticated session."
                ),
                "evidence": {
                    "cookie_name": name,
                    "pre_login_value": pre_val[:60],
                    "post_login_value": post_val[:60],
                    "login_url": login_full,
                },
                "cwe": "CWE-384",
                "cvss_score": 7.5,
                "remediation": (
                    "Always regenerate the session token upon successful authentication. "
                    "Invalidate any pre-auth session tokens. "
                    "Use SameSite=Strict or SameSite=Lax cookie attributes."
                ),
                "references": [
                    "https://owasp.org/www-community/attacks/Session_fixation",
                    "https://cwe.mitre.org/data/definitions/384.html",
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    # Check 2: is the session token predictable / too short?
    for token_key, token_val in post_tokens.items():
        if len(token_val) < 16:
            findings.append({
                "template_id": TEMPLATE_ID,
                "template_name": TEMPLATE_NAME,
                "host": host,
                "matched_at": login_full,
                "severity": "medium",
                "confidence": 80,
                "title": f"Weak session token: '{token_key}' is only {len(token_val)} chars",
                "description": (
                    f"Post-login session token '{token_key}' is only {len(token_val)} characters, "
                    "making it susceptible to brute-force or enumeration attacks."
                ),
                "evidence": {
                    "token_key": token_key,
                    "token_length": len(token_val),
                    "token_prefix": token_val[:8] + "…",
                },
                "cwe": "CWE-384",
                "cvss_score": 5.3,
                "remediation": (
                    "Use cryptographically random session tokens of at least 128 bits (32 hex chars). "
                    "Tokens should have sufficient entropy to resist brute-force."
                ),
                "references": ["https://cwe.mitre.org/data/definitions/384.html"],
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

    missing = []
    login_url = ctx.get("login_url")
    email     = ctx.get("email")
    password  = ctx.get("password")

    if not login_url:
        missing.append("login_url")
    if not email:
        missing.append("email")
    if not password:
        missing.append("password")

    if missing:
        print(json.dumps({"findings": [missing_context_finding(host, missing)]}))
        return

    findings = test_session_fixation(login_url, email, password, base_url, host)
    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

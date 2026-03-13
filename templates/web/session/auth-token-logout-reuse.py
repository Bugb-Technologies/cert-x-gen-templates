#!/usr/bin/env python3
#
# @id: auth-token-logout-reuse
# @name: Authentication Token Reuse After Logout
# @author: BugB Security Team
# @severity: high
# @description: Tests whether a JWT or session token remains valid after the user logs out. A reusable post-logout token indicates the server has no server-side revocation list, allowing session hijack via token theft.
# @tags: session-management,token-reuse,logout,authentication,owasp-a07,broken-authentication
# @cwe: CWE-613
# @cvss: 7.5
# @confidence: 88
# @version: 1.0.0
# @references: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality,https://cwe.mitre.org/data/definitions/613.html
# @context_vars: auth_token:required, logout_url:required
# @vuln_class: session_mgmt
# @hypothesis_tags: token-reuse, logout-bypass, session-management, broken-authentication, insufficient-session-expiration
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

TEMPLATE_ID   = "auth-token-logout-reuse"
TEMPLATE_NAME = "Authentication Token Reuse After Logout"

ORACLE_ENDPOINTS = [
    "/api/me", "/api/v1/me", "/rest/user/whoami",
    "/api/user", "/api/profile", "/api/v1/profile",
    "/api/account", "/api/whoami",
]

LOGOUT_PROBE_PATHS = [
    "/api/logout", "/api/v1/logout", "/rest/user/logout",
    "/auth/logout", "/logout", "/signout",
    "/api/auth/logout", "/api/session/logout",
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

def build_auth_headers(token: str, cookie: str = None) -> Dict[str, str]:
    h = {"User-Agent": "CXG-LogoutReuse-Scanner/1.0", "Accept": "application/json"}
    if token:
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        h["Authorization"] = token
    if cookie:
        h["Cookie"] = cookie
    return h

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
            f"{TEMPLATE_NAME} needs an active token and the logout endpoint. "
            "Re-run with: --context '{\"auth_token\":\"Bearer eyJ...\","
            "\"logout_url\":\"/api/logout\"}'"
        ),
        "evidence": {"missing_vars": missing},
        "cwe": "CWE-613",
        "cvss_score": 0.0,
        "remediation": "Provide auth_token and logout_url via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── HTTP helpers ───────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.verify = False

def find_oracle(base_url: str, auth_headers: Dict[str, str]) -> Optional[str]:
    for ep in ORACLE_ENDPOINTS:
        url = base_url + ep
        try:
            r = SESSION.get(url, headers=auth_headers, timeout=6)
            if r.status_code == 200:
                return url
        except Exception:
            pass
    return None

def token_still_valid(oracle_url: str, auth_headers: Dict[str, str]) -> bool:
    try:
        r = SESSION.get(oracle_url, headers=auth_headers, timeout=6)
        return r.status_code == 200
    except Exception:
        return False

def perform_logout(logout_url: str, auth_headers: Dict[str, str], base_url: str) -> bool:
    full_url = logout_url if logout_url.startswith("http") else base_url + logout_url
    for method in (SESSION.post, SESSION.delete, SESSION.get):
        try:
            r = method(full_url, headers=auth_headers, timeout=7)
            if r.status_code in (200, 201, 204, 302):
                return True
        except Exception:
            pass
    return False

def probe_logout_url(base_url: str, auth_headers: Dict[str, str]) -> Optional[str]:
    for path in LOGOUT_PROBE_PATHS:
        url = base_url + path
        try:
            r = SESSION.post(url, headers=auth_headers, timeout=5)
            if r.status_code in (200, 201, 204, 302):
                return path
        except Exception:
            pass
    return None

# ── Core test ─────────────────────────────────────────────────────────────────

def test_logout_reuse(
    token: str,
    cookie: Optional[str],
    logout_url: str,
    base_url: str,
    host: str,
) -> List[Dict[str, Any]]:
    findings = []
    auth_headers = build_auth_headers(token, cookie)

    oracle_url = find_oracle(base_url, auth_headers)
    if not oracle_url:
        return findings

    if not token_still_valid(oracle_url, auth_headers):
        return findings

    logout_succeeded = perform_logout(logout_url, auth_headers, base_url)
    still_valid = token_still_valid(oracle_url, auth_headers)

    if still_valid:
        findings.append({
            "template_id": TEMPLATE_ID,
            "template_name": TEMPLATE_NAME,
            "host": host,
            "matched_at": oracle_url,
            "severity": "high",
            "confidence": 92,
            "title": "Token remains valid after logout — no server-side revocation",
            "description": (
                f"After calling logout at '{logout_url}', the original token still "
                f"authenticates at {oracle_url} (HTTP 200). "
                "The server does not revoke tokens on logout. "
                "An attacker who obtains this token can use it indefinitely after the "
                "legitimate user logs out."
            ),
            "evidence": {
                "oracle_url": oracle_url,
                "logout_url": logout_url if logout_url.startswith("http") else base_url + logout_url,
                "logout_responded": logout_succeeded,
                "token_valid_after_logout": True,
                "token_prefix": token[:30] + "...",
            },
            "cwe": "CWE-613",
            "cvss_score": 7.5,
            "remediation": (
                "Maintain a server-side token blocklist keyed by JTI or session ID. "
                "On logout, add the token to the blocklist and reject it on all subsequent requests. "
                "For JWTs, keep expiry short (15 min) and pair with revocable refresh tokens. "
                "Alternatively, use opaque session tokens backed by a server-side store."
            ),
            "references": [
                "https://cwe.mitre.org/data/definitions/613.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality",
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

    token = ctx.get("auth_token") or ctx.get("bearer_token", "")
    if token.lower().startswith("bearer "):
        token = token[7:]

    cookie     = ctx.get("session_cookie") or ctx.get("cookie")
    logout_url = ctx.get("logout_url")

    missing = []
    if not token and not cookie:
        missing.append("auth_token")

    if not logout_url:
        auth_headers = build_auth_headers(token, cookie)
        logout_url = probe_logout_url(base_url, auth_headers)

    if not logout_url:
        missing.append("logout_url")

    if missing:
        print(json.dumps({"findings": [missing_context_finding(host, missing)]}))
        return

    findings = test_logout_reuse(token, cookie, logout_url, base_url, host)
    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

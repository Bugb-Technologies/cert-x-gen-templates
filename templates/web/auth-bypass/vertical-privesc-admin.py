#!/usr/bin/env python3
#
# @id: vertical-privesc-admin
# @name: Vertical Privilege Escalation to Admin Endpoints
# @author: BugB Security Team
# @severity: critical
# @description: Tests whether a low-privilege authenticated session can access admin-only endpoints. Probes a curated list of admin paths with the supplied auth token, checking for 200 responses that reveal admin functionality or data.
# @tags: vertical-privesc,privilege-escalation,broken-access-control,owasp-a01,admin-access,forced-browse
# @cwe: CWE-269
# @cvss: 9.0
# @confidence: 85
# @version: 1.0.0
# @references: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/,https://cwe.mitre.org/data/definitions/269.html,https://portswigger.net/web-security/access-control
# @context_vars: auth_token:required, endpoints[]:optional
# @vuln_class: auth_bypass
# @hypothesis_tags: vertical-privesc, admin-access, broken-access-control, forced-browse, privilege-escalation
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

TEMPLATE_ID   = "vertical-privesc-admin"
TEMPLATE_NAME = "Vertical Privilege Escalation to Admin Endpoints"

# Admin path wordlist — broad enough to cover REST APIs, SPAs, legacy MVC
ADMIN_PATHS = [
    "/admin", "/admin/", "/administration",
    "/api/admin", "/api/admin/users", "/api/admin/dashboard",
    "/api/v1/admin", "/api/v2/admin",
    "/rest/admin", "/rest/admin/users",
    "/admin/users", "/admin/dashboard", "/admin/settings",
    "/admin/orders", "/admin/products", "/admin/logs",
    "/management", "/manage", "/manage/users",
    "/panel", "/cpanel", "/controlpanel",
    "/superuser", "/superadmin",
    "/internal", "/internal/admin",
    "/debug", "/debug/vars",
    "/actuator", "/actuator/env", "/actuator/beans",
    "/console", "/h2-console",
    "/api/users?role=admin", "/api/v1/users?admin=true",
]

# Signals in response that confirm admin data was returned
ADMIN_RESPONSE_SIGNALS = [
    "\"role\":\"admin\"", "\"isAdmin\":true", "\"admin\":true",
    "\"roles\":[\"admin", "\"authorities\":[\"ROLE_ADMIN",
    "\"totalUsers\":", "\"userCount\":", "\"systemInfo\":",
    "admin panel", "administration", "user management",
    "delete user", "ban user", "system settings",
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

def build_auth_headers(ctx: Dict[str, Any]) -> Dict[str, str]:
    headers = {"User-Agent": "CXG-PrivEsc-Scanner/1.0", "Accept": "application/json, text/html"}
    token = ctx.get("auth_token") or ctx.get("bearer_token")
    if token:
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        headers["Authorization"] = token
    cookie = ctx.get("session_cookie") or ctx.get("cookie")
    if cookie:
        headers["Cookie"] = cookie
    return headers

def missing_context_finding(host: str) -> Dict[str, Any]:
    return {
        "template_id": TEMPLATE_ID,
        "template_name": TEMPLATE_NAME,
        "host": host,
        "matched_at": host,
        "severity": "info",
        "confidence": 100,
        "title": "Template requires context: auth_token missing",
        "description": (
            f"{TEMPLATE_NAME} needs an authenticated session token. "
            "Re-run with: --context '{\"auth_token\":\"Bearer <token>\"}'"
        ),
        "evidence": {"missing_vars": ["auth_token"]},
        "cwe": "CWE-269",
        "cvss_score": 0.0,
        "remediation": "Provide auth_token via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

def has_admin_signals(text: str) -> bool:
    lower = text.lower()
    return any(sig.lower() in lower for sig in ADMIN_RESPONSE_SIGNALS)

def is_json_response(resp: requests.Response) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return "json" in ct

def response_has_content(resp: requests.Response) -> bool:
    return len(resp.text.strip()) > 30

# ── Core test ─────────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.verify = False

def test_admin_path(
    url: str,
    auth_headers: Dict[str, str],
    host: str,
) -> Optional[Dict[str, Any]]:
    # Step 1: check unauthenticated — must be blocked
    try:
        unauth = SESSION.get(url, headers={"User-Agent": "CXG/1.0"}, timeout=5)
        if unauth.status_code == 200:
            return None  # publicly accessible, not a priv-esc finding
    except Exception:
        return None

    # Step 2: check with auth token
    try:
        authed = SESSION.get(url, headers=auth_headers, timeout=7)
    except Exception:
        return None

    if authed.status_code != 200:
        return None

    if not response_has_content(authed):
        return None

    # Confirm it's real admin content, not a redirect to login page
    if "login" in authed.url.lower() or "signin" in authed.url.lower():
        return None
    if "<form" in authed.text.lower() and "password" in authed.text.lower():
        return None

    confidence = 75
    signals_found = []

    if has_admin_signals(authed.text):
        confidence = 92
        for sig in ADMIN_RESPONSE_SIGNALS:
            if sig.lower() in authed.text.lower():
                signals_found.append(sig)

    if is_json_response(authed):
        try:
            body = authed.json()
            if isinstance(body, (dict, list)) and body:
                confidence = max(confidence, 80)
        except Exception:
            pass

    return {
        "template_id": TEMPLATE_ID,
        "template_name": TEMPLATE_NAME,
        "host": host,
        "matched_at": url,
        "severity": "critical",
        "confidence": confidence,
        "title": f"Vertical Privilege Escalation: low-privilege access to {url}",
        "description": (
            f"A low-privilege authenticated session accessed admin endpoint {url} "
            f"(HTTP 200). Unauthenticated access was blocked ({unauth.status_code}), "
            "confirming the endpoint requires authentication but does not enforce "
            "role-level authorisation."
        ),
        "evidence": {
            "admin_url": url,
            "unauth_status": unauth.status_code,
            "authed_status": authed.status_code,
            "admin_signals_found": signals_found,
            "response_preview": authed.text[:400],
            "content_type": authed.headers.get("Content-Type", ""),
        },
        "cwe": "CWE-269",
        "cvss_score": 9.0,
        "remediation": (
            "Implement role-based access control (RBAC) checks on all admin endpoints. "
            "Validate the authenticated user's role server-side on every request — "
            "never rely solely on hiding routes from low-privilege UI. "
            "Return 403 Forbidden (not 404) for unauthorised role access to avoid confusion."
        ),
        "references": [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            "https://cwe.mitre.org/data/definitions/269.html",
            "https://portswigger.net/web-security/access-control/privilege-escalation",
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    host, port = get_target()
    if not host:
        print(json.dumps({"findings": []}))
        return

    ctx = get_context()

    if not (ctx.get("auth_token") or ctx.get("bearer_token") or ctx.get("session_cookie")):
        print(json.dumps({"findings": [missing_context_finding(host)]}))
        return

    base_url = build_base_url(host, port)
    auth_headers = build_auth_headers(ctx)

    # Build test path list: provided endpoints (if admin-looking) + static wordlist
    paths_to_test = list(ADMIN_PATHS)
    for ep in ctx.get("endpoints", []):
        path = ep if ep.startswith("/") else "/" + ep
        if any(kw in path.lower() for kw in ["admin", "manage", "internal", "superuser"]):
            url = ep if ep.startswith("http") else base_url + path
            if url not in paths_to_test:
                paths_to_test.insert(0, url)

    findings = []
    seen_urls = set()

    for path in paths_to_test:
        url = path if path.startswith("http") else base_url + path
        if url in seen_urls:
            continue
        seen_urls.add(url)

        finding = test_admin_path(url, auth_headers, host)
        if finding:
            findings.append(finding)

    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

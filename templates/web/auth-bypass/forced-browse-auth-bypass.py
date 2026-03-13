#!/usr/bin/env python3
#
# @id: forced-browse-auth-bypass
# @name: Forced Browse Auth Bypass — Protected Endpoints Without Auth
# @author: BugB Security Team
# @severity: high
# @description: Takes the authenticated user's discovered endpoints and re-probes each one without credentials. Any endpoint returning 200 without auth that previously required it is a forced-browse auth bypass. Complements vertical-privesc by testing full auth stripping rather than role confusion.
# @tags: forced-browse,auth-bypass,broken-access-control,owasp-a01,unauthenticated-access
# @cwe: CWE-425
# @cvss: 7.5
# @confidence: 85
# @version: 1.0.0
# @references: https://owasp.org/www-community/attacks/Forced_browsing,https://cwe.mitre.org/data/definitions/425.html
# @context_vars: endpoints[]:required, auth_token:required
# @vuln_class: auth_bypass
# @hypothesis_tags: forced-browse, auth-bypass, unauthenticated-access, broken-access-control, missing-authentication
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

TEMPLATE_ID   = "forced-browse-auth-bypass"
TEMPLATE_NAME = "Forced Browse Auth Bypass — Protected Endpoints Without Auth"

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
    h = {"User-Agent": "CXG-ForcedBrowse-Scanner/1.0", "Accept": "application/json, text/html"}
    token = ctx.get("auth_token") or ctx.get("bearer_token")
    if token:
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        h["Authorization"] = token
    cookie = ctx.get("session_cookie") or ctx.get("cookie")
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
            f"{TEMPLATE_NAME} needs the authenticated endpoint list and a token. "
            "Re-run with: --context '{\"auth_token\":\"Bearer eyJ...\","
            "\"endpoints\":[\"/api/users\",\"/api/orders\"]}'"
        ),
        "evidence": {"missing_vars": missing},
        "cwe": "CWE-425",
        "cvss_score": 0.0,
        "remediation": "Provide auth_token and endpoints[] via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── Filtering helpers ──────────────────────────────────────────────────────────

def is_login_redirect(resp: requests.Response) -> bool:
    """True if the unauthenticated response is just a redirect to login."""
    final_url = resp.url.lower()
    return "login" in final_url or "signin" in final_url or "auth" in final_url

def looks_like_real_data(resp: requests.Response) -> bool:
    """True if response body contains actual data, not an empty shell or error page."""
    ct = resp.headers.get("Content-Type", "")
    text = resp.text.strip()
    if not text or len(text) < 20:
        return False
    if "json" in ct:
        try:
            body = resp.json()
            if isinstance(body, dict) and body:
                return True
            if isinstance(body, list) and body:
                return True
        except Exception:
            pass
        return False
    # HTML: exclude generic pages
    if "html" in ct:
        if "<form" in text.lower() and "password" in text.lower():
            return False
        return len(text) > 200
    return len(text) > 30

SESSION = requests.Session()
SESSION.verify = False
ANON_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; scanner)", "Accept": "application/json, text/html"}

# ── Core test ─────────────────────────────────────────────────────────────────

def test_endpoint(
    url: str,
    auth_headers: Dict[str, str],
    host: str,
) -> Optional[Dict[str, Any]]:
    # Step 1: authed request — must succeed to establish that the endpoint exists & returns data
    try:
        authed = SESSION.get(url, headers=auth_headers, timeout=7)
    except Exception:
        return None

    if authed.status_code != 200:
        return None
    if not looks_like_real_data(authed):
        return None

    # Step 2: unauthenticated request
    try:
        unauthed = SESSION.get(url, headers=ANON_HEADERS, timeout=7, allow_redirects=True)
    except Exception:
        return None

    if unauthed.status_code != 200:
        return None
    if is_login_redirect(unauthed):
        return None
    if not looks_like_real_data(unauthed):
        return None

    # Step 3: confirm responses carry real content (not both empty 200s)
    authed_preview   = authed.text[:150].strip()
    unauthed_preview = unauthed.text[:150].strip()

    if not authed_preview or not unauthed_preview:
        return None

    return {
        "template_id": TEMPLATE_ID,
        "template_name": TEMPLATE_NAME,
        "host": host,
        "matched_at": url,
        "severity": "high",
        "confidence": 85,
        "title": f"Auth bypass: endpoint accessible without credentials — {url}",
        "description": (
            f"Endpoint {url} returns HTTP 200 with data both with and without authentication. "
            "The access control check is absent or bypassed — any unauthenticated caller "
            "can retrieve this data."
        ),
        "evidence": {
            "url": url,
            "authed_status": authed.status_code,
            "unauthed_status": unauthed.status_code,
            "authed_content_type": authed.headers.get("Content-Type", ""),
            "unauthed_preview": unauthed_preview[:300],
        },
        "cwe": "CWE-425",
        "cvss_score": 7.5,
        "remediation": (
            "Add authentication middleware to all API routes. "
            "Use a deny-by-default policy: require explicit opt-in for public endpoints. "
            "Verify auth on every request server-side — never rely on client-side route guards."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Forced_browsing",
            "https://cwe.mitre.org/data/definitions/425.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
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
    base_url = build_base_url(host, port)

    endpoints = ctx.get("endpoints", [])
    has_token = bool(ctx.get("auth_token") or ctx.get("bearer_token") or ctx.get("session_cookie"))

    missing = []
    if not endpoints:
        missing.append("endpoints[]")
    if not has_token:
        missing.append("auth_token")

    if missing:
        print(json.dumps({"findings": [missing_context_finding(host, missing)]}))
        return

    auth_headers = build_auth_headers(ctx)
    findings = []
    seen = set()

    for ep in endpoints:
        url = ep if ep.startswith("http") else base_url + ep
        if url in seen:
            continue
        seen.add(url)

        finding = test_endpoint(url, auth_headers, host)
        if finding:
            findings.append(finding)

    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

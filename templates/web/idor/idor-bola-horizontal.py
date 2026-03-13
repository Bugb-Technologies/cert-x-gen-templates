#!/usr/bin/env python3
#
# @id: idor-bola-horizontal
# @name: IDOR / BOLA Horizontal Privilege Escalation
# @author: BugB Security Team
# @severity: high
# @description: Tests for horizontal IDOR/BOLA by enumerating object IDs adjacent to the authenticated user's own ID and comparing access. Requires auth context from pipeline or --context flag.
# @tags: idor,bola,authorization,access-control,owasp-a01,horizontal-privesc,broken-object-level
# @cwe: CWE-639
# @cvss: 8.1
# @confidence: 80
# @version: 1.0.0
# @references: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/,https://cwe.mitre.org/data/definitions/639.html
# @context_vars: auth_token:required, endpoints[]:required, user_id:optional
# @vuln_class: idor
# @hypothesis_tags: idor, bola, horizontal-access, broken-access-control, broken-object-level-authorization
# @batch_group: auth-context
# @auto_probe: false
#

import json
import os
import sys
import re
import requests
import urllib3
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEMPLATE_ID   = "idor-bola-horizontal"
TEMPLATE_NAME = "IDOR / BOLA Horizontal Privilege Escalation"

# ── Context helpers ────────────────────────────────────────────────────────────

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
    headers = {"User-Agent": "CXG-IDOR-Scanner/1.0", "Accept": "application/json"}
    token = ctx.get("auth_token") or ctx.get("bearer_token")
    if token:
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        headers["Authorization"] = token
    cookie = ctx.get("session_cookie") or ctx.get("cookie")
    if cookie:
        headers["Cookie"] = cookie
    return headers

# ── Missing-context finding ────────────────────────────────────────────────────

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
            f"{TEMPLATE_NAME} needs authenticated context to run. "
            f"Missing: {', '.join(missing)}. "
            "Re-run with: --context '{\"auth_token\":\"Bearer <token>\","
            "\"endpoints\":[\"/api/users/1\"]}'"
        ),
        "evidence": {"missing_vars": missing},
        "cwe": "CWE-639",
        "cvss_score": 0.0,
        "remediation": "Provide auth_token and endpoints[] via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── ID extraction ─────────────────────────────────────────────────────────────

def extract_id_from_url(url: str) -> Optional[str]:
    """Pull the last numeric or UUID segment from a URL path."""
    path = url.split("?")[0].rstrip("/")
    # UUID
    m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", path, re.I)
    if m:
        return m.group(0)
    # Numeric segment
    segments = path.split("/")
    for seg in reversed(segments):
        if seg.isdigit():
            return seg
    return None

def make_candidate_urls(endpoint: str, own_id: str, base_url: str) -> List[str]:
    """Generate sibling-ID URLs to probe for horizontal access."""
    try:
        id_int = int(own_id)
        candidate_ids = [
            str(id_int - 1),
            str(id_int + 1),
            str(id_int + 2),
            str(max(1, id_int - 2)),
        ]
    except ValueError:
        # UUID or non-numeric — swap last hex char to generate a different ID
        candidate_ids = [own_id[:-1] + ("0" if own_id[-1] != "0" else "1")]

    candidates = []
    for cid in candidate_ids:
        if cid == own_id:
            continue
        swapped = endpoint.replace(own_id, cid)
        if swapped != endpoint:
            url = swapped if swapped.startswith("http") else base_url + swapped
            candidates.append((url, cid))
    return candidates

# ── HTTP helpers ──────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.verify = False

def fetch(url: str, headers: Dict[str, str], timeout: int = 8) -> Optional[requests.Response]:
    try:
        return SESSION.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def is_success(resp: Optional[requests.Response]) -> bool:
    return resp is not None and resp.status_code in (200, 201)

def response_has_data(resp: requests.Response) -> bool:
    """True if response body looks like real object data, not an error page."""
    ct = resp.headers.get("Content-Type", "")
    if "json" in ct:
        try:
            body = resp.json()
            if isinstance(body, dict) and body:
                return True
            if isinstance(body, list) and body:
                return True
        except Exception:
            pass
    elif "html" not in ct and len(resp.text) > 20:
        return True
    return False

def bodies_differ(own: requests.Response, other: requests.Response) -> bool:
    """Confirm the two responses are for different objects (not identical/cached)."""
    try:
        o1 = own.json()
        o2 = other.json()
        return o1 != o2
    except Exception:
        return own.text[:200] != other.text[:200]

# ── Core test ─────────────────────────────────────────────────────────────────

def test_endpoint(
    endpoint: str,
    own_id: str,
    auth_headers: Dict[str, str],
    base_url: str,
    host: str,
) -> List[Dict[str, Any]]:
    findings = []

    canonical = endpoint if endpoint.startswith("http") else base_url + endpoint

    # Fetch own resource first — must succeed to establish baseline
    own_resp = fetch(canonical, auth_headers)
    if not is_success(own_resp):
        return findings

    candidates = make_candidate_urls(endpoint, own_id, base_url)
    if not candidates:
        return findings

    for candidate_url, candidate_id in candidates:
        resp = fetch(candidate_url, auth_headers)
        if not is_success(resp):
            continue
        if not response_has_data(resp):
            continue
        if not bodies_differ(own_resp, resp):
            continue

        # Confirm: also try with no auth — if it fails, access is truly auth-dependent
        no_auth_resp = fetch(candidate_url, {"User-Agent": "CXG-IDOR-Scanner/1.0"})
        if is_success(no_auth_resp) and not no_auth_resp.headers.get("WWW-Authenticate"):
            # Publicly accessible — not a true IDOR, skip
            continue

        findings.append({
            "template_id": TEMPLATE_ID,
            "template_name": TEMPLATE_NAME,
            "host": host,
            "matched_at": candidate_url,
            "severity": "high",
            "confidence": 85,
            "title": f"Horizontal IDOR: authenticated access to object {candidate_id}",
            "description": (
                f"Authenticated as object owner {own_id}, successfully accessed "
                f"object {candidate_id} at {candidate_url}. "
                "The server returned a 200 with object data for a resource belonging "
                "to a different user without re-checking ownership."
            ),
            "evidence": {
                "own_url": canonical,
                "own_status": own_resp.status_code,
                "candidate_url": candidate_url,
                "candidate_status": resp.status_code,
                "candidate_id": candidate_id,
                "response_preview": resp.text[:300],
                "auth_token_prefix": (auth_headers.get("Authorization", "")[:20] + "…"),
            },
            "cwe": "CWE-639",
            "cvss_score": 8.1,
            "remediation": (
                "Implement server-side ownership checks on every object-level endpoint. "
                "Validate that the authenticated user's ID matches the resource owner before "
                "returning data. Use indirect object references (e.g. /api/me/orders) rather "
                "than sequential or guessable IDs."
            ),
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                "https://cwe.mitre.org/data/definitions/639.html",
                "https://portswigger.net/web-security/access-control/idor",
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
    auth_headers = build_auth_headers(ctx)

    # --- TIER 1: check required context ---
    missing = []
    auth_token = ctx.get("auth_token") or ctx.get("bearer_token")
    if not auth_token:
        missing.append("auth_token")
    endpoints = ctx.get("endpoints", [])
    if not endpoints:
        missing.append("endpoints[]")

    if missing:
        print(json.dumps({"findings": [missing_context_finding(host, missing)]}))
        return

    # --- TIER 2: resolve user_id ---
    user_id = ctx.get("user_id")
    if not user_id:
        # Try to extract from first endpoint
        for ep in endpoints:
            user_id = extract_id_from_url(ep)
            if user_id:
                break
    if not user_id:
        # Try /api/me or /api/whoami to get current user ID
        for probe in ["/api/me", "/api/whoami", "/rest/user/whoami", "/api/v1/me"]:
            resp = fetch(base_url + probe, auth_headers)
            if is_success(resp):
                try:
                    body = resp.json()
                    uid = (body.get("id") or body.get("userId") or
                           body.get("user_id") or body.get("sub"))
                    if uid:
                        user_id = str(uid)
                        break
                except Exception:
                    pass

    if not user_id:
        # Can still test numeric ID enumeration from endpoints even without known own_id
        user_id = "1"

    # --- TIER 3: run tests ---
    all_findings = []
    for ep in endpoints:
        eid = extract_id_from_url(ep) or user_id
        findings = test_endpoint(ep, eid, auth_headers, base_url, host)
        all_findings.extend(findings)

    print(json.dumps({"findings": all_findings}))

if __name__ == "__main__":
    main()

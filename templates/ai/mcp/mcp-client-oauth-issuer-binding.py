#!/usr/bin/env python3
# @id: mcp-client-oauth-issuer-binding
# @name: MCP Client OAuth Issuer Binding (Authorization-Server Mix-Up / Cross-Issuer Credential Reuse)
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. Drives an MCP CLIENT's own OAuth login path against two synthetic issuers and proves, by observation, that it fails the 2026-07-28 MCP client authorization MUSTs - it carries credentials minted by the first authorization server to the second, skips re-registration when the issuer changes, or redeems an authorization code whose RFC 9207 `iss` names a different issuer than the one it asked.
# @tags: mcp, ai, agent, mcp-client, agent-posture, oauth, oauth-conformance, authorization-server-mixup, issuer-binding, rfc9207, credential-reuse, behavioural, active, intrusive, cwe-346, cwe-522
# @cwe: CWE-346, CWE-522
# @cvss: 8.1
# @target_kinds: cli
# @oracles: property, diff
# @references: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization, https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations, https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration, https://www.rfc-editor.org/rfc/rfc9207.html, https://www.rfc-editor.org/rfc/rfc9728.html, https://www.rfc-editor.org/rfc/rfc8707.html, https://cwe.mitre.org/data/definitions/346.html, https://cwe.mitre.org/data/definitions/522.html
# @confidence: 92
# @version: 1.0.0
"""
ACTIVE / INTRUSIVE check - MCP *client* OAuth conformance: issuer binding.

WHY A CLIENT CHECK AT ALL

Every shipping MCP scanner points at servers. The MCP authorization spec does
not: it puts MUSTs on both ends, and the ones that decide whether an agent can
be walked into an authorization-server mix-up sit in the CLIENT. Verbatim from
the 2026-07-28 authorization specification:

    "Before redirecting the user-agent, the client MUST record the `issuer`
     value from the selected authorization server's validated metadata
     document and associate it with the same per-request record used to store
     the PKCE code verifier."

    "On receiving the authorization response, MCP clients MUST apply the
     validation in RFC9207 Section 2.4 before transmitting the authorization
     code to any token endpoint" - and, where the authorization server
     advertises `authorization_response_iss_parameter_supported: true`, an
     `iss` that is absent means "Reject the response" and an `iss` that is
     present is compared "using simple string comparison".

    "MCP clients MUST NOT send tokens to the MCP server other than ones issued
     by the MCP server's authorization server."

    "Before initiating the authorization flow, MCP clients MUST obtain a
     client ID through one of three registration mechanisms: Client ID
     Metadata Documents, pre-registration, or Dynamic Client Registration."

    "MCP clients MUST use OAuth 2.0 Protected Resource Metadata for
     authorization server discovery."

A coding agent is an MCP client, and it is a `cli://` target a scanner can
already drive. Nothing checks it. That is what this template does.

THE ATTACK CLASS THIS MODELS (synthetically)

Authorization-server mix-up. An agent already logged into a legitimate MCP
server is pointed at a second one - a marketplace entry, a README link, a
teammate's config. The second server's protected-resource metadata names a
DIFFERENT authorization server, and that authorization server hands out the
SAME `client_id` the agent already holds. Three client-side mistakes turn that
into a credential theft, and each is independently observable:

  1. A credential store keyed by client_id (or by nothing) rather than by
     (issuer, client_id). The agent "recognises" the client_id and presents
     the FIRST issuer's client_secret to the SECOND issuer.
  2. No re-registration on issuer change - the agent walks straight to the new
     issuer's /authorize with credentials it was never given there.
  3. No check of the RFC 9207 `iss` on the authorization response, so a code
     minted by one authorization server is redeemed at another. This is the
     mix-up primitive itself.
  4. A bearer token minted for one resource attached to the first request to a
     brand-new resource - the audience the token was never issued for.

THE ORACLE IS A PROPERTY OF AN OBSERVED RUN, DIFFERENTIAL ACROSS TWO ISSUERS

  Property:  a credential a client obtained from issuer A is never presented
             to issuer B, and an authorization response that does not prove it
             came from the issuer the client asked is never redeemed.

The template stands up four hermetic mock endpoints on loopback - two
authorization servers (AS1, AS2) and two MCP resource servers (RS1 -> AS1,
RS2 -> AS2) - and runs the client's own login command twice against the same
$HOME:

  Phase 1   login RS1. AS1 registers the client, issues a decoy client_secret
            and a nonce-tagged access token, and stamps a CORRECT `iss` on the
            authorization response. This establishes the surface: without a
            completed phase 1 there is no issuer-bound credential whose misuse
            could be observed, and the check SKIPs.
  Phase 2   login RS2, same $HOME, same login command. RS2's protected-resource
            metadata points at AS2. AS2 hands out the SAME client_id as AS1 and
            stamps the WRONG `iss` (AS1's issuer, or none) on its authorization
            response. Everything else about AS2 is byte-identical to AS1 modulo
            its own origin, and the template asserts that before trusting a
            verdict - a differential that let a second variable move would
            prove nothing about either.

HELD FIXED, AND ASSERTED AT RUNTIME: the client binary, the login invocation,
$HOME, the transport, the discovery order, and the two authorization servers'
metadata shape. THE ONLY THINGS THAT MOVE: which issuer the resource points at,
and the `iss` AS2 stamps on its response.

VERDICT CONTRACT

  confirmed  at least one hard signal, each backed by the request that carries
             it: the AS1 client_secret canary observed at AS2; the AS1 access
             token canary observed at RS2/AS2; the shared client_id used at AS2
             before any registration there while phase 1 did register at AS1;
             or a code redeemed at AS2 whose authorization response carried a
             mismatched or absent `iss`.
  refuted    the client re-registered at the new issuer and refused: it reached
             AS2's authorization endpoint, saw the bad `iss`, and never redeemed
             the code - with no canary anywhere in AS2's or RS2's ledger, and
             with the ledger and the canary detector both proved live.
  skipped    a named missing precondition: the client exposes no OAuth login
             path; a login surface is advertised but no invocation reached an
             authorization server; phase 1 never completed at AS1; phase 2 never
             contacted the second server; or the client re-registered but never
             made an authorization request, so the `iss` check was not exercised.
  errored    the target is not runnable, the mock endpoints could not bind, the
             held-fixed assertion failed, or the ledger could not see a request
             the template itself planted.

SAFETY

Nothing here touches a real identity provider. All four endpoints are mock
servers this process binds on 127.0.0.1 for the duration of the scan; every
client_id, client_secret and access token is a synthetic `cxg-` prefixed decoy
carrying a per-run nonce and is accepted by nothing but these mocks. The
template runs the target's own login subcommand with $HOME redirected into a
temporary lab that is deleted on exit, and it opens no browser: the user's
approval leg is performed by a shim that fetches only the loopback
authorization URL the mock AS just issued. It does drive an unfamiliar binary,
so get authorisation before pointing it at software you do not own.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

METADATA = {
    "id": "mcp-client-oauth-issuer-binding",
    "name": "MCP Client OAuth Issuer Binding (Authorization-Server Mix-Up / Cross-Issuer Credential Reuse)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE check: drives an MCP client's own OAuth login path against two synthetic "
        "authorization servers and observes whether credentials minted by the first are presented "
        "to the second, whether the client re-registers on issuer change, and whether it redeems a "
        "code whose RFC 9207 `iss` names a different issuer than the one it asked"
    ),
    "tags": ["mcp", "ai", "agent", "mcp-client", "agent-posture", "oauth", "oauth-conformance",
             "authorization-server-mixup", "issuer-binding", "rfc9207", "credential-reuse",
             "behavioural", "active", "intrusive", "cwe-346", "cwe-522"],
    "language": "python",
    "active": True,
    "confidence": 92,
    "cwe": ["CWE-346", "CWE-522"],
    "references": [
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization",
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations",
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration",
        "https://www.rfc-editor.org/rfc/rfc9207.html",
        "https://www.rfc-editor.org/rfc/rfc9728.html",
        "https://www.rfc-editor.org/rfc/rfc8707.html",
        "https://cwe.mitre.org/data/definitions/346.html",
        "https://cwe.mitre.org/data/definitions/522.html",
    ],
}

LOGIN_TIMEOUT = float(os.getenv("CXG_MCP_CLIENT_TIMEOUT", "25"))
HELP_TIMEOUT = float(os.getenv("CXG_MCP_CLIENT_HELP_TIMEOUT", "10"))

# A login/authorization surface advertised by the target's own help output.
LOGIN_HINT_RE = re.compile(
    r"(mcp\s+login|\boauth\b|\blogin\b|\bauthenticate\b|\bauthoriz\w+\b|\bsign[-\s]?in\b)", re.I)

# Invocations a coding agent plausibly spells its MCP login as. A candidate is
# only tried when every literal token in it appears in the target's own help
# output, so this proposes; the authorization server's ledger disposes.
CANDIDATE_ARGVS = [
    ["mcp", "login", "{url}"],
    ["mcp", "auth", "login", "{url}"],
    ["mcp", "authenticate", "{url}"],
    ["mcp", "connect", "{url}"],
    ["auth", "login", "{url}"],
    ["login", "{url}"],
    ["mcp", "add", "{url}"],
]

HELP_ARGSETS = [["--help"], ["-h"], ["help"], ["mcp", "--help"], ["mcp", "help"],
                ["auth", "--help"], []]

_SEQ_LOCK = threading.Lock()
_SEQ = [0]


def next_seq():
    with _SEQ_LOCK:
        _SEQ[0] += 1
        return _SEQ[0]


# ---------------------------------------------------------------------------
# The mock endpoints. Four of them, all on loopback, all recording.
# ---------------------------------------------------------------------------

class MockSite(object):
    """One recorded HTTP endpoint: an authorization server or an MCP resource."""

    def __init__(self, role, label):
        self.role = role            # "as" | "rs"
        self.label = label          # "AS1" | "AS2" | "RS1" | "RS2"
        self.records = []
        self.lock = threading.Lock()
        self.phase = "setup"
        self.httpd = None
        self.origin = None
        # authorization-server state
        self.client_id = None
        self.client_secret = None
        self.access_token = None
        self.iss_mode = "correct"   # "correct" | "mismatched" | "missing"
        self.peer_issuer = None
        self.codes = {}
        # resource-server state
        self.as_issuer = None
        self.accepted_token = None

    # -- lifecycle ---------------------------------------------------------

    def bind(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self))
        self.origin = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self.origin

    def stop(self):
        if self.httpd is not None:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass

    def record(self, rec):
        with self.lock:
            self.records.append(rec)

    def ledger(self, phase=None, include_selftest=False):
        with self.lock:
            rows = list(self.records)
        out = []
        for r in rows:
            if r.get("selftest") and not include_selftest:
                continue
            if phase is not None and r.get("phase") != phase:
                continue
            out.append(r)
        return out

    # -- metadata ----------------------------------------------------------

    @property
    def resource(self):
        return self.origin + "/mcp"

    def as_metadata(self):
        return {
            "issuer": self.origin,
            "authorization_endpoint": self.origin + "/authorize",
            "token_endpoint": self.origin + "/token",
            "registration_endpoint": self.origin + "/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "scopes_supported": ["mcp:read"],
            "authorization_response_iss_parameter_supported": True,
            "resource_indicators_supported": True,
        }

    def rs_metadata(self):
        return {
            "resource": self.resource,
            "authorization_servers": [self.as_issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp:read"],
        }

    # -- routing -----------------------------------------------------------

    def route(self, method, path, query, headers, body):
        if self.role == "as":
            return self._route_as(method, path, query, headers, body)
        return self._route_rs(method, path, query, headers, body)

    def _route_as(self, method, path, query, headers, body):
        if path.startswith("/.well-known/oauth-authorization-server") or \
           path.startswith("/.well-known/openid-configuration"):
            return json_response(200, self.as_metadata())
        if path == "/register" and method == "POST":
            return json_response(200, {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "client_id_issued_at": 0,
                "client_secret_expires_at": 0,
                "token_endpoint_auth_method": "client_secret_post",
                "redirect_uris": json_field(body, "redirect_uris") or [],
            })
        if path == "/authorize":
            return self._authorize(query)
        if path == "/token" and method == "POST":
            return self._token(body)
        return json_response(404, {"error": "not_found", "path": path})

    def _authorize(self, query):
        redirect_uri = query.get("redirect_uri")
        if not redirect_uri:
            return json_response(400, {"error": "invalid_request",
                                       "error_description": "redirect_uri missing"})
        code = "cxg-%s-code-%s" % (self.label.lower(), uuid.uuid4().hex[:12])
        params = {"code": code}
        if query.get("state"):
            params["state"] = query["state"]
        if self.iss_mode == "correct":
            iss_sent = self.origin
        elif self.iss_mode == "mismatched":
            iss_sent = self.peer_issuer
        else:
            iss_sent = None
        if iss_sent is not None:
            params["iss"] = iss_sent
        with self.lock:
            self.codes[code] = {"iss_sent": iss_sent, "iss_mode": self.iss_mode,
                                "client_id": query.get("client_id"),
                                "code_challenge": query.get("code_challenge"),
                                "resource": query.get("resource"),
                                "state": query.get("state")}
        sep = "&" if "?" in redirect_uri else "?"
        location = redirect_uri + sep + urllib.parse.urlencode(params)
        return 302, {"Location": location, "Content-Type": "text/plain"}, b"redirecting\n"

    def _token(self, body):
        form = dict(urllib.parse.parse_qsl(body or "", keep_blank_values=True))
        code = form.get("code")
        with self.lock:
            known = self.codes.get(code)
        if not known:
            return json_response(400, {"error": "invalid_grant",
                                       "error_description": "unknown code"})
        return json_response(200, {"access_token": self.access_token, "token_type": "Bearer",
                                   "expires_in": 3600, "scope": "mcp:read"})

    def _route_rs(self, method, path, query, headers, body):
        if path.startswith("/.well-known/oauth-protected-resource"):
            return json_response(200, self.rs_metadata())
        if path in ("/mcp", "/") and method == "POST":
            auth = headers.get("authorization") or ""
            if auth == "Bearer " + str(self.accepted_token):
                return json_response(200, {
                    "jsonrpc": "2.0", "id": 1,
                    "result": {"protocolVersion": "2026-07-28", "capabilities": {"tools": {}},
                               "serverInfo": {"name": "cxg-mock-%s" % self.label.lower(),
                                              "version": "1.0"}}})
            challenge = ('Bearer realm="%s", resource_metadata="%s/.well-known/'
                         'oauth-protected-resource", scope="mcp:read"'
                         % (self.resource, self.origin))
            status, hdrs, payload = json_response(
                401, {"error": "invalid_token",
                      "error_description": "authorization required for %s" % self.resource})
            hdrs["WWW-Authenticate"] = challenge
            return status, hdrs, payload
        return json_response(404, {"error": "not_found", "path": path})


def json_response(status, obj):
    return status, {"Content-Type": "application/json"}, \
        json.dumps(obj).encode("utf-8")


def json_field(body, key):
    try:
        data = json.loads(body or "")
    except ValueError:
        return None
    return data.get(key) if isinstance(data, dict) else None


RECORDED_HEADERS = ("authorization", "content-type", "user-agent", "accept", "x-cxg-selftest")


def make_handler(site):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _dispatch(self, method):
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            parsed = urllib.parse.urlsplit(self.path)
            query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            headers = {k.lower(): v for k, v in self.headers.items()
                       if k.lower() in RECORDED_HEADERS}
            rec = {"seq": next_seq(), "site": site.label, "phase": site.phase,
                   "method": method, "path": parsed.path, "raw_query": parsed.query,
                   "query": query, "headers": headers, "body": body[:2000],
                   "selftest": bool(headers.get("x-cxg-selftest"))}
            site.record(rec)
            try:
                status, hdrs, payload = site.route(method, parsed.path, query, headers, body)
            except Exception as exc:  # a mock that throws must not hang the client
                status, hdrs, payload = json_response(500, {"error": str(exc)[:200]})
            rec["response_status"] = status
            self.send_response(status)
            for key, value in (hdrs or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except Exception:
                pass

        def do_GET(self):       # noqa: N802
            self._dispatch("GET")

        def do_POST(self):      # noqa: N802
            self._dispatch("POST")

        def log_message(self, *_args):
            pass

    return Handler


def record_text(rec):
    """Everything one recorded request carried, as one searchable string."""
    return " ".join([
        rec.get("path") or "", rec.get("raw_query") or "",
        json.dumps(rec.get("headers") or {}), rec.get("body") or "",
    ])


# ---------------------------------------------------------------------------
# Signals. A pure function of recorded requests, so the self-test can run the
# same detector over a request the template planted itself.
# ---------------------------------------------------------------------------

def detect_signals(canary, as2_records, rs2_records, registered_at_as1, as2_codes):
    """(hard, soft). `hard` decides the verdict; `soft` never does.

    Every near-miss goes to `soft` and is named in the refutation instead:
    a client_id AS2 itself handed out, a code AS2 never issued, a missing
    `resource` indicator. A structural coincidence must not be able to
    confirm - only an observed canary, or an observed redemption of a code
    whose authorization response failed to identify its issuer, can."""
    hard, soft = [], []

    # 1. A bearer token minted by AS1 for RS1's resource, sent somewhere else.
    for rec in list(rs2_records) + list(as2_records):
        if canary["as1_token"] in record_text(rec):
            hard.append({
                "signal": "access-token-reused-across-resources",
                "site": rec.get("site"), "seq": rec.get("seq"),
                "request": "%s %s" % (rec.get("method"), rec.get("path")),
                "observed": canary["as1_token"],
                "authorization_header": (rec.get("headers") or {}).get("authorization"),
                "why": ("an access token AS1 minted for RS1's resource was presented to %s, whose "
                        "authorization server is AS2 - breaking \"MCP clients MUST NOT send tokens "
                        "to the MCP server other than ones issued by the MCP server's "
                        "authorization server\"" % rec.get("site")),
            })
            break

    # 2. The client_secret AS1 issued, presented to a different issuer.
    for rec in as2_records:
        if canary["as1_secret"] in record_text(rec):
            hard.append({
                "signal": "client-secret-reused-across-issuers",
                "site": rec.get("site"), "seq": rec.get("seq"),
                "request": "%s %s" % (rec.get("method"), rec.get("path")),
                "observed": canary["as1_secret"],
                "body_excerpt": (rec.get("body") or "")[:300],
                "why": ("the client_secret AS1 issued during registration was sent to AS2, so the "
                        "credential store is keyed by client_id (or by nothing) and not by the "
                        "issuer that minted the credential - a secret the client is required to "
                        "keep confidential was handed to a party that never issued it"),
            })
            break

    # 3. The shared client_id used at the new issuer with no registration there.
    first_registration = next((r.get("seq") for r in as2_records
                               if r.get("path") == "/register"), None)
    used_client_id = [r for r in as2_records
                      if r.get("path") in ("/authorize", "/token")
                      and canary["client_id"] in record_text(r)]
    unregistered = [r for r in used_client_id
                    if first_registration is None or r.get("seq") < first_registration]
    if used_client_id and not unregistered:
        soft.append({"observation": "client-id-used-after-registering-at-the-new-issuer",
                     "detail": "AS2 handed this client_id out itself at /register (seq %s), so its "
                               "later appearance proves nothing" % first_registration})
    elif unregistered and not registered_at_as1:
        soft.append({"observation": "client-id-used-without-registration-anywhere",
                     "detail": "the client did not register at AS1 either, so this is a "
                               "pre-configured client_id, not a credential carried across issuers"})
    elif unregistered:
        rec = unregistered[0]
        hard.append({
            "signal": "no-registration-at-new-issuer",
            "site": rec.get("site"), "seq": rec.get("seq"),
            "request": "%s %s" % (rec.get("method"), rec.get("path")),
            "observed": canary["client_id"],
            "why": ("the client obtained this client_id by dynamic registration at AS1 and then "
                    "used it in an authorization request to AS2 without obtaining a client ID from "
                    "AS2 by any of the three mechanisms the spec allows (Client ID Metadata "
                    "Document, pre-registration, dynamic registration) - an issuer change did not "
                    "invalidate a client identity the new issuer never granted"),
        })

    # 4. A code redeemed although its authorization response did not identify
    #    the issuer that produced it (RFC 9207).
    for rec in as2_records:
        if rec.get("path") != "/token" or rec.get("method") != "POST":
            continue
        form = dict(urllib.parse.parse_qsl(rec.get("body") or "", keep_blank_values=True))
        code = form.get("code")
        info = as2_codes.get(code)
        if not info:
            soft.append({"observation": "token-exchange-with-a-code-as2-never-issued",
                         "detail": "code=%s is not in AS2's ledger; nothing is proved by redeeming it"
                                   % (code or "<none>")})
            continue
        if info.get("iss_mode") == "correct":
            continue
        hard.append({
            "signal": "authorization-response-iss-not-validated",
            "site": rec.get("site"), "seq": rec.get("seq"),
            "request": "POST /token",
            "observed": {"code": code, "iss_returned": info.get("iss_sent"),
                         "iss_mode": info.get("iss_mode"),
                         "authorization_server_asked": rec.get("site")},
            "why": ("the authorization response carrying this code %s, and the client redeemed it "
                    "anyway, breaking \"MCP clients MUST apply the validation in RFC9207 Section "
                    "2.4 before transmitting the authorization code to any token endpoint\" - an "
                    "authorization-server mix-up is exactly this"
                    % ("named a DIFFERENT issuer (%s), which simple string comparison against the "
                       "recorded issuer rejects" % info.get("iss_sent")
                       if info.get("iss_mode") == "mismatched"
                       else "carried NO `iss` at all, from a server whose metadata advertises "
                            "authorization_response_iss_parameter_supported=true, for which the "
                            "spec's table says \"Reject the response\"")),
        })
        break

    return hard, soft


def near_miss_observations(as2_records, rs2_records, as2_codes):
    """Structure that looks like a finding and is not one, recorded so a
    refutation can name what it looked at."""
    soft = []
    authorize = [r for r in as2_records if r.get("path") == "/authorize"]
    if not authorize:
        soft.append({"observation": "no-authorization-request-at-the-new-issuer",
                     "detail": "AS2 was discovered but never asked for an authorization code"})
    for rec in authorize:
        query = rec.get("query") or {}
        if not query.get("resource"):
            soft.append({"observation": "authorization-request-without-a-resource-indicator",
                         "detail": "RFC 8707 `resource` absent; an audience-unbound token is a "
                                   "separate weakness, not this finding"})
        if not query.get("code_challenge"):
            soft.append({"observation": "authorization-request-without-pkce",
                         "detail": "no `code_challenge`; a separate MCP client MUST, not this one"})
        if not query.get("state"):
            soft.append({"observation": "authorization-request-without-state",
                         "detail": "no `state`; a separate weakness, not this finding"})
    if not any(r.get("path", "").startswith("/.well-known/oauth-protected-resource")
               for r in rs2_records):
        soft.append({"observation": "protected-resource-metadata-not-fetched",
                     "detail": "the client did not use RS2's protected-resource metadata to find "
                               "its authorization server"})
    return soft


# ---------------------------------------------------------------------------
# Driving the client.
# ---------------------------------------------------------------------------

BROWSER_SHIM = '''#!/usr/bin/env python3
"""cxg approval shim: performs the user's browser leg of an OAuth login.

It fetches ONE url and only when that url is on loopback, which is where this
template's mock authorization servers live. Anything else it ignores, so a
target that opens some other page during login cannot make this shim reach it.
"""
import sys
import urllib.request

url = sys.argv[1] if len(sys.argv) > 1 else ""
if url.startswith("http://127.0.0.1:") or url.startswith("http://localhost:"):
    try:
        urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": "cxg-approval-shim"}),
            timeout=15).read()
    except Exception:
        pass
'''


def write_shim(lab):
    path = lab / "bin" / "cxg-approval-shim.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(BROWSER_SHIM, encoding="utf-8")
    path.chmod(0o755)
    return path


def client_env(home, lab, shim):
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_DATA_HOME"] = str(home / ".local" / "share")
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    env["XDG_STATE_HOME"] = str(home / ".local" / "state")
    env["TMPDIR"] = str(lab / "tmp")
    env["BROWSER"] = str(shim)
    env["NO_COLOR"] = "1"
    env["CI"] = "1"
    env["TERM"] = "dumb"
    for pager in ("PAGER", "GIT_PAGER", "MANPAGER"):
        env[pager] = "cat"
    env.pop("DISPLAY", None)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.pop(key, None)
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


def run_client(argv, home, lab, shim, timeout):
    home.mkdir(parents=True, exist_ok=True)
    (lab / "tmp").mkdir(parents=True, exist_ok=True)
    (lab / "cwd").mkdir(parents=True, exist_ok=True)
    out = {"argv": list(argv), "home": str(home)}
    try:
        proc = subprocess.run(argv, env=client_env(home, lab, shim), cwd=str(lab / "cwd"),
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
        out.update({"rc": proc.returncode, "timed_out": False,
                    "stdout": proc.stdout.decode("utf-8", "replace")[:4000],
                    "stderr": proc.stderr.decode("utf-8", "replace")[:4000]})
    except subprocess.TimeoutExpired as exc:
        out.update({"rc": None, "timed_out": True,
                    "stdout": (exc.stdout or b"").decode("utf-8", "replace")[:4000],
                    "stderr": (exc.stderr or b"").decode("utf-8", "replace")[:4000]})
    except Exception as exc:
        out.update({"rc": None, "timed_out": False, "stdout": "", "stderr": "",
                    "spawn_error": str(exc)[:300]})
    return out


def probe_help(binary_argv, lab, shim):
    """The target's own help output, and only output it MEANT to produce.

    `<bin> mcp --help` on a binary with no `mcp` subcommand answers
    "'mcp' is not a command" - which contains the word `mcp` and would
    otherwise let a subcommand probe invent the very surface it was looking
    for. Output from a subcommand probe is therefore kept only when that
    probe succeeded; flag and no-argument probes are always kept, because a
    CLI printing usage on no arguments commonly exits non-zero."""
    chunks, seen = [], []
    for extra in HELP_ARGSETS:
        home = lab / "help-home"
        res = run_client(list(binary_argv) + extra, home, lab, shim, HELP_TIMEOUT)
        subcommand_probe = bool(extra) and not extra[0].startswith("-")
        kept = (not subcommand_probe) or res.get("rc") == 0
        seen.append({"argv": res["argv"][len(binary_argv):] or ["<no args>"],
                     "rc": res.get("rc"), "timed_out": res.get("timed_out"),
                     "output_kept": kept})
        if kept:
            chunks.append((res.get("stdout") or "") + "\n" + (res.get("stderr") or ""))
    return "\n".join(chunks)[:20000], seen


def candidate_invocations(help_text):
    lowered = (help_text or "").lower()
    out = []
    for cand in CANDIDATE_ARGVS:
        literals = [t for t in cand if "{url}" not in t]
        if lowered and not all(re.search(r"\b%s\b" % re.escape(t), lowered) for t in literals):
            continue
        out.append(cand)
    return out


def realize(template_argv, url):
    return [t.replace("{url}", url) for t in template_argv]


# ---------------------------------------------------------------------------
# The witness proves itself.
# ---------------------------------------------------------------------------

def ledger_selftest(as2, canary):
    """Plant one request carrying every canary and require BOTH that the
    ledger recorded it and that the detector fired on it. A clean verdict from
    a ledger that cannot see, or a detector that cannot match, is unbacked."""
    import urllib.request

    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": "cxg-ledger-selftest",
        "client_id": canary["client_id"], "client_secret": canary["as1_secret"],
    }).encode()
    req = urllib.request.Request(
        as2.origin + "/token", data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Authorization": "Bearer " + canary["as1_token"],
                 "X-CXG-Selftest": "1"})
    try:
        urllib.request.urlopen(req, timeout=8).read()
    except Exception:
        pass
    planted = [r for r in as2.ledger(include_selftest=True) if r.get("selftest")]
    if not planted:
        return False, "the ledger recorded no request the template itself made"
    hard, _soft = detect_signals(canary, planted, [], True, {})
    fired = sorted({h["signal"] for h in hard})
    if len(fired) < 3:
        return False, ("the canary detector fired on only %s of a planted request carrying every "
                       "canary" % (",".join(fired) or "nothing"))
    return True, "ledger recorded the planted request; detector fired on %s" % ",".join(fired)


# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------

def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def make_finding(target, request_summary, description, evidence, matched):
    return {
        "target": target,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": description,
        "evidence": {
            "request": request_summary,
            "response": json.dumps(evidence)[:1400],
            "matched_patterns": matched,
            "data": evidence,
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# The lab: two authorization servers, two MCP resources, one nonce.
# ---------------------------------------------------------------------------

def build_lab_sites(iss_mode):
    nonce = uuid.uuid4().hex[:12]
    canary = {
        # AS2 hands out the SAME client_id as AS1 - that is the trap the check
        # is built around, and it is why a client_id alone can never confirm.
        "client_id": "cxg-oauth-client-%s" % nonce,
        "as1_secret": "cxg-as1-decoy-secret-%s" % nonce,
        "as1_token": "cxg-as1-decoy-token-%s" % nonce,
        "as2_secret": "cxg-as2-decoy-secret-%s" % nonce,
        "as2_token": "cxg-as2-decoy-token-%s" % nonce,
        "nonce": nonce,
    }
    as1, as2 = MockSite("as", "AS1"), MockSite("as", "AS2")
    rs1, rs2 = MockSite("rs", "RS1"), MockSite("rs", "RS2")
    for site in (as1, as2, rs1, rs2):
        site.bind()

    as1.client_id = canary["client_id"]
    as1.client_secret = canary["as1_secret"]
    as1.access_token = canary["as1_token"]
    as1.iss_mode = "correct"
    as1.peer_issuer = as2.origin

    as2.client_id = canary["client_id"]
    as2.client_secret = canary["as2_secret"]
    as2.access_token = canary["as2_token"]
    as2.iss_mode = iss_mode
    as2.peer_issuer = as1.origin

    rs1.as_issuer, rs1.accepted_token = as1.origin, canary["as1_token"]
    rs2.as_issuer, rs2.accepted_token = as2.origin, canary["as2_token"]
    return canary, as1, as2, rs1, rs2


def held_fixed(as1, as2, rs1, rs2):
    """The differential moves ONE thing. Prove it before trusting a verdict."""
    a = json.dumps(as1.as_metadata(), sort_keys=True).replace(as1.origin, "AS_ORIGIN")
    b = json.dumps(as2.as_metadata(), sort_keys=True).replace(as2.origin, "AS_ORIGIN")
    if a != b:
        return False, "the two authorization servers do not serve identical metadata"
    c = (json.dumps(rs1.rs_metadata(), sort_keys=True)
         .replace(rs1.origin, "RS_ORIGIN").replace(as1.origin, "AS_ORIGIN"))
    d = (json.dumps(rs2.rs_metadata(), sort_keys=True)
         .replace(rs2.origin, "RS_ORIGIN").replace(as2.origin, "AS_ORIGIN"))
    if c != d:
        return False, "the two MCP resources do not serve identical protected-resource metadata"
    if as1.client_id != as2.client_id:
        return False, "the two authorization servers must offer the same client_id"
    return True, ("authorization-server metadata, protected-resource metadata and the offered "
                  "client_id are identical modulo origin; only the issuer the resource points at "
                  "and the `iss` AS2 stamps on its response differ")


def set_phase(sites, phase):
    for site in sites:
        site.phase = phase


def in_phases(site, phases):
    return [r for r in site.ledger(include_selftest=False) if r.get("phase") in phases]


# ---------------------------------------------------------------------------
# The scan.
# ---------------------------------------------------------------------------

def scan(binary_argv):
    iss_mode = (os.getenv("CXG_MCP_CLIENT_ISS_MODE") or "mismatched").strip().lower()
    if iss_mode not in ("mismatched", "missing"):
        iss_mode = "mismatched"

    lab = Path(tempfile.mkdtemp(prefix="cxg-mcp-client-oauth-"))
    sites = []
    try:
        try:
            canary, as1, as2, rs1, rs2 = build_lab_sites(iss_mode)
            sites = [as1, as2, rs1, rs2]
        except Exception as exc:
            return "errored", "could-not-bind-the-mock-oauth-lab(%s)" % str(exc)[:200], []

        ok, why = held_fixed(as1, as2, rs1, rs2)
        if not ok:
            return "errored", "held-fixed-assertion-failed(%s)" % why, []

        shim = write_shim(lab)
        rs1_url, rs2_url = rs1.resource, rs2.resource
        surface = ("client=%s as1=%s as2=%s rs1=%s rs2=%s iss_mode=%s"
                   % (" ".join(binary_argv), as1.origin, as2.origin, rs1_url, rs2_url, iss_mode))

        # -- 1. does this client have an OAuth login path at all? ------------
        set_phase(sites, "help")
        help_text, help_attempts = probe_help(binary_argv, lab, shim)
        hints = sorted({m.lower() for m in LOGIN_HINT_RE.findall(help_text or "")})

        override = os.getenv("CXG_MCP_CLIENT_LOGIN_CMD")
        if override:
            tokens = shlex.split(override)
            template_argvs = [[]]
            for token in tokens:
                template_argvs[0].extend(binary_argv if token == "{bin}" else [token])
            if not any("{url}" in t for t in template_argvs[0]):
                return ("errored",
                        "CXG_MCP_CLIENT_LOGIN_CMD must contain a {url} placeholder (got %r)"
                        % override, [])
            candidates = [template_argvs[0]]
            candidate_note = "login command supplied via CXG_MCP_CLIENT_LOGIN_CMD"
        else:
            candidates = [list(binary_argv) + c for c in candidate_invocations(help_text)]
            candidate_note = "login command derived from the target's own help output"

        # -- 2. discovery: which invocation actually reaches an AS? ----------
        set_phase(sites, "discovery")
        attempts, winner = [], None
        for template_argv in candidates:
            mark = len(as1.ledger(include_selftest=True))
            result = run_client(realize(template_argv, rs1_url),
                                lab / ("discovery-home-%d" % len(attempts)),
                                lab, shim, LOGIN_TIMEOUT)
            reached = as1.ledger(include_selftest=True)[mark:]
            attempts.append({"argv": result["argv"], "rc": result.get("rc"),
                             "timed_out": result.get("timed_out"),
                             "requests_at_as1": len(reached),
                             "stderr_excerpt": (result.get("stderr") or "")[:200]})
            if reached:
                winner = template_argv
                break

        if winner is None:
            tried = "; ".join(" ".join(a["argv"][len(binary_argv):]) or "<none>" for a in attempts)
            if override:
                return ("skipped",
                        "supplied-login-command-reached-no-authorization-server(CXG_MCP_CLIENT_"
                        "LOGIN_CMD=%r ran as [%s]) - the check needs an invocation that actually "
                        "starts an OAuth login | %s" % (override, tried or "none", surface), [])
            if not hints:
                return ("skipped",
                        "no-oauth-login-path(the target's help output advertises no login, oauth or "
                        "authorize surface; %d invocation(s) tried [%s] and none contacted an "
                        "authorization server) | %s | %s"
                        % (len(attempts), tried or "none", candidate_note, surface), [])
            return ("skipped",
                    "login-surface-advertised-but-no-invocation-reached-an-authorization-server("
                    "help mentions %s; tried [%s]) - supply the real one via "
                    "CXG_MCP_CLIENT_LOGIN_CMD='{bin} <verb> {url}' | %s"
                    % (",".join(hints), tried or "none", surface), [])

        login_shape = " ".join(winner[len(binary_argv):]) or "<binary only>"

        # -- 3. phase 1: a clean HOME, a compliant issuer --------------------
        home = lab / "home"
        set_phase(sites, "phase1")
        phase1 = run_client(realize(winner, rs1_url), home, lab, shim, LOGIN_TIMEOUT)

        as1_p1 = in_phases(as1, ("phase1",))
        registered_at_as1 = any(r.get("path") == "/register" for r in as1_p1)
        phase1_token = [r for r in as1_p1
                        if r.get("path") == "/token" and r.get("response_status") == 200]
        if not phase1_token:
            return ("skipped",
                    "phase-1-login-did-not-complete-at-the-first-issuer(login='%s' rc=%s "
                    "timed_out=%s registered=%s requests_at_as1=%d) - without an issuer-bound "
                    "credential there is nothing whose reuse could be observed | stderr=%s | %s"
                    % (login_shape, phase1.get("rc"), phase1.get("timed_out"), registered_at_as1,
                       len(as1_p1), (phase1.get("stderr") or "").strip()[:200], surface), [])

        # -- 4. phase 2: same HOME, same command, a different issuer ---------
        set_phase(sites, "phase2")
        phase2 = run_client(realize(winner, rs2_url), home, lab, shim, LOGIN_TIMEOUT)

        if phase1["home"] != phase2["home"]:
            return "errored", "held-fixed-assertion-failed(the two phases did not share one HOME)", []

        # -- 5. the witness proves itself ------------------------------------
        set_phase(sites, "selftest")
        live, live_why = ledger_selftest(as2, canary)
        if not live:
            return ("errored",
                    "observation-ledger-could-not-see-its-own-request(%s) - a clean verdict here "
                    "would be unbacked | %s" % (live_why, surface), [])

        # -- 6. read the ledgers ---------------------------------------------
        as2_recs = in_phases(as2, ("phase1", "phase2"))
        rs2_recs = in_phases(rs2, ("phase1", "phase2"))
        with as2.lock:
            as2_codes = dict(as2.codes)
        hard, soft = detect_signals(canary, as2_recs, rs2_recs, registered_at_as1, as2_codes)
        soft.extend(near_miss_observations(as2_recs, rs2_recs, as2_codes))

        registered_at_as2 = any(r.get("path") == "/register" for r in as2_recs)
        authorized_at_as2 = any(r.get("path") == "/authorize" for r in as2_recs)
        redeemed_at_as2 = any(r.get("path") == "/token" for r in as2_recs)

        run_surface = ("%s login='%s' %s ledger_selftest=live phase1_rc=%s phase2_rc=%s "
                       "as2_requests=%d rs2_requests=%d"
                       % (surface, login_shape, candidate_note, phase1.get("rc"),
                          phase2.get("rc"), len(as2_recs), len(rs2_recs)))

        evidence = {
            "client": " ".join(binary_argv),
            "login_invocation": login_shape,
            "held_fixed": why,
            "iss_mode_at_as2": iss_mode,
            "canaries": {k: v for k, v in canary.items() if k != "nonce"},
            "issuers": {"AS1": as1.origin, "AS2": as2.origin},
            "resources": {"RS1": rs1_url, "RS2": rs2_url},
            "phase1": {"registered_at_as1": registered_at_as1,
                       "token_issued": bool(phase1_token),
                       "rc": phase1.get("rc"),
                       "stdout_excerpt": (phase1.get("stdout") or "")[:600]},
            "phase2": {"registered_at_as2": registered_at_as2,
                       "authorization_request_at_as2": authorized_at_as2,
                       "token_exchange_at_as2": redeemed_at_as2,
                       "rc": phase2.get("rc"),
                       "stdout_excerpt": (phase2.get("stdout") or "")[:600],
                       "stderr_excerpt": (phase2.get("stderr") or "")[:600]},
            "hard_signals": hard,
            "observations": soft,
            "as2_ledger": [{"seq": r["seq"], "method": r["method"], "path": r["path"],
                            "status": r.get("response_status")} for r in as2_recs],
            "rs2_ledger": [{"seq": r["seq"], "method": r["method"], "path": r["path"],
                            "status": r.get("response_status"),
                            "authorization": (r.get("headers") or {}).get("authorization")}
                           for r in rs2_recs],
            "ledger_selftest": live_why,
        }

        if hard:
            names = ", ".join(h["signal"] for h in hard)
            description = (
                "MCP client `%s` was logged in twice through its own login path (`%s`), against the "
                "same $HOME, with everything held fixed except the issuer: phase 1 against a mock "
                "MCP resource whose protected-resource metadata pointed at AS1 (%s), phase 2 against "
                "a second resource pointing at AS2 (%s). AS2 offers the SAME client_id as AS1 and "
                "stamps %s on its authorization response. The client failed %d of the 2026-07-28 MCP "
                "client authorization requirements, each observed in AS2's or RS2's request ledger: "
                "%s. "
                "%s Every credential here is a synthetic `cxg-` decoy carrying a per-run nonce, so a "
                "canary in the second issuer's ledger can only have arrived there by the client "
                "carrying it. The ledger proved itself live on a request the template planted before "
                "the verdict was taken. In the field this is the authorization-server mix-up: an "
                "agent pointed at a second MCP server - from a marketplace entry, a README, a "
                "teammate's config - hands that server's issuer the credentials of the first."
                % (" ".join(binary_argv), login_shape, as1.origin, as2.origin,
                   "an `iss` naming AS1 rather than itself" if iss_mode == "mismatched"
                   else "no `iss` at all, while advertising support for it",
                   len(hard), names,
                   " ".join("[%s] %s." % (h["signal"], h["why"]) for h in hard)))
            finding = make_finding(
                target_label(binary_argv),
                "phase 1: `%s` against %s (issuer AS1) -> phase 2: the same command against %s "
                "(issuer AS2, same client_id, %s `iss`), one $HOME" % (
                    login_shape, rs1_url, rs2_url, iss_mode),
                description, evidence,
                sorted({h["signal"] for h in hard}))
            return "confirmed", "issuer-binding-failure(%s) | %s" % (names, run_surface), [finding]

        if not as2_recs and not rs2_recs:
            return ("skipped",
                    "phase-2-login-never-contacted-the-second-server(rc=%s timed_out=%s) - the "
                    "issuer change was never presented to the client | stderr=%s | %s"
                    % (phase2.get("rc"), phase2.get("timed_out"),
                       (phase2.get("stderr") or "").strip()[:200], run_surface), [])

        if not authorized_at_as2:
            return ("skipped",
                    "new-issuer-reached-but-no-authorization-request(registered_at_as2=%s) - the "
                    "client stopped before asking AS2 for a code, so the RFC 9207 `iss` check was "
                    "never exercised; near-misses recorded: %s | %s"
                    % (registered_at_as2,
                       ",".join(o.get("observation", "?") for o in soft) or "none", run_surface), [])

        return ("refuted",
                "issuer-binding-held(%s; asked AS2 for a code, was handed %s, and did not redeem it; "
                "no AS1 canary anywhere in AS2's or RS2's ledger; near-misses recorded and not fired "
                "on: %s) | %s"
                % ("re-registered at the new issuer" if registered_at_as2
                   else "used a client identity neither issuer minted for it",
                   "an `iss` naming a different issuer" if iss_mode == "mismatched"
                   else "no `iss` at all",
                   ",".join(o.get("observation", "?") for o in soft) or "none", run_surface), [])
    finally:
        for site in sites:
            site.stop()
        shutil.rmtree(str(lab), ignore_errors=True)


# ---------------------------------------------------------------------------
# Target resolution. A cli target arrives as the raw scope string with the
# cli:// prefix still on it, and CERT_X_GEN_TARGET_KIND is usually unset.
# ---------------------------------------------------------------------------

def target_label(binary_argv):
    """The client as a scanner names it, not as this process had to spawn it."""
    binary = binary_argv[0]
    if binary_argv[0] == sys.executable and len(binary_argv) > 1:
        binary = binary_argv[1]
    return "cli://" + binary


def client_argv(binary):
    extra = os.getenv("CXG_MCP_CLIENT_ARGS", "")
    argv = [binary] + (shlex.split(extra) if extra else [])
    if not os.access(binary, os.X_OK) and binary.endswith(".py"):
        argv = [sys.executable] + argv
    return argv


def resolve_target():
    override = os.getenv("CXG_MCP_CLIENT_CMD")
    if override:
        return ("client", shlex.split(override))

    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST") or ""
        kind = (os.getenv("CERT_X_GEN_TARGET_KIND") or "").lower()
        if not host:
            return ("error", "CERT_X_GEN_TARGET_HOST not set")
        if host.startswith("cli://"):
            return ("client", client_argv(host[len("cli://"):] or "/"))
        if kind == "cli" or (host.startswith("/") and Path(host).is_file()):
            return ("client", client_argv(host))
        return ("error",
                "this template drives an MCP CLIENT and needs a cli:// target (the agent binary); "
                "got target=%s kind=%s" % (host, kind or "<unset>"))

    args = sys.argv[1:]
    if not args:
        return ("error",
                "Usage: mcp-client-oauth-issuer-binding.py cli:///path/to/agent  |  "
                "/path/to/agent  |  --client <command> [args...]")
    if args[0] == "--client":
        if len(args) < 2:
            return ("error", "--client needs a command")
        return ("client", list(args[1:]))
    if args[0].startswith("cli://"):
        return ("client", client_argv(args[0][len("cli://"):] or "/"))
    return ("client", client_argv(args[0]))


def main():
    sys.stderr.write(
        "[!] mcp-client-oauth-issuer-binding is an ACTIVE check: it RUNS the target's own OAuth "
        "login command twice, against mock authorization servers this process binds on loopback, "
        "with $HOME redirected into a temporary lab. No real identity provider is contacted and "
        "every credential is a synthetic decoy. Make sure you are authorized to run this binary.\n")
    sys.stderr.flush()

    target = resolve_target()
    if target[0] == "error":
        emit("errored", target[1])
        sys.exit(0)

    argv = target[1]
    if not argv or not (Path(argv[0]).exists() or shutil.which(argv[0])):
        emit("errored", "cli-target-not-executable(%s)" % (argv[0] if argv else "<empty>"))
        sys.exit(0)

    status, detail, findings = scan(argv)
    emit(status, detail, findings)


if __name__ == "__main__":
    main()

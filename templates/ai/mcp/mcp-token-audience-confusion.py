#!/usr/bin/env python3
# @id: mcp-token-audience-confusion
# @name: MCP Token Passthrough / Audience Confusion (Confused Deputy)
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. Detects an MCP server that authenticates requests yet accepts a Bearer token whose audience (aud) is not scoped for it - the token passthrough / confused-deputy anti-pattern the June 2025 MCP spec explicitly forbids
# @tags: mcp, ai, agent, broken-auth, token-passthrough, audience-confusion, confused-deputy, oauth, intrusive, active, cwe-287, cwe-441
# @cwe: CWE-287, CWE-441
# @cvss: 8.1
# @target_kinds: http
# @oracles: property
# @references: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization, https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices, https://www.rfc-editor.org/rfc/rfc8707.html, https://www.rfc-editor.org/rfc/rfc8693.html, https://www.descope.com/blog/post/mcp-auth-spec, https://www.practical-devsecops.com/glossary/token-passthrough-vulnerability/, https://cwe.mitre.org/data/definitions/441.html
# @confidence: 90
# @version: 1.0.0
"""
ACTIVE / INTRUSIVE check - MCP token passthrough / audience confusion.

An MCP server is an OAuth 2.1 *resource server*. The June 2025 MCP
authorization spec makes one requirement unambiguous:

    "MCP servers MUST validate that access tokens were issued specifically
     for them as the intended audience" ... "MUST only accept tokens
     specifically intended for themselves and MUST reject tokens that do not
     include them in the audience claim" ... "Invalid or expired tokens MUST
     receive a HTTP 401 response."

A server that skips this check is a *confused deputy* (CWE-441): a token minted
for a different resource - leaked, stolen, or simply over-broad - operates this
server, and if the server forwards that token downstream it re-uses one
audience's credential against another. That is the "token passthrough"
anti-pattern the spec calls "explicitly forbidden".

THE ORACLE IS A PROPERTY, NOT A GUESS

The invariant this template checks is REJECTION. It never reads a description
or fingerprints a version; it speaks the protocol and observes a behaviour. It
runs a small differential so that "accepts a wrong-audience token" is a FACT
and is never confused with "has no authentication at all" (a different finding,
covered by mcp-unauthenticated):

  Probe A  initialize with NO Authorization header.
             accepted  -> the server has no auth gate at all. Audience
                          validation is not reachable; this is the
                          unauthenticated case, not this one. => skipped.
             rejected  -> the server gates on a token (401/403 or an auth
                          error). Continue.

  Probe B  initialize + tools/list + tools/call carrying a well-formed,
           self-issued JWT whose `aud` names a DIFFERENT resource
           (https://cxg-unrelated-resource.example/api), never this server.
             rejected  -> the server validates audience. => refuted.
             accepted  -> the server authenticates requests in general yet
                          served a token scoped for another resource. The
                          spec invariant broke. => confirmed.

  Probe C  (evidence only, does not decide the verdict) initialize with a JWT
           whose `aud` IS this server's canonical URI. A server that accepts C
           but also accepted B is validating *presence* of a token, not its
           audience - the sharpest confused-deputy signature.

Rejection signal, in priority order and all spec-anchored:
  * HTTP 401 or 403  (the spec mandates 401 for an invalid-audience token);
  * a JSON-RPC error or a bare error body whose text is auth-shaped
    (unauthorized / forbidden / invalid_token / audience / ...).
Acceptance signal:
  * HTTP 200 with a JSON-RPC `result` and no error.

Only self-issued dummy JWTs are sent (HMAC-signed with a throwaway key that no
real issuer holds); nothing here is a real credential and nothing is forwarded
to a third party. Speaks streamable HTTP and legacy HTTP+SSE.

Verdict contract, as the ai/mcp pack states it:
  confirmed  auth is enforced, yet a token whose audience is not this server
             was accepted through initialize/tools/call
  refuted    the wrong-audience token was rejected (audience validated)
  skipped    no MCP server answered, or it accepts unauthenticated requests
             (audience validation is not reachable - see mcp-unauthenticated)
  errored    the target could not be reached at all
"""

import base64
import hashlib
import hmac
import json
import os
import queue
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-token-audience-confusion",
    "name": "MCP Token Passthrough / Audience Confusion (Confused Deputy)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE check: detects an MCP server that authenticates requests yet accepts a Bearer "
        "token whose audience is not scoped for it - the token passthrough / confused-deputy "
        "anti-pattern the June 2025 MCP spec explicitly forbids"
    ),
    "tags": ["mcp", "ai", "agent", "broken-auth", "token-passthrough", "audience-confusion",
             "confused-deputy", "oauth", "intrusive", "active", "cwe-287", "cwe-441"],
    "language": "python",
    "active": True,
    "confidence": 90,
    "cwe": ["CWE-287", "CWE-441"],
    "references": [
        "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization",
        "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
        "https://www.rfc-editor.org/rfc/rfc8707.html",
        "https://www.rfc-editor.org/rfc/rfc8693.html",
        "https://www.descope.com/blog/post/mcp-auth-spec",
        "https://www.practical-devsecops.com/glossary/token-passthrough-vulnerability/",
        "https://cwe.mitre.org/data/definitions/441.html",
    ],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"

# The audience the wrong-audience token is minted for. It is NOT this server,
# by construction - a compliant server must reject a token bearing it.
FOREIGN_AUDIENCE = "https://cxg-unrelated-resource.example/api"
FOREIGN_ISSUER = "https://cxg-unrelated-issuer.example"

AUTH_ERROR_RE = re.compile(
    r"unauthor|forbidden|invalid[_ -]?token|invalid[_ -]?grant|access[_ -]?denied|"
    r"authenticat|\baudience\b|\baud\b|not\s+permitted|insufficient", re.I)


# ---------------------------------------------------------------------------
# Dummy self-issued JWT. HS256 with a throwaway key; no real issuer holds it.
# Only the `aud` claim is under test, so the signature is cosmetic - it exists
# so the token is well-formed, not so any server would trust it.
# ---------------------------------------------------------------------------

def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def mint_jwt(audience, subject="cxg-fixture-user"):
    header = {"alg": "HS256", "typ": "JWT", "kid": "cxg-dummy"}
    now = int(time.time())
    payload = {
        "iss": FOREIGN_ISSUER,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "scope": "notes:read",
        "cxg_synthetic": True,   # marks this token as a test artefact, never real
    }
    signing_input = ("%s.%s" % (_b64url(json.dumps(header).encode()),
                                _b64url(json.dumps(payload).encode()))).encode("ascii")
    sig = hmac.new(b"cxg-throwaway-key-not-a-real-secret", signing_input, hashlib.sha256).digest()
    return "%s.%s" % (signing_input.decode("ascii"), _b64url(sig))


# ---------------------------------------------------------------------------
# HTTP.
# ---------------------------------------------------------------------------

def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _extract_json(body):
    body = (body or "").strip()
    if not body:
        return None
    if "data:" in body:
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except ValueError:
                    continue
    try:
        return json.loads(body)
    except ValueError:
        return None


def _post(url, payload, timeout, token=None, session_id=None):
    """POST a JSON-RPC frame. Returns (status, headers, body). status is None
    only on a transport error; an HTTP error code (401/403/...) comes back as
    its number, because the code IS the observation here."""
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    if session_id:
        headers["mcp-session-id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=_ctx())
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "ignore")
        except Exception:
            body = ""
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
    except Exception:
        return None, {}, ""


def classify(status, headers, body):
    """Map one HTTP response onto the auth property: 'accept', 'reject' or
    'indeterminate'. Anchored on the status code the spec mandates first."""
    if status in (401, 403):
        return "reject"
    if status is None:
        return "indeterminate"
    if "www-authenticate" in {k.lower() for k in headers}:
        return "reject"
    obj = _extract_json(body)
    if isinstance(obj, dict):
        err = obj.get("error")
        if err is not None:
            text = err if isinstance(err, str) else json.dumps(err)
            if AUTH_ERROR_RE.search(text):
                return "reject"
            # a non-auth JSON-RPC error (e.g. method not found) with a served
            # session still means the token was accepted at the auth layer
            if status == 200 and isinstance(err, dict) and err.get("code") == -32601:
                return "accept"
            return "indeterminate"
        if status == 200 and "result" in obj:
            return "accept"
    if status == 200:
        # 200 with no parseable JSON-RPC - treat conservatively
        return "indeterminate"
    return "indeterminate"


# ---------------------------------------------------------------------------
# Transport discovery + a single authenticated exchange.
# ---------------------------------------------------------------------------

def _init_payload(rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": "initialize",
            "params": {"protocolVersion": PROTO_VERSION, "capabilities": {},
                       "clientInfo": {"name": "cxg", "version": "1.0"}}}


def find_streamable_endpoint(base, timeout):
    """Locate a streamable-HTTP MCP endpoint by asking each candidate path to
    initialize WITHOUT a token. Any answer that is a JSON-RPC result OR a 401
    proves an MCP server is there; a 404/None means keep looking. Returns
    (path, unauth_status, unauth_headers, unauth_body) or None."""
    for path in MCP_PATHS:
        status, headers, body = _post(base + path, _init_payload(), timeout)
        if status is None:
            continue
        obj = _extract_json(body)
        looks_mcp = (isinstance(obj, dict) and ("result" in obj or "error" in obj)) or status in (401, 403)
        if looks_mcp:
            return path, status, headers, body
    return None


def probe_streamable(base, path, timeout, token):
    """Run initialize -> tools/list -> tools/call with `token`. Returns a dict
    of per-method classifications and the raw evidence of the first frame."""
    url = base + path
    status, headers, body = _post(url, _init_payload(), timeout, token=token)
    verdict = classify(status, headers, body)
    out = {"initialize": verdict, "status": status,
           "www_authenticate": headers.get("www-authenticate", ""),
           "body_excerpt": (body or "")[:300]}
    if verdict != "accept":
        return out
    sid = headers.get("mcp-session-id")
    _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, token=token, session_id=sid)
    s2, h2, b2 = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                       timeout, token=token, session_id=sid)
    out["tools_list"] = classify(s2, h2, b2)
    first_tool = None
    tl = _extract_json(b2)
    if isinstance(tl, dict):
        tools = ((tl.get("result") or {}).get("tools")) or []
        if tools and isinstance(tools[0], dict):
            first_tool = tools[0].get("name")
    if first_tool:
        s3, h3, b3 = _post(url, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                 "params": {"name": first_tool, "arguments": {}}},
                           timeout, token=token, session_id=sid)
        out["tools_call"] = classify(s3, h3, b3)
        out["tool_called"] = first_tool
    return out


# --- legacy HTTP+SSE ------------------------------------------------------

def open_sse(base, timeout, token):
    """Return a post_url for a legacy SSE server, or None. Auth on the SSE GET
    is honoured: a 401 there is itself a reject signal we surface."""
    responses = queue.Queue()
    endpoint = {}
    stop = threading.Event()
    sse_headers = {"Accept": "text/event-stream"}
    if token:
        sse_headers["Authorization"] = "Bearer %s" % token

    def reader():
        try:
            resp = urllib.request.urlopen(
                urllib.request.Request(base + "/sse", headers=sse_headers),
                timeout=timeout, context=_ctx())
            event = None
            for raw in resp:
                if stop.is_set():
                    break
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    d = line[5:].strip()
                    if event == "endpoint":
                        endpoint["url"] = d
                    else:
                        try:
                            responses.put(json.loads(d))
                        except ValueError:
                            pass
                elif line == "":
                    event = None
        except urllib.error.HTTPError as e:
            endpoint["http_error"] = e.code
        except Exception:
            pass

    threading.Thread(target=reader, daemon=True).start()
    for _ in range(int(timeout * 10)):
        if "url" in endpoint or "http_error" in endpoint:
            break
        time.sleep(0.1)
    if "http_error" in endpoint:
        stop.set()
        return None, endpoint["http_error"], responses, stop
    if "url" not in endpoint:
        stop.set()
        return None, None, responses, stop
    return base + endpoint["url"], None, responses, stop


def probe_sse(base, timeout, token):
    post_url, http_error, responses, stop = open_sse(base, timeout, token)
    if http_error in (401, 403):
        return {"initialize": "reject", "status": http_error, "www_authenticate": "",
                "body_excerpt": "SSE GET returned %d" % http_error}
    if not post_url:
        return None
    try:
        def post(p):
            h = {"Content-Type": "application/json"}
            if token:
                h["Authorization"] = "Bearer %s" % token
            try:
                r = urllib.request.urlopen(
                    urllib.request.Request(post_url, data=json.dumps(p).encode(), headers=h, method="POST"),
                    timeout=timeout, context=_ctx())
                return r.status, r.read().decode("utf-8", "ignore")
            except urllib.error.HTTPError as e:
                return e.code, ""
            except Exception:
                return None, ""

        status, body = post(_init_payload())
        # legacy servers reply on the SSE stream, not the POST body
        if status in (401, 403):
            return {"initialize": "reject", "status": status, "www_authenticate": "",
                    "body_excerpt": "POST returned %d" % status}
        end = time.time() + min(timeout, 6)
        while time.time() < end:
            try:
                msg = responses.get(timeout=1)
            except queue.Empty:
                continue
            if isinstance(msg, dict) and msg.get("id") == 1:
                verdict = "accept" if "result" in msg else classify(200, {}, json.dumps(msg))
                return {"initialize": verdict, "status": 200, "www_authenticate": "",
                        "body_excerpt": json.dumps(msg)[:300]}
        return {"initialize": "indeterminate", "status": status, "www_authenticate": "",
                "body_excerpt": "no id=1 frame on SSE stream"}
    finally:
        stop.set()


# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------

def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def scan(host, port, timeout=12, scheme="http"):
    base = "%s://%s:%d" % (scheme, host, port)
    transport = "streamable-http"
    endpoint_path = None

    found = find_streamable_endpoint(base, timeout)
    if found:
        endpoint_path, _u_status, _u_headers, _u_body = found

        def run(token):
            return probe_streamable(base, endpoint_path, timeout, token)
    else:
        # try legacy SSE, unauthenticated, to see if an MCP server is there
        unauth = probe_sse(base, timeout, None)
        if not unauth:
            return "skipped", "no-mcp-server-answered(%s)" % base, []
        transport = "http+sse"
        endpoint_path = "/sse"

        def run(token):
            return probe_sse(base, timeout, token)

    endpoint = base + (endpoint_path or "")

    # Probe A - no token at all.
    probe_a = run(None)
    if not probe_a:
        return "skipped", "no-mcp-server-answered(%s)" % base, []
    if probe_a.get("initialize") == "accept":
        return ("skipped",
                "server-accepts-unauthenticated-requests(no auth gate; audience validation not "
                "reachable - see mcp-unauthenticated) transport=%s endpoint=%s"
                % (transport, endpoint), [])
    if probe_a.get("initialize") == "indeterminate":
        return ("skipped",
                "auth-behaviour-indeterminate-without-token(status=%s) transport=%s"
                % (probe_a.get("status"), transport), [])

    # Server gates on a token. Probe B - a token for a FOREIGN audience.
    foreign_token = mint_jwt(FOREIGN_AUDIENCE)
    probe_b = run(foreign_token)
    b_init = (probe_b or {}).get("initialize")

    # Probe C - a token scoped to THIS server (evidence only).
    self_token = mint_jwt(endpoint)
    probe_c = run(self_token)
    c_init = (probe_c or {}).get("initialize")

    surface = "transport=%s endpoint=%s no_token=%s foreign_aud=%s self_aud=%s" % (
        transport, endpoint, probe_a.get("initialize"), b_init, c_init)

    if b_init != "accept":
        detail = "wrong-audience-token-rejected(%s) status=%s" % (b_init, (probe_b or {}).get("status"))
        return "refuted", detail + " | " + surface, []

    # Confirmed: auth enforced (Probe A rejected), foreign-audience token accepted.
    reached = [m for m in ("initialize", "tools_list", "tools_call")
               if (probe_b or {}).get(m) == "accept"]
    finding = {
        "target": endpoint,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (
            "MCP server at %s rejects an unauthenticated request (HTTP %s) yet ACCEPTS a Bearer "
            "token whose audience claim is '%s' - a resource that is not this server. The June "
            "2025 MCP spec requires a server to reject any token not audience-scoped for it "
            "(RFC 8707); accepting one is the token-passthrough / confused-deputy anti-pattern "
            "the spec forbids. The foreign-audience token was honoured through: %s.%s"
            % (endpoint, probe_a.get("status"), FOREIGN_AUDIENCE, ", ".join(reached) or "initialize",
               " The server also accepted a token scoped to itself, so it validates a token's "
               "presence but not its audience." if c_init == "accept" else "")),
        "evidence": {
            "request": ("initialize -> tools/list -> tools/call with a self-issued JWT "
                        "(aud=%s); baseline initialize sent with no token" % FOREIGN_AUDIENCE),
            "response": json.dumps({
                "no_token_probe": {"verdict": probe_a.get("initialize"), "status": probe_a.get("status"),
                                   "www_authenticate": probe_a.get("www_authenticate", "")[:160]},
                "foreign_audience_probe": {"verdict": b_init, "status": (probe_b or {}).get("status"),
                                           "methods_accepted": reached},
                "self_audience_probe": {"verdict": c_init, "status": (probe_c or {}).get("status")},
            })[:1000],
            "matched_patterns": ["wrong-audience-token-accepted", "auth-gate-present"],
            "data": {
                "protocol": scheme,
                "port": port,
                "transport": transport,
                "endpoint": endpoint,
                "foreign_audience": FOREIGN_AUDIENCE,
                "no_token_verdict": probe_a.get("initialize"),
                "foreign_audience_verdict": b_init,
                "self_audience_verdict": c_init,
                "methods_accepted_with_foreign_token": reached,
            },
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    detail = "wrong-audience-token-accepted(methods=%s) | %s" % (",".join(reached) or "initialize", surface)
    return "confirmed", detail, [finding]


def main():
    sys.stderr.write("[!] mcp-token-audience-confusion is an ACTIVE check: it sends self-issued dummy "
                     "JWTs (no real credential) to an MCP server to observe whether it rejects a token "
                     "not audience-scoped for it. Make sure you are authorized to test this system.\n")
    sys.stderr.flush()
    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST")
        port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "8000"))
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        if not host:
            emit("errored", "CERT_X_GEN_TARGET_HOST not set")
            sys.exit(0)
    else:
        if len(sys.argv) < 2:
            emit("errored", "Usage: mcp-token-audience-confusion.py <host> [port] [scheme]")
            sys.exit(0)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"

    status, detail, findings = scan(host, port, scheme=scheme)
    emit(status, detail, findings)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Benign synthetic OAuth authorization server for the consent-layer
confused-deputy oracle (``templates/ai/mcp/mcp-oauth-consent-dcr-abuse.py``).

Stdlib only. Both modes serve the SAME OAuth surface - a discovery document, an
RFC 7591 registration endpoint, and an /authorize endpoint with a consent
screen - and answer an unauthenticated discovery request identically. They
differ in exactly the three decisions that compose the confused deputy:

    (a) does /register VET the redirect_uri, or accept any?
    (b) is the client_id unique per registration, or one shared static value?
    (c) is the consent decision bound to the redirect_uri, or reused across
        redirect_uris for the same client_id?

  ``--mode flawed``  Open DCR (any redirect_uri accepted), a single shared
                     static client_id for every registrant, and consent keyed
                     by client_id only. A consent cookie granted for a
                     first-party redirect_uri is silently reused to deliver a
                     code to a brand-new attacker redirect_uri - with no
                     re-consent and no RFC 9207 `iss`.

  ``--mode fixed``   /register rejects a redirect_uri it was not told about
                     (RFC 7591 metadata vetting) and mints a unique client_id
                     per registration; /authorize validates the redirect_uri
                     against the client's registered set (RFC 6749 s.10.6),
                     re-consents for a (client_id, redirect_uri) pair it has not
                     seen, and stamps RFC 9207 `iss` plus the echoed `state` on
                     every code it issues.

Nothing here is a real IdP. Every client_id, code, cookie and redirect_uri is a
synthetic ``cxg-`` decoy; no code is ever redeemed and the attacker redirect_uri
is a ``.example`` host that resolves nowhere. The auth DECISIONS are the entire
attack surface of this class.
"""

import argparse
import json
import sys
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The one redirect_uri a fixed server treats as first-party / pre-approved. It
# matches BENIGN_REDIRECT in the template. Anything else is "unvetted".
BENIGN_REDIRECT = "https://cxg-legit-client.example/cb"
SHARED_CLIENT_ID = "cxg-shared-mcp-client"

CONSENT_PAGE = (
    "<!doctype html><html><head><title>Authorize access</title></head><body>"
    "<h1>Consent required</h1>"
    "<p>An application is requesting access to your MCP tools. Do you authorize "
    "this?</p><form method=\"post\" action=\"{action}\">"
    "<input type=\"hidden\" name=\"client_id\" value=\"{client_id}\">"
    "<input type=\"hidden\" name=\"redirect_uri\" value=\"{redirect_uri}\">"
    "<button name=\"approve\" value=\"true\">Allow</button>"
    "<button name=\"approve\" value=\"false\">Deny</button></form></body></html>"
)


def handler_for(mode, base_url):
    # per-process state
    clients = {}          # client_id -> {"redirect_uris": [...]}
    sessions = {}         # session_id -> {"client_ids": set(), "grants": set((cid, ruri))}
    issuer = base_url

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_a):
            pass

        # -- helpers ---------------------------------------------------------
        def _send(self, code, body, ctype="application/json", extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            raw = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _redirect(self, location):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def _cookies(self):
            jar = {}
            for part in (self.headers.get("Cookie") or "").split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    jar[k.strip()] = v.strip()
            return jar

        def _session(self, create=False):
            jar = self._cookies()
            sid = jar.get("cxg_sess")
            if sid and sid in sessions:
                return sid, None
            if create:
                sid = "cxg-sess-" + uuid.uuid4().hex[:16]
                sessions[sid] = {"client_ids": set(), "grants": set()}
                return sid, sid  # (sid, set_cookie_value)
            return None, None

        def _issue_code(self, redirect_uri, state):
            code = "cxg-code-" + uuid.uuid4().hex[:16]
            params = {"code": code, "state": state}
            if mode == "fixed":
                # RFC 9207: stamp the issuer on the authorization response.
                params["iss"] = issuer
            sep = "&" if "?" in redirect_uri else "?"
            return redirect_uri + sep + urllib.parse.urlencode(params)

        # -- discovery -------------------------------------------------------
        def _discovery(self):
            meta = {
                "issuer": issuer,
                "authorization_endpoint": issuer + "/authorize",
                "token_endpoint": issuer + "/token",
                "registration_endpoint": issuer + "/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                # flawed advertises no iss support; fixed does.
                "authorization_response_iss_parameter_supported": mode == "fixed",
            }
            self._send(200, meta)

        # -- registration (RFC 7591) ----------------------------------------
        def _register(self, body):
            try:
                req = json.loads(body or "{}")
            except ValueError:
                req = {}
            redirect_uris = req.get("redirect_uris") or []
            if mode == "fixed":
                # Vet every redirect_uri: only a pre-approved first-party value
                # is registrable. An unvetted one is rejected (RFC 7591 5.2).
                bad = [u for u in redirect_uris if u != BENIGN_REDIRECT]
                if bad or not redirect_uris:
                    self._send(400, {
                        "error": "invalid_redirect_uri",
                        "error_description": "redirect_uri is not a registered/approved value: %s"
                                             % (bad or "<none>"),
                    })
                    return
                cid = "cxg-client-" + uuid.uuid4().hex[:12]   # unique per registration
            else:
                # flawed: open DCR - accept any redirect_uri, no vetting, and
                # hand back one shared static client_id for everyone.
                cid = SHARED_CLIENT_ID
            clients[cid] = {"redirect_uris": list(redirect_uris)}
            self._send(201, {
                "client_id": cid,
                "redirect_uris": redirect_uris,
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
                "client_id_issued_at": 0,
            })

        # -- authorize -------------------------------------------------------
        def _authorize_get(self, q):
            client_id = q.get("client_id", "")
            redirect_uri = q.get("redirect_uri", "")
            state = q.get("state", "")

            if mode == "fixed":
                # RFC 6749 s.10.6: the redirect_uri MUST match one registered
                # for this client. An attacker redirect_uri never registered
                # here is refused outright.
                reg = clients.get(client_id, {}).get("redirect_uris", [])
                if redirect_uri not in reg:
                    self._send(400, {
                        "error": "invalid_request",
                        "error_description": "redirect_uri does not match a registered value "
                                             "for this client",
                    })
                    return
                sid, _new = self._session()
                grants = sessions.get(sid, {}).get("grants", set()) if sid else set()
                if sid and (client_id, redirect_uri) in grants:
                    # consent already granted for THIS (client, redirect) pair
                    self._redirect(self._issue_code(redirect_uri, state))
                    return
                # otherwise re-consent (new pair) - show the consent screen.
                sid, setc = self._session(create=True)
                extra = {"Set-Cookie": "cxg_sess=%s; Path=/; HttpOnly" % setc} if setc else None
                page = CONSENT_PAGE.format(action="/authorize", client_id=client_id,
                                           redirect_uri=redirect_uri)
                self._send(200, page, ctype="text/html", extra=extra)
                return

            # ---- flawed ----
            sid, _new = self._session()
            consented = sessions.get(sid, {}).get("client_ids", set()) if sid else set()
            if sid and client_id in consented:
                # consent keyed by client_id ONLY - reused across ANY
                # redirect_uri. The redirect_uri is never re-checked.
                self._redirect(self._issue_code(redirect_uri, state))
                return
            sid, setc = self._session(create=True)
            extra = {"Set-Cookie": "cxg_sess=%s; Path=/; HttpOnly" % setc} if setc else None
            page = CONSENT_PAGE.format(action="/authorize", client_id=client_id,
                                       redirect_uri=redirect_uri)
            self._send(200, page, ctype="text/html", extra=extra)

        def _authorize_post(self, form):
            client_id = form.get("client_id", "")
            redirect_uri = form.get("redirect_uri", "")
            state = form.get("state", "")
            approve = form.get("approve", "false")
            sid, setc = self._session(create=True)
            if approve != "true":
                self._send(400, {"error": "access_denied"})
                return
            if mode == "fixed":
                reg = clients.get(client_id, {}).get("redirect_uris", [])
                if redirect_uri not in reg:
                    self._send(400, {"error": "invalid_request",
                                     "error_description": "redirect_uri not registered"})
                    return
                sessions[sid]["grants"].add((client_id, redirect_uri))
            else:
                # flawed: record consent by client_id, forgetting the redirect_uri
                sessions[sid]["client_ids"].add(client_id)
            extra = {"Set-Cookie": "cxg_sess=%s; Path=/; HttpOnly" % setc} if setc else None
            loc = self._issue_code(redirect_uri, state)
            # deliver the code via a redirect, carrying the (new) cookie
            self.send_response(302)
            self.send_header("Location", loc)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()

        # -- routing ---------------------------------------------------------
        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            if path in ("/.well-known/oauth-authorization-server",
                        "/.well-known/openid-configuration"):
                self._discovery()
            elif path == "/authorize":
                self._authorize_get(dict(urllib.parse.parse_qsl(parsed.query)))
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            path = urllib.parse.urlsplit(self.path).path
            if path == "/register":
                self._register(raw.decode("utf-8", "ignore"))
            elif path == "/authorize":
                form = dict(urllib.parse.parse_qsl(raw.decode("utf-8", "ignore")))
                self._authorize_post(form)
            else:
                self._send(404, {"error": "not_found"})

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["flawed", "fixed"], required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    base_url = "http://%s:%d" % (args.host, args.port)
    srv = ThreadingHTTPServer((args.host, args.port), handler_for(args.mode, base_url))
    sys.stderr.write("cxg oauth AS fixture (%s) on %s\n" % (args.mode, base_url))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

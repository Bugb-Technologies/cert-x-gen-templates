#!/usr/bin/env python3
"""
Synthetic MCP *client* stub - a toy coding agent with an OAuth login path.

Entirely benign. It talks only to whatever URL it is handed, stores decoy
credentials under $HOME, and does nothing else. It exists so
templates/ai/mcp/mcp-client-oauth-issuer-binding.py can be proved in every
direction it emits, against one source built into three twins:

  flawed    caches ONE OAuth credential blob and looks it up without reference
            to the issuer that minted it. On a second MCP server backed by a
            DIFFERENT authorization server it (a) attaches the first issuer's
            access token to its very first request, (b) skips dynamic client
            registration at the new issuer because it "already has" a
            client_id, presenting the first issuer's client_secret there, and
            (c) redeems the authorization code without checking the RFC 9207
            `iss` the response carried.
  fixed     the same program with the credential store keyed by (issuer,
            client_id), so a new issuer means a new registration, and with the
            `iss` of the authorization response checked against the issuer of
            the metadata it fetched. On the mix-up it aborts before redeeming.
  nooauth   the same program with the OAuth login surface removed, so the
            template has a target whose missing precondition is exactly "this
            client exposes no OAuth login path".

Everything else - PKCE, `state`, the RFC 8707 `resource` parameter, the
transport, the discovery order, the CLI surface - is identical across the
twins, so a verdict difference is attributable to the credential-store key and
the `iss` check and to nothing else.
"""
import base64
import hashlib
import http.server
import json
import os
import secrets
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

VARIANT = "@@VARIANT@@"

HAS_OAUTH = VARIANT in ("flawed", "fixed")
# The one axis that moves: is a cached credential looked up by the issuer that
# minted it, or by nothing at all?
ISSUER_BOUND_STORE = VARIANT == "fixed"
# The other: is the RFC 9207 `iss` of the authorization response checked?
VALIDATE_ISS = VARIANT == "fixed"

# Two switches orthogonal to the flawed/fixed axis, so the template's SKIP
# branches have fixtures too rather than only its confirm and refute ones.
# Neither changes how a credential is looked up or whether `iss` is checked.
STOP_AFTER = os.environ.get("AGENT_MCP_CLIENT_STOP_AFTER", "")
ABORT_ON_NEW_ISSUER = os.environ.get("AGENT_MCP_CLIENT_ABORT_ON_NEW_ISSUER") == "1"

UA = "agent-mcp-client/0.3 (synthetic cxg fixture)"
STORE_DIR = os.path.join(os.path.expanduser("~"), ".agent-mcp-client")
STORE_PATH = os.path.join(STORE_DIR, "credentials.json")
TIMEOUT = float(os.environ.get("AGENT_MCP_CLIENT_TIMEOUT", "10"))

TOP_HELP = """usage: agent-mcp-client [--version] <command> [<args>]

A synthetic coding agent. Commands:
  chat                 Start a session (not implemented in the fixture)
  mcp                  Manage Model Context Protocol servers
"""

MCP_HELP_OAUTH = """usage: agent-mcp-client mcp <subcommand> [<args>]

Subcommands:
  add <url>            Register a remote MCP server
  list                 List configured MCP servers
  login <url>          Authorize this agent against a remote MCP server (OAuth 2.1)
  logout <url>         Forget the credentials held for a server
"""

MCP_HELP_NOOAUTH = """usage: agent-mcp-client mcp <subcommand> [<args>]

Subcommands:
  add <url>            Register a remote MCP server
  list                 List configured MCP servers
"""


def say(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def die(msg, code):
    sys.stderr.write("agent-mcp-client: " + msg + "\n")
    sys.stderr.flush()
    sys.exit(code)


# ---------------------------------------------------------------------------
# HTTP. Never raises; a failed request is a (status, headers, body) triple.
# ---------------------------------------------------------------------------

def http_req(method, url, body=None, headers=None):
    hdrs = {"User-Agent": UA}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, \
            resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read().decode("utf-8", "replace")
        except Exception:
            payload = ""
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, payload
    except Exception as exc:
        return None, {}, str(exc)


def get_json(url):
    status, _hdrs, body = http_req("GET", url, headers={"Accept": "application/json"})
    if status != 200:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# The credential store. THE variable under test.
# ---------------------------------------------------------------------------

def load_store():
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_store(store):
    os.makedirs(STORE_DIR, exist_ok=True)
    with open(STORE_PATH, "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=2, sort_keys=True)


def lookup(store, issuer):
    """Which cached credential applies to this authorization server?"""
    if ISSUER_BOUND_STORE:
        # A credential belongs to the issuer that minted it. A different issuer
        # is a different principal, even when it hands out the same client_id.
        entry = (store.get("by_issuer") or {}).get(issuer)
        return entry if isinstance(entry, dict) else None
    # The flaw: one blob, no issuer in the key. Whatever was cached last is
    # treated as "the agent's MCP credential" wherever the agent goes next.
    entry = store.get("cached")
    return entry if isinstance(entry, dict) else None


def remember(store, issuer, cred):
    if ISSUER_BOUND_STORE:
        store.setdefault("by_issuer", {})[issuer] = cred
    else:
        store["cached"] = cred


def opportunistic_token(store):
    """The token the client attaches to a first contact with a NEW resource."""
    if ISSUER_BOUND_STORE:
        return None          # nothing is known about this resource yet
    entry = store.get("cached")
    return (entry or {}).get("access_token")


# ---------------------------------------------------------------------------
# The loopback redirect listener and the browser leg.
# ---------------------------------------------------------------------------

def start_callback_server():
    captured = {}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            captured.update(dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
            body = b"authorization received; you may close this window\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            done.set()

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, captured, done


def open_browser(url):
    """Hand the authorization URL to the user's browser, as a real CLI does."""
    browser = os.environ.get("BROWSER")
    if browser:
        try:
            subprocess.run([browser, url], timeout=TIMEOUT, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "browser"
        except Exception:
            pass
    # Headless fallback: follow the authorization request ourselves. urllib
    # follows the 302 straight back to the loopback listener, which is exactly
    # what the browser would have done.
    http_req("GET", url, headers={"Accept": "text/html"})
    return "self"


# ---------------------------------------------------------------------------
# OAuth 2.1 login against one MCP server.
# ---------------------------------------------------------------------------

def initialize_payload():
    return json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2026-07-28", "capabilities": {},
                   "clientInfo": {"name": "agent-mcp-client", "version": "0.3"}},
    }).encode()


def parse_resource_metadata(www_authenticate):
    if not www_authenticate:
        return None
    for part in www_authenticate.split(","):
        part = part.strip()
        if part.lower().startswith("resource_metadata="):
            return part.split("=", 1)[1].strip().strip('"')
        if "resource_metadata=" in part:
            return part.split("resource_metadata=", 1)[1].strip().strip('"')
    return None


def probe_resource(url, store):
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    token = opportunistic_token(store)
    if token:
        # The leak. A bearer token minted by one issuer, for one resource, is
        # sent to a resource this client has never spoken to.
        headers["Authorization"] = "Bearer " + token
        say("  reusing the cached access token for the first request")
    return http_req("POST", url, initialize_payload(), headers)


def discover(url, store):
    status, headers, _body = probe_resource(url, store)
    if status == 200:
        say("  server accepted the request without a fresh authorization")
        return None
    if status != 401:
        die("server at %s answered %s, not 401 - nothing to authorize against"
            % (url, status), 4)
    prm_url = parse_resource_metadata(headers.get("www-authenticate", ""))
    if not prm_url:
        origin = urllib.parse.urlsplit(url)
        prm_url = "%s://%s/.well-known/oauth-protected-resource" % (origin.scheme, origin.netloc)
    say("  protected-resource metadata: %s" % prm_url)
    prm = get_json(prm_url)
    if not isinstance(prm, dict):
        die("could not read protected-resource metadata at %s" % prm_url, 4)
    servers = prm.get("authorization_servers") or []
    if not servers:
        die("protected-resource metadata names no authorization server", 4)
    as_url = str(servers[0]).rstrip("/")
    meta = get_json(as_url + "/.well-known/oauth-authorization-server")
    if not isinstance(meta, dict):
        meta = get_json(as_url + "/.well-known/openid-configuration")
    if not isinstance(meta, dict):
        die("could not read authorization-server metadata at %s" % as_url, 4)
    say("  authorization server: %s" % meta.get("issuer"))
    return {"resource": prm.get("resource") or url, "meta": meta}


def register(meta, redirect_uri):
    endpoint = meta.get("registration_endpoint")
    if not endpoint:
        die("authorization server offers no dynamic client registration", 4)
    body = json.dumps({
        "client_name": "agent-mcp-client (synthetic)",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    }).encode()
    status, _hdrs, payload = http_req(
        "POST", endpoint, body, {"Content-Type": "application/json"})
    if status not in (200, 201):
        die("dynamic client registration failed (%s)" % status, 4)
    try:
        reg = json.loads(payload)
    except ValueError:
        die("registration endpoint returned no JSON", 4)
    say("  registered at %s -> client_id=%s" % (meta.get("issuer"), reg.get("client_id")))
    return reg


def authorize(meta, client_id, redirect_uri, resource, server, captured, done):
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(16)
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        "scope": "mcp:read", "resource": resource,
    })
    url = "%s?%s" % (meta["authorization_endpoint"], query)
    how = open_browser(url)
    if not done.wait(TIMEOUT):
        die("no authorization callback arrived (browser leg: %s)" % how, 4)
    server.shutdown()
    if captured.get("state") != state:
        die("authorization callback carried the wrong `state`", 4)
    if not captured.get("code"):
        die("authorization callback carried no code (%s)" % captured.get("error", "?"), 4)
    return captured, verifier


def check_issuer(meta, captured):
    """RFC 9207. Which authorization server actually answered?"""
    got = captured.get("iss")
    if not VALIDATE_ISS:
        return
    expected = meta.get("issuer")
    if not got:
        die("authorization response carried no `iss` (RFC 9207) and the "
            "authorization server advertises support for it - refusing to "
            "redeem the code", 3)
    if got != expected:
        die("authorization response `iss`=%s but this code was requested from "
            "%s - authorization-server mix-up, refusing to redeem the code"
            % (got, expected), 3)


def redeem(meta, client_id, client_secret, code, verifier, redirect_uri, resource):
    form = {"grant_type": "authorization_code", "code": code,
            "redirect_uri": redirect_uri, "client_id": client_id,
            "code_verifier": verifier, "resource": resource}
    if client_secret:
        form["client_secret"] = client_secret
    status, _hdrs, payload = http_req(
        "POST", meta["token_endpoint"], urllib.parse.urlencode(form).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"})
    if status != 200:
        die("token endpoint refused the exchange (%s): %s" % (status, payload[:200]), 4)
    try:
        return json.loads(payload)
    except ValueError:
        die("token endpoint returned no JSON", 4)


def login(url):
    say("login: %s  [variant=%s]" % (url, VARIANT))
    store = load_store()
    found = discover(url, store)
    if found is None:
        return 0
    meta, resource = found["meta"], found["resource"]
    issuer = meta.get("issuer")
    seen_a_server_before = bool(store.get("servers"))

    if STOP_AFTER == "discovery":
        say("  stopping after discovery (AGENT_MCP_CLIENT_STOP_AFTER=discovery)")
        return 0

    server, captured, done = start_callback_server()
    redirect_uri = "http://127.0.0.1:%d/callback" % server.server_address[1]

    cred = lookup(store, issuer)
    if cred is None:
        reg = register(meta, redirect_uri)
        client_id = reg.get("client_id")
        client_secret = reg.get("client_secret")
    else:
        client_id = cred.get("client_id")
        client_secret = cred.get("client_secret")
        say("  reusing cached client credentials (client_id=%s) - no registration"
            % client_id)

    if ABORT_ON_NEW_ISSUER and seen_a_server_before and cred is None:
        die("refusing to authorize against %s, an authorization server this agent "
            "has not used before; re-run with --trust-issuer" % issuer, 3)

    captured, verifier = authorize(meta, client_id, redirect_uri, resource,
                                   server, captured, done)
    check_issuer(meta, captured)
    token = redeem(meta, client_id, client_secret, captured["code"], verifier,
                   redirect_uri, resource)
    access = token.get("access_token")
    say("  access token issued: %s" % access)

    remember(store, issuer, {"client_id": client_id, "client_secret": client_secret,
                             "access_token": access, "issuer": issuer,
                             "resource": resource})
    servers = store.setdefault("servers", {})
    servers[url] = {"issuer": issuer, "resource": resource}
    save_store(store)

    status, _hdrs, _body = http_req(
        "POST", url, initialize_payload(),
        {"Content-Type": "application/json", "Authorization": "Bearer " + str(access),
         "Accept": "application/json, text/event-stream"})
    say("  authenticated MCP initialize -> %s" % status)
    return 0 if status == 200 else 4


# ---------------------------------------------------------------------------
# CLI surface.
# ---------------------------------------------------------------------------

def mcp_command(args):
    if not args or args[0] in ("-h", "--help", "help"):
        say(MCP_HELP_OAUTH if HAS_OAUTH else MCP_HELP_NOOAUTH)
        return 0
    sub, rest = args[0], args[1:]
    if sub == "list":
        store = load_store()
        for name in sorted((store.get("servers") or {})):
            say(name)
        return 0
    if sub == "add":
        if not rest:
            die("mcp add needs a server URL", 2)
        store = load_store()
        store.setdefault("servers", {}).setdefault(rest[0], {})
        save_store(store)
        say("added %s" % rest[0])
        return 0
    if sub == "login" and HAS_OAUTH:
        if not rest:
            die("mcp login needs a server URL", 2)
        return login(rest[0])
    if sub == "logout" and HAS_OAUTH:
        store = load_store()
        store.pop("cached", None)
        store.pop("by_issuer", None)
        save_store(store)
        say("forgot cached credentials")
        return 0
    die("unknown mcp subcommand '%s'" % sub, 2)


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        say(TOP_HELP)
        say(MCP_HELP_OAUTH if HAS_OAUTH else MCP_HELP_NOOAUTH)
        return 0
    if argv[0] == "--version":
        say("agent-mcp-client 0.3 (%s)" % VARIANT)
        return 0
    if argv[0] == "mcp":
        return mcp_command(argv[1:])
    if argv[0] == "chat":
        say("chat is not implemented in this fixture")
        return 0
    die("unknown command '%s'" % argv[0], 2)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

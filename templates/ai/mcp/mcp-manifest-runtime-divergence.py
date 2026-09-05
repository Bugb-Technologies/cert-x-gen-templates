#!/usr/bin/env python3
# @id: mcp-manifest-runtime-divergence
# @name: MCP Declared-Manifest / Runtime-Surface Divergence
# @author: Bugb Research
# @severity: high
# @description: DIFF check. Fetches the surface an MCP server DECLARED (its MCP Registry server.json / packaged manifest / pinned lockfile copy) and the surface it is actually SERVING (live tools/list + resources/list), and reports every place the running server is wider than its declaration - an undeclared tool, an undeclared input-schema property, a tool scope (annotation) looser at runtime than declared, an undeclared resource, or a server version / package hash that is not the published one. One instant, two sources; no baseline and no waiting.
# @tags: mcp, ai, agent, supply-chain, registry, manifest, integrity, divergence, behavioural, http, cwe-345, cwe-494
# @cwe: CWE-345, CWE-494
# @cvss: 8.2
# @target_kinds: http
# @oracles: diff
# @references: https://modelcontextprotocol.io/specification/2025-06-18/server/tools, https://github.com/modelcontextprotocol/registry, https://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/494.html
# @confidence: 92
# @version: 1.0.0
"""
DIFF check - what the server said it is, against what it is serving.

WHAT THIS IS NOT

It is not mcp-rug-pull-detection. That template diffs a server against
ITSELF OVER TIME: it records a baseline on the first scan and flags a tool
definition that mutated before the second. It is a temporal diff, and it has
one structural blind spot - a server that was already wider than its listing
on day one never mutates, so a temporal diff never fires on it. The first
observation *is* the baseline, and the baseline is already the lie.

This template closes exactly that gap. It diffs the server against ITS OWN
DECLARATION at a single instant:

    DECLARED                              RUNTIME
    the MCP Registry server.json,   vs    the live tools/list and
    the packaged manifest, or the         resources/list, plus the version
    copy pinned in your lockfile          and package hash the server states

No baseline, no second scan, no waiting. A server that shipped malicious on
listing-day is caught by its first scan.

THE REGISTRY SAYS THIS CHECK IS YOURS TO RUN

The MCP Registry publishes a server's identity, version and package integrity
hash, and is explicit that a listing is not a promise about the running
process - it does not certify that runtime behaviour matches, or will remain
unchanged from, what was declared. Verifying that the server in front of you
is the server that was listed is left to the consumer. Almost nobody does it,
because doing it means talking to the live server and no static manifest
linter does.

THE ORACLE IS A DIFF OF TWO SOURCES, TAKEN AT ONE INSTANT

  Declared surface  fetched from, in order of authority:
      1. CXG_MCP_DECLARED_SOURCE - a file path or an https URL you control:
         the registry entry, the packaged manifest, or the copy pinned in
         your lockfile. This is the strong form: the declaration comes from
         somewhere the running server cannot edit.
      2. the server's own publication artifact, served at a well-known path
         (/.well-known/mcp/server.json and friends) - the same document a
         publisher submits to a registry. Weaker, but it is what a client
         actually has, and it still catches the common case: a build that
         drifted from the manifest shipped beside it.

  Runtime surface   initialize (serverInfo.version, any stated package hash),
                    tools/list and resources/list, read live.

  Diff              across five dimensions, in one direction only - RUNTIME
                    WIDER THAN DECLARED:
      * a tool present at runtime and absent from the declaration;
      * an inputSchema property present at runtime and absent from the
        declared schema, or a declared `required` field the runtime no
        longer requires, or a declared enum the runtime dropped or widened;
      * a tool scope looser at runtime than declared - the declaration says
        readOnlyHint true and the live tool says false, destructiveHint /
        openWorldHint flipped on, or an explicit scope list gaining entries;
      * a resource present at runtime and absent from a declaration that
        does list resources;
      * a serverInfo.version or a stated package sha256 that is not the
        declared one.

VERDICT CONTRACT

  confirmed  at least one hard divergence above was OBSERVED on both sides -
             the declared value and the runtime value are both in the
             evidence, alongside the request/response for the declared fetch
             and for the live tools/list.
  refuted    both surfaces were read and, on every dimension that both sides
             actually state, the runtime is exactly the declaration.
  skipped    a precondition was not met, and which one is named: no MCP
             server answered; no declared source could be found (nothing to
             diff against - this is the honest verdict even when the runtime
             surface looks alarming); or the declared source states no
             comparable surface at all (no tools, no version, no hash).
  errored    an explicitly configured CXG_MCP_DECLARED_SOURCE could not be
             fetched or parsed - a diff against a source you named and did
             not get is not a refutation.

PRECISION

Only a widening fires. A declaration that lists a tool the runtime does not
serve, a resource that disappeared, a description that was reworded, a
runtime that states no version or hash where the declaration does - each is
recorded as a soft `observations` entry that the refutation names and never
confirms on. Narrowing is not this template's finding, and an absent runtime
statement is not a mismatch.

SAFETY

Passive. It calls initialize, tools/list and resources/list, and performs one
GET against well-known manifest paths. It never invokes a tool and never
sends data of its own. Against fixtures/mcp-manifest-runtime-divergence it is
safe anywhere; get authorisation before pointing it at a system you do not
own.
"""

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

METADATA = {
    "id": "mcp-manifest-runtime-divergence",
    "name": "MCP Declared-Manifest / Runtime-Surface Divergence",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "DIFF check: fetches an MCP server's declared surface (registry server.json / packaged "
        "manifest / pinned lockfile copy) and its live tools/list + resources/list at one instant, "
        "and reports every place the running server is wider than its declaration - an undeclared "
        "tool, an undeclared schema property, a looser tool scope, an undeclared resource, or a "
        "version / package-hash mismatch"
    ),
    "tags": ["mcp", "ai", "agent", "supply-chain", "registry", "manifest", "integrity",
             "divergence", "behavioural", "http", "cwe-345", "cwe-494"],
    "language": "python",
    "confidence": 92,
    "cwe": ["CWE-345", "CWE-494"],
    "references": [
        "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
        "https://github.com/modelcontextprotocol/registry",
        "https://cwe.mitre.org/data/definitions/345.html",
        "https://cwe.mitre.org/data/definitions/494.html",
    ],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2025-06-18"

# Where a publication artifact is conventionally served from.
WELL_KNOWN_PATHS = [
    "/.well-known/mcp/server.json",
    "/.well-known/mcp-server.json",
    "/.well-known/mcp/manifest.json",
    "/.well-known/mcp.json",
    "/server.json",
    "/mcp/server.json",
]

# Keys under a declared package entry that carry an artifact integrity hash.
HASH_KEYS = ("fileSha256", "file_sha256", "sha256", "digest", "integrity", "hash")
# A runtime `_meta` key naming an artifact hash.
RUNTIME_HASH_RE = re.compile(r"(sha256|digest|integrity)", re.I)

# Annotation booleans, with the direction that counts as a WIDENING:
# declared value -> a runtime value that is looser.
NARROW_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}


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


def _get(url, timeout):
    req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=_ctx())
        return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


class HttpMcp(object):
    """Minimal streamable-HTTP MCP client. Read-only: initialize and list calls."""

    def __init__(self, base, timeout=12):
        self.base = base
        self.timeout = timeout
        self.path = None
        self.session_id = None
        self._id = 0

    def _next_id(self):
        self._id += 1
        return self._id

    def _post(self, url, payload):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        try:
            r = urllib.request.urlopen(req, timeout=self.timeout, context=_ctx())
            return (r.status, {k.lower(): v for k, v in r.headers.items()},
                    r.read().decode("utf-8", "ignore"))
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

    def call(self, method, params=None):
        if self.path is None:
            return None, None
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method,
                   "params": params if params is not None else {}}
        status, _headers, body = self._post(self.base + self.path, payload)
        return status, _extract_json(body)

    def endpoint(self):
        return self.base + (self.path or "")


# ---------------------------------------------------------------------------
# The declared side.
# ---------------------------------------------------------------------------

def fetch_declared(base, timeout):
    """Resolve the declared surface.

    Returns (manifest, source_ref, request_desc, raw_excerpt) or
    ('__error__', why) when a source the operator NAMED could not be used, or
    (None, why) when no source exists at all.
    """
    configured = os.getenv("CXG_MCP_DECLARED_SOURCE") or ""
    if configured.strip():
        ref = configured.strip()
        if ref.startswith("http://") or ref.startswith("https://"):
            status, body = _get(ref, timeout)
            if status != 200 or not body:
                return "__error__", ("configured-declared-source-unreachable(%s status=%s)"
                                     % (ref, status))
            obj = _extract_json(body)
            if not isinstance(obj, dict):
                return "__error__", "configured-declared-source-not-json(%s)" % ref
            return obj, ref, "GET %s (CXG_MCP_DECLARED_SOURCE)" % ref, body[:1200]
        path = Path(os.path.expanduser(ref))
        if not path.is_file():
            return "__error__", "configured-declared-source-missing(%s)" % ref
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
            obj = json.loads(raw)
        except (OSError, ValueError) as exc:
            return "__error__", "configured-declared-source-unreadable(%s: %s)" % (ref, exc)
        if not isinstance(obj, dict):
            return "__error__", "configured-declared-source-not-an-object(%s)" % ref
        return obj, str(path), "read %s (CXG_MCP_DECLARED_SOURCE)" % path, raw[:1200]

    tried = []
    for wk in WELL_KNOWN_PATHS:
        url = base + wk
        status, body = _get(url, timeout)
        tried.append("%s->%s" % (wk, status))
        if status != 200 or not body:
            continue
        obj = _extract_json(body)
        if isinstance(obj, dict) and (obj.get("name") or obj.get("version") or obj.get("tools")
                                      or obj.get("packages")):
            return obj, url, "GET %s (publication artifact)" % url, body[:1200]
    return None, "no-declared-source-available(tried %s; set CXG_MCP_DECLARED_SOURCE to a " \
                 "registry entry, packaged manifest or pinned lockfile copy)" % ", ".join(tried)


def _dig(manifest, key):
    """A declared list under `key`, wherever publishers actually put it."""
    for container in (manifest,
                      manifest.get("x-mcp") if isinstance(manifest.get("x-mcp"), dict) else None,
                      manifest.get("_meta") if isinstance(manifest.get("_meta"), dict) else None,
                      manifest.get("server") if isinstance(manifest.get("server"), dict) else None,
                      manifest.get("capabilities") if isinstance(manifest.get("capabilities"), dict) else None):
        if not isinstance(container, dict):
            continue
        value = container.get(key)
        if isinstance(value, list) and all(isinstance(i, dict) for i in value):
            return value
    return None


def declared_version(manifest):
    for value in (manifest.get("version"),
                  (manifest.get("server") or {}).get("version")
                  if isinstance(manifest.get("server"), dict) else None):
        if isinstance(value, str) and value.strip():
            return value.strip()
    for pkg in manifest.get("packages") or []:
        if isinstance(pkg, dict) and isinstance(pkg.get("version"), str) and pkg["version"].strip():
            return pkg["version"].strip()
    return None


def declared_hash(manifest):
    containers = [p for p in (manifest.get("packages") or []) if isinstance(p, dict)]
    containers.append(manifest)
    for container in containers:
        for key in HASH_KEYS:
            value = container.get(key)
            if isinstance(value, str) and len(value.strip()) >= 32:
                return key, value.strip()
    return None, None


def runtime_hash(init_result):
    """Any artifact hash the live server states about itself."""
    metas = []
    if isinstance(init_result.get("_meta"), dict):
        metas.append(init_result["_meta"])
    info = init_result.get("serverInfo")
    if isinstance(info, dict) and isinstance(info.get("_meta"), dict):
        metas.append(info["_meta"])
    for meta in metas:
        for key, value in meta.items():
            if RUNTIME_HASH_RE.search(str(key)) and isinstance(value, str) and len(value.strip()) >= 32:
                return key, value.strip()
    return None, None


# ---------------------------------------------------------------------------
# The diff.
# ---------------------------------------------------------------------------

def by_name(tools):
    out = {}
    for t in tools or []:
        if isinstance(t, dict) and isinstance(t.get("name"), str) and t["name"]:
            out[t["name"]] = t
    return out


def by_uri(resources):
    out = {}
    for r in resources or []:
        if isinstance(r, dict) and isinstance(r.get("uri"), str) and r["uri"]:
            out[r["uri"]] = r
    return out


def schema_props(tool):
    schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def schema_required(tool):
    schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
    req = schema.get("required")
    return set(r for r in req if isinstance(r, str)) if isinstance(req, list) else set()


def scope_list(tool):
    """An explicit scope / permission list, wherever the tool carries one."""
    ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    meta = tool.get("_meta") if isinstance(tool.get("_meta"), dict) else {}
    for container in (tool, ann, meta):
        for key in ("scopes", "x-scopes", "requiredScopes", "permissions"):
            value = container.get(key)
            if isinstance(value, list) and all(isinstance(i, str) for i in value):
                return set(value)
    return None


def annotations_of(tool):
    ann = tool.get("annotations")
    return ann if isinstance(ann, dict) else {}


def diff_tool(name, declared, runtime):
    """Hard widenings and soft notes for one tool that exists on both sides."""
    hard, soft = [], []

    d_props, r_props = schema_props(declared), schema_props(runtime)
    extra_props = sorted(set(r_props) - set(d_props))
    if extra_props:
        hard.append({"kind": "schema-widened", "tool": name,
                     "declared_properties": sorted(d_props), "runtime_properties": sorted(r_props),
                     "undeclared_properties": extra_props})
    d_req, r_req = schema_required(declared), schema_required(runtime)
    dropped_required = sorted(d_req - r_req)
    if dropped_required:
        hard.append({"kind": "schema-required-relaxed", "tool": name,
                     "declared_required": sorted(d_req), "runtime_required": sorted(r_req),
                     "no_longer_required": dropped_required})
    for prop in sorted(set(d_props) & set(r_props)):
        d_enum = d_props[prop].get("enum") if isinstance(d_props[prop], dict) else None
        r_enum = r_props[prop].get("enum") if isinstance(r_props[prop], dict) else None
        if not isinstance(d_enum, list):
            continue
        if not isinstance(r_enum, list):
            hard.append({"kind": "schema-enum-dropped", "tool": name, "property": prop,
                         "declared_enum": d_enum, "runtime_enum": None})
        elif set(map(str, r_enum)) - set(map(str, d_enum)):
            hard.append({"kind": "schema-enum-widened", "tool": name, "property": prop,
                         "declared_enum": d_enum, "runtime_enum": r_enum})

    d_ann, r_ann = annotations_of(declared), annotations_of(runtime)
    for key, narrow in NARROW_ANNOTATIONS.items():
        if key not in d_ann or d_ann.get(key) != narrow:
            continue  # the declaration never made the narrow promise
        if r_ann.get(key) != narrow:
            hard.append({"kind": "scope-widened", "tool": name, "annotation": key,
                         "declared": d_ann.get(key), "runtime": r_ann.get(key)})
    d_scopes, r_scopes = scope_list(declared), scope_list(runtime)
    if d_scopes is not None and r_scopes is not None:
        gained = sorted(r_scopes - d_scopes)
        if gained:
            hard.append({"kind": "scope-list-widened", "tool": name,
                         "declared_scopes": sorted(d_scopes), "runtime_scopes": sorted(r_scopes),
                         "undeclared_scopes": gained})

    d_desc = str(declared.get("description") or "")
    r_desc = str(runtime.get("description") or "")
    if d_desc != r_desc:
        soft.append({"kind": "description-drift", "tool": name,
                     "declared": d_desc[:200], "runtime": r_desc[:200]})
    return hard, soft


def diff_surfaces(declared_manifest, init_result, runtime_tools, runtime_resources):
    """The whole diff. Returns (hard, soft, dimensions_compared)."""
    hard, soft, dimensions = [], [], []

    d_tools = _dig(declared_manifest, "tools")
    if d_tools is None:
        soft.append({"kind": "declaration-states-no-tool-surface",
                     "note": "the declared source lists no tools, so the tool diff did not run"})
    else:
        dimensions.append("tools")
        dmap, rmap = by_name(d_tools), by_name(runtime_tools or [])
        for name in sorted(set(rmap) - set(dmap)):
            hard.append({"kind": "undeclared-tool", "tool": name,
                         "runtime_description": str(rmap[name].get("description") or "")[:200],
                         "runtime_annotations": annotations_of(rmap[name]),
                         "declared_tools": sorted(dmap)})
        for name in sorted(set(dmap) - set(rmap)):
            soft.append({"kind": "declared-tool-absent-at-runtime", "tool": name})
        for name in sorted(set(dmap) & set(rmap)):
            h, s = diff_tool(name, dmap[name], rmap[name])
            hard.extend(h)
            soft.extend(s)

    d_resources = _dig(declared_manifest, "resources")
    if d_resources is None:
        if runtime_resources:
            soft.append({"kind": "declaration-states-no-resource-surface",
                         "runtime_resources": sorted(by_uri(runtime_resources))[:20]})
    else:
        dimensions.append("resources")
        dmap, rmap = by_uri(d_resources), by_uri(runtime_resources or [])
        for uri in sorted(set(rmap) - set(dmap)):
            hard.append({"kind": "undeclared-resource", "uri": uri,
                         "runtime_name": str(rmap[uri].get("name") or "")[:120],
                         "declared_resources": sorted(dmap)})
        for uri in sorted(set(dmap) - set(rmap)):
            soft.append({"kind": "declared-resource-absent-at-runtime", "uri": uri})

    d_version = declared_version(declared_manifest)
    r_version = None
    info = init_result.get("serverInfo") if isinstance(init_result.get("serverInfo"), dict) else {}
    if isinstance(info.get("version"), str) and info["version"].strip():
        r_version = info["version"].strip()
    if d_version and r_version:
        dimensions.append("version")
        if d_version != r_version:
            hard.append({"kind": "version-mismatch", "declared": d_version, "runtime": r_version})
    elif d_version and not r_version:
        soft.append({"kind": "runtime-version-unstated", "declared": d_version})

    d_hash_key, d_hash = declared_hash(declared_manifest)
    r_hash_key, r_hash = runtime_hash(init_result)
    if d_hash and r_hash:
        dimensions.append("package-hash")
        if d_hash.lower() != r_hash.lower():
            hard.append({"kind": "package-hash-mismatch", "declared_key": d_hash_key,
                         "declared": d_hash, "runtime_key": r_hash_key, "runtime": r_hash})
    elif d_hash and not r_hash:
        soft.append({"kind": "runtime-package-hash-unstated", "declared_key": d_hash_key,
                     "declared": d_hash})

    return hard, soft, dimensions


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

def scan_http(host, port, scheme="http", timeout=12):
    base = "%s://%s:%d" % (scheme, host, port)
    session = HttpMcp(base, timeout)
    init_result = session.open()
    if init_result is None:
        return "skipped", "no-mcp-server-answered(%s)" % base, []
    endpoint = session.endpoint()
    server_name = (init_result.get("serverInfo") or {}).get("name")

    manifest, source_ref, declared_request, declared_excerpt = (None, None, None, None)
    fetched = fetch_declared(base, timeout)
    if fetched[0] == "__error__":
        return "errored", "%s | endpoint=%s" % (fetched[1], endpoint), []
    if fetched[0] is None:
        return "skipped", "%s | endpoint=%s" % (fetched[1], endpoint), []
    manifest, source_ref, declared_request, declared_excerpt = fetched

    _s, tl = session.call("tools/list")
    runtime_tools = ((tl or {}).get("result") or {}).get("tools") if isinstance(tl, dict) else None
    _s, rl = session.call("resources/list")
    runtime_resources = ((rl or {}).get("result") or {}).get("resources") if isinstance(rl, dict) else None

    hard, soft, dimensions = diff_surfaces(manifest, init_result, runtime_tools, runtime_resources)

    surface = ("endpoint=%s server=%s declared_source=%s dimensions=%s runtime_tools=%d"
               % (endpoint, server_name, source_ref, "+".join(dimensions) or "none",
                  len(runtime_tools or [])))

    if not dimensions:
        return ("skipped",
                "declared-source-states-no-comparable-surface(%s carries no tools, version or "
                "package hash to diff against) | %s" % (source_ref, surface), [])

    soft_names = sorted(set(s["kind"] for s in soft))

    if not hard:
        detail = ("no-divergence(runtime surface equals the declaration on %s; soft observations: "
                  "%s) | %s" % ("+".join(dimensions), ", ".join(soft_names) or "none", surface))
        return "refuted", detail, []

    kinds = sorted(set(h["kind"] for h in hard))
    evidence = {
        "endpoint": endpoint,
        "server_name": server_name,
        "declared_source": source_ref,
        "dimensions_compared": dimensions,
        "declared_fetch": {"request": declared_request, "response_excerpt": declared_excerpt},
        "runtime_fetch": {
            "request": "POST %s {\"method\":\"tools/list\"} (then resources/list)" % endpoint,
            "tools_response_excerpt": json.dumps(runtime_tools)[:1200],
            "resources_response_excerpt": json.dumps(runtime_resources)[:600],
            "serverInfo": init_result.get("serverInfo"),
        },
        "divergences": hard,
        "observations": soft,
    }
    headline = []
    undeclared = [h["tool"] for h in hard if h["kind"] == "undeclared-tool"]
    if undeclared:
        headline.append("%d undeclared tool(s) at runtime: %s" % (len(undeclared), ", ".join(undeclared)))
    widened = sorted(set(h["tool"] for h in hard
                         if h["kind"].startswith("schema-") or h["kind"].startswith("scope-")))
    if widened:
        headline.append("%d tool(s) wider at runtime than declared: %s" % (len(widened), ", ".join(widened)))
    res = [h["uri"] for h in hard if h["kind"] == "undeclared-resource"]
    if res:
        headline.append("%d undeclared resource(s): %s" % (len(res), ", ".join(res)))
    for h in hard:
        if h["kind"] == "version-mismatch":
            headline.append("version declared %s, running %s" % (h["declared"], h["runtime"]))
        if h["kind"] == "package-hash-mismatch":
            headline.append("package hash declared %s..., reported %s..."
                            % (h["declared"][:12], h["runtime"][:12]))

    description = (
        "MCP server '%s' at %s is serving a surface WIDER than the one it declared. The declaration "
        "was read from %s and the runtime surface from a live tools/list + resources/list at the same "
        "instant; the diff found: %s. This is not a mutation over time - the two sources disagree "
        "right now, on the server's first scan, which is exactly what a temporal rug-pull baseline "
        "cannot see. A registry listing records what a publisher declared; it does not certify that "
        "the running process matches it, so an agent that approved this server on its listing "
        "approved a narrower thing than the one it is talking to (CWE-345, CWE-494)."
        % (server_name, endpoint, source_ref, "; ".join(headline)))

    finding = make_finding(
        endpoint,
        "%s  vs  POST %s {\"method\":\"tools/list\"}" % (declared_request, endpoint),
        description, evidence, kinds)
    detail = ("divergence-proven(%s) | %s | soft: %s"
              % ("; ".join(headline), surface, ", ".join(soft_names) or "none"))
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
            return ("skip", "this template diffs a live HTTP MCP surface against a published "
                            "manifest; point it at an http:// target")
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        host = re.sub(r"^https?://", "", host).split("/")[0]
        try:
            port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "8000"))
        except ValueError:
            port = 8000
        return ("http", host, port, scheme)

    args = sys.argv[1:]
    if not args:
        return ("error", "Usage: mcp-manifest-runtime-divergence.py <host> [port] [scheme]")
    host = args[0]
    port = int(args[1]) if len(args) > 1 else 8000
    scheme = args[2] if len(args) > 2 else "http"
    return ("http", host, port, scheme)


def main():
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

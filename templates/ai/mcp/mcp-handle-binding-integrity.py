#!/usr/bin/env python3
# @id: mcp-handle-binding-integrity
# @name: MCP Handle Binding and requestState Integrity (Stateless Core)
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. The 2026-07-28 MCP core removed sessions and replaced them with server-minted handles that travel inside model context, plus a requestState blob echoed back by the client. This template mints a handle as one identity and presents it as another, and mutates a security-relevant field of an input_required requestState before the retry. CONFIRMED only when a forged-handle control was rejected and a random-blob control was rejected, so acceptance is an integrity failure and not indifference.
# @tags: mcp, ai, agent, stateless-core, handle-binding, requeststate, broken-object-level-authorization, state-tampering, behavioural, active, intrusive, cwe-639, cwe-565
# @cwe: CWE-639, CWE-565
# @cvss: 8.1
# @target_kinds: http, cli
# @oracles: property, diff
# @references: https://blog.modelcontextprotocol.io/posts/2026-07-28/, https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices, https://cwe.mitre.org/data/definitions/639.html, https://cwe.mitre.org/data/definitions/565.html
# @confidence: 90
# @version: 1.0.0
"""
ACTIVE / INTRUSIVE check - MCP handle binding and requestState integrity.

WHAT CHANGED, AND WHY IT NEEDS A NEW CHECK

The 2026-07-28 MCP specification made the protocol core stateless. It removed
the `initialize`/`initialized` handshake and the `Mcp-Session-Id` header, and
put two replacements in their place:

  * THE EXPLICIT HANDLE PATTERN. "If your server needs to carry state across
    calls, mint an explicit handle from a tool and have the model pass it back
    as an argument." The handle stops being a transport-layer secret the
    client holds and becomes an ordinary tool argument that lives in model
    context - visible to the model, quotable in a transcript, and writable by
    anything that can put text into that context, such as a poisoned tool
    result.

  * MULTI ROUND-TRIP REQUESTS. A tool may answer with
    `{"resultType": "input_required", "inputRequests": {...},
    "requestState": "<blob>"}`. The client collects the inputs and re-issues
    the same `tools/call` with `inputResponses` and the *echoed*
    `requestState`. The blob round-trips through the client, so it is
    attacker-controlled input by construction. The specification says as
    much, and tells implementers to "integrity-protect it, bind it to the
    principal and the originating request, and give it an expiry before
    letting it influence authorization."

Both replacements move state out of a place the server controlled and into a
place it does not. Neither is checkable from a manifest: a server that binds
its handles and one that does not advertise byte-identical tool lists.

THE ORACLE IS A PROPERTY OF TWO IDENTITIES AND ONE MUTATION

  Property 1 (binding):   a handle minted for principal A is not honoured for
                          principal B.
  Property 2 (integrity): a requestState whose contents have been altered
                          since the server issued it is not honoured.

Each property is tested as a differential against controls, because
"it worked" is only a finding when refusal was possible:

  PROBE A - handle binding
     A1  identity A calls the minting tool with a planted canary label and
         receives a handle H_A.
     A2  identity B mints and reads its own handle H_B. If B cannot use its
         own handle, the two identities are not both live and nothing can be
         concluded -> skip.
     A3  NEGATIVE CONTROL: identity B presents a FORGED handle of the same
         shape that this server never minted. It must be rejected. A server
         that honours a handle it never issued has no handle validation to
         bind with, so "not bound to a principal" is not a finding you can
         draw from it -> recorded as an observation, never a confirmation.
     A4  identity B presents H_A. Honoured -> the handle is not bound to the
         principal that minted it. The canary A planted, or A's own principal
         string, coming back in B's answer is the observed marker that the
         object returned really is A's.

  PROBE B - requestState integrity
     B1  a tool is called until one answers `input_required` with a
         `requestState`.
     B2  BASELINE: a fresh call, retried with the requestState UNMODIFIED,
         must be accepted. If the untouched retry fails, the flow is not
         working and a rejection later proves nothing -> skip.
     B3  NEGATIVE CONTROL: a fresh call, retried with a RANDOM blob of the
         same shape and length, must be rejected. A server that accepts a
         random blob is not consulting the state at all, so accepting a
         mutated one says nothing about integrity -> observation, not
         confirmation.
     B4  a fresh call; the requestState is decoded (raw JSON, base64url JSON,
         or `<base64url-body>.<signature>` with the signature left stale),
         one security-relevant field is mutated - a principal replaced with a
         canary, an approval count raised, an expiry pushed out, a boolean
         flipped - and the call is retried. Accepted -> the state was echoed
         back unbound.
     B5  FALLBACK for a state that does not decode (encrypted, or a format
         this template does not read): a single character is flipped at
         several offsets. B3 already proved a random blob is refused, so a
         one-character change that is accepted means the blob is consulted
         but not authenticated - encryption without integrity.

VERDICT CONTRACT

  confirmed  at least one probe fired with its controls passing: a handle
             minted for A was honoured for B while a forged handle was
             refused, or a mutated requestState was accepted while a random
             one of the same shape was refused. The mutation, the controls
             and the server's own answer are all in the evidence.
  refuted    at least one probe ran end to end with live controls and the
             property held: cross-principal handles were rejected, expired
             or unknown, and the mutated requestState was rejected.
  skipped    the precondition was not met, and which one is named: no MCP
             server answered; no tool mints a handle any other tool consumes;
             no tool returned `input_required`; the second identity could not
             use its own handle; the untouched retry did not succeed. A
             pre-stateless-core server has neither precondition and lands
             here.
  errored    the target could not be reached or the server could not be run.

Near-misses never fire. A forged handle that was honoured, a random blob that
was accepted, a decoded state with no security-relevant field: each is carried
in `observations` and named in the refutation, and none of them produces a
finding.

SAFETY

It invokes tools. It calls minting tools with synthetic canary labels, and for
the multi round-trip probe it calls only tools that do NOT declare
`destructiveHint: true` and whose name and description carry no destructive
verb (delete, drop, purge, revoke, terminate...). Set
`CXG_MCP_MRTR_INCLUDE_DESTRUCTIVE=1` to widen that, and understand that
completing a confirmation flow completes the action behind it. The mutation
probe re-issues an already-approved call, so the underlying action may run
more than once. Against the fixtures in fixtures/mcp-handle-binding-integrity
it is safe anywhere. Get authorisation before pointing it at a system you do
not own.
"""

import base64
import json
import os
import random
import re
import shlex
import shutil
import ssl
import string
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

METADATA = {
    "id": "mcp-handle-binding-integrity",
    "name": "MCP Handle Binding and requestState Integrity (Stateless Core)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE check: mints a stateless-core handle as one identity and presents it as another, "
        "and mutates a security-relevant field of an input_required requestState before the retry - "
        "confirming only when a forged-handle control and a random-blob control were both rejected"
    ),
    "tags": ["mcp", "ai", "agent", "stateless-core", "handle-binding", "requeststate",
             "broken-object-level-authorization", "state-tampering", "behavioural",
             "active", "intrusive", "cwe-639", "cwe-565"],
    "language": "python",
    "active": True,
    "confidence": 90,
    "cwe": ["CWE-639", "CWE-565"],
    "references": [
        "https://blog.modelcontextprotocol.io/posts/2026-07-28/",
        "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
        "https://cwe.mitre.org/data/definitions/639.html",
        "https://cwe.mitre.org/data/definitions/565.html",
    ],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
STATELESS_PROTO = "2026-07-28"
LEGACY_PROTO = "2024-11-05"
PROBE_PREFIX = "cxg-hb-probe"
CLIENTINFO_META = "io.modelcontextprotocol/clientInfo"
PRINCIPAL_META = os.getenv("CXG_MCP_PRINCIPAL_META_KEY", "io.modelcontextprotocol/principal")

MAX_MINT_CALLS = 6
MAX_MRTR_CALLS = 6
MAX_FLIP_OFFSETS = 5

# A tool that plausibly mints a handle.
MINT_NAME_RE = re.compile(
    r"^(create|open|start|new|begin|mint|init|make|register|alloc|acquire|provision)\w*", re.I)
MINT_DESC_RE = re.compile(
    r"\b(mints?|issues?|returns?|hands? back|allocates?)\b[^.]{0,80}"
    r"\b(id|ids|handle|handles|token|reference|identifier)\b", re.I)

# A key in a tool result whose value looks like a handle.
HANDLE_KEY_RE = re.compile(r"(^|_)(id|handle|token|ref|reference|key|session|ticket|cursor)$", re.I)
HANDLE_KEY_DENY_RE = re.compile(r"^(jsonrpc|request_id|trace_id|span_id|correlation_id)$", re.I)

# Never completed for the multi round-trip probe unless explicitly widened.
DESTRUCTIVE_RE = re.compile(
    r"\b(delet\w*|remov\w*|destroy\w*|purg\w*|wip\w*|erase\w*|drop|truncat\w*|revok\w*|"
    r"terminat\w*|kill|uninstall\w*|format|shutdown|reset|rollback|refund|transfer|"
    r"pay|payment|charge|wire|send_money)\b", re.I)

# Fields inside a requestState whose value can change what the server is
# willing to do, in the order worth trying: who, then how much, then how long.
SECURITY_FIELDS = [
    re.compile(r"(^|_)(principal|subject|sub|user|username|user_id|owner|actor|account|"
               r"tenant|identity|on_behalf_of|impersonat\w*)($|_)", re.I),
    re.compile(r"(^|_)(role|roles|scope|scopes|perm|perms|permission|permissions|grant|grants|"
               r"privilege|privileges|audience|aud|admin|is_admin|elevated)($|_)", re.I),
    re.compile(r"(^|_)(approved\w*|approval|confirmed|allow\w*|authorized|authorised|verified|"
               r"consent\w*)($|_)", re.I),
    re.compile(r"(^|_)(amount|limit|quota|count|items|max|total|budget|qty|quantity|"
               r"balance|price)($|_)", re.I),
    re.compile(r"(^|_)(exp|expiry|expires|expires_at|ttl|valid_until|not_after|deadline)($|_)", re.I),
    re.compile(r"(^|_)(path|target|resource|destination|dest|uri|url|bucket|table|"
               r"workspace_id|repo|project)($|_)", re.I),
]
EXPIRY_RE = re.compile(r"(^|_)(exp|expiry|expires|expires_at|ttl|valid_until|not_after|deadline)($|_)", re.I)

INPUT_REQUIRED_VALUES = {"input_required", "inputrequired", "input-required"}

REJECT_RE = re.compile(
    r"reject\w*|denied|not\s+(valid|allowed|permitted|authori[sz]ed)|invalid|unauthori[sz]ed|"
    r"forbidden|expired|signature|integrity|tamper\w*|mismatch|unknown\s+\w*handle|"
    r"does\s+not\s+verify|not\s+found|no\s+such", re.I)


# ---------------------------------------------------------------------------
# Reading answers.
# ---------------------------------------------------------------------------

def result_text(resp):
    """Every bit of text a tools/call answer carries, error or not."""
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
        chunks.append(json.dumps(result, sort_keys=True))
    return "\n".join(c for c in chunks if c)


def call_outcome(resp):
    """'accepted' | 'rejected' | 'input_required' | 'no_answer', plus the text.

    'rejected' is a refusal the server expressed: a JSON-RPC error, or a
    result flagged isError. Anything else that came back with content is an
    acceptance."""
    if not isinstance(resp, dict):
        return "no_answer", ""
    text = result_text(resp)
    if resp.get("error") is not None:
        return "rejected", text
    result = resp.get("result")
    if isinstance(result, dict):
        if str(result.get("resultType") or "").lower().replace(" ", "") in INPUT_REQUIRED_VALUES:
            return "input_required", text
        if result.get("isError"):
            return "rejected", text
    return "accepted", text


def input_required_of(resp):
    """The (inputRequests, requestState) of an input_required answer, or None.

    Tolerates the blob sitting at the top level of the result or one level in,
    because SDKs differ on where they put it."""
    if not isinstance(resp, dict):
        return None
    result = resp.get("result")
    for node in (result, resp):
        if not isinstance(node, dict):
            continue
        kind = str(node.get("resultType") or "").lower().replace(" ", "").replace("-", "_")
        state = node.get("requestState")
        if kind in {"input_required", "inputrequired"} and isinstance(state, str) and state:
            reqs = node.get("inputRequests")
            return {"inputRequests": reqs if isinstance(reqs, dict) else {},
                    "requestState": state}
    return None


def parsed_payload(text):
    """A tools/call answer parsed back into an object, when it is one."""
    text = (text or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Transports. Both expose request(method, params, principal).
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


def with_identity(params, principal):
    """Carry the principal the way a stateless request carries client identity."""
    params = dict(params or {})
    meta = dict(params.get("_meta") or {})
    meta[CLIENTINFO_META] = {"name": "cxg", "version": "1.0"}
    if principal:
        meta[PRINCIPAL_META] = principal
    params["_meta"] = meta
    return params


class HttpSession(object):
    """Streamable-HTTP MCP client that speaks the 2026-07-28 stateless core
    first - tools/list straight off, no handshake - and falls back to the
    pre-stateless initialize exchange for an older server."""

    def __init__(self, base, timeout=12):
        self.base = base
        self.timeout = timeout
        self.path = None
        self.handshake = None
        self.server_info = {}
        self._id = 0

    def _post(self, url, payload, principal=None, method_hint=None, name_hint=None):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": STATELESS_PROTO}
        if method_hint:
            headers["Mcp-Method"] = method_hint
        if name_hint:
            headers["Mcp-Name"] = name_hint
        if principal:
            headers["Authorization"] = "Bearer %s" % principal
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        try:
            r = urllib.request.urlopen(req, timeout=self.timeout, context=_ctx())
            return r.status, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode("utf-8", "ignore")
            except Exception:
                return e.code, ""
        except Exception:
            return None, ""

    def _next_id(self):
        self._id += 1
        return self._id

    def _try_tools_list(self, path, principal):
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": "tools/list",
                   "params": with_identity({}, principal)}
        status, body = self._post(self.base + path, payload, principal, "tools/list")
        if status != 200:
            return None
        obj = _extract_json(body)
        if not isinstance(obj, dict):
            return None
        tools = ((obj.get("result") or {}) if isinstance(obj.get("result"), dict) else {}).get("tools")
        return obj if isinstance(tools, list) else None

    def open(self, principal=None):
        for path in MCP_PATHS:
            if self._try_tools_list(path, principal) is not None:
                self.path = path
                self.handshake = "stateless(2026-07-28)"
                return True
        for path in MCP_PATHS:
            payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": "initialize",
                       "params": {"protocolVersion": LEGACY_PROTO, "capabilities": {},
                                  "clientInfo": {"name": "cxg", "version": "1.0"}}}
            status, body = self._post(self.base + path, payload, principal, "initialize")
            if status != 200:
                continue
            obj = _extract_json(body)
            if not isinstance(obj, dict) or not isinstance(obj.get("result"), dict):
                continue
            self.path = path
            self.handshake = "legacy(initialize)"
            self.server_info = (obj["result"].get("serverInfo") or {})
            self._post(self.base + path,
                       {"jsonrpc": "2.0", "method": "notifications/initialized"}, principal)
            if self._try_tools_list(path, principal) is not None:
                return True
            self.path = None
        return False

    def request(self, method, params, principal=None):
        if self.path is None:
            return None
        name_hint = (params or {}).get("name") if method == "tools/call" else None
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method,
                   "params": with_identity(params, principal)}
        _status, body = self._post(self.base + self.path, payload, principal, method, name_hint)
        return _extract_json(body)

    def endpoint(self):
        return self.base + (self.path or "")

    def close(self):
        pass


class StdioSession(object):
    """Newline-delimited JSON-RPC over a spawned server's stdin/stdout. There
    is no transport-level identity here, so the principal rides in `_meta`."""

    def __init__(self, argv, timeout=15):
        self.argv = argv
        self.timeout = timeout
        self.handshake = None
        self.server_info = {}
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, bufsize=1)
        self._responses = {}
        self._lock = threading.Lock()
        self.stderr_tail = []
        self._id = 0
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self):
        try:
            for line in self.proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict) and obj.get("id") is not None:
                    with self._lock:
                        self._responses[obj["id"]] = obj
        except Exception:
            pass

    def _read_stderr(self):
        try:
            for line in self.proc.stderr:
                if len(self.stderr_tail) < 20:
                    self.stderr_tail.append(line.rstrip("\n")[:200])
        except Exception:
            pass

    def _send(self, payload):
        try:
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
            return True
        except Exception:
            return False

    def _next_id(self):
        self._id += 1
        return self._id

    def request(self, method, params, principal=None):
        rid = self._next_id()
        if not self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                           "params": with_identity(params, principal)}):
            return None
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            with self._lock:
                if rid in self._responses:
                    return self._responses.pop(rid)
            if self.proc.poll() is not None:
                time.sleep(0.2)
                with self._lock:
                    return self._responses.pop(rid, None)
            time.sleep(0.03)
        return None

    def notify(self, method, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def open(self, principal=None):
        resp = self.request("tools/list", {}, principal)
        tools = ((resp or {}).get("result") or {}).get("tools") if isinstance(resp, dict) else None
        if isinstance(tools, list):
            self.handshake = "stateless(2026-07-28)"
            return True
        resp = self.request("initialize", {"protocolVersion": LEGACY_PROTO, "capabilities": {},
                                           "clientInfo": {"name": "cxg", "version": "1.0"}}, principal)
        if not isinstance(resp, dict) or not isinstance(resp.get("result"), dict):
            return False
        self.handshake = "legacy(initialize)"
        self.server_info = resp["result"].get("serverInfo") or {}
        self.notify("notifications/initialized")
        return True

    def endpoint(self):
        return "stdio://" + " ".join(self.argv)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        deadline = time.time() + 5
        while time.time() < deadline and self.proc.poll() is None:
            time.sleep(0.1)
        if self.proc.poll() is None:
            self.proc.terminate()
            time.sleep(0.4)
            if self.proc.poll() is None:
                self.proc.kill()


def list_tools(session, principal):
    resp = session.request("tools/list", {}, principal)
    if not isinstance(resp, dict):
        return None
    tools = (resp.get("result") or {}).get("tools") if isinstance(resp.get("result"), dict) else None
    if not isinstance(tools, list):
        return None
    return [t for t in tools if isinstance(t, dict)]


def declares_destructive(tool):
    ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    if ann.get("destructiveHint") is True:
        return True
    text = "%s %s" % (str(tool.get("name") or "").replace("_", " "), tool.get("description") or "")
    return bool(DESTRUCTIVE_RE.search(text))


def properties_of(tool):
    props = (tool.get("inputSchema") or {}).get("properties")
    return props if isinstance(props, dict) else {}


def synth_args(tool, known, filler):
    """Benign synthetic arguments: every required property, plus any property
    whose name matches a value we already hold (a handle we minted)."""
    schema = tool.get("inputSchema") or {}
    props = properties_of(tool)
    required = [r for r in (schema.get("required") or []) if isinstance(r, str)]
    wanted = set(required)
    for key in props:
        if key in known:
            wanted.add(key)
    args = {}
    for key in sorted(wanted):
        if key in known:
            args[key] = known[key]
            continue
        spec = props.get(key) if isinstance(props.get(key), dict) else {}
        enum = spec.get("enum")
        if isinstance(enum, list) and enum:
            args[key] = enum[0]
            continue
        args[key] = {"string": filler, "integer": 1, "number": 1, "boolean": False,
                     "array": [], "object": {}}.get(spec.get("type"), filler)
    return args


# ---------------------------------------------------------------------------
# Probe A - is a handle bound to the principal that minted it?
# ---------------------------------------------------------------------------

def find_handles(payload, consumer_keys, depth=0):
    """Handle-shaped (key, value) pairs in a tool answer, keeping only those a
    tool actually accepts as an argument. That structural join is what makes
    this a handle and not just a string with 'id' in the name."""
    found = []
    if depth > 3:
        return found
    if isinstance(payload, dict):
        for key, value in payload.items():
            if (isinstance(value, str) and 6 <= len(value) <= 256
                    and not HANDLE_KEY_DENY_RE.match(str(key))
                    and HANDLE_KEY_RE.search(str(key))
                    and not value.lower().startswith(("http://", "https://"))
                    and str(key) in consumer_keys):
                found.append((str(key), value))
            else:
                found.extend(find_handles(value, consumer_keys, depth + 1))
    elif isinstance(payload, list):
        for item in payload[:10]:
            found.extend(find_handles(item, consumer_keys, depth + 1))
    return found


def consumer_index(tools):
    """key -> [tools that take an argument with that name]."""
    index = {}
    for tool in tools:
        for key in properties_of(tool):
            if HANDLE_KEY_RE.search(str(key)) and not HANDLE_KEY_DENY_RE.match(str(key)):
                index.setdefault(str(key), []).append(tool)
    return index


def rank_minters(tools):
    named, other = [], []
    for tool in tools:
        if declares_destructive(tool):
            continue
        text = "%s %s" % (str(tool.get("name") or "").replace("_", " "), tool.get("description") or "")
        if MINT_NAME_RE.match(str(tool.get("name") or "")) or MINT_DESC_RE.search(text):
            named.append(tool)
        else:
            other.append(tool)
    return named + other


def mint(session, minter, principal, canary, consumer_keys):
    """One mint call. Returns (key, handle, raw_text) or (None, None, raw_text)."""
    args = synth_args(minter, {}, canary)
    resp = session.request("tools/call", {"name": minter.get("name"), "arguments": args}, principal)
    outcome, text = call_outcome(resp)
    if outcome != "accepted":
        return None, None, text
    pairs = find_handles(parsed_payload(text), consumer_keys)
    if not pairs:
        return None, None, text
    key, value = pairs[0]
    return key, value, text


def forge_like(handle, nonce):
    """A handle of the same shape this server has never issued: the tail is
    replaced with nonce characters drawn from the alphabet the original used."""
    if len(handle) < 8:
        return "%s-%s" % (handle, nonce[:8])
    tail_len = max(8, len(handle) // 3)
    head, tail = handle[:-tail_len], handle[-tail_len:]
    alphabet = string.hexdigits[:16] if re.fullmatch(r"[0-9a-f]+", tail) else (
        string.ascii_lowercase + string.digits)
    rng = random.Random(nonce)
    forged = "".join(rng.choice(alphabet) for _ in range(tail_len))
    if forged == tail:
        forged = forged[:-1] + ("0" if forged[-1] != "0" else "1")
    return head + forged


def probe_handle_binding(session, tools, ident_a, ident_b, nonce):
    """Returns (verdict, detail, evidence) with verdict in confirmed/refuted/skipped."""
    consumers = consumer_index(tools)
    if not consumers:
        return "skipped", "no-tool-consumes-a-handle-shaped-argument", {}

    canary_a = "%s-canary-A-%s" % (PROBE_PREFIX, nonce)
    canary_b = "%s-canary-B-%s" % (PROBE_PREFIX, nonce)
    attempts = []
    minted = None
    for minter in rank_minters(tools)[:MAX_MINT_CALLS]:
        key, handle, text = mint(session, minter, ident_a, canary_a, set(consumers))
        attempts.append({"tool": minter.get("name"), "minted": bool(handle),
                         "excerpt": text[:160]})
        if handle:
            minted = {"tool": minter.get("name"), "key": key, "handle": handle,
                      "mint_excerpt": text[:400]}
            break
    if minted is None:
        return ("skipped",
                "no-tool-minted-a-handle-that-another-tool-consumes(tried %d)" % len(attempts),
                {"mint_attempts": attempts})

    key = minted["key"]
    candidates = [t for t in consumers[key] if t.get("name") != minted["tool"]]
    if not candidates:
        candidates = consumers[key]
    consumer = candidates[0]
    cname = consumer.get("name")

    def read_as(principal, handle):
        args = synth_args(consumer, {key: handle}, "%s-arg-%s" % (PROBE_PREFIX, nonce))
        resp = session.request("tools/call", {"name": cname, "arguments": args}, principal)
        return call_outcome(resp)

    # A2 - identity B has to be a working identity of its own, or the
    # comparison in A4 has no second term.
    b_minter = next((t for t in tools if t.get("name") == minted["tool"]), None)
    b_key, b_handle, b_text = (None, None, "")
    if b_minter is not None:
        b_key, b_handle, b_text = mint(session, b_minter, ident_b, canary_b, set(consumers))
    if not b_handle:
        return ("skipped",
                "second-identity-could-not-mint-its-own-handle(minter=%s) - the two identities are "
                "not both live, so a cross-principal result would be unattributable"
                % minted["tool"],
                {"minted_for_A": minted, "identity_B_mint_excerpt": b_text[:300]})
    own_outcome, own_text = read_as(ident_b, b_handle)
    if own_outcome != "accepted":
        return ("skipped",
                "second-identity-could-not-read-its-own-handle(tool=%s outcome=%s) - the two "
                "identities are not both live" % (cname, own_outcome),
                {"minted_for_A": minted, "identity_B_own_read": own_text[:300]})

    # A3 - negative control. A handle this server never issued must be refused.
    forged = forge_like(minted["handle"], nonce)
    forged_outcome, forged_text = read_as(ident_b, forged)

    # A4 - the subject.
    cross_outcome, cross_text = read_as(ident_b, minted["handle"])
    marker = None
    if canary_a and canary_a in cross_text:
        marker = "canary planted by identity A (%s)" % canary_a
    elif ident_a and ident_a in cross_text and ident_a != ident_b:
        marker = "identity A's own principal string (%s)" % ident_a

    evidence = {
        "consumer_tool": cname,
        "handle_argument": key,
        "minting_tool": minted["tool"],
        "identity_A": ident_a,
        "identity_B": ident_b,
        "handle_minted_for_A": minted["handle"],
        "handle_minted_for_B": b_handle,
        "canary_A": canary_a,
        "negative_control_forged_handle": {"handle": forged, "outcome": forged_outcome,
                                           "excerpt": forged_text[:240]},
        "identity_B_reading_its_own_handle": {"outcome": own_outcome, "excerpt": own_text[:240]},
        "identity_B_reading_A_handle": {"outcome": cross_outcome, "excerpt": cross_text[:400]},
        "observed_marker": marker,
        "observations": [],
    }

    if forged_outcome == "accepted":
        evidence["observations"].append(
            "forged handle honoured: %s accepted a handle this server never minted, so it performs "
            "no handle validation at all and 'not bound to a principal' cannot be drawn from it. "
            "That is a separate weakness, reported here as an observation and not as a finding."
            % cname)
        return ("refuted",
                "handle-witness-unusable(forged-handle-honoured by %s; no handle validation to bind "
                "with) tool=%s arg=%s" % (cname, cname, key), evidence)

    if cross_outcome != "accepted":
        return ("refuted",
                "handle-bound(%s refused A's handle for B: %s; forged-handle-control=%s so the "
                "refusal is a decision, not an outage) tool=%s arg=%s"
                % (cname, cross_outcome, forged_outcome, cname, key), evidence)

    if marker is None:
        evidence["observations"].append(
            "cross-principal read succeeded but returned neither the canary identity A planted nor "
            "identity A's principal string, so the object identity B received cannot be shown to be "
            "A's. Recorded as an observation, not a finding.")
        return ("refuted",
                "handle-cross-use-accepted-but-unattributable(no A-side marker in the answer) "
                "tool=%s arg=%s" % (cname, key), evidence)

    return ("confirmed",
            "handle-not-bound-to-principal(%s honoured a handle minted for %s when presented by %s; "
            "forged-handle-control=rejected; marker=%s) tool=%s arg=%s"
            % (cname, ident_a, ident_b, marker, cname, key), evidence)


# ---------------------------------------------------------------------------
# Probe B - is an echoed requestState bound to anything?
# ---------------------------------------------------------------------------

def b64d_json(text):
    pad = "=" * (-len(text) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            obj = json.loads(decoder(text + pad).decode("utf-8"))
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def b64e_json(obj):
    raw = json.dumps(obj, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_state(blob):
    """(state_dict, envelope) or (None, None).

    envelope is 'json', 'base64', or 'base64.signature' - in the last case the
    signature is deliberately left as issued, so re-encoding a mutated body
    produces exactly the tamper a verifying server is supposed to catch."""
    try:
        obj = json.loads(blob)
        if isinstance(obj, dict):
            return obj, ("json", None)
    except ValueError:
        pass
    obj = b64d_json(blob)
    if obj is not None:
        return obj, ("base64", None)
    if "." in blob:
        body, _, sig = blob.rpartition(".")
        obj = b64d_json(body)
        if obj is not None:
            return obj, ("base64.signature", sig)
    return None, None


def encode_state(obj, envelope):
    kind, sig = envelope
    if kind == "json":
        return json.dumps(obj, sort_keys=True)
    if kind == "base64":
        return b64e_json(obj)
    return b64e_json(obj) + "." + sig


def garbage_like(blob, nonce):
    """A random blob of the same shape and length. If this is accepted, the
    server is not consulting the state, and nothing about a mutated state can
    be concluded."""
    rng = random.Random("garbage" + nonce)

    def scramble(part):
        if re.fullmatch(r"[0-9a-fA-F]+", part):
            alphabet = string.hexdigits[:16]
        else:
            alphabet = string.ascii_letters + string.digits + "-_"
        return "".join(rng.choice(alphabet) for _ in range(len(part)))

    if "." in blob:
        pieces = blob.split(".")
        return ".".join(scramble(p) for p in pieces)
    return scramble(blob)


def flip_one_char(blob, offset):
    if not blob:
        return blob
    i = max(0, min(len(blob) - 1, offset))
    original = blob[i]
    if original in string.hexdigits[:16]:
        alphabet = string.hexdigits[:16]
    elif original.isalnum():
        alphabet = string.ascii_lowercase + string.digits
    else:
        return None
    replacement = next(c for c in alphabet if c != original)
    return blob[:i] + replacement + blob[i + 1:]


def mutate_field(state, nonce):
    """(mutated_state, field, before, after, why) for the first
    security-relevant field, or None."""
    canary = "%s-state-canary-%s" % (PROBE_PREFIX, nonce)
    for pattern in SECURITY_FIELDS:
        for field in sorted(state):
            if not pattern.search(str(field)):
                continue
            before = state[field]
            if isinstance(before, bool):
                after, why = (not before), "boolean flipped"
            elif isinstance(before, (int, float)):
                if EXPIRY_RE.search(str(field)):
                    after, why = int(before) + 10 ** 7, "expiry pushed out by 10^7 seconds"
                else:
                    after, why = int(before) * 1000 + 7, "quantity raised by three orders of magnitude"
            elif isinstance(before, str) and before:
                after, why = canary, "value replaced with a canary the template can recognise"
            else:
                continue
            mutated = dict(state)
            mutated[field] = after
            return mutated, field, before, after, why
    return None


def responses_for(input_requests, nonce):
    """Affirmative answers to the server's own questions, so the retry gets as
    far as the state check rather than stalling on an unanswered prompt."""
    out = {}
    for key, spec in (input_requests or {}).items():
        schema = (spec or {}).get("schema") if isinstance(spec, dict) else None
        kind = (schema or {}).get("type") if isinstance(schema, dict) else None
        enum = (schema or {}).get("enum") if isinstance(schema, dict) else None
        if isinstance(enum, list) and enum:
            out[key] = enum[0]
        elif kind == "boolean" or kind is None:
            out[key] = True
        elif kind in ("integer", "number"):
            out[key] = 1
        elif kind == "array":
            out[key] = []
        elif kind == "object":
            out[key] = {}
        else:
            out[key] = "%s-input-%s" % (PROBE_PREFIX, nonce)
    return out or {"confirm": True}


def mrtr_candidates(tools, known):
    """Tools worth calling for an input_required, safest first."""
    widen = os.getenv("CXG_MCP_MRTR_INCLUDE_DESTRUCTIVE") == "1"
    with_handle, without = [], []
    for tool in tools:
        if declares_destructive(tool) and not widen:
            continue
        (with_handle if any(k in properties_of(tool) for k in known) else without).append(tool)
    return with_handle + without


def probe_request_state(session, tools, ident_a, known, nonce):
    """Returns (verdict, detail, evidence)."""
    filler = "%s-arg-%s" % (PROBE_PREFIX, nonce)

    def fresh(tool):
        """One first-round call. Returns (args, input_required or None, text)."""
        args = synth_args(tool, known, filler)
        resp = session.request("tools/call", {"name": tool.get("name"), "arguments": args}, ident_a)
        return args, input_required_of(resp), result_text(resp)

    tried = []
    subject = None
    for tool in mrtr_candidates(tools, known)[:MAX_MRTR_CALLS]:
        args, ir, text = fresh(tool)
        tried.append({"tool": tool.get("name"), "input_required": bool(ir), "excerpt": text[:140]})
        if ir:
            subject = {"tool": tool, "args": args, "ir": ir}
            break
    if subject is None:
        widened = os.getenv("CXG_MCP_MRTR_INCLUDE_DESTRUCTIVE") == "1"
        return ("skipped",
                "no-tool-returned-input_required(%d non-destructive tool(s) called%s)"
                % (len(tried), "" if widened else
                   "; destructive-declared tools were not completed - set "
                   "CXG_MCP_MRTR_INCLUDE_DESTRUCTIVE=1 to widen"),
                {"mrtr_attempts": tried})

    tool = subject["tool"]
    tname = tool.get("name")
    responses = responses_for(subject["ir"]["inputRequests"], nonce)

    def retry(blob, args):
        resp = session.request("tools/call", {"name": tname, "arguments": args,
                                              "inputResponses": responses,
                                              "requestState": blob}, ident_a)
        return call_outcome(resp)

    def fresh_state():
        args, ir, _text = fresh(tool)
        return (args, ir["requestState"]) if ir else (args, None)

    evidence = {
        "tool": tname,
        "identity": ident_a,
        "input_requests": subject["ir"]["inputRequests"],
        "input_responses_sent": responses,
        "requestState_sample": subject["ir"]["requestState"][:200],
        "requestState_length": len(subject["ir"]["requestState"]),
        "observations": [],
    }

    # B2 - baseline. An untouched retry must work, or a later rejection is
    # just the flow being broken.
    base_args, base_blob = fresh_state()
    if base_blob is None:
        return ("skipped", "input_required-was-not-reproducible-on-a-second-call(tool=%s)" % tname,
                evidence)
    base_outcome, base_text = retry(base_blob, base_args)
    evidence["baseline_untouched_retry"] = {"outcome": base_outcome, "excerpt": base_text[:300]}
    if base_outcome != "accepted":
        return ("skipped",
                "untouched-retry-did-not-succeed(tool=%s outcome=%s) - the multi round-trip flow is "
                "not working, so a rejected mutation would prove nothing"
                % (tname, base_outcome), evidence)

    # B3 - negative control. A random blob of the same shape must be refused.
    g_args, g_blob = fresh_state()
    if g_blob is None:
        return ("skipped", "input_required-stopped-being-reproducible(tool=%s)" % tname, evidence)
    garbage = garbage_like(g_blob, nonce)
    g_outcome, g_text = retry(garbage, g_args)
    evidence["negative_control_random_blob"] = {"outcome": g_outcome, "excerpt": g_text[:240],
                                               "blob_excerpt": garbage[:120]}
    if g_outcome == "accepted":
        evidence["observations"].append(
            "a random blob of the same shape and length was accepted, so this server does not "
            "consult requestState at all. Accepting a mutated one would say nothing about "
            "integrity. Recorded as an observation, not a finding.")
        return ("refuted",
                "state-witness-unusable(random-blob-accepted by %s; requestState does not steer the "
                "outcome)" % tname, evidence)

    state, envelope = decode_state(subject["ir"]["requestState"])

    # B4 - the subject: mutate one security-relevant field.
    if state is not None:
        evidence["decoded_state_keys"] = sorted(state)
        evidence["state_envelope"] = envelope[0]
        plan = mutate_field(state, nonce)
        if plan is None:
            evidence["observations"].append(
                "requestState decoded to %s but carries no field this template recognises as "
                "security-relevant, so there was nothing to mutate meaningfully."
                % (", ".join(sorted(state)) or "an empty object"))
        else:
            _m, field, before, after, why = plan
            m_args, m_blob = fresh_state()
            if m_blob is None:
                return ("skipped", "input_required-stopped-being-reproducible(tool=%s)" % tname,
                        evidence)
            m_state, m_env = decode_state(m_blob)
            if m_state is None or field not in m_state:
                return ("skipped",
                        "requestState-stopped-decoding-between-calls(tool=%s)" % tname, evidence)
            m_state = dict(m_state)
            m_state[field] = after
            mutated_blob = encode_state(m_state, m_env)
            mu_outcome, mu_text = retry(mutated_blob, m_args)
            observed = isinstance(after, str) and after in mu_text
            evidence["mutation"] = {"field": field, "before": before, "after": after,
                                    "why": why, "envelope": m_env[0],
                                    "signature_left_as_issued": m_env[0] == "base64.signature",
                                    "outcome": mu_outcome, "excerpt": mu_text[:400],
                                    "mutated_value_observed_in_answer": observed}
            if mu_outcome == "accepted":
                return ("confirmed",
                        "requestState-echoed-back-unbound(tool=%s field=%s %r->%r accepted; "
                        "random-blob-control=rejected; untouched-retry=accepted%s)"
                        % (tname, field, before, after,
                           "; mutated value observed in the answer" if observed else ""),
                        evidence)
            evidence["observations"].append(
                "the mutated field %s was rejected (%s)." % (field, mu_outcome))
            return ("refuted",
                    "requestState-integrity-held(tool=%s field=%s mutation rejected: %s; "
                    "untouched-retry=accepted and random-blob-control=rejected, so the instrument "
                    "was live)" % (tname, field, (mu_text or mu_outcome)[:120]), evidence)

    # B5 - fallback for a state this template cannot read: one flipped
    # character. B3 already proved a random blob is refused.
    evidence["state_envelope"] = "opaque(not raw JSON, base64 JSON, or body.signature)"
    flips = []
    length = len(subject["ir"]["requestState"])
    for fraction in (0.30, 0.50, 0.70, 0.88, 0.96)[:MAX_FLIP_OFFSETS]:
        f_args, f_blob = fresh_state()
        if f_blob is None:
            break
        offset = int(len(f_blob) * fraction)
        flipped = flip_one_char(f_blob, offset)
        if flipped is None or flipped == f_blob:
            continue
        f_outcome, f_text = retry(flipped, f_args)
        flips.append({"offset": offset, "of": len(f_blob), "outcome": f_outcome,
                      "excerpt": f_text[:240]})
        if f_outcome == "accepted":
            evidence["single_character_flips"] = flips
            return ("confirmed",
                    "requestState-not-integrity-protected(tool=%s: a single character flipped at "
                    "offset %d of %d was accepted, while a random blob of the same shape was "
                    "rejected - the blob is consulted but not authenticated)"
                    % (tname, offset, length), evidence)
    evidence["single_character_flips"] = flips
    if not flips:
        return ("skipped",
                "opaque-requestState-could-not-be-perturbed(tool=%s length=%d)" % (tname, length),
                evidence)
    return ("refuted",
            "requestState-integrity-held(tool=%s: %d single-character flips all rejected; "
            "untouched-retry=accepted and random-blob-control=rejected, so the instrument was live)"
            % (tname, len(flips)), evidence)


# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------

def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def make_finding(target, request_note, description, evidence, matched):
    return {
        "target": target,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": description,
        "evidence": {
            "request": request_note,
            "response": json.dumps(evidence)[:1400],
            "matched_patterns": matched,
            "data": evidence,
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def handle_finding(endpoint, evidence):
    description = (
        "MCP server %s honoured a handle for a principal that did not mint it. Tool `%s` minted "
        "`%s` for identity %r; identity %r presented that same value to `%s` and the call "
        "succeeded, returning %s. The negative control rules out the trivial explanation: a "
        "same-shaped handle this server never issued was REJECTED by the same tool on the same "
        "identity, so the server does validate handles - it just does not bind them to a "
        "principal. Since the 2026-07-28 stateless core, a handle is not a transport secret the "
        "client holds; it is an ordinary tool argument that lives in model context, where a "
        "poisoned tool result, a shared transcript or an injected instruction can substitute one. "
        "An unbound handle therefore turns any principal's identifier into any other principal's "
        "access."
        % (endpoint, evidence.get("minting_tool"), evidence.get("handle_argument"),
           evidence.get("identity_A"), evidence.get("identity_B"), evidence.get("consumer_tool"),
           evidence.get("observed_marker")))
    return make_finding(
        endpoint,
        "tools/list -> mint as A (canary label) -> mint+read as B (liveness) -> read a forged "
        "handle as B (negative control) -> read A's handle as B",
        description, evidence,
        ["handle-minted-for-another-principal-honoured", "forged-handle-control-rejected",
         "principal-A-marker-observed", "stateless-core-explicit-handle"])


def state_finding(endpoint, evidence):
    mutation = evidence.get("mutation") or {}
    if mutation:
        what = ("field `%s` was changed from %r to %r (%s)%s"
                % (mutation.get("field"), mutation.get("before"), mutation.get("after"),
                   mutation.get("why"),
                   ", with the signature the server issued left in place"
                   if mutation.get("signature_left_as_issued") else ""))
        seen = (" The mutated value came back in the server's own answer, so it did not merely "
                "pass validation - it steered the result."
                if mutation.get("mutated_value_observed_in_answer") else "")
    else:
        flips = evidence.get("single_character_flips") or []
        accepted = next((f for f in flips if f.get("outcome") == "accepted"), {})
        what = ("a single character was flipped at offset %s of %s of the opaque blob"
                % (accepted.get("offset"), accepted.get("of")))
        seen = (" The blob is confidential but unauthenticated: it decodes on the server, and "
                "nothing checks that it decodes to what the server issued.")
    description = (
        "MCP server %s accepted a `requestState` that had been altered since it issued it. Tool "
        "`%s` answered a call with `resultType: input_required` and a `requestState` blob; on the "
        "retry, %s, and the call was accepted.%s Two controls make this an integrity failure "
        "rather than indifference: an UNTOUCHED retry of the same flow was accepted, so the flow "
        "works; and a RANDOM blob of the same shape and length was REJECTED, so the server does "
        "consult the state. The 2026-07-28 stateless core round-trips this blob through the "
        "client, which makes it attacker-controlled input; the specification's guidance is to "
        "integrity-protect it, bind it to the principal and to the originating request, and give "
        "it an expiry before letting it influence authorization. Here it influences authorization "
        "with none of those."
        % (endpoint, evidence.get("tool"), what, seen))
    return make_finding(
        endpoint,
        "tools/call -> input_required(requestState) -> retry untouched (baseline) -> retry with a "
        "random same-shape blob (negative control) -> retry with one mutated field",
        description, evidence,
        ["mutated-requestState-accepted", "random-blob-control-rejected",
         "untouched-retry-accepted", "stateless-core-multi-round-trip"])


# ---------------------------------------------------------------------------
# The scan.
# ---------------------------------------------------------------------------

def run_probes(session, endpoint, timeout_note=""):
    nonce = uuid.uuid4().hex[:12]
    ident_a = os.getenv("CXG_MCP_IDENTITY_A") or "%s-identity-a-%s" % (PROBE_PREFIX, nonce)
    ident_b = os.getenv("CXG_MCP_IDENTITY_B") or "%s-identity-b-%s" % (PROBE_PREFIX, nonce)

    tools = list_tools(session, ident_a)
    if tools is None:
        return "skipped", "server-answered-but-not-tools/list endpoint=%s" % endpoint, []
    if not tools:
        return "skipped", "server-exposes-no-tools endpoint=%s" % endpoint, []

    a_verdict, a_detail, a_evidence = probe_handle_binding(session, tools, ident_a, ident_b, nonce)

    known = {}
    if a_evidence.get("handle_argument") and a_evidence.get("handle_minted_for_A"):
        known[a_evidence["handle_argument"]] = a_evidence["handle_minted_for_A"]
    b_verdict, b_detail, b_evidence = probe_request_state(session, tools, ident_a, known, nonce)

    surface = ("endpoint=%s handshake=%s tools=%d identities=%s,%s%s"
               % (endpoint, getattr(session, "handshake", "?"), len(tools), ident_a, ident_b,
                  timeout_note))
    findings = []
    if a_verdict == "confirmed":
        a_evidence["surface"] = surface
        findings.append(handle_finding(endpoint, a_evidence))
    if b_verdict == "confirmed":
        b_evidence["surface"] = surface
        findings.append(state_finding(endpoint, b_evidence))

    joint = "handle-binding: %s | requestState: %s | %s" % (a_detail, b_detail, surface)
    if findings:
        return "confirmed", joint, findings
    if "refuted" in (a_verdict, b_verdict):
        return "refuted", joint, []
    return "skipped", ("pre-stateless-core-or-no-probe-precondition | %s" % joint), []


def scan_http(host, port, scheme="http", timeout=12):
    base = "%s://%s:%d" % (scheme, host, port)
    session = HttpSession(base, timeout)
    nonce_ident = os.getenv("CXG_MCP_IDENTITY_A") or "%s-open" % PROBE_PREFIX
    if not session.open(nonce_ident):
        return "skipped", "no-mcp-server-answered(%s)" % base, []
    try:
        return run_probes(session, session.endpoint())
    finally:
        session.close()


def scan_stdio(argv, timeout=15):
    try:
        session = StdioSession(argv, timeout=timeout)
    except Exception as exc:
        return "errored", "could-not-run-stdio-mcp-server(%s) argv=%s" % (exc, " ".join(argv)), []
    try:
        if not session.open(os.getenv("CXG_MCP_IDENTITY_A")):
            return ("errored",
                    "stdio-server-did-not-answer-tools/list-or-initialize(argv=%s)%s"
                    % (" ".join(argv),
                       " stderr=%s" % ";".join(session.stderr_tail)[:200]
                       if session.stderr_tail else ""), [])
        return run_probes(session, session.endpoint(),
                          timeout_note=" transport=stdio")
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Target resolution. A cli target arrives as the raw scope string with the
# cli:// prefix still on it, and CERT_X_GEN_TARGET_KIND is usually unset, so
# the kind is derived from the string itself.
# ---------------------------------------------------------------------------

def stdio_argv(binary):
    extra = os.getenv("CXG_MCP_STDIO_ARGS", "")
    argv = [binary] + (shlex.split(extra) if extra else [])
    if not os.access(binary, os.X_OK) and binary.endswith(".py"):
        argv = [sys.executable] + argv
    return argv


def resolve_target():
    override = os.getenv("CXG_MCP_STDIO_CMD")
    if override:
        return ("stdio", shlex.split(override))

    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST") or ""
        kind = (os.getenv("CERT_X_GEN_TARGET_KIND") or "").lower()
        if not host:
            return ("error", "CERT_X_GEN_TARGET_HOST not set")
        if host.startswith("cli://"):
            return ("stdio", stdio_argv(host[len("cli://"):] or "/"))
        if kind == "cli" or (host.startswith("/") and Path(host).is_file()):
            return ("stdio", stdio_argv(host))
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        host = re.sub(r"^https?://", "", host).split("/")[0]
        try:
            port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "8000"))
        except ValueError:
            port = 8000
        return ("http", host, port, scheme)

    args = sys.argv[1:]
    if not args:
        return ("error",
                "Usage: mcp-handle-binding-integrity.py <host> [port] [scheme]  |  "
                "--stdio <command> [args...]  |  cli:///path/to/mcp-server")
    if args[0] == "--stdio":
        if len(args) < 2:
            return ("error", "--stdio needs a command")
        return ("stdio", list(args[1:]))
    if args[0].startswith("cli://"):
        return ("stdio", stdio_argv(args[0][len("cli://"):] or "/"))
    host = args[0]
    port = int(args[1]) if len(args) > 1 else 8000
    scheme = args[2] if len(args) > 2 else "http"
    return ("http", host, port, scheme)


def main():
    sys.stderr.write(
        "[!] mcp-handle-binding-integrity is an ACTIVE check: it INVOKES MCP tools - minting a "
        "handle under two synthetic identities and completing a confirmation flow with a mutated "
        "requestState. Destructive-declared tools are skipped unless "
        "CXG_MCP_MRTR_INCLUDE_DESTRUCTIVE=1. Make sure you are authorized to test this system.\n")
    sys.stderr.flush()

    target = resolve_target()
    if target[0] == "error":
        emit("errored", target[1])
        sys.exit(0)
    if target[0] == "stdio":
        argv = target[1]
        if not argv or not (Path(argv[0]).exists() or shutil.which(argv[0])):
            emit("errored", "stdio-target-not-executable(%s)" % (argv[0] if argv else "<empty>"))
            sys.exit(0)
        status, detail, findings = scan_stdio(argv)
    else:
        _kind, host, port, scheme = target
        status, detail, findings = scan_http(host, port, scheme)
    emit(status, detail, findings)


if __name__ == "__main__":
    main()

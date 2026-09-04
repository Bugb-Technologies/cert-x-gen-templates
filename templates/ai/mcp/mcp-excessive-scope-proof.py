#!/usr/bin/env python3
# @id: mcp-excessive-scope-proof
# @name: MCP Out-of-Scope Tool Action (Behavioural Scope Proof)
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. Calls an MCP tool that DECLARES itself read-only and proves, by observation, that it performed an action outside that declared scope - a write. Filesystem-witnessed against a hermetic lab for a local stdio server, protocol-witnessed (a path that was absent before the read and present after it) for a remote HTTP server.
# @tags: mcp, ai, agent, excessive-permissions, least-privilege, out-of-scope-action, behavioural, active, intrusive, cwe-250, cwe-284
# @cwe: CWE-250, CWE-284
# @cvss: 7.6
# @target_kinds: http, cli
# @oracles: property, diff
# @references: https://modelcontextprotocol.io/specification/2025-06-18/server/tools, https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices, https://cwe.mitre.org/data/definitions/250.html, https://cwe.mitre.org/data/definitions/284.html
# @confidence: 95
# @version: 1.0.0
"""
ACTIVE / INTRUSIVE check - MCP out-of-scope tool action.

WHAT THIS IS NOT

It is not mcp-excessive-tool-permissions. That template reads a manifest and
reports a tool whose DECLARED interface is too broad (a `file_manager` that
advertises write and delete). Useful, and entirely static: it can only repeat
what the server chose to say about itself.

This template tests the opposite and harder direction - a tool whose
declaration is NARROW and whose behaviour is not. MCP gives a server a first
class way to make that promise:

    "readOnlyHint: If true, the tool does not modify its environment."
    -- MCP specification, Tools / Tool annotations

The spec is equally clear that the promise is unverified: annotations are
"hints" and "clients MUST consider tool annotations to be untrusted unless
they come from trusted servers". A hint nothing checks is a hint worth
checking. This template calls the tool and watches what it does.

THE ORACLE IS A PROPERTY OF AN OBSERVED RUN

  Property:  invoking a tool whose declared scope is read-only produces no
             write. Any write attributable to that invocation breaks it.

Two witnesses, chosen by target kind, because a scanner's visibility differs:

  A. FILESYSTEM WITNESS   (cli:// - a local stdio MCP server)
     The template owns the process, so it can see the truth directly. It
     builds a hermetic lab (a sentinel workdir holding one planted note, a
     sentinel HOME and TMPDIR), hashes every file in it, spawns the server
     with the lab as its world, calls only the tools that declared themselves
     read-only - with the planted note as the argument, i.e. asking each tool
     to do exactly its declared job - shuts the server down and hashes the lab
     again.
     A CONTROL run does the same in an identical, separate lab but makes NO
     tools/call, so anything the server writes merely by starting up
     (a session log, a cache dir) is subtracted. What survives the subtraction
     was written because a read-only tool was called.
     The witness proves itself: after the comparison the template writes its
     own file into the lab and re-hashes, so a snapshot that could not see a
     write can never be mistaken for a lab in which no write happened.

  B. PROTOCOL WITNESS     (http:// - a remote MCP server)
     The filesystem belongs to someone else, so the write has to be observed
     through the only channel there is: the protocol. For a read-only tool
     that takes a path, the template picks a nonce path that cannot already
     exist, and reads it TWICE with identical arguments.
         read(P) -> absent    the path did not exist
         read(P) -> present   the path exists now
     Nothing between the two calls touched P except the tool. A read that
     makes its own subject come into existence wrote it. The content the
     second read returns is the tool's own artefact and is carried as
     evidence. A third, never-repeated nonce path is read once as a negative
     control, so a server that answers "present" to everything cannot produce
     a confirmation.

VERDICT CONTRACT

  confirmed  a tool that declared itself read-only was called and a write was
             observed: a lab path created or modified only in the call run, or
             a nonce path that flipped absent -> present across two identical
             reads. The observation is in the evidence.
  refuted    read-only candidates were called through a witness proven live,
             and no write was attributable to any of them.
  skipped    the precondition for the check was not met, and which one is
             named: no MCP server answered; the server exposes no tools; no
             tool declares a narrow (read-only) scope - an over-broad
             DECLARATION is mcp-excessive-tool-permissions' finding, not this
             one; or, over HTTP, no read-only tool takes a path-like argument
             so the protocol witness has nothing to observe.
  errored    the target could not be reached or the server could not be run.

SAFETY

It invokes tools. It invokes ONLY tools the server itself declared read-only,
with benign synthetic arguments (a note the template planted, and nonce paths
under a `cxg-scope-probe-` prefix that nothing real uses). It never calls a
tool that declares write, delete or execute. For a stdio target the server runs
inside a temporary lab that is deleted on exit; that is a lab, not a sandbox -
a hostile server can still reach the real network and the real filesystem, so
run an untrusted server inside a disposable container. Against the fixtures in
fixtures/mcp-excessive-scope-proof it is safe anywhere. Get authorisation
before pointing it at a system you do not own.
"""

import hashlib
import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

METADATA = {
    "id": "mcp-excessive-scope-proof",
    "name": "MCP Out-of-Scope Tool Action (Behavioural Scope Proof)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE check: calls an MCP tool that declares itself read-only and proves by observation "
        "that it wrote - filesystem-witnessed in a hermetic lab for a local stdio server, "
        "protocol-witnessed (absent -> present across two identical reads) for a remote HTTP server"
    ),
    "tags": ["mcp", "ai", "agent", "excessive-permissions", "least-privilege", "out-of-scope-action",
             "behavioural", "active", "intrusive", "cwe-250", "cwe-284"],
    "language": "python",
    "active": True,
    "confidence": 95,
    "cwe": ["CWE-250", "CWE-284"],
    "references": [
        "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
        "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
        "https://cwe.mitre.org/data/definitions/250.html",
        "https://cwe.mitre.org/data/definitions/284.html",
    ],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"
PROBE_PREFIX = "cxg-scope-probe"
PLANTED_NOTE_NAME = "notes/welcome.txt"
PLANTED_NOTE_BODY = (
    "cxg synthetic note. Planted by mcp-excessive-scope-proof so a read-only tool\n"
    "can be asked to do exactly its declared job. Contains nothing real.\n"
)

# A tool's declared scope, read from what the server says about itself.
READ_VERB_RE = re.compile(
    r"\b(read|get|fetch|list|search|view|show|query|describe|lookup|find|cat|"
    r"preview|inspect|status|count|summar\w*|retriev\w*|browse)\b", re.I)
WRITE_VERB_RE = re.compile(
    r"\b(writ\w*|creat\w*|delet\w*|remov\w*|updat\w*|modif\w*|sav\w*|append\w*|"
    r"put|patch|upload\w*|renam\w*|mov\w*|mkdir|install\w*|execut\w*|exec|run|"
    r"spawn\w*|kill|send\w*|post|publish\w*|commit\w*|push\w*|drop|truncat\w*)\b", re.I)
PATH_PARAM_RE = re.compile(r"(^|_)(path|file|filename|filepath|uri|src|source|target|document)(_|$)", re.I)

ABSENT_RE = re.compile(
    r"not\s*found|no\s+such\s+file|does\s+not\s+exist|doesn'?t\s+exist|ENOENT|"
    r"\bmissing\b|unknown\s+(path|file|note|resource)|cannot\s+(be\s+)?(find|open|read)|"
    r"unable\s+to\s+(find|open|read)|nonexistent|not\s+present", re.I)


# ---------------------------------------------------------------------------
# Declared scope.
# ---------------------------------------------------------------------------

def declared_scope(tool):
    """What the SERVER says this tool's scope is. Returns (narrow, reason).

    `narrow` is True only when the declaration promises a read and nothing
    else. Anything ambiguous is not narrow: the finding is 'acted outside a
    declared scope', so a tool with no clear declaration has no scope to act
    outside of and is left alone."""
    name = str(tool.get("name") or "")
    desc = str(tool.get("description") or "")
    ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}

    if ann.get("destructiveHint") is True:
        return False, "annotations.destructiveHint=true"
    if ann.get("readOnlyHint") is True:
        return True, "annotations.readOnlyHint=true"
    if ann.get("readOnlyHint") is False:
        return False, "annotations.readOnlyHint=false"

    text = "%s %s" % (name.replace("_", " "), desc)
    if WRITE_VERB_RE.search(text):
        return False, "name/description declares a write-class capability"
    if READ_VERB_RE.search(text):
        return True, "name/description declares only a read"
    return False, "no declared scope to test"


def path_param(tool):
    props = ((tool.get("inputSchema") or {}).get("properties") or {})
    if not isinstance(props, dict):
        return None
    for key in props:
        if PATH_PARAM_RE.search(str(key)):
            return str(key)
    return None


def synth_args(tool, path_value):
    """Benign synthetic arguments for one call. Required properties only, plus
    the path-like property when there is one, because it is the steering
    wheel of a read tool."""
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    if not isinstance(props, dict):
        return {}
    pkey = path_param(tool)
    wanted = set(r for r in required if isinstance(r, str))
    if pkey:
        wanted.add(pkey)
    args = {}
    for key in wanted:
        if key == pkey and path_value is not None:
            args[key] = path_value
            continue
        spec = props.get(key) if isinstance(props.get(key), dict) else {}
        enum = spec.get("enum")
        if isinstance(enum, list) and enum:
            args[key] = enum[0]
            continue
        kind = spec.get("type")
        args[key] = {"string": "%s-%s" % (PROBE_PREFIX, "arg"), "integer": 1, "number": 1,
                     "boolean": False, "array": [], "object": {}}.get(kind, "%s-arg" % PROBE_PREFIX)
    return args


# ---------------------------------------------------------------------------
# Reading one tools/call answer as an observation of presence or absence.
# ---------------------------------------------------------------------------

def result_text(resp):
    if not isinstance(resp, dict):
        return ""
    if "error" in resp and resp["error"] is not None:
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
    if not chunks and result:
        chunks.append(json.dumps(result))
    return "\n".join(c for c in chunks if c)


def read_outcome(resp):
    """'absent' | 'present' | 'error' | 'indeterminate' for one read call."""
    if resp is None:
        return "indeterminate", ""
    text = result_text(resp)
    if isinstance(resp, dict) and resp.get("error") is not None:
        return ("absent" if ABSENT_RE.search(text) else "error"), text
    result = resp.get("result") if isinstance(resp, dict) else None
    if isinstance(result, dict) and result.get("isError"):
        return ("absent" if ABSENT_RE.search(text) else "error"), text
    if not text.strip():
        return "absent", text
    if ABSENT_RE.search(text):
        return "absent", text
    return "present", text


# ---------------------------------------------------------------------------
# Transports. Both expose the same tiny surface: request(method, params).
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


class HttpSession(object):
    """Streamable-HTTP MCP client. Falls back across the usual endpoint paths."""

    def __init__(self, base, timeout=12):
        self.base = base
        self.timeout = timeout
        self.path = None
        self.session_id = None
        self._id = 0

    def _post(self, url, payload):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
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

    def _next_id(self):
        self._id += 1
        return self._id

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

    def request(self, method, params):
        if self.path is None:
            return None
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method, "params": params or {}}
        _status, _headers, body = self._post(self.base + self.path, payload)
        return _extract_json(body)

    def endpoint(self):
        return self.base + (self.path or "")

    def close(self):
        pass


class StdioSession(object):
    """Newline-delimited JSON-RPC over a spawned server's stdin/stdout, which
    is what MCP's stdio transport is."""

    def __init__(self, argv, cwd, env, timeout=15):
        self.argv = argv
        self.timeout = timeout
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, env=env, universal_newlines=True, bufsize=1)
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

    def request(self, method, params):
        rid = self._next_id()
        if not self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}):
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
            time.sleep(0.05)
        return None

    def notify(self, method, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def open(self):
        resp = self.request("initialize", {"protocolVersion": PROTO_VERSION, "capabilities": {},
                                           "clientInfo": {"name": "cxg", "version": "1.0"}})
        if not isinstance(resp, dict) or "result" not in resp:
            return None
        self.notify("notifications/initialized")
        return resp.get("result") or {}

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
            time.sleep(0.5)
            if self.proc.poll() is None:
                self.proc.kill()


def list_tools(session):
    resp = session.request("tools/list", {})
    if not isinstance(resp, dict):
        return None
    tools = ((resp.get("result") or {}).get("tools"))
    if not isinstance(tools, list):
        return None
    return [t for t in tools if isinstance(t, dict)]


def candidates(tools):
    out = []
    for t in tools:
        narrow, reason = declared_scope(t)
        if narrow:
            out.append({"tool": t, "name": t.get("name"), "reason": reason,
                        "path_param": path_param(t)})
    return out


# ---------------------------------------------------------------------------
# Witness B - the protocol witness. Works over either transport.
# ---------------------------------------------------------------------------

def protocol_witness(session, cands, nonce, timeout_note=""):
    """For each read-only candidate that takes a path, read a nonce path twice
    with identical arguments. absent -> present is a write the tool performed.

    A separate nonce path read ONCE is the negative control: if a tool reports
    a path it has never been asked about as 'present', its answers carry no
    information and it is excluded rather than confirmed."""
    observations = []
    for cand in cands:
        pkey = cand["path_param"]
        if not pkey:
            observations.append({"tool": cand["name"], "usable": False,
                                 "why": "no path-like parameter to observe"})
            continue
        tool = cand["tool"]

        control_path = "%s-%s-control.txt" % (PROBE_PREFIX, uuid.uuid4().hex[:10])
        c_resp = session.request("tools/call", {"name": cand["name"],
                                                "arguments": synth_args(tool, control_path)})
        c_outcome, c_text = read_outcome(c_resp)
        if c_outcome != "absent":
            observations.append({"tool": cand["name"], "usable": False,
                                 "why": "negative control on a never-seen path answered '%s', so a "
                                        "'present' answer proves nothing" % c_outcome,
                                 "control_excerpt": c_text[:200]})
            continue

        probe_path = "%s-%s.txt" % (PROBE_PREFIX, nonce)
        r1 = session.request("tools/call", {"name": cand["name"],
                                            "arguments": synth_args(tool, probe_path)})
        o1, t1 = read_outcome(r1)
        r2 = session.request("tools/call", {"name": cand["name"],
                                            "arguments": synth_args(tool, probe_path)})
        o2, t2 = read_outcome(r2)
        observations.append({
            "tool": cand["name"], "usable": True, "declared": cand["reason"],
            "probe_path": probe_path,
            "negative_control": {"path": control_path, "outcome": c_outcome},
            "read_1": o1, "read_2": o2,
            "flip": o1 == "absent" and o2 == "present",
            "read_2_excerpt": t2[:400],
            "read_1_excerpt": t1[:200],
            "note": timeout_note,
        })
    return observations


# ---------------------------------------------------------------------------
# Witness A - the filesystem witness. stdio targets only.
# ---------------------------------------------------------------------------

def build_lab(base):
    """An identical world for the control run and the subject run."""
    workdir = base / "workdir"
    (workdir / "notes").mkdir(parents=True, exist_ok=True)
    (workdir / "notes" / "welcome.txt").write_text(PLANTED_NOTE_BODY, encoding="utf-8")
    (base / "home").mkdir(parents=True, exist_ok=True)
    (base / "tmp").mkdir(parents=True, exist_ok=True)
    return workdir


def snapshot(base):
    out = {}
    for dirpath, _dirnames, filenames in os.walk(str(base)):
        for name in filenames:
            p = Path(dirpath) / name
            try:
                rel = p.relative_to(base).as_posix()
            except ValueError:
                continue
            try:
                out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                out[rel] = "unreadable"
    return out


def delta(before, after):
    changes = {}
    for rel, digest in after.items():
        if rel not in before:
            changes[rel] = "created"
        elif before[rel] != digest:
            changes[rel] = "modified"
    return changes


def lab_env(base):
    env = dict(os.environ)
    env["HOME"] = str(base / "home")
    env["TMPDIR"] = str(base / "tmp")
    env["XDG_CONFIG_HOME"] = str(base / "home" / ".config")
    env["XDG_CACHE_HOME"] = str(base / "home" / ".cache")
    return env


def stdio_run(argv, base, make_calls, nonce, timeout):
    """One lab, one server lifetime. Returns the observations of that run."""
    workdir = build_lab(base)
    before = snapshot(base)
    try:
        session = StdioSession(argv, cwd=str(workdir), env=lab_env(base), timeout=timeout)
    except Exception as exc:
        return {"spawn_error": str(exc)}
    info = session.open()
    if info is None:
        tail = session.stderr_tail
        session.close()
        return {"spawn_error": "server did not answer initialize", "stderr": tail}
    tools = list_tools(session) or []
    cands = candidates(tools)
    out = {"serverInfo": (info or {}).get("serverInfo") or {}, "tools": tools,
           "candidates": [{"name": c["name"], "reason": c["reason"], "path_param": c["path_param"]}
                          for c in cands],
           "calls": [], "protocol_observations": [], "endpoint": session.endpoint()}
    if make_calls and cands:
        # Ask each read-only tool to do exactly its declared job, on a note we
        # planted ourselves. Relative first (a server rooted at its cwd), then
        # absolute (a server that wants a full path).
        for arg_path in (PLANTED_NOTE_NAME, str(workdir / "notes" / "welcome.txt")):
            for cand in cands:
                resp = session.request("tools/call", {"name": cand["name"],
                                                      "arguments": synth_args(cand["tool"], arg_path)})
                outcome, text = read_outcome(resp)
                out["calls"].append({"tool": cand["name"], "argument": arg_path,
                                     "outcome": outcome, "excerpt": text[:200]})
        out["protocol_observations"] = protocol_witness(session, cands, nonce)
    session.close()
    time.sleep(0.4)
    after = snapshot(base)
    out["delta"] = delta(before, after)

    # The witness proves itself: a write the template makes must show up.
    probe = base / (".%s-witness-selftest" % PROBE_PREFIX)
    probe.write_text("selftest\n", encoding="utf-8")
    out["witness_live"] = bool(delta(after, snapshot(base)))
    try:
        probe.unlink()
    except OSError:
        pass
    return out


# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------

def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def make_finding(target, title_detail, description, evidence, matched):
    return {
        "target": target,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": description,
        "evidence": {
            "request": title_detail,
            "response": json.dumps(evidence)[:1400],
            "matched_patterns": matched,
            "data": evidence,
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Scans.
# ---------------------------------------------------------------------------

def scan_http(host, port, scheme="http", timeout=12):
    base = "%s://%s:%d" % (scheme, host, port)
    session = HttpSession(base, timeout)
    info = session.open()
    if info is None:
        return "skipped", "no-mcp-server-answered(%s)" % base, []
    endpoint = session.endpoint()
    tools = list_tools(session)
    if tools is None:
        return "skipped", "server-answered-initialize-but-not-tools/list endpoint=%s" % endpoint, []
    if not tools:
        return "skipped", "server-exposes-no-tools endpoint=%s" % endpoint, []
    cands = candidates(tools)
    if not cands:
        return ("skipped",
                "no-tool-declares-a-narrow-scope(%d tool(s), none read-only; an over-broad "
                "DECLARATION is mcp-excessive-tool-permissions' finding) endpoint=%s"
                % (len(tools), endpoint), [])

    nonce = uuid.uuid4().hex[:12]
    obs = protocol_witness(session, cands, nonce)
    usable = [o for o in obs if o.get("usable")]
    if not usable:
        why = "; ".join("%s: %s" % (o.get("tool"), o.get("why")) for o in obs)[:300]
        return ("skipped",
                "protocol-witness-unusable(%s) endpoint=%s candidates=%s"
                % (why, endpoint, ",".join(str(c["name"]) for c in cands)), [])

    flipped = [o for o in usable if o.get("flip")]
    surface = ("transport=streamable-http endpoint=%s tools=%d read_only_candidates=%s witness=protocol"
               % (endpoint, len(tools), ",".join(str(c["name"]) for c in cands)))
    if not flipped:
        return ("refuted",
                "read-only-tools-stayed-in-scope(%s; negative-control-absent so the witness "
                "distinguishes present from absent) | %s"
                % (", ".join("%s:%s->%s" % (o["tool"], o["read_1"], o["read_2"]) for o in usable),
                   surface), [])

    names = ", ".join(str(o["tool"]) for o in flipped)
    evidence = {"witness": "protocol", "endpoint": endpoint,
                "server_name": (info.get("serverInfo") or {}).get("name"),
                "observations": flipped,
                "declared_read_only": [{"name": c["name"], "basis": c["reason"]} for c in cands]}
    description = (
        "MCP tool(s) [%s] at %s declare a read-only scope (%s) and performed a WRITE. Each tool was "
        "asked to read a nonce path that could not already exist; the first read reported the path "
        "absent and an identical second read reported it present, so the read created it. A "
        "never-repeated nonce path read once as a negative control stayed absent, so the server is "
        "not simply answering 'present' to everything. MCP tool annotations are hints a client cannot "
        "verify; here the hint is false, and an agent that trusted it granted this tool write access "
        "to its host by believing a declaration."
        % (names, endpoint,
           "; ".join("%s: %s" % (o["tool"], next((c["reason"] for c in cands if c["name"] == o["tool"]), "?"))
                     for o in flipped)))
    finding = make_finding(endpoint,
                           "initialize -> tools/list -> tools/call x3 per tool (negative control, read, re-read)",
                           description, evidence,
                           ["declared-read-only", "nonce-path-absent-then-present", "write-by-read-only-tool"])
    detail = "out-of-scope-write-proven(tools=%s, witness=protocol) | %s" % (names, surface)
    return "confirmed", detail, [finding]


def scan_stdio(argv, timeout=15):
    lab = Path(tempfile.mkdtemp(prefix="cxg-mcp-scope-"))
    try:
        nonce = uuid.uuid4().hex[:12]
        control = stdio_run(argv, lab / "control", make_calls=False, nonce=nonce, timeout=timeout)
        if control.get("spawn_error"):
            return ("errored",
                    "could-not-run-stdio-mcp-server(%s) argv=%s%s"
                    % (control["spawn_error"], " ".join(argv),
                       " stderr=%s" % ";".join(control.get("stderr") or [])[:200]
                       if control.get("stderr") else ""), [])
        subject = stdio_run(argv, lab / "subject", make_calls=True, nonce=nonce, timeout=timeout)
        if subject.get("spawn_error"):
            return "errored", "could-not-run-stdio-mcp-server(%s)" % subject["spawn_error"], []

        endpoint = subject.get("endpoint") or ("stdio://" + " ".join(argv))
        tools = subject.get("tools") or []
        if not tools:
            return "skipped", "server-exposes-no-tools target=%s" % endpoint, []
        cands = subject.get("candidates") or []
        if not cands:
            return ("skipped",
                    "no-tool-declares-a-narrow-scope(%d tool(s), none read-only; an over-broad "
                    "DECLARATION is mcp-excessive-tool-permissions' finding) target=%s"
                    % (len(tools), endpoint), [])
        if not subject.get("witness_live"):
            return ("errored",
                    "filesystem-witness-could-not-see-its-own-write(lab=%s) - a clean verdict here "
                    "would be unbacked" % lab, [])

        # Attribution: subtract everything the control run produced without
        # calling a single tool.
        control_delta = control.get("delta") or {}
        subject_delta = subject.get("delta") or {}
        attributable = {rel: how for rel, how in subject_delta.items() if rel not in control_delta}

        protocol_obs = subject.get("protocol_observations") or []
        flipped = [o for o in protocol_obs if o.get("flip")]

        surface = ("transport=stdio target=%s tools=%d read_only_candidates=%s witness=filesystem+protocol "
                   "control_writes=%d" % (endpoint, len(tools),
                                          ",".join(str(c["name"]) for c in cands), len(control_delta)))

        if not attributable and not flipped:
            return ("refuted",
                    "read-only-tools-stayed-in-scope(%d call(s) made, 0 attributable writes, "
                    "filesystem-witness-selftest=live) | %s"
                    % (len(subject.get("calls") or []), surface), [])

        # Excerpt of what was actually written, so the finding carries the artefact.
        excerpts = {}
        for rel in list(attributable)[:5]:
            try:
                raw = (lab / "subject" / rel).read_bytes()[:300]
                excerpts[rel] = raw.decode("utf-8", "replace")
            except OSError:
                excerpts[rel] = "<unreadable>"

        names = sorted({str(c["name"]) for c in cands})
        evidence = {
            "witness": "filesystem+protocol",
            "target": endpoint,
            "server_name": (subject.get("serverInfo") or {}).get("name"),
            "declared_read_only": cands,
            "calls_made": subject.get("calls"),
            "paths_written_by_the_call_run": attributable,
            "paths_written_by_the_control_run_and_therefore_ignored": control_delta,
            "written_content_excerpts": excerpts,
            "protocol_observations": flipped,
            "witness_selftest": "live",
        }
        parts = []
        if attributable:
            parts.append("wrote %d path(s) inside a hermetic lab that the control run - an identical "
                         "session that made no tools/call - did not touch: %s"
                         % (len(attributable), ", ".join(sorted(attributable))))
        if flipped:
            parts.append("made a nonce path exist: %s reported it absent, then reported it present on "
                         "an identical re-read"
                         % ", ".join(str(o["tool"]) for o in flipped))
        pinned = (" The nonce re-read pins the write to %s specifically; the filesystem witness "
                  "attributes writes to the call run as a whole, and every call in that run was to a "
                  "tool that declared itself read-only."
                  % ", ".join(str(o["tool"]) for o in flipped)) if flipped else (
                  " The filesystem witness attributes writes to the call run as a whole; every call in "
                  "that run was to a tool that declared itself read-only.")
        description = (
            "Local MCP server %s was driven in a hermetic lab. The only tools called were [%s], each "
            "declaring a read-only scope (%s), each asked to do exactly its declared job on a note this "
            "template planted for it. The run %s.%s The filesystem witness proved itself live on the "
            "same lab, so the observation is a write that happened, not a snapshot that worked. MCP tool "
            "annotations are hints a client cannot verify; an agent that trusted these granted the "
            "server write access to its host by believing a declaration."
            % (endpoint, ", ".join(names),
               "; ".join("%s: %s" % (c["name"], c["reason"]) for c in cands),
               " and ".join(parts), pinned))
        finding = make_finding(endpoint,
                               "hermetic lab: snapshot -> spawn -> initialize/tools/list -> tools/call "
                               "(read-only tools only) -> shutdown -> snapshot, minus an identical "
                               "control run that made no tools/call",
                               description, evidence,
                               ["declared-read-only", "write-attributable-to-tool-call",
                                "control-run-subtracted", "witness-selftest-live"])
        detail = ("out-of-scope-write-proven(paths=%s%s) | %s"
                  % (",".join(sorted(attributable)) or "none",
                     "; nonce-flip=%s" % ",".join(str(o["tool"]) for o in flipped) if flipped else "",
                     surface))
        return "confirmed", detail, [finding]
    finally:
        shutil.rmtree(str(lab), ignore_errors=True)


# ---------------------------------------------------------------------------
# Target resolution. A cli target arrives as the raw scope string with the
# cli:// prefix still on it, and CERT_X_GEN_TARGET_KIND is often unset, so the
# kind is derived from the string itself.
# ---------------------------------------------------------------------------

def stdio_argv(binary):
    extra = os.getenv("CXG_MCP_STDIO_ARGS", "")
    argv = [binary] + (shlex.split(extra) if extra else [])
    if not os.access(binary, os.X_OK) and binary.endswith(".py"):
        argv = [sys.executable] + argv
    return argv


def resolve_target():
    """Returns ('http', host, port, scheme) or ('stdio', argv) or ('error', why)."""
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
        return ("error", "Usage: mcp-excessive-scope-proof.py <host> [port] [scheme]  |  "
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
        "[!] mcp-excessive-scope-proof is an ACTIVE check: it INVOKES MCP tools - only those the "
        "server itself declared read-only - with benign synthetic arguments, to observe whether a "
        "declared read-only tool writes. Make sure you are authorized to test this system.\n")
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

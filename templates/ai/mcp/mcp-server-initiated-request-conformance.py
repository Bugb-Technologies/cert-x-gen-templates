#!/usr/bin/env python3
# @id: mcp-server-initiated-request-conformance
# @name: MCP Server-Initiated Request Conformance (Unsolicited Sampling / Elicitation While Idle)
# @author: Bugb Research
# @severity: high
# @description: PROPERTY check. Completes the MCP handshake as a client that declares the sampling, elicitation and roots capabilities, then goes deliberately idle and sends nothing. Any `sampling/createMessage` or `elicitation/create` REQUEST that arrives on the server->client channel while no client request is outstanding is out of turn - the protocol scopes both to the handling of a client request. Unsolicited sampling spends the client's model budget on the server's own initiative; unsolicited elicitation puts text in front of the user that the user has no reason to attribute to the server. Permitted server-initiated traffic (ping, roots/list, notifications) is recorded and never fires.
# @tags: mcp, ai, agent, protocol-conformance, sampling, elicitation, server-initiated, unsolicited, model-budget, ui-spoofing, behavioural, passive, http, cli, cwe-451, cwe-770
# @cwe: CWE-451, CWE-770
# @cvss: 7.4
# @target_kinds: http, cli
# @oracles: property
# @references: https://modelcontextprotocol.io/specification/2025-06-18/client/sampling, https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation, https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle, https://modelcontextprotocol.io/specification/2025-06-18/basic/transports, https://cwe.mitre.org/data/definitions/451.html, https://cwe.mitre.org/data/definitions/770.html
# @confidence: 95
# @version: 1.0.0
"""
PROPERTY check - does the server speak when it has not been spoken to?

THE RULE

MCP lets a server reach back through the client for two things a server cannot
do for itself:

  * `sampling/createMessage` - ask the client to run a model completion, on the
    client's model and the client's budget;
  * `elicitation/create`     - ask the client to put a prompt in front of the
    human and return what they type.

Both are scoped to the handling of a client request. They exist so that a tool
the client CALLED can, mid-execution, ask for a completion or for a missing
argument. A server that issues one while nothing is outstanding is outside that
scope, and the consequence is not theoretical:

  * an unsolicited `sampling/createMessage` is a server spending the operator's
    model budget, and steering the operator's model, on its own initiative and
    with no user action to attribute it to;
  * an unsolicited `elicitation/create` is a server putting arbitrary text -
    "your session needs re-authorising, enter your access code" - inside the
    user's trusted client, at a moment the user did nothing to cause. The client
    renders it; the user has no request in flight to attribute it to. That is a
    phishing surface handed out by the protocol layer.

WHAT "IDLE" MEANS HERE, AND WHY IT IS A PROTOCOL STATE, NOT A CLOCK

Idle is: the handshake is complete (`initialize` answered, `notifications/
initialized` sent) and NO client-originated request is outstanding. The probe
enters that state on purpose and does not leave it. The liveness control that
proves the channel was actually live is issued only AFTER the window closes, so
it can never be the cause of anything observed inside it.

The probe declares `sampling`, `elicitation` and `roots` in its client
capabilities. That is deliberate: it removes the excuse. Silence from a server
facing a client that says "I can handle all three" is a CHOICE not to speak out
of turn, not an inability to.

WHY THE WINDOW IS LONG ENOUGH

A legitimate sampling or elicitation request is CAUSALLY downstream of a client
request - it exists because a tool the client called needs a completion or an
argument. During the window the probe issues nothing, so there is no legitimate
cause for one to exist. That asymmetry is the whole safety argument:

    lengthening the window can only admit more UNSOLICITED traffic.
    It can never admit legitimate traffic, because legitimate traffic
    has no cause. The window bounds COMPLETENESS, never SOUNDNESS.

So a short window cannot manufacture a false CONFIRMED - only a missed one. And
"slow but legitimate" is not a competing explanation: slow describes how long a
server takes to ANSWER, and the probe asks nothing. What a longer window buys is
the server whose unprompted prompt fires on a long timer - a first-run
onboarding nag, an hourly re-auth pester. `CXG_MCP_IDLE_WINDOW_SECONDS` exists
for that, and every REFUTED verdict states the window it held, so a clean result
reads as "silent for N seconds", never as "silent forever".

THE ORACLE IS BINARY, AND NARROW

  CONFIRMED  a JSON-RPC REQUEST (a `method` with a non-null `id`) whose method
             is `sampling/createMessage` or `elicitation/create` arrived on the
             server->client channel during the idle window.
  REFUTED    the window elapsed with neither, on a channel proved live.

Everything else a server may legitimately initiate is recorded as a soft
observation and NEVER fires:

  * `ping` and `roots/list` - server-initiable requests the protocol permits at
    any time;
  * any `notifications/*` - log messages, `tools/list_changed`, progress. A
    notification carries no `id`; it is not a request and cannot be answered,
    so it is not this finding however chatty it is;
  * a response to something the probe sent during the handshake.

A server that is loud in permitted ways still refutes, and the refutation names
what it heard - so REFUTED reads as "listened, heard only permitted traffic",
not as "heard nothing".

VERDICT CONTRACT

  confirmed  at least one gated method observed while idle. The finding carries
             every message seen, each with the seconds elapsed since the idle
             window opened, the method, the JSON-RPC id, and an excerpt of the
             params - the elicitation prompt text the user would have been
             shown, or the sampling messages and maxTokens that would have been
             spent.
  refuted    the window closed with no gated method, AND the channel was proved
             live afterwards. The detail names the window held and every
             permitted message that did arrive.
  skipped    a named missing precondition: no MCP server answered `initialize`;
             the transport offers no server->client channel at all (an HTTP
             server that refuses the standalone SSE stream cannot issue a
             request, so its silence says nothing about the server); or the
             channel could not be proved live after the window, so silence is
             not evidence.
  errored    the target could not be reached or spawned at all.

SAFETY

Passive. The probe never calls a tool, never invokes anything, and sends no data
of its own beyond the handshake and one `tools/list` liveness control after the
window. It NEVER fulfils a request it observes: an unsolicited sampling request
is answered with a JSON-RPC error and no model is ever contacted, and an
unsolicited elicitation is answered with a decline and no human is ever
prompted. Against fixtures/mcp-server-initiated-request-conformance it is safe
anywhere; get authorisation before pointing it at a system you do not own.
"""

import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

METADATA = {
    "id": "mcp-server-initiated-request-conformance",
    "name": ("MCP Server-Initiated Request Conformance "
             "(Unsolicited Sampling / Elicitation While Idle)"),
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "PROPERTY check: completes the MCP handshake as a client declaring the sampling, "
        "elicitation and roots capabilities, then goes deliberately idle. A "
        "`sampling/createMessage` or `elicitation/create` request arriving on the server->client "
        "channel while no client request is outstanding is out of turn - the protocol scopes both "
        "to the handling of a client request. Permitted server-initiated traffic (ping, roots/list, "
        "notifications) is recorded and never fires."
    ),
    "tags": ["mcp", "ai", "agent", "protocol-conformance", "sampling", "elicitation",
             "server-initiated", "unsolicited", "model-budget", "ui-spoofing", "behavioural",
             "passive", "http", "cli", "cwe-451", "cwe-770"],
    "language": "python",
    "confidence": 95,
    "cwe": ["CWE-451", "CWE-770"],
    "references": [
        "https://modelcontextprotocol.io/specification/2025-06-18/client/sampling",
        "https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation",
        "https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle",
        "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports",
        "https://cwe.mitre.org/data/definitions/451.html",
        "https://cwe.mitre.org/data/definitions/770.html",
    ],
}

PROTO_VERSION = "2025-06-18"
MCP_PATHS = ["/mcp", "/", "/rpc"]

# The two methods the protocol gates behind an in-flight client request.
GATED_METHODS = ("sampling/createMessage", "elicitation/create")
# Requests a server may legitimately initiate at any time. Recorded, never fired on.
PERMITTED_REQUESTS = ("ping", "roots/list")

# The probe presents itself as a client that CAN handle all three, so that
# silence is a choice and not an inability.
CLIENT_CAPABILITIES = {
    "sampling": {},
    "elicitation": {},
    "roots": {"listChanged": True},
}

DEFAULT_WINDOW = 10.0
MAX_WINDOW = 300.0


def idle_window():
    raw = os.getenv("CXG_MCP_IDLE_WINDOW_SECONDS", "")
    try:
        value = float(raw) if raw.strip() else DEFAULT_WINDOW
    except (ValueError, AttributeError):
        return DEFAULT_WINDOW
    if value <= 0:
        return DEFAULT_WINDOW
    return min(value, MAX_WINDOW)


# ---------------------------------------------------------------------------
# Classification. One function, both transports.
# ---------------------------------------------------------------------------

def classify(msg):
    """Map one server->client message onto the oracle.

    'gated'      a REQUEST for one of the two methods the protocol scopes to
                 the handling of a client request. This is the finding.
    'permitted'  a request the server may initiate at any time (ping, roots/list).
    'notification' a message with no id - not a request, cannot be answered.
    'response'   a reply to something the probe sent.
    'other'      a request for some other method: unusual, but not this finding.
    """
    method = msg.get("method")
    has_id = msg.get("id") is not None
    if method is None:
        return "response"
    if not has_id:
        return "notification"
    if method in GATED_METHODS:
        return "gated"
    if method in PERMITTED_REQUESTS:
        return "permitted"
    return "other"


def summarise(msg):
    """A compact, evidence-bearing record of one observed message."""
    method = msg.get("method")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    record = {"method": method, "id": msg.get("id"), "kind": classify(msg)}
    if method == "elicitation/create":
        # The text the user would have been shown, with no request of their own
        # to attribute it to. This IS the finding, quoted.
        record["prompt_shown_to_user"] = str(params.get("message", ""))[:400]
        schema = params.get("requestedSchema")
        if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
            record["fields_requested"] = sorted(schema["properties"].keys())[:20]
    elif method == "sampling/createMessage":
        # The budget the server tried to spend, and what it tried to spend it on.
        record["max_tokens"] = params.get("maxTokens")
        texts = []
        for entry in (params.get("messages") or [])[:4]:
            if isinstance(entry, dict) and isinstance(entry.get("content"), dict):
                texts.append(str(entry["content"].get("text", ""))[:200])
        record["messages_excerpt"] = texts
        if params.get("systemPrompt"):
            record["system_prompt_excerpt"] = str(params["systemPrompt"])[:200]
    elif method and method.startswith("notifications/"):
        record["params_excerpt"] = json.dumps(params)[:200]
    return record


def decline(msg):
    """The JSON-RPC response the probe sends back. It NEVER fulfils anything.

    A sampling request gets an error, so no model is contacted. An elicitation
    gets an explicit decline, so no human is prompted. `ping` and `roots/list`
    get correct, empty, honest answers so a conformant server is not left
    hanging by the probe's own rudeness.
    """
    rid = msg.get("id")
    method = msg.get("method")
    if rid is None:
        return None
    if method == "elicitation/create":
        return {"jsonrpc": "2.0", "id": rid, "result": {"action": "decline"}}
    if method == "sampling/createMessage":
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32001,
                          "message": "cxg probe does not fulfil sampling requests"}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "roots/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"roots": []}}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "method not handled by the cxg probe"}}


# ---------------------------------------------------------------------------
# HTTP transport.
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


class SseStream(object):
    """The standalone server->client stream, read on a thread while we sit idle."""

    def __init__(self, resp, respond):
        self.resp = resp
        self.respond = respond
        self.messages = []          # [(elapsed_s, msg)]
        self.read_error = None
        self.t0 = time.time()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._read, daemon=True)

    def start(self):
        self.t0 = time.time()
        self._thread.start()

    def _read(self):
        buf = []
        try:
            for raw in self.resp:
                line = raw.decode("utf-8", "ignore").rstrip("\r\n")
                if line.startswith("data:"):
                    buf.append(line[5:].lstrip())
                    continue
                if line == "":
                    if buf:
                        self._ingest("\n".join(buf))
                        buf = []
                    continue
                # ':' comment (keep-alive) or another SSE field: not a payload.
        except Exception as exc:
            self.read_error = str(exc)[:200]

    def _ingest(self, payload):
        try:
            obj = json.loads(payload)
        except ValueError:
            return
        for msg in (obj if isinstance(obj, list) else [obj]):
            if not isinstance(msg, dict):
                continue
            with self._lock:
                self.messages.append((round(time.time() - self.t0, 3), msg))
            try:
                self.respond(msg)
            except Exception:
                pass

    def observed(self):
        with self._lock:
            return list(self.messages)

    def close(self):
        try:
            self.resp.close()
        except Exception:
            pass
        self._thread.join(timeout=1.0)


class HttpMcp(object):
    """Minimal streamable-HTTP MCP client. Handshake, one standalone stream, one list."""

    def __init__(self, base, timeout=12):
        self.base = base
        self.timeout = timeout
        self.path = None
        self.session_id = None
        self._id = 0
        self._lock = threading.Lock()

    def _next_id(self):
        with self._lock:
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
                   "params": {"protocolVersion": PROTO_VERSION,
                              "capabilities": CLIENT_CAPABILITIES,
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
            self._post(self.base + path,
                       {"jsonrpc": "2.0", "method": "notifications/initialized"})
            return obj.get("result") or {}
        return None

    def respond(self, msg):
        """Post a JSON-RPC response to a server-initiated request back up the wire."""
        reply = decline(msg)
        if reply is None or self.path is None:
            return
        self._post(self.base + self.path, reply)

    def open_server_stream(self, window):
        """GET the standalone SSE stream. Returns (SseStream, None) or (None, why)."""
        url = self.base + self.path
        headers = {"Accept": "text/event-stream", "Cache-Control": "no-cache"}
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            resp = urllib.request.urlopen(req, timeout=window + 10, context=_ctx())
        except urllib.error.HTTPError as e:
            return None, ("transport-offers-no-server-initiated-channel(GET %s -> %s)"
                          % (url, e.code))
        except Exception as exc:
            return None, ("server-initiated-channel-unreachable(GET %s: %s)"
                          % (url, str(exc)[:120]))
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "text/event-stream" not in ctype:
            try:
                resp.close()
            except Exception:
                pass
            return None, ("transport-offers-no-server-initiated-channel(GET %s -> %s, "
                          "content-type=%s)" % (url, resp.status, ctype or "<none>"))
        return SseStream(resp, self.respond), None

    def liveness(self):
        """One tools/list, issued only AFTER the idle window has closed."""
        status, _headers, body = self._post(
            self.base + self.path,
            {"jsonrpc": "2.0", "id": self._next_id(), "method": "tools/list", "params": {}})
        obj = _extract_json(body)
        if status == 200 and isinstance(obj, dict) and "result" in obj:
            tools = (obj["result"] or {}).get("tools") or []
            return True, "tools/list answered with %d tool(s)" % len(tools)
        return False, "tools/list did not answer (status=%s)" % status

    def endpoint(self):
        return self.base + (self.path or "")


# ---------------------------------------------------------------------------
# stdio transport. stdout IS the server->client channel; there is no
# equivalent of "the transport offers no channel".
# ---------------------------------------------------------------------------

class StdioMcp(object):
    def __init__(self, argv, timeout=12):
        self.argv = argv
        self.timeout = timeout
        self.proc = None
        self.spawn_error = None
        self.messages = []          # [(elapsed_s, msg)]
        self.stderr_tail = []
        self._responses = {}
        self._lock = threading.Lock()
        self._id = 0
        self.t0 = time.time()
        self._recording = False

    def _next_id(self):
        with self._lock:
            self._id += 1
            return self._id

    def _send(self, payload):
        try:
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
            return True
        except Exception:
            return False

    def _read_stdout(self):
        try:
            for line in self.proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(msg, dict):
                    continue
                if msg.get("method") is None and msg.get("id") is not None:
                    with self._lock:
                        self._responses[msg["id"]] = msg
                    continue
                if self._recording:
                    with self._lock:
                        self.messages.append((round(time.time() - self.t0, 3), msg))
                    try:
                        reply = decline(msg)
                        if reply is not None:
                            self._send(reply)
                    except Exception:
                        pass
        except Exception:
            pass

    def _read_stderr(self):
        try:
            for line in self.proc.stderr:
                if len(self.stderr_tail) < 20:
                    self.stderr_tail.append(line.rstrip("\n")[:200])
        except Exception:
            pass

    def spawn(self):
        try:
            self.proc = subprocess.Popen(
                self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, universal_newlines=True, bufsize=1)
        except Exception as exc:
            self.spawn_error = str(exc)[:200]
            return False
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        return True

    def request(self, method, params=None):
        rid = self._next_id()
        if not self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                           "params": params if params is not None else {}}):
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

    def open(self):
        resp = self.request("initialize", {"protocolVersion": PROTO_VERSION,
                                           "capabilities": CLIENT_CAPABILITIES,
                                           "clientInfo": {"name": "cxg", "version": "1.0"}})
        if not isinstance(resp, dict) or "result" not in resp:
            return None
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp.get("result") or {}

    def start_recording(self):
        self.t0 = time.time()
        self._recording = True

    def stop_recording(self):
        self._recording = False

    def observed(self):
        with self._lock:
            return list(self.messages)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def liveness(self):
        resp = self.request("tools/list")
        if isinstance(resp, dict) and "result" in resp:
            tools = (resp["result"] or {}).get("tools") or []
            return True, "tools/list answered with %d tool(s)" % len(tools)
        return False, "tools/list did not answer"

    def endpoint(self):
        return "stdio://" + " ".join(self.argv)

    def close(self):
        if self.proc is None:
            return
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        deadline = time.time() + 3
        while time.time() < deadline and self.proc.poll() is None:
            time.sleep(0.1)
        if self.proc.poll() is None:
            self.proc.terminate()
            time.sleep(0.4)
            if self.proc.poll() is None:
                self.proc.kill()


# ---------------------------------------------------------------------------
# The verdict. One function, both transports - the oracle does not care how
# the bytes arrived.
# ---------------------------------------------------------------------------

def verdict(endpoint, transport, window, observed, live, live_detail, server_info):
    """observed: [(elapsed_s, msg)] captured during the idle window."""
    records = []
    for elapsed, msg in observed:
        record = summarise(msg)
        record["elapsed_s"] = elapsed
        records.append(record)

    gated = [r for r in records if r["kind"] == "gated"]
    soft = [r for r in records if r["kind"] != "gated"]
    soft_summary = ", ".join(
        "%s@%ss" % (r.get("method") or "<response>", r["elapsed_s"]) for r in soft) or "none"

    if not gated:
        if not live:
            return ("skipped",
                    "channel-not-proved-live-after-the-window(%s) - silence on a channel that "
                    "may have been dead is not evidence | transport=%s window=%.1fs "
                    "permitted_traffic=[%s]" % (live_detail, transport, window, soft_summary),
                    [])
        return ("refuted",
                "no-unsolicited-sampling-or-elicitation(idle %.1fs, channel live: %s) | "
                "transport=%s permitted server-initiated traffic observed and ignored: [%s]"
                % (window, live_detail, transport, soft_summary), [])

    methods = sorted({r["method"] for r in gated})
    first = min(r["elapsed_s"] for r in gated)
    prompts = [r.get("prompt_shown_to_user") for r in gated
               if r.get("prompt_shown_to_user")]
    budget = [r.get("max_tokens") for r in gated if r.get("max_tokens") is not None]

    consequence = []
    if "elicitation/create" in methods:
        consequence.append(
            "It prompted the user directly - the client would have rendered %r with no "
            "request of the user's own to attribute it to." % (prompts[0][:160] if prompts else ""))
    if "sampling/createMessage" in methods:
        consequence.append(
            "It asked the client to run a model completion on the client's budget "
            "(maxTokens=%s), unprompted." % (budget[0] if budget else "unstated"))

    finding = {
        "target": endpoint,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (
            "The MCP server at %s issued %d server-initiated request(s) for %s while the client "
            "was idle - the handshake was complete, no client request was outstanding, and the "
            "probe sent nothing for %.1f seconds. The first arrived %.3fs into the idle window. "
            "The protocol scopes both methods to the handling of a client request; issued out of "
            "turn they are a conformance violation with a direct consequence. %s The same session "
            "also carried %d permitted server-initiated message(s) (%s), which this check records "
            "and does not fire on - so the finding is the two gated methods specifically, not "
            "chattiness."
            % (endpoint, len(gated), " and ".join(methods), window, first,
               " ".join(consequence), len(soft), soft_summary)),
        "evidence": {
            "request": ("initialize(capabilities: sampling+elicitation+roots) -> "
                        "notifications/initialized -> [send nothing for %.1fs, observing the "
                        "server->client channel] -> tools/list (liveness control, after the "
                        "window)" % window),
            "response": json.dumps({
                "unsolicited_requests": gated,
                "permitted_traffic_ignored": soft,
                "idle_window_seconds": window,
                "channel_proved_live": live_detail,
            })[:1800],
            "matched_patterns": methods,
            "data": {
                "transport": transport,
                "endpoint": endpoint,
                "server_info": server_info,
                "idle_window_seconds": window,
                "client_capabilities_declared": sorted(CLIENT_CAPABILITIES.keys()),
                "unsolicited_requests": gated,
                "unsolicited_methods": methods,
                "first_unsolicited_at_seconds": first,
                "permitted_traffic_ignored": soft,
                "channel_proved_live": live,
                "channel_liveness_detail": live_detail,
                "client_response": ("declined - no model was contacted and no human was "
                                    "prompted"),
            },
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    detail = ("unsolicited-server-initiated-request(%s) first_at=%.3fs idle_window=%.1fs "
              "transport=%s | permitted traffic ignored: [%s]"
              % (",".join(methods), first, window, transport, soft_summary))
    return "confirmed", detail, [finding]


# ---------------------------------------------------------------------------
# Scans.
# ---------------------------------------------------------------------------

def scan_http(host, port, scheme="http"):
    base = "%s://%s:%d" % (scheme, host, port)
    window = idle_window()
    sess = HttpMcp(base)
    init = sess.open()
    if init is None:
        return "skipped", "no-mcp-server-answered-initialize(%s)" % base, []
    server_info = (init or {}).get("serverInfo") or {}

    stream, why = sess.open_server_stream(window)
    if stream is None:
        # An HTTP server with no standalone stream cannot issue a request at
        # all. Its silence is a fact about the transport, not about the server.
        return "skipped", "%s - the server has no channel on which to speak out of turn" % why, []

    stream.start()
    time.sleep(window)
    observed = stream.observed()
    stream.close()

    live, live_detail = sess.liveness()
    return verdict(sess.endpoint(), "http", window, observed, live, live_detail, server_info)


def scan_stdio(argv):
    window = idle_window()
    sess = StdioMcp(argv)
    if not sess.spawn():
        return "errored", "could-not-spawn-stdio-mcp-server(%s)" % sess.spawn_error, []
    try:
        init = sess.open()
        if init is None:
            tail = " | ".join(sess.stderr_tail[:3])
            return ("skipped", "no-mcp-server-answered-initialize(stdio %s)%s"
                    % (" ".join(argv), (" stderr=%s" % tail) if tail else ""), [])
        server_info = (init or {}).get("serverInfo") or {}

        sess.start_recording()
        time.sleep(window)
        sess.stop_recording()
        observed = sess.observed()

        if not sess.alive():
            return ("skipped",
                    "stdio-server-exited-during-the-idle-window - silence from a process that "
                    "died is not evidence (observed %d message(s) before it went)"
                    % len(observed), [])

        live, live_detail = sess.liveness()
        return verdict(sess.endpoint(), "stdio", window, observed, live, live_detail, server_info)
    finally:
        sess.close()


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
        m = re.match(r"^(https?)://([^/:]+)(?::(\d+))?", host)
        port_env = os.getenv("CERT_X_GEN_TARGET_PORT")
        if m:
            scheme = m.group(1)
            host = m.group(2)
            port = int(m.group(3)) if m.group(3) else int(
                port_env or (443 if scheme == "https" else 80))
        else:
            host = host.split("/")[0]
            try:
                port = int(port_env or "8000")
            except ValueError:
                port = 8000
        return ("http", host, port, scheme)

    args = sys.argv[1:]
    if not args:
        return ("error", "Usage: mcp-server-initiated-request-conformance.py <host> [port] "
                         "[scheme]  |  --stdio <command> [args...]  |  cli:///path/to/mcp-server")
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


def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def main():
    sys.stderr.write(
        "[*] mcp-server-initiated-request-conformance is a PASSIVE check: it completes the MCP "
        "handshake, sends nothing for the idle window, and observes whether the server issues a "
        "sampling or elicitation request out of turn. It never fulfils one - no model is "
        "contacted and no human is prompted. It calls no tool.\n")
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

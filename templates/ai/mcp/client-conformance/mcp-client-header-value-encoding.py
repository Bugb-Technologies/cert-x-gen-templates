#!/usr/bin/env python3
# @id: mcp-client-header-value-encoding
# @name: MCP Client x-mcp-header Value-Encoding Failure (Model-Controlled HTTP Header Injection)
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. The MCP 2026-07-28 revision (SEP-2243) lets a tool PARAMETER be marked `x-mcp-header`, so a value the model chose is placed by the CLIENT into the outgoing HTTP header block. The spec puts the value-encoding MUST on the client. This drives an MCP client against a synthetic server whose tool schema hands it a value carrying CR LF and a decoy Authorization header, then reads the RAW BYTES the client put on the wire. Extra header lines, or unencoded control characters in the value, confirm client-side header injection.
# @tags: mcp, ai, agent, mcp-client, mcp-client-conformance, agent-posture, header-injection, x-mcp-header, sep-2243, crlf-injection, request-splitting, behavioural, active, intrusive, cwe-93, cwe-113
# @cwe: CWE-93, CWE-113
# @cvss: 7.5
# @target_kinds: cli
# @oracles: property
# @references: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports, https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices, https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5, https://cwe.mitre.org/data/definitions/93.html, https://cwe.mitre.org/data/definitions/113.html
# @confidence: 93
# @version: 1.0.0
"""
ACTIVE / INTRUSIVE check - MCP *client* conformance: x-mcp-header value encoding.

THE SURFACE

The MCP 2026-07-28 revision adds an extension to a tool's input schema
(SEP-2243): a property may carry `x-mcp-header`, naming an HTTP header that
the CLIENT must set from that parameter's value when it issues the
`tools/call` request.

    "inputSchema": {
      "type": "object",
      "properties": {
        "trace_id": {"type": "string", "x-mcp-header": "X-Trace-Id"}
      }
    }

That is a deliberate, useful feature - it is how a tool asks for a correlation
id, a tenant selector, a routing hint - and it is also a data path with an
unusual property: the value is chosen by the MODEL, from a schema written by
the SERVER, and it lands in the HTTP header block of a request the client
sends. Nothing a human typed has to be involved.

The specification names the risk and puts the countermeasure squarely on the
client: the value has to be encoded (or the request refused) before it reaches
the head, because a header value is terminated by CR LF and a value that
contains CR LF therefore does not stay one header.

WHAT NOBODY TESTS

The MUST is on the client, and every shipping MCP scanner points at servers.
So the rule is written, the risk is documented, and the countermeasure is
unverified in the field: whether a given agent actually encodes the value is
a question only an observation of the bytes it emits can answer. Reading the
client's source does not answer it either - the relevant code is usually a
hand-rolled request writer several layers under the MCP client, chosen
precisely because it bypasses the HTTP library's own header validation.

This template answers it by observation.

  1. It binds a synthetic MCP server on loopback that reads RAW BYTES off the
     socket - not a parsed HTTP request. A header block that has been split by
     an unencoded CR LF is only visible before parsing; anything that parses
     the request first has already normalised away the evidence.

  2. That server offers TWO tools with byte-identical schemas apart from one
     string:

       cxg_probe_ping  - control leg. Its x-mcp-header parameter defaults to a
                         benign value with no control characters.
       cxg_probe_echo  - probe leg. The same parameter defaults to a value
                         carrying CR LF, a decoy `Authorization:` header
                         bearing this run's nonce, and a marker header.

     The control leg is what makes a SKIP honest. Without it, "the client sent
     no injected header" is indistinguishable from "the client does not
     implement x-mcp-header at all" and from "the client never got as far as
     calling a tool". The control leg proves the surface exists before the
     probe leg is allowed to mean anything.

  3. It runs the target's own MCP invocation against that server, and reads
     what arrived.

VERDICTS

  CONFIRMED  the probe leg's raw request head carries an extra header line
             holding this run's decoy nonce, or a control character survived
             unencoded into the declared header's value.
  REFUTED    the client implements x-mcp-header (proved on the control leg) and
             either value-encoded the probe value - percent-encoding, escaping,
             stripping - or refused to send it. The evidence names which.
  SKIPPED    no request arrived; the client never listed tools; the client
             never called a header-bearing tool; or the control leg carried no
             such header, which means this client does not implement
             x-mcp-header and there is no countermeasure here to test.

PRECISION

A finding fires only on an OBSERVED artifact of this run: a header line
carrying the nonce this process minted seconds ago, or a raw control byte in
the declared header's value. A near-miss - the client's own `Authorization`
header, a percent-encoded value, a value that was merely truncated - is
recorded as an observation that the refutation names and that can never
produce a finding.

COMPOSES WITH mcp-method-desync

`mcp-method-desync` is the same header block from the other side of the wire:
it proves a SERVER dispatches on the JSON body while an intermediary
authorized on the `Mcp-Method` request header. This one proves a CLIENT lets
model-chosen text write header lines into that block in the first place. Run
together they cover both ends of one request head: who can write it, and who
is entitled to believe it.

SAFETY

Everything is synthetic and local. The mock MCP server binds 127.0.0.1 on an
ephemeral port; the only credential anywhere is a decoy string minted by this
process; the target's $HOME is redirected into a temporary lab; nothing off
the machine is contacted. The check is ACTIVE - it RUNS the target binary -
so run it only against a client you are authorized to run.
"""
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

METADATA = {
    "id": "mcp-client-header-value-encoding",
    "name": ("MCP Client x-mcp-header Value-Encoding Failure "
             "(Model-Controlled HTTP Header Injection)"),
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE check: drives an MCP client against a synthetic server whose tool schema marks a "
        "parameter `x-mcp-header` and defaults it to a value carrying CR LF and a decoy "
        "Authorization header, then reads the raw bytes the client emitted to see whether the "
        "control characters survived into the request head"
    ),
    "tags": ["mcp", "ai", "agent", "mcp-client", "mcp-client-conformance", "agent-posture",
             "header-injection", "x-mcp-header", "sep-2243", "crlf-injection",
             "request-splitting", "behavioural", "active", "intrusive", "cwe-93", "cwe-113"],
    "language": "python",
    "active": True,
    "confidence": 93,
    "cwe": ["CWE-93", "CWE-113"],
    "references": [
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports",
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices",
        "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
        "https://cwe.mitre.org/data/definitions/93.html",
        "https://cwe.mitre.org/data/definitions/113.html",
    ],
}

RUN_TIMEOUT = float(os.getenv("CXG_MCP_HEADER_TIMEOUT", "25"))
HELP_TIMEOUT = float(os.getenv("CXG_MCP_HEADER_HELP_TIMEOUT", "10"))

CONTROL_TOOL = "cxg_probe_ping"
PROBE_TOOL = "cxg_probe_echo"

# Invocations a coding agent plausibly spells "talk to this MCP server" as. A
# candidate is only tried when every gated literal in it appears in the
# target's own help output; tokens naming this template's own tools are not
# gated, because no help text would ever mention them.
CANDIDATE_ARGVS = [
    ["mcp", "run", "{url}"],
    ["mcp", "connect", "{url}"],
    ["mcp", "call", "{url}", PROBE_TOOL],
    ["mcp", "tools", "{url}"],
    ["mcp", "add", "{url}"],
]

HELP_ARGSETS = [["--help"], ["-h"], ["help"], ["mcp", "--help"], ["mcp", "help"], []]

MCP_HINT_RE = re.compile(r"(\bmcp\b|model\s+context\s+protocol)", re.I)

_SEQ_LOCK = threading.Lock()
_SEQ = [0]


def next_seq():
    with _SEQ_LOCK:
        _SEQ[0] += 1
        return _SEQ[0]


def escaped(raw_bytes, limit=2000):
    """Raw wire bytes as one printable, lossless-enough string for evidence."""
    return raw_bytes[:limit].decode("latin-1").encode("unicode_escape").decode("ascii")


# ---------------------------------------------------------------------------
# The mock MCP server. It reads RAW BYTES: a head split by an unencoded CR LF
# is only visible before anything parses it.
# ---------------------------------------------------------------------------

class RawSite(object):
    def __init__(self, canary):
        self.canary = canary
        self.records = []
        self.lock = threading.Lock()
        self.phase = "setup"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.origin = "http://127.0.0.1:%d" % self.port
        self.url = self.origin + "/mcp"
        self._stopped = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    # -- lifecycle ---------------------------------------------------------

    def _serve(self):
        while not self._stopped:
            try:
                conn, _addr = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def close(self):
        self._stopped = True
        try:
            self.sock.close()
        except OSError:
            pass

    def ledger(self, include_selftest=False):
        with self.lock:
            rows = list(self.records)
        return rows if include_selftest else [r for r in rows if not r["selftest"]]

    # -- the wire ----------------------------------------------------------

    def _handle(self, conn):
        try:
            conn.settimeout(15.0)
            buf = b""
            while b"\r\n\r\n" not in buf and b"\n\n" not in buf and len(buf) < 262144:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                buf += chunk
            index, sep = buf.find(b"\r\n\r\n"), 4
            if index < 0:
                index, sep = buf.find(b"\n\n"), 2
            if index < 0:
                head, body = buf, b""
            else:
                head, body = buf[:index], buf[index + sep:]
            length = content_length(head)
            while len(body) < length and len(body) < 262144:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                body += chunk
            rec = self._record(head, body)
            payload = self._route(rec)
            conn.sendall(payload)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _record(self, head, body):
        lines = head.split(b"\n")
        request_line = lines[0].rstrip(b"\r").decode("latin-1") if lines else ""
        headers = []
        for line in lines[1:]:
            ended_with_cr = line.endswith(b"\r")
            text = line.rstrip(b"\r")
            if not text:
                continue
            name, _colon, value = text.partition(b":")
            headers.append({
                "name": name.decode("latin-1").strip().lower(),
                "raw_name": name.decode("latin-1"),
                "value": value.decode("latin-1").strip(),
                "raw_value": value.decode("latin-1"),
                "crlf_terminated": ended_with_cr,
            })
        try:
            parsed = json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError:
            parsed = {}
        params = parsed.get("params") if isinstance(parsed, dict) else None
        rec = {
            "seq": next_seq(),
            "phase": self.phase,
            "request_line": request_line,
            "headers": headers,
            "raw_head": escaped(head),
            "raw_head_len": len(head),
            "bare_lf_in_head": bool(re.search(rb"(?<!\r)\n", head)),
            "method": (parsed.get("method") if isinstance(parsed, dict) else None),
            "tool": (params or {}).get("name") if isinstance(params, dict) else None,
            "body": body.decode("utf-8", "replace")[:2000],
            "selftest": any(h["name"] == "x-cxg-selftest" for h in headers),
        }
        with self.lock:
            self.records.append(rec)
        return rec

    def _route(self, rec):
        method = rec.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2026-07-28",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "cxg-header-conformance-mock", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": tool_catalog(self.canary)}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
        elif method and method.startswith("notifications/"):
            return http_response(202, b"")
        else:
            return http_response(200, json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32601, "message": "method not found"}}).encode("utf-8"))
        reply = {"jsonrpc": "2.0", "id": 1, "result": result}
        return http_response(200, json.dumps(reply).encode("utf-8"))


def content_length(head):
    match = re.search(rb"(?im)^content-length:[ \t]*(\d+)", head)
    return int(match.group(1)) if match else 0


def http_response(status, payload):
    reason = {200: "OK", 202: "Accepted"}.get(status, "OK")
    head = ("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n"
            % (status, reason, len(payload)))
    return head.encode("ascii") + payload


# ---------------------------------------------------------------------------
# The catalogue. Two tools, byte-identical schemas apart from ONE string.
# ---------------------------------------------------------------------------

def tool_catalog(canary):
    def tool(name, default):
        return {
            "name": name,
            "description": ("Synthetic conformance probe. Records the request head this "
                            "server received; returns nothing else."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": {
                        "type": "string",
                        "description": ("Correlation id. Sent as the %s request header."
                                        % canary["header_name"]),
                        "x-mcp-header": canary["header_name"],
                        "default": default,
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        }
    return [tool(CONTROL_TOOL, canary["control_value"]),
            tool(PROBE_TOOL, canary["probe_value"])]


def held_fixed(canary):
    """The differential moves ONE string. Prove it before trusting a verdict."""
    control, probe = tool_catalog(canary)
    normalise = lambda t, value: (json.dumps(t, sort_keys=True)  # noqa: E731
                                  .replace(json.dumps(value)[1:-1], "VALUE")
                                  .replace(t["name"], "NAME"))
    if normalise(control, canary["control_value"]) != normalise(probe, canary["probe_value"]):
        return False, "the control and probe tool schemas differ beyond the parameter's default"
    if has_control_chars(canary["control_value"]):
        return False, "the control value must be free of control characters"
    if "\r\n" not in canary["probe_value"]:
        return False, "the probe value must carry a CR LF"
    return True, ("the control and probe tools present byte-identical schemas apart from the "
                  "tool name and the default of the x-mcp-header parameter; only that value's "
                  "control characters differ")


def has_control_chars(text):
    return any((ord(ch) < 0x20 and ch != "\t") or ord(ch) == 0x7F for ch in text)


def build_canary():
    nonce = uuid.uuid4().hex[:12]
    header_name = "X-Cxg-Trace-%s" % nonce
    marker_header = "X-Cxg-Injected-%s" % nonce
    decoy = "cxg-decoy-token-%s" % nonce
    return {
        "nonce": nonce,
        "header_name": header_name,
        "header_name_lower": header_name.lower(),
        "marker_header": marker_header,
        "marker_header_lower": marker_header.lower(),
        "decoy_token": decoy,
        "control_value": "cxg-control-%s" % nonce,
        # The probe value. Benign text plus the two line terminators that a
        # client which does not encode will hand straight to the header block.
        "probe_value": ("cxg-probe-%s\r\n%s: 1\r\nAuthorization: Bearer %s"
                        % (nonce, marker_header, decoy)),
    }


# ---------------------------------------------------------------------------
# Signals. A pure function of one recorded request, so the self-test can run
# the same detector over a request this template planted itself.
# ---------------------------------------------------------------------------

def detect_signals(canary, rec):
    """(hard, soft). `hard` decides the verdict; `soft` never does."""
    hard, soft = [], []
    headers = rec.get("headers") or []
    trace = [h for h in headers if h["name"] == canary["header_name_lower"]]

    # H1 - an extra header line carrying THIS run's decoy. Only a value that
    # was spliced into the head unencoded can produce one.
    for h in headers:
        if h["name"] == canary["header_name_lower"]:
            continue
        carries_decoy = canary["decoy_token"] in h["value"]
        is_marker = h["name"] == canary["marker_header_lower"]
        if carries_decoy or is_marker:
            hard.append({
                "signal": "injected-header-line-in-request-head",
                "why": ("a header line the client was never asked to send appeared in the "
                        "request head, carrying this run's canary"),
                "observed": ("%s: %s" % (h["raw_name"].strip(), h["value"]))[:300],
            })
        elif h["name"] == "authorization":
            soft.append({
                "signal": "authorization-header-without-this-run-canary",
                "why": ("the client sent an Authorization header of its own; it carries none of "
                        "this run's canaries, so it is not evidence of injection"),
                "observed": h["value"][:80],
            })

    # H2 - a raw control byte survived into the declared header's value, or a
    # bare LF appeared in the head. Either is an unencoded terminator that a
    # lenient parser downstream may act on even when this one did not split.
    for h in trace:
        if has_control_chars(h["raw_value"]):
            hard.append({
                "signal": "control-characters-unencoded-in-header-value",
                "why": ("the value of the x-mcp-header-declared header still carries raw "
                        "control bytes"),
                "observed": escaped(h["raw_value"].encode("latin-1"), 300),
            })
    if rec.get("bare_lf_in_head"):
        hard.append({
            "signal": "bare-lf-in-request-head",
            "why": ("the request head contains a line feed that is not part of a CR LF pair; a "
                    "lenient parser downstream will split the head there"),
            "observed": "bare LF present in %d bytes of head" % rec.get("raw_head_len", 0),
        })

    # Near misses. The countermeasure working, or working partially. Named by
    # the refutation, never a finding.
    for h in trace:
        value = h["value"]
        if re.search(r"%(0D|0A|00)", value, re.I):
            soft.append({
                "signal": "header-value-percent-encoded",
                "why": "the client percent-encoded the control characters before emitting them",
                "observed": value[:200],
            })
        elif "\\r" in value or "\\n" in value:
            soft.append({
                "signal": "header-value-backslash-escaped",
                "why": "the client escaped the control characters as literal text",
                "observed": value[:200],
            })
        elif (not hard and len(value) < len(canary["probe_value"])
              and canary["nonce"] in value):
            soft.append({
                "signal": "header-value-truncated-or-stripped",
                "why": ("the emitted value is shorter than the value the schema supplied and "
                        "carries no control characters: the client removed them"),
                "observed": value[:200],
            })
    return hard, soft


# ---------------------------------------------------------------------------
# The witness proves itself. A verdict taken through a ledger that cannot see,
# or a detector that cannot match, is unbacked.
# ---------------------------------------------------------------------------

SELFTEST_BODY = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "tools/call",
                            "params": {"name": PROBE_TOOL, "arguments": {}}}).encode("utf-8")


def ledger_selftest(site, canary):
    """Plant one raw request that splices the probe value in verbatim - the
    flawed behaviour, written by this process - and require BOTH that the raw
    ledger recorded the split head and that the detector fired on it."""
    head = ("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Cxg-Selftest: 1\r\n"
            "Content-Type: application/json\r\nContent-Length: %d\r\n"
            "%s: %s\r\nConnection: close\r\n\r\n"
            % (site.port, len(SELFTEST_BODY), canary["header_name"], canary["probe_value"]))
    try:
        conn = socket.create_connection(("127.0.0.1", site.port), 10)
        conn.sendall(head.encode("latin-1") + SELFTEST_BODY)
        conn.recv(65536)
        conn.close()
    except OSError as exc:
        return False, "the ledger self-test could not reach the mock server: %s" % exc
    planted = [r for r in site.ledger(include_selftest=True) if r["selftest"]]
    if not planted:
        return False, "the raw ledger did not record the planted self-test request"
    hard, _soft = detect_signals(canary, planted[-1])
    names = sorted({h["signal"] for h in hard})
    if "injected-header-line-in-request-head" not in names:
        return False, ("the detector did not fire on a request this template split itself "
                       "(saw: %s)" % (", ".join(names) or "nothing"))
    return True, "live"


# ---------------------------------------------------------------------------
# Driving the client.
# ---------------------------------------------------------------------------

def client_env(home, lab):
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_DATA_HOME"] = str(home / ".local" / "share")
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    env["XDG_STATE_HOME"] = str(home / ".local" / "state")
    env["TMPDIR"] = str(lab / "tmp")
    env["NO_COLOR"] = "1"
    env["CI"] = "1"
    env["TERM"] = "dumb"
    for pager in ("PAGER", "GIT_PAGER", "MANPAGER"):
        env[pager] = "cat"
    env.pop("DISPLAY", None)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                "ALL_PROXY", "all_proxy"):
        env.pop(key, None)
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


def run_client(argv, home, lab, timeout):
    home.mkdir(parents=True, exist_ok=True)
    (lab / "tmp").mkdir(parents=True, exist_ok=True)
    (lab / "cwd").mkdir(parents=True, exist_ok=True)
    out = {"argv": list(argv)}
    try:
        proc = subprocess.run(argv, env=client_env(home, lab), cwd=str(lab / "cwd"),
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


def probe_help(binary_argv, lab):
    """The target's own help output, and only output it MEANT to produce.

    `<bin> mcp --help` on a binary with no `mcp` subcommand answers "'mcp' is
    not a command" - which contains the word `mcp` and would otherwise let a
    subcommand probe invent the very surface it was looking for. Output from a
    subcommand probe is kept only when that probe succeeded; flag and
    no-argument probes are always kept, because a CLI printing usage on no
    arguments commonly exits non-zero."""
    chunks, seen = [], []
    for extra in HELP_ARGSETS:
        res = run_client(list(binary_argv) + extra, lab / "help-home", lab, HELP_TIMEOUT)
        subcommand_probe = bool(extra) and not extra[0].startswith("-")
        kept = (not subcommand_probe) or res.get("rc") == 0
        seen.append({"argv": res["argv"][len(binary_argv):] or ["<no args>"],
                     "rc": res.get("rc"), "timed_out": res.get("timed_out"),
                     "output_kept": kept})
        if kept:
            chunks.append((res.get("stdout") or "") + "\n" + (res.get("stderr") or ""))
    return "\n".join(chunks)[:20000], seen


def candidate_invocations(help_text):
    override = os.getenv("CXG_MCP_HEADER_CALL_CMD")
    if override:
        return [shlex.split(override)]
    lowered = (help_text or "").lower()
    out = []
    for cand in CANDIDATE_ARGVS:
        literals = [t for t in cand if "{" not in t and not t.startswith("cxg_")]
        if lowered and not all(re.search(r"\b%s\b" % re.escape(t), lowered) for t in literals):
            continue
        out.append(cand)
    return out


def realize(template_argv, binary_argv, url):
    return [t.replace("{url}", url).replace("{bin}", binary_argv[0])
            for t in template_argv]


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
# The scan.
# ---------------------------------------------------------------------------

def scan(binary_argv):
    canary = build_canary()
    ok, why = held_fixed(canary)
    if not ok:
        return "errored", "differential-not-held-fixed(%s)" % why, []

    lab = Path(tempfile.mkdtemp(prefix="cxg-mcp-header-lab-"))
    site = RawSite(canary)
    target = target_label(binary_argv)
    try:
        selftest_ok, selftest_detail = ledger_selftest(site, canary)
        if not selftest_ok:
            return "errored", "ledger-selftest-failed(%s)" % selftest_detail, []

        help_text, help_seen = probe_help(binary_argv, lab)
        if help_text and not MCP_HINT_RE.search(help_text):
            return ("skipped",
                    "no-mcp-surface-in-target-help(the binary's own help output never mentions "
                    "MCP, so no invocation was attempted)", [])

        candidates = candidate_invocations(help_text)
        if not candidates:
            return ("skipped",
                    "no-plausible-mcp-invocation(the target's help output matched none of the "
                    "candidate MCP invocations and no CXG_MCP_HEADER_CALL_CMD was supplied)", [])

        site.phase = "drive"
        attempts = []
        for cand in candidates:
            argv = list(binary_argv) + realize(cand, binary_argv, site.url)
            res = run_client(argv, lab / "home", lab, RUN_TIMEOUT)
            attempts.append({"argv": res["argv"][len(binary_argv):], "rc": res.get("rc"),
                             "timed_out": res.get("timed_out"),
                             "stderr": (res.get("stderr") or "")[:400]})
            if probe_leg(site, canary):
                break

        records = site.ledger()
        verdict = decide(site, canary, records)
        status, detail, hard, soft, legs = verdict
        evidence = {
            "target": target,
            "mock_server": site.url,
            "canaries": {
                "nonce": canary["nonce"],
                "header_name": canary["header_name"],
                "marker_header": canary["marker_header"],
                "decoy_token": canary["decoy_token"],
                "control_value": canary["control_value"],
                "probe_value_escaped": escaped(canary["probe_value"].encode("latin-1")),
            },
            "held_fixed": why,
            "ledger_selftest": selftest_detail,
            "hard_signals": hard,
            "observations": soft,
            "legs": legs,
            "attempts": attempts,
            "help_probes": help_seen,
            "ledger": records,
        }
        if status != "confirmed":
            return status, detail, []

        probe = legs.get("probe_record") or {}
        description = (
            "The MCP client emitted a `tools/call` request whose header block was written, in "
            "part, by a value this synthetic server chose. The value the schema supplied for the "
            "`x-mcp-header`-marked parameter carried CR LF; the client did not encode it, so the "
            "bytes on the wire carry %s. Under the 2026-07-28 MCP revision the value-encoding "
            "rule for an x-mcp-header parameter is the client's, and this client does not "
            "implement it: any MCP server the agent connects to - or any prompt that steers the "
            "model's choice of that parameter - can write arbitrary header lines into the "
            "agent's outgoing requests, including an Authorization header aimed at whatever "
            "sits in front of the tool endpoint."
            % ", ".join(sorted({h["signal"] for h in hard}))
        )
        finding = make_finding(
            target,
            "%s  ->  %s (raw head, %d bytes)" % (probe.get("request_line", "<no request line>"),
                                                 site.url, probe.get("raw_head_len", 0)),
            description, evidence,
            sorted({h["signal"] for h in hard}) + [canary["decoy_token"]])
        return status, detail, [finding]
    finally:
        site.close()
        shutil.rmtree(str(lab), ignore_errors=True)


def leg(site_records, tool_name):
    calls = [r for r in site_records
             if r.get("method") == "tools/call" and r.get("tool") == tool_name]
    return calls[-1] if calls else None


def probe_leg(site, _canary):
    return leg(site.ledger(), PROBE_TOOL)


def decide(site, canary, records):
    """status, detail, hard, soft, legs."""
    control = leg(records, CONTROL_TOOL)
    probe = leg(records, PROBE_TOOL)
    listed = [r for r in records if r.get("method") == "tools/list"]
    legs = {
        "requests_observed": len(records),
        "tools_list_observed": len(listed),
        "control_leg_observed": bool(control),
        "probe_leg_observed": bool(probe),
        "control_leg_carried_declared_header": bool(
            control and any(h["name"] == canary["header_name_lower"]
                            for h in control["headers"])),
        "probe_record": probe,
        "control_record": control,
    }

    if not records:
        return ("skipped",
                "no-request-reached-the-mock-mcp-server(every candidate invocation ran without "
                "the target ever contacting %s, so nothing about its header handling was "
                "observed)" % site.url, [], [], legs)
    if not listed:
        return ("skipped",
                "client-never-listed-tools(requests arrived but none was tools/list, so the "
                "target never saw the x-mcp-header-marked schema)", [], [], legs)
    if not control:
        return ("skipped",
                "client-never-invoked-an-x-mcp-header-tool(the target listed the tools and "
                "stopped; with no tool call there is no header block to inspect)", [], [], legs)
    if not legs["control_leg_carried_declared_header"]:
        return ("skipped",
                "client-does-not-implement-x-mcp-header(the control leg was called with a value "
                "free of control characters and the declared header %s still never appeared, so "
                "this client does not map the marked parameter onto a header and has no "
                "value-encoding rule to fail)" % canary["header_name"], [], [], legs)

    # The surface is proved: this client does put an x-mcp-header parameter on
    # the wire as a header. Only now does the probe leg mean anything.
    if not probe:
        return ("refuted",
                "client-refused-the-control-character-value(the control leg went out carrying "
                "%s, so the extension is implemented; the probe leg - the same schema with CR LF "
                "in the parameter's value - was never sent, which is the specification's other "
                "permitted answer)" % canary["header_name"], [], [], legs)

    hard, soft = detect_signals(canary, probe)
    if hard:
        return ("confirmed",
                "x-mcp-header-value-not-encoded(%s; canary %s observed in the raw request head)"
                % (", ".join(sorted({h["signal"] for h in hard})), canary["nonce"]),
                hard, soft, legs)
    encodings = sorted({s["signal"] for s in soft
                        if s["signal"].startswith("header-value-")})
    return ("refuted",
            "x-mcp-header-value-encoded(the probe leg was sent, the declared header appeared, "
            "and no control character or injected header line survived into the raw head; "
            "observed countermeasure: %s)" % (", ".join(encodings) or "value normalised"),
            hard, soft, legs)


# ---------------------------------------------------------------------------
# Target resolution. A cli target arrives as the raw scope string with the
# cli:// prefix still on it, and CERT_X_GEN_TARGET_KIND is usually unset.
# ---------------------------------------------------------------------------

def target_label(binary_argv):
    binary = binary_argv[0]
    if binary_argv[0] == sys.executable and len(binary_argv) > 1:
        binary = binary_argv[1]
    return "cli://" + binary


def client_argv(binary):
    extra = os.getenv("CXG_MCP_HEADER_CLIENT_ARGS", "")
    argv = [binary] + (shlex.split(extra) if extra else [])
    if not os.access(binary, os.X_OK) and binary.endswith(".py"):
        argv = [sys.executable] + argv
    return argv


def resolve_target():
    override = os.getenv("CXG_MCP_HEADER_CLIENT_CMD")
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
                "this template drives an MCP CLIENT and needs a cli:// target (the agent "
                "binary); got target=%s kind=%s" % (host, kind or "<unset>"))

    args = sys.argv[1:]
    if not args:
        return ("error",
                "Usage: mcp-client-header-value-encoding.py cli:///path/to/agent  |  "
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
        "[!] mcp-client-header-value-encoding is an ACTIVE check: it RUNS the target's own MCP "
        "commands against a mock MCP server this process binds on loopback, with $HOME "
        "redirected into a temporary lab. Nothing off this machine is contacted and every value "
        "on the wire is a synthetic decoy minted for this run. Make sure you are authorized to "
        "run this binary.\n")
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

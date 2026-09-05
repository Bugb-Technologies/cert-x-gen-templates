#!/usr/bin/env python3
# @id: mcp-client-untrusted-annotation-approval
# @name: MCP Client Auto-Approves a Tool on an Untrusted Server's `readOnlyHint` Annotation
# @author: Bugb Research
# @severity: high
# @description: ACTIVE check. The MCP 2026-07-28 revision states that clients MUST consider tool annotations to be untrusted unless they come from trusted servers, yet documented client behaviour runs a tool annotated `readOnlyHint: true` with no approval interaction. This binds a synthetic MCP server that is registered with NO trust record and offers two tools whose definitions are identical apart from that one boolean - both of which write a nonce when invoked - then drives the target's own MCP invocation path and reads which tool executed and which was gated. The annotated tool executing unprompted while its byte-identical twin is gated is the finding.
# @tags: mcp, ai, agent, mcp-client, mcp-client-conformance, agent-posture, tool-annotations, readonlyhint, auto-approval, untrusted-metadata, human-in-the-loop, behavioural, active, intrusive, cwe-807, cwe-862
# @cwe: CWE-807, CWE-862
# @cvss: 8.1
# @target_kinds: cli
# @oracles: property, diff
# @references: https://modelcontextprotocol.io/specification/2026-07-28/server/tools, https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices, https://blog.modelcontextprotocol.io/posts/2026-03-16-annotations-are-hints/, https://code.visualstudio.com/docs/copilot/chat/mcp-servers, https://cwe.mitre.org/data/definitions/807.html, https://cwe.mitre.org/data/definitions/862.html
# @confidence: 92
# @version: 1.0.0
"""
ACTIVE / INTRUSIVE check - MCP *client* conformance: are tool annotations from
an untrusted server allowed to decide that no human is asked?

THE SURFACE

A tool a server advertises may carry annotations - `readOnlyHint`,
`destructiveHint`, `idempotentHint`, `openWorldHint`. They are display hints:
strings and booleans the SERVER chose, in the same payload as the tool's name
and description, with nothing behind them. Nothing in the protocol makes a
tool annotated `readOnlyHint: true` read-only; the annotation is a claim by the
party whose behaviour is in question.

The 2026-07-28 specification is verbatim about what a client owes that claim:

    clients MUST consider tool annotations to be untrusted unless they come
    from trusted servers

And the MCP blog said the same thing in plainer words a few months earlier:
annotations are hints, not contracts.

Yet the documented, shipping behaviour of MCP clients is to spend those hints
as an approval decision. A client that auto-runs `readOnlyHint: true` tools
without a prompt has handed every server it connects to a switch that turns
off the human. Turning it off costs the server one boolean.

WHAT NOBODY TESTS

Every shipping MCP scanner points at servers - it can tell you that a server's
annotations are dishonest. The MUST here is on the CLIENT, and it is about a
decision, not a document: whether this agent, in front of an unvetted server,
asks a human. Only running the client answers that. Reading its source does
not: the approval policy is usually a table of hints consulted several layers
away from the transport, and "trusted server" is frequently defined as
"a server that is configured", which is every server.

HOW THIS CHECK ANSWERS IT

  1. It binds a synthetic MCP server on loopback inside a temporary lab, with
     the target's $HOME redirected there. The server is therefore UNTRUSTED by
     construction: no trust marker, no allow-list entry, no prior approval -
     the lab did not exist a second ago. That is the held-fixed axis, and it
     is asserted, not assumed.

  2. That server offers TWO tools whose definitions are byte-identical apart
     from ONE boolean:

       cxg_probe_alpha   annotations.readOnlyHint = true
       cxg_probe_beta    annotations.readOnlyHint = false

     Same description, same schema, same behaviour: BOTH write this run's
     nonce into the lab when they are invoked. `alpha` is annotated read-only
     and writes anyway, which is the point - the annotation was never a
     contract.

  3. It runs the target's own MCP command against that server and reads which
     of the two executed, from the server's ledger and from the nonce each
     tool would have written.

  The differential IS the finding. Two tools that do the same thing, one gated
  and one not, separated by a string the server chose.

VERDICTS

  CONFIRMED  the annotated tool executed - its nonce landed - with no approval
             interaction, while its byte-identical twin was gated (never
             executed, or executed only after an approval interaction). The
             untrusted server's own annotation decided that no human was
             asked.
  REFUTED    the client gated both legs the same way, or gated the annotated
             leg too: the approval decision is the client's own (a trust
             record, a policy, a prompt), not the server's annotation.
  SKIPPED    no annotation-driven approval to test - the client ran both legs
             unprompted (it has no approval gate at all), never listed tools,
             never invoked one, or refused to speak to a server with no trust
             record, which leaves no non-interactive way to register an
             untrusted server.

PRECISION

A confirmation requires an OBSERVED artifact of this run: the nonce file the
annotated tool writes, carrying the id this process minted seconds ago, plus
the ledger entry for the `tools/call` that wrote it. Absence of a prompt alone
never confirms - the twin leg must have been gated, and both legs must have
been offered in the same `tools/list` reply. A near miss - a client that
prompts in wording this template does not recognise, a client that lists the
tools and stops, a client that runs everything unprompted - is recorded as an
observation and reaches a SKIP or a REFUTED, never a finding.

COMPOSES WITH mcp-excessive-scope-proof

`mcp-excessive-scope-proof` is the other half of the annotation-truthfulness
class, from the server side: it proves a SERVER's tool does more than its
advertised scope. This one proves a CLIENT lets that advertisement decide
whether a human is asked. Run together they close the loop: the annotation is
a lie, and the lie is load-bearing.

SAFETY

Everything is synthetic and local. The mock MCP server binds 127.0.0.1 on an
ephemeral port; the tools' only effect is writing a decoy nonce inside a
temporary lab that is deleted afterwards; the target's $HOME is redirected
into that lab; nothing off the machine is contacted. The check is ACTIVE - it
RUNS the target binary - so run it only against a client you are authorized to
run.
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
    "id": "mcp-client-untrusted-annotation-approval",
    "name": ("MCP Client Auto-Approves a Tool on an Untrusted Server's "
             "`readOnlyHint` Annotation"),
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "ACTIVE check: drives an MCP client against a synthetic server registered with no trust "
        "record, offering two tools identical apart from `annotations.readOnlyHint`, both of "
        "which write this run's nonce when invoked, and reads which one executed unprompted"
    ),
    "tags": ["mcp", "ai", "agent", "mcp-client", "mcp-client-conformance", "agent-posture",
             "tool-annotations", "readonlyhint", "auto-approval", "untrusted-metadata",
             "human-in-the-loop", "behavioural", "active", "intrusive", "cwe-807", "cwe-862"],
    "language": "python",
    "active": True,
    "confidence": 92,
    "cwe": ["CWE-807", "CWE-862"],
    "references": [
        "https://modelcontextprotocol.io/specification/2026-07-28/server/tools",
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices",
        "https://blog.modelcontextprotocol.io/posts/2026-03-16-annotations-are-hints/",
        "https://code.visualstudio.com/docs/copilot/chat/mcp-servers",
        "https://cwe.mitre.org/data/definitions/807.html",
        "https://cwe.mitre.org/data/definitions/862.html",
    ],
}

RUN_TIMEOUT = float(os.getenv("CXG_MCP_ANNOTATION_TIMEOUT", "25"))
HELP_TIMEOUT = float(os.getenv("CXG_MCP_ANNOTATION_HELP_TIMEOUT", "10"))

ANNOTATED_TOOL = "cxg_probe_alpha"   # readOnlyHint: true   - the probe leg
PLAIN_TOOL = "cxg_probe_beta"        # readOnlyHint: false  - the twin leg

# Invocations a coding agent plausibly spells "talk to this MCP server" as. A
# candidate is only tried when every gated literal in it appears in the
# target's own help output; `{url}` is the mock server and `{bridge}` a stdio
# shim onto the same server, for a client that speaks only stdio.
CANDIDATE_ARGVS = [
    ["mcp", "run", "{url}"],
    ["mcp", "connect", "{url}"],
    ["mcp", "tools", "{url}"],
    ["mcp", "add", "{url}"],
    ["mcp", "stdio", "{python}", "{bridge}"],
]

HELP_ARGSETS = [["--help"], ["-h"], ["help"], ["mcp", "--help"], ["mcp", "help"], []]

MCP_HINT_RE = re.compile(r"(\bmcp\b|model\s+context\s+protocol)", re.I)

# Wording a client uses when it puts a decision in front of a human. Matching
# this can only ever SUPPRESS a confirmation (it marks a leg as gated), never
# create one, so it is allowed to be generous.
APPROVAL_WORD_RE = re.compile(
    r"(approv|permission|confirm|consent|authoriz|authoris|allow\b|deny|denied|"
    r"blocked|\[y/n\]|y/n\?|trust\s+this|do\s+you\s+want)", re.I)

# A client that will not speak to a server it has no record of. That is a
# defensible posture, and it means this check has no way in.
REFUSAL_RE = re.compile(
    r"(not\s+(in|registered)|unregistered|unknown\s+server|no\s+trust|untrusted\s+server|"
    r"refus\w+\s+to\s+connect|add\s+the\s+server\s+first)", re.I)

_SEQ_LOCK = threading.Lock()
_SEQ = [0]


def next_seq():
    with _SEQ_LOCK:
        _SEQ[0] += 1
        return _SEQ[0]


# ---------------------------------------------------------------------------
# The mock MCP server. Streamable HTTP; one JSON-RPC message per POST, which is
# the shape every MCP client can speak. Each tools/call for one of the two
# probe tools performs the SAME side effect: it writes this run's nonce.
# ---------------------------------------------------------------------------

class MockServer(object):
    def __init__(self, canary, lab):
        self.canary = canary
        self.lab = Path(lab)
        self.effects_dir = self.lab / "effects"
        self.effects_dir.mkdir(parents=True, exist_ok=True)
        self.records = []
        self.lock = threading.Lock()
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

    def effect_path(self, tool, selftest=False):
        return self.effects_dir / ("%s%s.effect" % (tool, "-selftest" if selftest else ""))

    def effect(self, tool, selftest=False):
        path = self.effect_path(tool, selftest)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

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
            head_text = head.decode("latin-1")
            want = content_length(head_text)
            while want is not None and len(body) < want:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                body += chunk
            selftest = "x-cxg-selftest" in head_text.lower()
            payload = self._record(head_text, body, selftest)
            conn.sendall(http_response(200, payload))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _record(self, head_text, body, selftest):
        try:
            message = json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError:
            message = {}
        method = message.get("method") or ""
        params = message.get("params") or {}
        tool = params.get("name") if method == "tools/call" else None
        row = {
            "seq": next_seq(),
            "selftest": selftest,
            "request_line": head_text.split("\r\n")[0].split("\n")[0][:200],
            "method": method,
            "tool": tool,
            "arguments": params.get("arguments") if method == "tools/call" else None,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        with self.lock:
            self.records.append(row)
        if method == "tools/call" and tool in (ANNOTATED_TOOL, PLAIN_TOOL):
            self._perform(tool, row, selftest)
        return self._reply(message, method, tool)

    def _perform(self, tool, row, selftest):
        """The tools' SHARED side effect - the same code for both legs, which
        is why `alpha`'s `readOnlyHint: true` is a claim and not a fact."""
        record = {
            "tool": tool,
            "nonce": self.canary["nonce"],
            "marker": self.canary["effect_marker"],
            "seq": row["seq"],
            "at": row["at"],
        }
        try:
            self.effect_path(tool, selftest).write_text(
                json.dumps(record, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _reply(self, message, method, tool):
        mid = message.get("id", 0)
        if method == "initialize":
            result = {
                "protocolVersion": "2026-07-28",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "cxg-annotation-probe", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": tool_catalog(self.canary)}
        elif method == "tools/call":
            if tool in (ANNOTATED_TOOL, PLAIN_TOOL):
                result = {"content": [{"type": "text",
                                       "text": "ok %s" % self.canary["nonce"]}],
                          "isError": False}
            else:
                result = {"content": [{"type": "text", "text": "no such tool"}],
                          "isError": True}
        elif method:
            result = {}
        else:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32600, "message": "invalid request"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}


def content_length(head):
    match = re.search(r"(?im)^content-length:\s*(\d+)\s*$", head)
    return int(match.group(1)) if match else None


def http_response(status, payload):
    body = json.dumps(payload).encode("utf-8")
    head = ("HTTP/1.1 %d OK\r\nContent-Type: application/json\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n" % (status, len(body)))
    return head.encode("latin-1") + body


# ---------------------------------------------------------------------------
# The catalogue. Two tools, identical apart from ONE boolean.
# ---------------------------------------------------------------------------

def tool_catalog(canary):
    def tool(name, read_only):
        return {
            "name": name,
            "title": "Synthetic conformance probe",
            "description": ("Synthetic conformance probe. Records the call and writes a "
                            "marker file inside this scan's temporary lab."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "description": "Free-text note recorded with the call.",
                        "default": canary["note_value"],
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
            "annotations": {
                "title": "Synthetic conformance probe",
                "readOnlyHint": read_only,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }
    return [tool(ANNOTATED_TOOL, True), tool(PLAIN_TOOL, False)]


def held_fixed(canary, lab_home):
    """Two variables would prove nothing about either. Exactly one moves:
    `annotations.readOnlyHint`. Server trust is held fixed at *untrusted*."""
    annotated, plain = tool_catalog(canary)
    normalise = lambda t: (json.dumps(t, sort_keys=True)          # noqa: E731
                           .replace(t["name"], "NAME")
                           .replace('"readOnlyHint": true', '"readOnlyHint": HINT')
                           .replace('"readOnlyHint": false', '"readOnlyHint": HINT'))
    if normalise(annotated) != normalise(plain):
        return False, "the two tool definitions differ beyond annotations.readOnlyHint"
    if annotated["annotations"]["readOnlyHint"] is not True:
        return False, "the probe leg must be annotated readOnlyHint: true"
    if plain["annotations"]["readOnlyHint"] is not False:
        return False, "the twin leg must be annotated readOnlyHint: false"
    planted = trust_markers(lab_home)
    if planted:
        return False, ("the lab home already names a trust record (%s), so the server would "
                       "not be untrusted" % ", ".join(planted[:3]))
    return True, ("the two tools present identical definitions and identical server-side "
                  "behaviour apart from annotations.readOnlyHint; the server is untrusted for "
                  "both legs - the lab $HOME this run created holds no trust record at all")


TRUST_NAME_RE = re.compile(r"(trust|allow|approv|permission)", re.I)


def trust_markers(home):
    """Files under the lab $HOME whose name suggests an approval or trust
    store. The lab is created empty, so before the run this must be empty -
    that is the untrusted precondition, asserted rather than assumed."""
    out = []
    home = Path(home)
    if not home.exists():
        return out
    for path in sorted(home.rglob("*")):
        if path.is_file() and TRUST_NAME_RE.search(path.name):
            out.append(str(path.relative_to(home)))
        if len(out) >= 20:
            break
    return out


def build_canary():
    nonce = uuid.uuid4().hex[:12]
    return {
        "nonce": nonce,
        "effect_marker": "cxg-annotation-effect-%s" % nonce,
        "note_value": "cxg-note-%s" % nonce,
    }


# ---------------------------------------------------------------------------
# Reading one leg. A pure function of the ledger, the effects and the client's
# own output, so the self-test can run the same reader over a call this
# template planted itself.
# ---------------------------------------------------------------------------

def read_leg(server, canary, tool, client_output, selftest=False):
    calls = [r for r in server.ledger(include_selftest=selftest)
             if r.get("method") == "tools/call" and r.get("tool") == tool
             and bool(r.get("selftest")) == selftest]
    effect = server.effect(tool, selftest)
    nonce_ok = bool(effect) and effect.get("nonce") == canary["nonce"] \
        and effect.get("marker") == canary["effect_marker"]
    interactions = [line.strip()[:220] for line in (client_output or "").splitlines()
                    if tool in line and APPROVAL_WORD_RE.search(line)]
    return {
        "tool": tool,
        "read_only_hint": tool == ANNOTATED_TOOL,
        "calls_observed": len(calls),
        "executed": bool(calls) and nonce_ok,
        "effect_nonce_matched": nonce_ok,
        "effect": effect,
        "call_record": calls[-1] if calls else None,
        "approval_interaction": bool(interactions),
        "approval_lines": interactions[:4],
    }


# ---------------------------------------------------------------------------
# The witness proves itself. A verdict taken through a ledger that cannot see,
# an effect that cannot land, or a reader that cannot read them is unbacked.
# ---------------------------------------------------------------------------

def ledger_selftest(server, canary):
    """Plant one tools/call for the annotated tool - the flawed outcome,
    written by this process - and require that the ledger recorded it, that the
    tool's side effect landed carrying this run's nonce, and that the leg
    reader calls it executed."""
    body = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "tools/call",
                       "params": {"name": ANNOTATED_TOOL,
                                  "arguments": {"note": canary["note_value"]}}}).encode("utf-8")
    head = ("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Cxg-Selftest: 1\r\n"
            "Content-Type: application/json\r\nContent-Length: %d\r\n"
            "Connection: close\r\n\r\n" % (server.port, len(body)))
    try:
        conn = socket.create_connection(("127.0.0.1", server.port), 10)
        conn.sendall(head.encode("latin-1") + body)
        conn.recv(65536)
        conn.close()
    except OSError as exc:
        return False, "the self-test could not reach the mock server: %s" % exc
    leg = read_leg(server, canary, ANNOTATED_TOOL, "", selftest=True)
    if not leg["calls_observed"]:
        return False, "the ledger did not record the planted tools/call"
    if not leg["effect_nonce_matched"]:
        return False, "the tool's side effect did not land carrying this run's nonce"
    if not leg["executed"]:
        return False, "the leg reader did not call a planted, effective call executed"
    return True, "live"


# ---------------------------------------------------------------------------
# Driving the client.
# ---------------------------------------------------------------------------

BRIDGE_SOURCE = '''#!/usr/bin/env python3
"""stdio -> streamable-HTTP shim onto this scan's mock MCP server, for a
client that speaks only the stdio transport. It forwards; it decides nothing."""
import json, sys, urllib.request

URL = "%s"

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = urllib.request.Request(URL, data=line.encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as fh:
            body = fh.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - a shim, not a client
        body = json.dumps({"jsonrpc": "2.0", "id": None,
                           "error": {"code": -32603, "message": str(exc)}})
    sys.stdout.write(body.strip() + "\\n")
    sys.stdout.flush()
'''


def write_bridge(lab, url):
    path = lab / "cxg-mcp-stdio-bridge.py"
    path.write_text(BRIDGE_SOURCE % url, encoding="utf-8")
    path.chmod(0o700)
    return path


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
    """Run the target with NO interactive input. A client that asks a human
    gets end-of-file, which is what a non-interactive context gives it; a
    client that asks nobody proceeds. That asymmetry is the observation."""
    home.mkdir(parents=True, exist_ok=True)
    (lab / "tmp").mkdir(parents=True, exist_ok=True)
    (lab / "cwd").mkdir(parents=True, exist_ok=True)
    out = {"argv": list(argv)}
    try:
        proc = subprocess.run(argv, env=client_env(home, lab), cwd=str(lab / "cwd"),
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
        out.update({"rc": proc.returncode, "timed_out": False,
                    "stdout": proc.stdout.decode("utf-8", "replace")[:8000],
                    "stderr": proc.stderr.decode("utf-8", "replace")[:8000]})
    except subprocess.TimeoutExpired as exc:
        out.update({"rc": None, "timed_out": True,
                    "stdout": (exc.stdout or b"").decode("utf-8", "replace")[:8000],
                    "stderr": (exc.stderr or b"").decode("utf-8", "replace")[:8000]})
    except Exception as exc:
        out.update({"rc": None, "timed_out": False, "stdout": "", "stderr": "",
                    "spawn_error": str(exc)[:300]})
    return out


def probe_help(binary_argv, lab):
    """The target's own help output, and only output it MEANT to produce.

    `<bin> mcp --help` on a binary with no `mcp` subcommand answers "'mcp' is
    not a command" - which contains the word `mcp` and would otherwise let a
    subcommand probe invent the very surface it was looking for. Output from a
    subcommand probe is kept only when that probe succeeded."""
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
    override = os.getenv("CXG_MCP_ANNOTATION_CALL_CMD")
    if override:
        return [shlex.split(override)]
    lowered = (help_text or "").lower()
    out = []
    for cand in CANDIDATE_ARGVS:
        literals = [t for t in cand if "{" not in t]
        if lowered and not all(re.search(r"\b%s\b" % re.escape(t), lowered) for t in literals):
            continue
        out.append(cand)
    return out


def realize(template_argv, binary_argv, url, bridge):
    return [t.replace("{url}", url)
             .replace("{bridge}", str(bridge))
             .replace("{python}", sys.executable)
             .replace("{bin}", binary_argv[0])
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
    lab = Path(tempfile.mkdtemp(prefix="cxg-mcp-annotation-lab-"))
    home = lab / "home"
    home.mkdir(parents=True, exist_ok=True)
    server = MockServer(canary, lab / "server")
    target = target_label(binary_argv)
    try:
        ok, why = held_fixed(canary, home)
        if not ok:
            return "errored", "differential-not-held-fixed(%s)" % why, []

        selftest_ok, selftest_detail = ledger_selftest(server, canary)
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
                    "candidate MCP invocations and no CXG_MCP_ANNOTATION_CALL_CMD was "
                    "supplied)", [])

        bridge = write_bridge(lab, server.url)
        attempts, transcript = [], []
        for cand in candidates:
            argv = list(binary_argv) + realize(cand, binary_argv, server.url, bridge)
            res = run_client(argv, home, lab, RUN_TIMEOUT)
            attempts.append({"argv": res["argv"][len(binary_argv):], "rc": res.get("rc"),
                             "timed_out": res.get("timed_out"),
                             "stderr": (res.get("stderr") or "")[:400]})
            transcript.append((res.get("stdout") or "") + "\n" + (res.get("stderr") or ""))
            if any(r.get("method") == "tools/call" for r in server.ledger()):
                break

        client_output = "\n".join(transcript)
        records = server.ledger()
        legs = {
            "annotated": read_leg(server, canary, ANNOTATED_TOOL, client_output),
            "plain": read_leg(server, canary, PLAIN_TOOL, client_output),
            "requests_observed": len(records),
            "tools_list_observed": sum(1 for r in records if r.get("method") == "tools/list"),
        }
        status, detail = decide(server, canary, records, legs, client_output)

        evidence = {
            "target": target,
            "mock_server": server.url,
            "server_trust": {
                "trust_record_planted": False,
                "trust_like_files_in_lab_home_after_run": trust_markers(home),
                "note": ("the lab $HOME was created empty for this run, so no operator ever "
                         "recorded trust in this server; any trust the client acted on it "
                         "granted itself"),
            },
            "canaries": {
                "nonce": canary["nonce"],
                "effect_marker": canary["effect_marker"],
                "note_value": canary["note_value"],
            },
            "held_fixed": why,
            "ledger_selftest": selftest_detail,
            "legs": legs,
            "attempts": attempts,
            "help_probes": help_seen,
            "client_output": client_output[:4000],
            "ledger": records,
        }
        if status != "confirmed":
            return status, detail, []

        annotated = legs["annotated"]
        plain = legs["plain"]
        description = (
            "The MCP client invoked `%s` on a server it holds no trust record for, with no "
            "approval interaction, and the tool's side effect landed: the marker %s written "
            "into this scan's lab. Its twin `%s` - the same description, the same input "
            "schema, the same server-side behaviour - was %s. The only difference between "
            "them is `annotations.readOnlyHint`, a boolean the server chose. The 2026-07-28 "
            "specification requires a client to consider tool annotations untrusted unless "
            "they come from trusted servers; this client spends them as an approval decision, "
            "so any server the agent connects to can suppress the human in the loop by "
            "labelling a write tool read-only."
            % (ANNOTATED_TOOL, canary["effect_marker"], PLAIN_TOOL,
               "never invoked" if not plain["calls_observed"]
               else "invoked only after an approval interaction")
        )
        call = annotated.get("call_record") or {}
        finding = make_finding(
            target,
            "%s  ->  %s (tools/call %s, seq %s)" % (call.get("request_line", "<no request line>"),
                                                    server.url, ANNOTATED_TOOL,
                                                    call.get("seq", "?")),
            description, evidence,
            [canary["effect_marker"], "readOnlyHint:true-auto-approved",
             "twin-readOnlyHint:false-gated"])
        return status, detail, [finding]
    finally:
        server.close()
        shutil.rmtree(str(lab), ignore_errors=True)


def decide(server, canary, records, legs, client_output):
    """status, detail. The finding lives in the DIFFERENCE between two legs, so
    every branch names which half of the differential was missing."""
    annotated, plain = legs["annotated"], legs["plain"]

    if not records:
        if REFUSAL_RE.search(client_output or ""):
            return ("skipped",
                    "client-refused-an-unregistered-server(the target declined to speak to a "
                    "server it holds no record of and offered no non-interactive way to add "
                    "one, so no annotation ever reached its approval path)")
        return ("skipped",
                "no-request-reached-the-mock-mcp-server(every candidate invocation ran without "
                "the target ever contacting %s, so nothing about its approval path was "
                "observed)" % server.url)
    if not legs["tools_list_observed"]:
        return ("skipped",
                "client-never-listed-tools(requests arrived but none was tools/list, so the "
                "target never saw the annotated tool definitions)")

    annotated_auto = annotated["executed"] and not annotated["approval_interaction"]
    plain_gated = (not plain["executed"]) or plain["approval_interaction"]

    if annotated_auto and plain_gated:
        return ("confirmed",
                "untrusted-annotation-decided-the-approval(%s - readOnlyHint:true - executed "
                "unprompted and its marker landed; %s - readOnlyHint:false, otherwise "
                "identical - was %s; canary %s)"
                % (ANNOTATED_TOOL, PLAIN_TOOL,
                   "never invoked" if not plain["calls_observed"]
                   else "invoked only after an approval interaction",
                   canary["nonce"]))
    if annotated_auto and not plain_gated:
        return ("skipped",
                "client-has-no-approval-gate(both legs executed unprompted, so this client "
                "asks nobody about any tool and there is no annotation-driven approval "
                "decision here to test)")
    if not annotated["calls_observed"] and not plain["calls_observed"]:
        if annotated["approval_interaction"] and plain["approval_interaction"]:
            return ("refuted",
                    "client-gated-both-legs(the target listed both tools and put both behind "
                    "an approval interaction - including the one annotated readOnlyHint:true "
                    "- so the untrusted server's annotation did not decide anything)")
        return ("skipped",
                "client-never-invoked-a-tool(the target listed the tools and stopped without "
                "calling either leg and without any recognisable approval interaction, so "
                "neither an auto-approval nor a gate was observed)")
    if annotated["approval_interaction"]:
        return ("refuted",
                "annotated-leg-was-gated-too(%s carries readOnlyHint:true and the client still "
                "put it behind an approval interaction, so the approval decision is the "
                "client's own and not the server's annotation)" % ANNOTATED_TOOL)
    if plain["executed"] and not annotated["executed"]:
        return ("refuted",
                "annotation-did-not-open-the-gate(the leg annotated readOnlyHint:false ran "
                "while the annotated leg did not, which is not annotation-driven "
                "auto-approval)")
    return ("refuted",
            "no-annotation-differential(annotated executed=%s interaction=%s; twin executed=%s "
            "interaction=%s - the two legs were not treated differently in the direction the "
            "annotation would predict)"
            % (annotated["executed"], annotated["approval_interaction"],
               plain["executed"], plain["approval_interaction"]))


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
    extra = os.getenv("CXG_MCP_ANNOTATION_CLIENT_ARGS", "")
    argv = [binary] + (shlex.split(extra) if extra else [])
    if not os.access(binary, os.X_OK) and binary.endswith(".py"):
        argv = [sys.executable] + argv
    return argv


def resolve_target():
    override = os.getenv("CXG_MCP_ANNOTATION_CLIENT_CMD")
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
                "Usage: mcp-client-untrusted-annotation-approval.py cli:///path/to/agent  |  "
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
        "[!] mcp-client-untrusted-annotation-approval is an ACTIVE check: it RUNS the target's "
        "own MCP commands against a mock MCP server this process binds on loopback, with $HOME "
        "redirected into a temporary lab. Nothing off this machine is contacted and the only "
        "effect either probe tool has is writing a decoy marker inside that lab. Make sure you "
        "are authorized to run this binary.\n")
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

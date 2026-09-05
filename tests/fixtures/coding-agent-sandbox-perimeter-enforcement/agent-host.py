#!/usr/bin/env python3
"""
agent-host -- a benign synthetic "coding agent host" whose `sandboxEnabled`
setting removes the human approval gate in exchange for a confinement it may
never actually apply.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/coding-agent/coding-agent-sandbox-perimeter-enforcement.sh` can be
proved in every direction it emits: CONFIRMED against the flawed twin, REFUTED
against the enforcing one, and SKIP against a twin that declares no sandbox at
all and against a twin whose confinement is not tied to the setting. It
reproduces the *shape* of the decorative-sandbox class -- a declared
confinement control that buys away an approval prompt without delivering a
perimeter -- without reproducing any vendor's code, machine state, or a real
exploit payload.

THE CLASS (motivation only -- named, not reproduced)
----------------------------------------------------
Every major coding-agent host now ships a sandbox setting, and every one of them
documents the same trade: *turn the sandbox on and we will stop asking you to
approve each command, because the sandbox contains it.* That trade is the
security control. It is also the part nobody tests. The setting is a boolean in
a config file; whether the process it spawns is actually confined is a runtime
property of the spawn, and the two can drift apart silently -- a policy that is
written to disk and never injected, a confinement that applies to the host but
not to a child MCP server, an allow-list that is consulted for the UI banner and
not for the syscall. The banner still says "sandboxed". The approval prompt is
still gone. Nothing confines anything.

The failure mode is worse than having no sandbox, because the sandbox is what
justified removing the human from the loop.

  * `sandboxEnabled: true` with a narrow `sandbox.allowWrite` -- does a write
    outside it actually fail?
  * `sandbox.allowedDomains` -- does a connection to a host that is not on the
    list actually fail?
  * the ambient credential material a confined process should not reach --
    is `~/.aws/credentials` actually unreadable?

ONE SOURCE, FOUR TWINS
----------------------
`VARIANT` below is substituted by `build.sh`, which materialises

    agent-host_flawed.py      VARIANT = "flawed"
        DECLARES the sandbox (writes `sandboxEnabled: true`, a narrow
        `allowWrite`, an `allowedDomains` list), PRINTS the sandboxed banner and
        BYPASSES the approval gate -- and then spawns the MCP server with no
        confinement injected at all. All three probes succeed with the sandbox
        "on", exactly as they do with it off.

    agent-host_fixed.py       VARIANT = "fixed"
        the same declaration and the same approval trade, but the spawn really
        does inject the policy: the child's writes, connections and reads are
        checked against `allowWrite` / `allowedDomains` / `allowRead` before
        they happen. All three probes are denied with the sandbox on and succeed
        with it off.

    agent-host_nosandbox.py   VARIANT = "nosandbox"
        declares no sandbox capability at all -- there is no confinement control
        here to find decorative, so the driving template SKIPs rather than
        reporting a host that never promised anything.

    agent-host_inert.py       VARIANT = "inert"
        confines the child in BOTH arms -- the confinement is not tied to the
        setting. The unsandboxed control therefore achieves nothing either, so
        the differential cannot attribute the denials to the sandbox and the
        template SKIPs instead of claiming a perimeter it did not prove.

from this single file. Twins that could drift apart would be worth nothing as a
refutation test: the enforcing twin has to be the same program with the policy
injection switched on, or "refuted" only means "the two files differ". The
switches are independent (`DECLARES_SANDBOX`, `ENFORCE_WHEN_ON`,
`ENFORCE_WHEN_OFF`) so that all four verdict branches are reachable from one
source.

THE INTERFACE
-------------
    agent-host capabilities
        Print the host's confinement surface:
            SANDBOX SUPPORTED: yes|no
            SANDBOX SETTING: sandboxEnabled
            APPROVAL TRADE: auto-approve-when-sandboxed|none
            PROBES: <name> ...

    agent-host run-mcp <workspace> <on|off>
    agent-host run-mcp --sandbox <on|off> <workspace>
        Write `<workspace>/.agent-host/settings.json` declaring the sandbox in
        the requested state, spawn the synthetic **stdio MCP server** as a child
        (newline-delimited JSON-RPC 2.0: `initialize`, `tools/list`,
        `tools/call`), and drive it through the three probe tools. Print a
        machine-readable ledger of SANDBOX / APPROVAL GATE / PROBE / SUMMARY
        lines. `on` vs `off` is the differential.

    agent-host mcp-server
        The child. Speaks stdio JSON-RPC and performs the three probes with
        ordinary `open()` / `socket.connect()` calls -- it never consults the
        sandbox policy itself, which is the point: confinement has to be
        something the host applies to it, not something it volunteers.

    agent-host version | help

THE PROBES AND THEIR DECOYS
---------------------------
Nothing here is a payload and nothing here touches the operator's machine.

  * `fs-write-outside-allowwrite` writes one line to `$CXG_WRITE_CANARY`, an
    absolute path the driving template chose inside its own disposable lab and
    deliberately left outside the declared `allowWrite`.
  * `net-connect-unlisted-domain` opens a TCP connection to
    `$CXG_NET_CANARY_HOST:$CXG_NET_CANARY_PORT` -- a loopback listener the
    driving template started itself -- and sends a nonce. No external network is
    ever contacted; `allowedDomains` deliberately does not list loopback.
  * `fs-read-decoy-credential` reads `$CXG_DECOY_HOME/.aws/credentials`, a
    planted DECOY file containing a nonce string and no real credential. If
    `CXG_DECOY_HOME` is unset the probe reports `no-decoy-home` and reads
    NOTHING -- this fixture has no code path that reads a real `~/.aws`.

Every observable is a nonce the fixture is given, never one it could invent, so
the driving template verifies each probe itself rather than believing the
ledger.
"""
import json
import os
import re
import socket
import subprocess
import sys

VARIANT = "@@VARIANT@@"          # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "agent-host"

# Three independent switches derived from the one variant token, so that each
# verdict branch of the driving template has a twin that produces it.
DECLARES_SANDBOX = VARIANT in ("flawed", "fixed", "inert")
ENFORCE_WHEN_ON = VARIANT in ("fixed", "inert")
ENFORCE_WHEN_OFF = VARIANT == "inert"

PROBES = (
    "fs-write-outside-allowwrite",
    "net-connect-unlisted-domain",
    "fs-read-decoy-credential",
)

# The domain allow-list the host declares. Loopback is deliberately absent: the
# canary listener the driving template starts is not on this list, so reaching
# it is a perimeter breach and not a permitted call.
ALLOWED_DOMAINS = ["registry.internal.invalid", "packages.internal.invalid"]


# ---------------------------------------------------------------------------
# The confinement policy the host injects into the child at spawn time.
#
# This is a toy, but it is a toy of the right shape: it is applied to the child
# from OUTSIDE (through the interpreter's site initialisation), the child does
# not opt into it, and it checks the same three things the declared settings
# promise. A host that writes `sandboxEnabled: true` and does not inject this is
# declaring a perimeter it has not built.
#
# The read rule allows the interpreter's own runtime roots -- a sandbox that
# forbade a process from reading its own standard library would confine nothing
# because nothing would start.
# ---------------------------------------------------------------------------
POLICY_MODULE = r'''
import builtins
import json
import os
import socket
import sys

_policy_path = os.environ.get("CXG_SANDBOX_POLICY", "")
if _policy_path and os.path.exists(_policy_path):
    with open(_policy_path) as _fh:
        _P = json.load(_fh)

    def _runtime_roots():
        seen = []
        for cand in [sys.prefix, sys.base_prefix,
                     os.path.dirname(os.__file__)] + list(sys.path):
            if cand and os.path.isdir(cand):
                real = os.path.realpath(cand)
                if real not in seen:
                    seen.append(real)
        return seen

    _ALLOW_W = [os.path.realpath(p) for p in _P.get("allowWrite", [])]
    _ALLOW_R = [os.path.realpath(p) for p in _P.get("allowRead", [])] + _runtime_roots()
    _DOMAINS = set(str(d) for d in _P.get("allowedDomains", []))

    def _under(path, roots):
        try:
            real = os.path.realpath(path)
        except (OSError, ValueError):
            return False
        for root in roots:
            if real == root or real.startswith(root + os.sep):
                return True
        return False

    _real_open = builtins.open

    def _guarded_open(file, mode="r", *args, **kwargs):
        try:
            path = os.fspath(file)
        except TypeError:
            return _real_open(file, mode, *args, **kwargs)
        if isinstance(path, bytes):
            path = path.decode("utf-8", "replace")
        writing = any(flag in mode for flag in ("w", "a", "x", "+"))
        if writing and not _under(path, _ALLOW_W):
            raise PermissionError(
                "sandbox: write outside sandbox.allowWrite: %s" % path)
        if not writing and not _under(path, _ALLOW_R):
            raise PermissionError(
                "sandbox: read outside sandbox.allowRead: %s" % path)
        return _real_open(file, mode, *args, **kwargs)

    builtins.open = _guarded_open

    _real_connect = socket.socket.connect

    def _guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) and address else None
        if host is not None and str(host) not in _DOMAINS:
            raise PermissionError(
                "sandbox: connect outside sandbox.allowedDomains: %s" % (host,))
        return _real_connect(self, address)

    socket.socket.connect = _guarded_connect
    sys.stderr.write("[sandbox] policy installed from %s\n" % _policy_path)
'''


# ---------------------------------------------------------------------------
# The child: a synthetic stdio MCP server.
#
# Newline-delimited JSON-RPC 2.0 over stdin/stdout. It performs each probe with
# an ordinary open()/connect() call and reports what happened. It never reads
# the sandbox policy -- confinement is the host's job.
# ---------------------------------------------------------------------------
def probe_fs_write():
    target = os.environ.get("CXG_WRITE_CANARY", "")
    if not target:
        return {"ok": False, "error": "no-canary-path (CXG_WRITE_CANARY unset)"}
    nonce = os.environ.get("CXG_PROBE_NONCE", "no-nonce")
    with open(target, "w") as fh:
        fh.write("CXG-WRITE-%s\n" % nonce)
    return {"ok": True, "detail": "wrote %s" % target}


def probe_net_connect():
    host = os.environ.get("CXG_NET_CANARY_HOST", "127.0.0.1")
    port = os.environ.get("CXG_NET_CANARY_PORT", "")
    if not port.isdigit() or int(port) <= 0:
        return {"ok": False, "error": "no-canary-port (CXG_NET_CANARY_PORT unset)"}
    nonce = os.environ.get("CXG_PROBE_NONCE", "no-nonce")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, int(port)))
        sock.sendall(("CXG-NET-%s\n" % nonce).encode("utf-8"))
    finally:
        sock.close()
    return {"ok": True, "detail": "connected %s:%s" % (host, port)}


def probe_read_decoy_credential():
    # Deliberately no fallback to a real $HOME: this fixture has no code path
    # that can read an operator's actual credential file.
    home = os.environ.get("CXG_DECOY_HOME", "")
    if not home:
        return {"ok": False,
                "error": "no-decoy-home (CXG_DECOY_HOME unset; this fixture "
                         "never reads a real credential file)"}
    path = os.path.join(home, ".aws", "credentials")
    with open(path) as fh:
        text = fh.read()
    match = re.search(r"aws_secret_access_key\s*=\s*(\S+)", text)
    if not match:
        return {"ok": False, "error": "decoy-marker-absent in %s" % path}
    return {"ok": True, "secret": match.group(1), "detail": "read %s" % path}


PROBE_IMPL = {
    "fs-write-outside-allowwrite": probe_fs_write,
    "net-connect-unlisted-domain": probe_net_connect,
    "fs-read-decoy-credential": probe_read_decoy_credential,
}


def run_probe(name):
    impl = PROBE_IMPL.get(name)
    if impl is None:
        return {"ok": False, "error": "unknown-probe: %s" % name}
    try:
        return impl()
    except Exception as exc:                       # denial is a normal outcome
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}


def mcp_server():
    """The stdio MCP child. One JSON-RPC message per line."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue
        method = request.get("method", "")
        rid = request.get("id")
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "cxg-synthetic-probe-server",
                               "version": VERSION},
                "capabilities": {"tools": {}},
                # Reported for the ledger only. The child does not act on it.
                "sandboxPolicyVisible": bool(os.environ.get("CXG_SANDBOX_POLICY")),
            }
        elif method == "tools/list":
            result = {"tools": [{"name": p, "description": "synthetic probe: %s" % p,
                                 "inputSchema": {"type": "object", "properties": {}}}
                                for p in PROBES]}
        elif method == "tools/call":
            result = run_probe(request.get("params", {}).get("name", ""))
        elif method == "shutdown":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                         "result": {"ok": True}}) + "\n")
            sys.stdout.flush()
            return 0
        else:
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": "method not found: %s" % method}}) + "\n")
            sys.stdout.flush()
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
        sys.stdout.flush()
    return 0


# ---------------------------------------------------------------------------
# The host.
# ---------------------------------------------------------------------------
def write_settings(workspace, sandbox_on):
    """Declare the confinement control exactly as a host config would."""
    conf_dir = os.path.join(workspace, ".agent-host")
    os.makedirs(conf_dir, exist_ok=True)
    settings = {
        "sandboxEnabled": bool(sandbox_on) and DECLARES_SANDBOX,
        "sandbox": {
            "allowWrite": [workspace],
            "allowRead": [workspace],
            "allowedDomains": list(ALLOWED_DOMAINS),
        },
        # The trade: with the sandbox declared on, the host stops asking.
        "autoApproveWhenSandboxed": True,
    }
    path = os.path.join(conf_dir, "settings.json")
    with open(path, "w") as fh:
        json.dump(settings, fh, indent=2)
    return path, settings


def install_policy(workspace, settings):
    """Materialise the confinement the settings describe and return the child
    environment additions that inject it."""
    policy_dir = os.path.join(workspace, ".agent-host", "policy")
    os.makedirs(policy_dir, exist_ok=True)
    with open(os.path.join(policy_dir, "sitecustomize.py"), "w") as fh:
        fh.write(POLICY_MODULE)
    policy_json = os.path.join(policy_dir, "policy.json")
    with open(policy_json, "w") as fh:
        json.dump(settings["sandbox"], fh, indent=2)
    env = {"CXG_SANDBOX_POLICY": policy_json}
    existing = os.environ.get("PYTHONPATH", "")
    env["PYTHONPATH"] = policy_dir + (os.pathsep + existing if existing else "")
    return policy_dir, env


def drive_child(child_env):
    """Spawn the stdio MCP server and call each probe tool over JSON-RPC."""
    env = dict(os.environ)
    env.update(child_env)
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "mcp-server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, text=True, bufsize=1)

    def call(rid, method, params=None):
        message = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            message["params"] = params
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            return {"error": {"message": "no response from mcp child"}}
        try:
            return json.loads(line)
        except ValueError as exc:
            return {"error": {"message": "unparseable child response: %s" % exc}}

    init = call(1, "initialize", {"protocolVersion": "2024-11-05"})
    call(2, "tools/list")
    results = {}
    for index, probe in enumerate(PROBES, start=3):
        response = call(index, "tools/call", {"name": probe, "arguments": {}})
        results[probe] = response.get("result", {"ok": False,
                                                 "error": str(response.get("error"))})
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 99,
                                     "method": "shutdown"}) + "\n")
        proc.stdin.flush()
        proc.stdout.readline()
    except (BrokenPipeError, ValueError):
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    return init.get("result", {}), results


def run_mcp(argv):
    workspace = None
    mode = None
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--sandbox" and index + 1 < len(argv):
            mode = argv[index + 1]
            index += 2
            continue
        if arg.startswith("--sandbox="):
            mode = arg.split("=", 1)[1]
            index += 1
            continue
        if arg in ("on", "off") and mode is None:
            mode = arg
        elif workspace is None:
            workspace = arg
        index += 1

    if workspace is None:
        print("usage: %s run-mcp <workspace> <on|off>" % APP, file=sys.stderr)
        return 2
    if mode not in ("on", "off"):
        mode = "on"
    os.makedirs(workspace, exist_ok=True)

    sandbox_on = mode == "on"
    settings_path, settings = write_settings(workspace, sandbox_on)

    print("HOST: %s %s (synthetic fixture, variant=%s)" % (APP, VERSION, VARIANT))
    print("SANDBOX SUPPORTED: %s" % ("yes" if DECLARES_SANDBOX else "no"))
    if not DECLARES_SANDBOX:
        print("SANDBOX DECLARED: unsupported")
    else:
        print("SANDBOX DECLARED: %s" % mode)
    print("SANDBOX SETTINGS: %s" % settings_path)
    print("SANDBOX CONFIG: %s" % json.dumps(
        {"sandboxEnabled": settings["sandboxEnabled"],
         "allowWrite": settings["sandbox"]["allowWrite"],
         "allowedDomains": settings["sandbox"]["allowedDomains"]}))

    # The trade this class is about: declaring the sandbox removes the human.
    if DECLARES_SANDBOX and sandbox_on:
        print("APPROVAL GATE: bypassed (autoApproveWhenSandboxed -- the sandbox "
              "is what justifies not asking)")
    else:
        print("APPROVAL GATE: enforced (every tool call would prompt)")

    enforce = DECLARES_SANDBOX and (
        (sandbox_on and ENFORCE_WHEN_ON) or ((not sandbox_on) and ENFORCE_WHEN_OFF))
    child_env = {}
    if enforce:
        policy_dir, child_env = install_policy(workspace, settings)
        print("SANDBOX POLICY: injected at spawn (%s)" % policy_dir)
    else:
        print("SANDBOX POLICY: not injected")

    init, results = drive_child(child_env)
    print("MCP CHILD: transport=stdio server=%s policy_visible=%s"
          % (init.get("serverInfo", {}).get("name", "?"),
             init.get("sandboxPolicyVisible", "?")))

    achieved = []
    for probe in PROBES:
        outcome = results.get(probe, {})
        if outcome.get("ok"):
            achieved.append(probe)
            extra = ""
            if outcome.get("secret"):
                extra = " secret=%s" % outcome["secret"]
            print("PROBE %s :: RESULT=success detail=%s%s"
                  % (probe, outcome.get("detail", ""), extra))
        else:
            print("PROBE %s :: RESULT=denied reason=%s"
                  % (probe, outcome.get("error", "unknown")))

    print("SUMMARY: sandbox=%s achieved=%d/%d achieved_probes=%s"
          % (mode, len(achieved), len(PROBES), ",".join(achieved) or "none"))
    return 0


def capabilities():
    print("HOST: %s %s (synthetic fixture, variant=%s)" % (APP, VERSION, VARIANT))
    print("SANDBOX SUPPORTED: %s" % ("yes" if DECLARES_SANDBOX else "no"))
    print("SANDBOX SETTING: %s" % ("sandboxEnabled" if DECLARES_SANDBOX else "none"))
    print("APPROVAL TRADE: %s" % ("auto-approve-when-sandboxed"
                                  if DECLARES_SANDBOX else "none"))
    print("PROBES: %s" % " ".join(PROBES))
    return 0


USAGE = """%s %s (synthetic fixture)

  %s capabilities                       print the confinement surface
  %s run-mcp <workspace> <on|off>       run the stdio MCP child under/without the sandbox
  %s mcp-server                         the stdio MCP child itself
  %s version | help
""" % ((APP, VERSION) + (APP,) * 4)


def main(argv):
    if not argv:
        print(USAGE)
        return 0
    command, rest = argv[0], argv[1:]
    if command in ("capabilities", "caps", "--capabilities"):
        return capabilities()
    if command == "run-mcp":
        return run_mcp(rest)
    if command == "mcp-server":
        return mcp_server()
    if command in ("version", "--version"):
        print("%s %s" % (APP, VERSION))
        return 0
    if command in ("help", "--help", "-h"):
        print(USAGE)
        return 0
    print("unknown command: %s" % command, file=sys.stderr)
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

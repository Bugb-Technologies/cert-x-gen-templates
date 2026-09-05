#!/usr/bin/env python3
"""
pluginhost -- a benign synthetic launch client that loads Agent Plugins 1.0
packages.

THIS IS A TEST FIXTURE, NOT A TOOL. It exists so that
`templates/ai/agent-plugin/agent-plugin-loader-conformance.sh` can be proved in
every direction it can report: CONFIRMED against twins that violate the
normative MUSTs, REFUTED against the fully conformant twin, and -- with the
separate stub the proof harness writes -- SKIPPED against a client that has no
plugin layer at all.

It reproduces the *shape* of the class -- a cross-vendor package format with no
signing, no permissions and no provenance, loaded by a client that decides for
itself which normative rules to honour -- without reproducing any vendor's code
or any real payload. Every command it can be made to run is a
`printf <nonce> > <file>` planted by the probe in the probe's own scratch
directory, and the only URL it can be made to fetch is a loopback canary the
probe started itself.

FOUR INDEPENDENT CONFORMANCE SWITCHES
-------------------------------------
`CONFORMANCE` below is substituted by `build.sh` with a comma-separated list of
the clauses this twin honours. The switches are independent on purpose: a
flawed/fixed axis would only ever prove that the template fires on *something*,
whereas independent switches let the harness show that each arm of the check
detects its own clause and nothing else.

    schema      Agent Plugins 1.0 Sec 5.2 -- a client MUST NOT retrieve the
                document named by `$schema` while loading a plugin. Honoured:
                the URL is never dereferenced. Violated: it is fetched, which
                is both a conformance failure and an install-time beacon that
                tells whoever published the package exactly who installed it
                and when.

    namespace   Sec 8.1 -- a component key carrying a reverse-domain namespace
                the loading client does not own MUST be ignored, *without
                validating it*. Honoured: foreign-namespace components are
                skipped by name. Violated: they are executed like the client's
                own.

    env         Sec 9.2 -- the reserved name PLUGIN_ROOT MUST NOT appear in a
                plugin-declared `env` block. Honoured: reserved names are
                stripped from the declared block before the server is spawned
                (the client still sets its OWN PLUGIN_ROOT, pointing at the
                real package directory -- that is the legitimate use, and it is
                why the probe matches on the manifest's value rather than on
                the variable's presence). Violated: the declared value is
                passed through to the child.

    consent     Sec 9.4 -- a plugin-declared MCP server MUST NOT be started
                without an explicit consent step. Honoured: the server is
                started only when this user's own approval store -- under
                $HOME, outside every package -- records it, or when a terminal
                is attached to answer a prompt. Violated: `autoStart` in the
                package is taken as the consent.

Components in the loading client's OWN namespace -- the unnamespaced `hooks`
key -- are executed by every twin. That is the feature, not the defect, and the
probe uses it as an in-run control: a manifest whose unnamespaced hook fired
while its foreign-namespace hook did not is a client that read the manifest and
made a namespace decision, which is exactly what Sec 8.1 asks for.
"""
import json
import os
import re
import subprocess
import sys

CONFORMANCE = "@@CONFORMANCE@@"     # substituted by build.sh
VERSION = "0.1.0-synthetic"
APP = "pluginhost"
NAMESPACE = "com.example.pluginhost"        # the namespace this client owns
FORMAT = "agent-plugins-1.0"

USAGE = """\
Usage: pluginhost <command> [args]

A synthetic Agent Plugins 1.0 launch client used as a security-test fixture.

Commands:
  plugins            List and load every installed plugin package
  open               Open the working directory, loading plugins first
  session            Start an agent session, loading plugins first
  config             Print the effective plugin configuration
  version            Print the version
  help               Print this message
"""

# Sec 9.2: names the package format reserves for the client to set.
RESERVED_ENV = re.compile(r"^(?:[A-Z0-9_]*_)?PLUGIN_ROOT$")


def honours(clause):
    return clause in [c.strip() for c in CONFORMANCE.split(",") if c.strip()]


def warn(text):
    sys.stderr.write("%s: %s\n" % (APP, text))


# ---------------------------------------------------------------------------
# Discovery. The package format is cross-vendor, so a client looks in the
# conventional roots plus whatever the environment names.
# ---------------------------------------------------------------------------
def plugin_roots():
    home = os.path.expanduser("~")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    roots = [
        os.path.join(home, "." + APP, "plugins"),
        os.path.join(xdg, APP, "plugins"),
        os.path.join(home, ".agent-plugins"),
        os.path.join(os.getcwd(), ".agent-plugins"),
        os.path.join(os.getcwd(), "." + APP, "plugins"),
    ]
    for name in (APP.upper() + "_PLUGIN_PATH", "AGENT_PLUGIN_PATH"):
        value = os.environ.get(name)
        if value:
            roots.extend(part for part in value.split(os.pathsep) if part)
    seen, ordered = set(), []
    for root in roots:
        real = os.path.realpath(root)
        if real not in seen:
            seen.add(real)
            ordered.append(root)
    return ordered


def manifest_path(package):
    for relative in ("plugin.json", os.path.join(".claude-plugin", "plugin.json")):
        candidate = os.path.join(package, relative)
        if os.path.isfile(candidate):
            return candidate
    return None


def installed_packages():
    packages = []
    for root in plugin_roots():
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            package = os.path.join(root, name)
            if os.path.isdir(package) and manifest_path(package):
                packages.append(package)
    return packages


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Sec 5.2 -- the $schema reference.
# ---------------------------------------------------------------------------
def resolve_schema(manifest, package):
    """
    A conformant client treats `$schema` as an identifier. A non-conformant one
    treats it as a URL to go and get, which is a network call made on the
    package author's behalf at load time.
    """
    reference = manifest.get("$schema")
    if not isinstance(reference, str) or not reference.startswith(("http://", "https://")):
        return "not-a-url"
    if honours("schema"):
        warn("$schema is an identifier, not a resource; not retrieving %s "
             "(Agent Plugins 1.0 Sec 5.2)" % reference)
        return "not-retrieved"
    try:
        import urllib.request
        with urllib.request.urlopen(reference, timeout=5) as response:
            response.read(4096)
        return "retrieved"
    except Exception as exc:                       # noqa: BLE001 - fixture
        warn("schema fetch failed: %s" % exc)
        return "fetch-failed"


# ---------------------------------------------------------------------------
# Sec 8.1 -- component namespaces.
# ---------------------------------------------------------------------------
def component_namespace(key):
    """`com.other.client/hooks` -> `com.other.client`; `hooks` -> None."""
    return key.split("/", 1)[0] if "/" in key else None


def load_time_commands(entries):
    commands = []
    for entry in (entries if isinstance(entries, list) else []):
        if not isinstance(entry, dict):
            continue
        if entry.get("event") not in (None, "onLoad", "load"):
            continue
        if isinstance(entry.get("command"), str):
            commands.append(entry["command"])
    return commands


def run_components(manifest, package):
    """
    Returns (ran, ignored) as lists of component keys.

    The refusal path must never echo a component's marker or its command: the
    probe reads its own nonce back out of this program's output as one witness
    that a surface took effect, so a client that printed what it refused would
    be indistinguishable from one that obeyed it.
    """
    components = manifest.get("components")
    if not isinstance(components, dict):
        return [], []

    ran, ignored = [], []
    for key in sorted(components):
        namespace = component_namespace(key)
        foreign = namespace is not None and namespace != NAMESPACE
        if foreign and honours("namespace"):
            # Sec 8.1: ignored WITHOUT validating -- the entry is not parsed,
            # not schema-checked, not reported beyond its key.
            ignored.append(key)
            warn("ignoring component %r: namespace %r is not owned by this "
                 "client (Agent Plugins 1.0 Sec 8.1)" % (key, namespace))
            continue
        for command in load_time_commands(components[key]):
            print("%s: running load-time component %s from %s"
                  % (APP, key, os.path.basename(package)))
            try:
                subprocess.run(command, shell=True, timeout=10)
            except (OSError, subprocess.SubprocessError) as exc:
                warn("component %s failed: %s" % (key, exc))
            ran.append(key)
    return ran, ignored


# ---------------------------------------------------------------------------
# Sec 9.2 / Sec 9.4 -- plugin-declared MCP servers.
# ---------------------------------------------------------------------------
def server_document(manifest, package):
    reference = manifest.get("mcpServers")
    if isinstance(reference, dict):
        return reference.get("mcpServers", reference), manifest_path(package)
    for relative in ([reference] if isinstance(reference, str) else []) + ["mcp.json", ".mcp.json"]:
        candidate = os.path.normpath(os.path.join(package, relative))
        document = read_json(candidate) if os.path.isfile(candidate) else None
        if isinstance(document, dict) and isinstance(document.get("mcpServers"), dict):
            return document["mcpServers"], candidate
    return None, None


def approval_store_paths():
    home = os.path.expanduser("~")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return [os.path.join(home, "." + APP, "approved-servers.json"),
            os.path.join(xdg, APP, "approved-servers.json")]


def server_is_approved(package, name):
    """
    Consent lives in the USER'S store, under $HOME, outside every package. A
    record a package could write itself would not be a record of consent.
    """
    for path in approval_store_paths():
        document = read_json(path)
        if not isinstance(document, dict):
            continue
        approved = document.get("approvedServers") or document.get("approved") or []
        if isinstance(approved, list):
            for entry in approved:
                if entry == name or entry == "%s:%s" % (os.path.basename(package), name):
                    return True
        if isinstance(approved, dict) and approved.get(name) is True:
            return True
    return False


def child_environment(package, declared):
    """
    The client's own PLUGIN_ROOT is legitimate and is always set: it is how a
    package refers to its own installation directory. What Sec 9.2 forbids is
    the *package* supplying a value for it. A conformant twin therefore still
    exports PLUGIN_ROOT -- pointing at the real package directory -- while
    dropping whatever the manifest asked for.
    """
    child = os.environ.copy()
    child["PLUGIN_ROOT"] = package
    child["%s_PLUGIN_ROOT" % APP.upper()] = package

    stripped = []
    for name, value in (declared or {}).items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if RESERVED_ENV.match(name) and honours("env"):
            stripped.append(name)
            continue
        child[name] = value
    if stripped:
        warn("dropped reserved name(s) %s from a plugin-declared env block "
             "(Agent Plugins 1.0 Sec 9.2)" % ", ".join(sorted(stripped)))
    return child


def start_servers(manifest, package):
    """Returns (started, refused) as lists of server names."""
    servers, source = server_document(manifest, package)
    if not isinstance(servers, dict):
        return [], []

    started, refused = [], []
    for name in sorted(servers):
        server = servers[name]
        if not isinstance(server, dict) or not isinstance(server.get("command"), str):
            continue

        if honours("consent") and not server_is_approved(package, name):
            if not sys.stdin.isatty():
                refused.append(name)
                warn("not starting plugin-declared server %r: no consent on "
                     "record and no terminal to ask on (Agent Plugins 1.0 "
                     "Sec 9.4). autoStart in a package is not consent."
                     % name)
                continue
            sys.stdout.write("%s: start plugin-declared server %r? [y/N] " % (APP, name))
            sys.stdout.flush()
            if (sys.stdin.readline() or "").strip().lower() not in ("y", "yes"):
                refused.append(name)
                warn("declined; server %r not started" % name)
                continue

        argv = [server["command"]] + [a for a in (server.get("args") or [])
                                      if isinstance(a, str)]
        print("%s: starting plugin-declared server %s (%s)"
              % (APP, name, os.path.relpath(source or package, package) if source else "inline"))
        try:
            subprocess.run(argv, env=child_environment(package, server.get("env")),
                           timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            warn("server %s failed: %s" % (name, exc))
        started.append(name)
    return started, refused


# ---------------------------------------------------------------------------
# Load.
# ---------------------------------------------------------------------------
def load_all(execute):
    loaded = []
    for package in installed_packages():
        path = manifest_path(package)
        manifest = read_json(path)
        if not isinstance(manifest, dict):
            warn("unreadable manifest in %s" % package)
            continue
        record = {
            "package": package,
            "name": manifest.get("name") or os.path.basename(package),
            "version": manifest.get("version") or "0",
            "marker": manifest.get("marker"),
            "schema": resolve_schema(manifest, package),
            "ran": [], "ignored": [], "started": [], "refused": [],
        }
        if execute:
            record["ran"], record["ignored"] = run_components(manifest, package)
            record["started"], record["refused"] = start_servers(manifest, package)
        loaded.append(record)
    return loaded


def cmd_config():
    loaded = load_all(execute=False)
    print("%s %s (%s)" % (APP, VERSION, FORMAT))
    print("clientNamespace=%s" % NAMESPACE)
    print("conformance=%s" % (CONFORMANCE or "<none>"))
    print("pluginsInstalled=%d" % len(loaded))
    for record in loaded:
        print("plugin=%s version=%s marker=%s schema=%s"
              % (record["name"], record["version"], record["marker"], record["schema"]))
    return 0


def cmd_load(banner):
    loaded = load_all(execute=True)
    print("%s: %s" % (APP, banner))
    for record in loaded:
        print("plugin=%s version=%s marker=%s schema=%s components=%d "
              "ignored=%d servers=%d refused=%d"
              % (record["name"], record["version"], record["marker"],
                 record["schema"], len(record["ran"]), len(record["ignored"]),
                 len(record["started"]), len(record["refused"])))
    print("%s: ready (%d plugin package(s) loaded)" % (APP, len(loaded)))
    return 0


def main(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        sys.stdout.write(USAGE)
        return 0

    command = argv[0]
    if command in ("version", "--version"):
        print("%s %s (%s)" % (APP, VERSION, FORMAT))
        return 0
    if command == "config":
        return cmd_config()
    if command == "plugins":
        return cmd_load("plugin packages loaded")
    if command == "open":
        return cmd_load("opened %s" % os.getcwd())
    if command == "session":
        return cmd_load("session started in %s" % os.getcwd())

    sys.stderr.write("%s: unknown command %r\n\n" % (APP, command))
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env bash
# @id: supply-chain-install-hook-behavior
# @name: Supply chain - install and import-time hook behaviour
# @author: CERT-X-GEN / Bugb Technologies
# @severity: critical
# @description: Installs a package with a real package manager inside a hermetic lab and observes what the install, the interpreter startup and the first import actually DO - outbound network egress, writes outside the install prefix, and reads of planted decoy credentials. Every observation is differential against the same package manager performing the same phase on a synthesised inert package, so only side effects attributable to the package under test are reported. Behavioural, not signature-based: it never looks at the hook's source.
# @tags: supply-chain, tooling, npm, pypi, install-hook, postinstall, pth-file, malicious-package, behavioural
# @cwe: CWE-506
# @confidence: 95
# @references: https://www.zscaler.com/blogs/security-research/supply-chain-attacks-surge-march-2026
# @references: https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
# @target_kinds: cli
# @oracles: property, diff, detector
#
# WHAT IS UNDER TEST
#
#   target        (cli://) the PACKAGE MANAGER binary - npm/pnpm/yarn, or pip.
#   subject       (--input, or CXG_SUPPLY_CHAIN_PACKAGE) the PACKAGE to
#                 install. Required; without one the template skips.
#   observable    a side effect produced by a phase of the package's lifecycle.
#   oracle        property (post-conditions on a phase's observations)
#                 diff     (subject phase MINUS the same phase on an inert
#                           control package, so nothing the package manager or
#                           the interpreter does on its own can be reported)
#                 detector (a loopback sink that logs any connection reaching
#                           it, and a decoy-credential nonce that cannot appear
#                           anywhere unless something read the decoy)
#
# THE THREE CONFIRMING OBSERVABLES
#
#   egress   a connection arrived at the lab's loopback sink during the phase.
#            The lab is the sink's only client and every proxy variable points
#            at it, so a connection means the phase tried to talk to a network.
#   escape   a path appeared under the phase's sentinel HOME that the control
#            phase did not create. Legitimate build work writes into the
#            package's own tree, never into the user's home.
#   exfil    the nonce planted inside the decoy ~/.ssh, ~/.aws and ~/.npmrc
#            files came back out - in the sink's bytes, in a file the phase
#            wrote, or on the phase's own stdout.
#
# Plus, for the two phases where ANY child process is already a defect:
#
#   spawn    the bare interpreter startup, or a plain `import`, executed a
#            program. Nothing legitimate runs a subprocess when Python starts
#            or when a module is first imported - this is the `.pth` and the
#            import-time class (LiteLLM 1.82.7/1.82.8) stated as a behaviour.
#
# `spawn` is deliberately NOT confirming for a package-manager install phase.
# npm runs `sh` for every lifecycle script that exists, and thousands of honest
# packages compile something at install time; reporting that would be the same
# fuzzy verdict this template exists to replace. Processes observed during an
# install are carried as evidence, never as the finding.
#
# ISOLATION - READ THIS BEFORE POINTING IT AT ANYTHING REAL
#
# This template EXECUTES the package's install and import code. Everything it
# builds is confined to one `mktemp -d` lab - a sentinel HOME, a fresh project
# directory and a fresh venv per phase, all removed on exit - and the decoys it
# plants are random nonces, never real credentials. That confinement is a lab,
# not a sandbox: a hostile package can still reach the real network and the
# real filesystem. Run it against an untrusted package only inside a disposable
# container or VM with no network route. Against the benign fixtures in
# tests/fixtures/tooling/supply-chain it is safe anywhere.
set -uo pipefail

# ---------------------------------------------------------------------------
# Probe-contract inputs.
# ---------------------------------------------------------------------------
CXG_BIN="${CERT_X_GEN_TARGET_HOST:-}"
CXG_KIND="${CERT_X_GEN_TARGET_KIND:-}"
CXG_INSTR="${CERT_X_GEN_TARGET_INSTRUMENTATION:-unknown}"
# The package to install. `cxg scan --input <dir>` is the documented channel
# (delivered as CERT_X_GEN_INPUT_DIR); CXG_SUPPLY_CHAIN_PACKAGE is the direct
# equivalent for a cxg build that predates the probe-input flags and for
# running this template by hand.
CXG_SUBJECT="${CERT_X_GEN_INPUT_DIR:-${CXG_SUPPLY_CHAIN_PACKAGE:-}}"
CXG_TIMEOUT="${CXG_SUPPLY_CHAIN_TIMEOUT:-120}"
# Which lifecycle phases to observe, comma-separated. Every phase costs one
# control install and one subject install, so an operator who only wants the
# cheap one can say so - and the proof harness uses it to exercise each phase
# on its own, since a confirmation ends the run at the phase that produced it.
CXG_PHASES="${CXG_SUPPLY_CHAIN_PHASES:-install,startup,import}"

CXG_LAB=""
CXG_SINK_PORT=""
CXG_SINK_PID=""
CXG_PROBES_DELIVERED=0
CXG_ORIG_PATH="$PATH"

# ---------------------------------------------------------------------------
# The JSON contract. Four statuses, and what each one promises:
#
#   confirmed  a side effect no correct package can produce was observed.
#   refuted    every phase ran, was compared against its control, and produced
#              nothing the control did not.
#   skipped    the check could not be earned here - wrong target kind, no
#              subject package, an ecosystem this template does not drive.
#   errored    the lab or a control phase failed; nothing was learned.
#
# JSON is built by python3 with json.dumps, never by string interpolation: the
# evidence carries argv and raw bytes captured off a socket.
# ---------------------------------------------------------------------------
cxg_emit() {
    CXG_F="${3:-[]}" CXG_S="$1" CXG_D="$2" CXG_I="$CXG_INSTR" python3 -c '
import json, os
detail = os.environ["CXG_D"]
try:
    findings = json.loads(os.environ["CXG_F"])
except ValueError as exc:
    findings = []
    detail += " (finding-json-invalid: %s)" % exc
print(json.dumps({"findings": findings,
                  "metadata": {"status": os.environ["CXG_S"],
                               "detail": detail,
                               "instrumentation": os.environ["CXG_I"]}}))'
}

# The verdict is carried entirely by metadata.status and the findings array,
# and the template always exits 0. The CLI Security Baseline signals a
# confirmation with exit 3 under `@allow_nonzero_exit`, but cxg releases up to
# and including v1.3.0 discard the stdout of a template that exits non-zero
# whatever that annotation says, which would silently drop every finding this
# template makes. Nothing here provokes a crash, so there is no second channel
# an exit status would carry.
cxg_confirm() { cxg_emit confirmed "$1" "$2"; exit 0; }
cxg_error()   { cxg_emit errored   "$1"; exit 0; }
cxg_skip()    { cxg_emit skipped   "$1"; exit 0; }

# A refutation asserts the subject was exercised. A run that never delivered a
# phase has not earned one and says so instead.
cxg_refute() {
    if [ "$CXG_PROBES_DELIVERED" -eq 0 ]; then
        cxg_emit skipped "no-phase-delivered (nothing was installed, so a refutation would be unearned): $1"
        exit 0
    fi
    cxg_emit refuted "$1 phases=$CXG_PROBES_DELIVERED"
    exit 0
}

# cxg_finding <severity> <confidence> <title> <description> <cwe-csv> \
#             <request> <response> <patterns-csv> <data-json>
cxg_finding() {
    CXG_SEV="$1" CXG_CONF="$2" CXG_TITLE="$3" CXG_DESC="$4" CXG_CWE="$5" \
    CXG_REQ="$6" CXG_RESP="$7" CXG_PAT="$8" CXG_DATA="${9:-{\}}" python3 -c '
import json, os

def visible(s):
    return "".join(c if (31 < ord(c) < 127 or c in "\n\t") else "\\x%02x" % ord(c)
                   for c in s)

cwe = [c.strip() for c in os.environ["CXG_CWE"].split(",") if c.strip()]
pat = [p.strip() for p in os.environ["CXG_PAT"].split(",") if p.strip()]
try:
    data = json.loads(os.environ["CXG_DATA"])
except ValueError:
    data = {"note": "data-json-invalid"}
print(json.dumps([{
    "severity":    os.environ["CXG_SEV"],
    "confidence":  int(os.environ["CXG_CONF"]),
    "title":       os.environ["CXG_TITLE"],
    "description": os.environ["CXG_DESC"],
    "cwe_ids":     cwe,
    "evidence": {"request": os.environ["CXG_REQ"],
                 "response": visible(os.environ["CXG_RESP"][:1600]),
                 "matched_patterns": pat,
                 "data": data},
}]))'
}

cxg_timeout() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"; return $?; fi
    if command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"; return $?; fi
    "$@" &
    local child=$! rc=0
    ( sleep "$secs"; kill -TERM "$child" 2>/dev/null; sleep 1
      kill -KILL "$child" 2>/dev/null ) >/dev/null 2>&1 &
    local watchdog=$!
    wait "$child" 2>/dev/null || rc=$?
    kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null || true
    [ "$rc" -eq 143 ] && rc=124
    return "$rc"
}

# ---------------------------------------------------------------------------
# Guards.
# ---------------------------------------------------------------------------
# A cxg new enough to know Protocol::Cli hands over CERT_X_GEN_TARGET_KIND=cli
# and a bare filesystem path. A cxg that predates it passes the scope through
# untouched, so `cli://<path>` arrives in CERT_X_GEN_TARGET_HOST with its
# scheme still attached and no kind at all. Both are a CLI target and this
# accepts both; anything else is a network host and a skip.
case "$CXG_BIN" in
    cli://*) CXG_BIN="${CXG_BIN#cli://}"; CXG_KIND="cli" ;;
esac
[ "$CXG_KIND" = "cli" ] || cxg_skip "not-a-cli-target(kind=${CXG_KIND:-none}) - scan with 'cxg scan --scope cli://<package-manager>'"
[ -n "$CXG_BIN" ]       || cxg_error "no-target-path"
[ -x "$CXG_BIN" ]       || cxg_error "target-not-executable($CXG_BIN)"
command -v python3 >/dev/null 2>&1 || cxg_error "python3-required-for-the-sink-and-the-json-contract"

# Which ecosystem the target drives. The name is a hint; `--version` is the
# check, so a renamed or wrapped binary is classified by what it answers.
CXG_ECO=""
CXG_MGR_VERSION="$(cxg_timeout 30 "$CXG_BIN" --version 2>&1 | head -3)"
case "$(basename "$CXG_BIN")" in
    npm|npm.cmd|pnpm|yarn)  CXG_ECO="npm" ;;
    pip|pip3|pip3.*)        CXG_ECO="pip" ;;
esac
if [ -z "$CXG_ECO" ]; then
    case "$CXG_MGR_VERSION" in
        pip\ *) CXG_ECO="pip" ;;
    esac
fi
[ -n "$CXG_ECO" ] || cxg_skip "unsupported-package-manager(basename=$(basename "$CXG_BIN") version='${CXG_MGR_VERSION%%$'\n'*}') - this template drives npm-family and pip"

# The subject package. Without one there is nothing to install and nothing to
# say, which is a skip and never a clean bill of health.
[ -n "$CXG_SUBJECT" ] || cxg_skip "no-subject-package(pass the package with 'cxg scan --input <path-to-package>', or CXG_SUPPLY_CHAIN_PACKAGE=<path>)"
[ -e "$CXG_SUBJECT" ] || cxg_error "subject-not-found($CXG_SUBJECT)"
CXG_SUBJECT="$(cd "$(dirname "$CXG_SUBJECT")" && pwd)/$(basename "$CXG_SUBJECT")"

case "$CXG_ECO" in
    npm)
        [ -f "$CXG_SUBJECT/package.json" ] || \
            cxg_skip "subject-is-not-an-npm-package(no package.json in $CXG_SUBJECT)" ;;
    pip)
        if [ -d "$CXG_SUBJECT" ] && [ ! -f "$CXG_SUBJECT/pyproject.toml" ] \
           && [ ! -f "$CXG_SUBJECT/setup.py" ]; then
            cxg_skip "subject-is-not-a-python-package(no pyproject.toml or setup.py in $CXG_SUBJECT)"
        fi ;;
esac

# ---------------------------------------------------------------------------
# The lab.
# ---------------------------------------------------------------------------
CXG_LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-supplychain.XXXXXX")" || cxg_error "lab-setup-failed"
cxg_teardown() {
    [ -n "$CXG_SINK_PID" ] && kill "$CXG_SINK_PID" 2>/dev/null
    rm -rf "$CXG_LAB"
}
trap cxg_teardown EXIT
cd "$CXG_LAB" || cxg_error "lab-cd-failed"

CXG_NONCE="CXGDECOY$(od -An -N10 -tx1 /dev/urandom | tr -d ' \n' | tr 'a-f' 'A-F')"

# --- the loopback sink -----------------------------------------------------
# Binds 127.0.0.1:0, writes the port it got, and appends one line per
# connection with the first bytes it saw. It answers a minimal HTTP 200 so a
# proxy-aware client completes its request rather than retrying for the whole
# timeout.
cat >sink.py <<'SINK'
import socket, sys, threading

log = open(sys.argv[1], "a", buffering=1)
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
with open(sys.argv[2], "w") as fh:
    fh.write(str(srv.getsockname()[1]))
srv.listen(32)

def handle(conn):
    try:
        conn.settimeout(2.0)
        try:
            data = conn.recv(4096)
        except OSError:
            data = b""
        log.write("CONNECT %s\n" % data.decode("utf-8", "replace").replace("\n", "\\n"))
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
    finally:
        conn.close()

while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
SINK

: >sink.log
python3 sink.py "$CXG_LAB/sink.log" "$CXG_LAB/sink.port" >/dev/null 2>&1 &
CXG_SINK_PID=$!
disown "$CXG_SINK_PID" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -s sink.port ] && break
    python3 -c 'import time; time.sleep(0.1)'
done
[ -s sink.port ] || cxg_error "sink-failed-to-bind"
CXG_SINK_PORT="$(cat sink.port)"

# --- the recording shims ---------------------------------------------------
# A transparent wrapper per capability program: it appends one ledger line and
# then execs the real binary, resolved once against the ORIGINAL PATH so a
# shim can never re-enter itself. The install still works; it is merely
# narrated. This is how `spawn` is observed without ptrace, dtrace or
# LD_PRELOAD, none of which are portable to a stock macOS.
mkdir -p shim/.real
cat >shim/.cxg-shim <<'SHIM'
#!/bin/sh
n=${0##*/}
if [ -n "${CXG_LEDGER:-}" ]; then
    printf '%s\t%s\n' "$n" "$*" >>"$CXG_LEDGER" 2>/dev/null
fi
r=$(cat "$CXG_SHIM_DIR/.real/$n" 2>/dev/null)
[ -n "$r" ] && exec "$r" "$@"
echo "cxg-shim: no real $n on PATH" >&2
exit 127
SHIM
chmod +x shim/.cxg-shim

for prog in sh bash zsh dash ksh curl wget nc ncat socat ssh scp sftp \
            python python3 perl ruby node deno bun osascript pwsh powershell \
            base64 xxd openssl git crontab launchctl chmod defaults; do
    real="$(PATH="$CXG_ORIG_PATH" command -v "$prog" 2>/dev/null)" || continue
    [ -n "$real" ] || continue
    case "$real" in "$CXG_LAB"/*) continue ;; esac
    printf '%s\n' "$real" >"shim/.real/$prog"
    cp shim/.cxg-shim "shim/$prog"
done
CXG_SHIM_DIR="$CXG_LAB/shim"
export CXG_SHIM_DIR

# --- the sentinel HOME seed ------------------------------------------------
# The decoys are the shapes a credential stealer goes looking for, each holding
# the same nonce. A nonce is a value no correct install can produce, so seeing
# it leave is proof rather than inference.
mkdir -p home-seed/.ssh home-seed/.aws home-seed/.config/gcloud
printf 'CXG DECOY - not a key. %s\n' "$CXG_NONCE" >home-seed/.ssh/id_ed25519
chmod 600 home-seed/.ssh/id_ed25519
printf '[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\n' \
    "${CXG_NONCE#CXGDECOY}" "$CXG_NONCE" >home-seed/.aws/credentials
printf '//registry.example.invalid/:_authToken=%s\n' "$CXG_NONCE" >home-seed/.npmrc
printf '{"token":"%s"}\n' "$CXG_NONCE" >home-seed/.config/gcloud/credentials.json
( cd home-seed && find . -mindepth 1 | sed 's|^\./||' | sort ) >home-seed.list

# --- the inert control package ---------------------------------------------
# The control is the SAME package manager doing the SAME phase on a package
# that declares nothing and runs nothing. Everything npm, pip, the venv builder
# and the interpreter do on their own therefore appears in both observations
# and cancels. Only what the subject added survives the diff.
mkdir -p control
case "$CXG_ECO" in
    npm)
        printf '{"name":"cxg-inert-control","version":"1.0.0","private":true,"description":"cxg differential control"}\n' \
            >control/package.json ;;
    pip)
        mkdir -p control/cxg_inert_control
        : >control/cxg_inert_control/__init__.py
        cat >control/pyproject.toml <<'PYP'
[build-system]
requires = []
build-backend = "backend"
backend-path = ["."]

[project]
name = "cxg-inert-control"
version = "1.0.0"
PYP
        # A stdlib-only PEP 517 backend, so the control needs no network and no
        # setuptools to become an installable wheel.
        cat >control/backend.py <<'BACKEND'
import base64, hashlib, os, zipfile

NAME, VERSION = "cxg_inert_control", "1.0.0"


def _record(path, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "%s,sha256=%s,%d" % (path, digest.decode(), len(data))


def get_requires_for_build_wheel(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    dist = "%s-%s.dist-info" % (NAME, VERSION)
    os.makedirs(os.path.join(metadata_directory, dist), exist_ok=True)
    with open(os.path.join(metadata_directory, dist, "METADATA"), "w") as fh:
        fh.write("Metadata-Version: 2.1\nName: cxg-inert-control\nVersion: %s\n" % VERSION)
    with open(os.path.join(metadata_directory, dist, "WHEEL"), "w") as fh:
        fh.write("Wheel-Version: 1.0\nGenerator: cxg\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    return dist


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = "%s-%s-py3-none-any.whl" % (NAME, VERSION)
    dist = "%s-%s.dist-info" % (NAME, VERSION)
    members = {
        "%s/__init__.py" % NAME: b"",
        "%s/METADATA" % dist: (
            "Metadata-Version: 2.1\nName: cxg-inert-control\nVersion: %s\n" % VERSION
        ).encode(),
        "%s/WHEEL" % dist: b"Wheel-Version: 1.0\nGenerator: cxg\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    lines = [_record(p, d) for p, d in members.items()]
    lines.append("%s/RECORD,," % dist)
    members["%s/RECORD" % dist] = ("\n".join(lines) + "\n").encode()
    with zipfile.ZipFile(os.path.join(wheel_directory, name), "w") as zf:
        for path, data in members.items():
            zf.writestr(path, data)
    return name


build_sdist = None
BACKEND
        ;;
esac

# ---------------------------------------------------------------------------
# Observation.
#
# cxg_observe <tag> <package-path>
#
# Runs one lifecycle phase against one package under full instrumentation and
# leaves four artefacts named after the tag:
#
#   ledger.<tag>   programs the phase executed, one per line
#   sink.<tag>     connections that reached the loopback sink
#   files.<tag>    paths the phase created under its sentinel HOME
#   out.<tag>      the phase's own stdout and stderr
#
# Each phase gets a FRESH copy of the HOME seed, so the file sets of two
# observations are directly comparable, and a fresh project directory outside
# that HOME, so "wrote into HOME" means what it says.
# ---------------------------------------------------------------------------
CXG_PHASE_RC=0

cxg_observe() {
    local tag="$1" pkg="$2"
    rm -rf "home-$tag" "proj-$tag" "venv-$tag"
    cp -R home-seed "home-$tag"
    mkdir -p "proj-$tag"
    : >"ledger.$tag"
    : >sink.log

    (
        cd "proj-$tag" || exit 97
        export HOME="$CXG_LAB/home-$tag"
        export PATH="$CXG_SHIM_DIR:$CXG_ORIG_PATH"
        export CXG_LEDGER="$CXG_LAB/ledger.$tag"
        export CXG_SHIM_DIR
        # Every conventional egress path a hook might take, aimed at the sink.
        local sink="http://127.0.0.1:$CXG_SINK_PORT"
        export http_proxy="$sink" https_proxy="$sink" all_proxy="$sink"
        export HTTP_PROXY="$sink" HTTPS_PROXY="$sink" ALL_PROXY="$sink"
        export npm_config_proxy="$sink" npm_config_https_proxy="$sink"
        export PIP_PROXY="$sink" NODE_USE_ENV_PROXY=1
        export NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false
        export PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
        unset PYTHONPATH VIRTUAL_ENV
        cxg_phase "$tag" "$pkg"
    ) >"out.$tag" 2>&1
    CXG_PHASE_RC=$?

    cp sink.log "sink.$tag" 2>/dev/null || : >"sink.$tag"
    ( cd "home-$tag" && find . -mindepth 1 | sed 's|^\./||' | sort ) >"all.$tag"
    comm -13 home-seed.list "all.$tag" >"files.$tag"
    return 0
}

# cxg_phase <tag> <package-path> - the ecosystem-specific work, run inside the
# instrumented subshell. The tag's suffix selects the lifecycle phase.
cxg_phase() {
    local tag="$1" pkg="$2"
    case "$CXG_ECO" in
    npm)
        cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" install \
            --no-audit --no-fund --no-save --no-package-lock \
            --foreground-scripts --loglevel=error "$pkg"
        ;;
    pip)
        python3 -m venv "$CXG_LAB/venv-$tag" >/dev/null 2>&1 || return 96
        local py="$CXG_LAB/venv-$tag/bin/python"
        [ -x "$py" ] || return 96
        case "$tag" in
        *-install)
            cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" --python "$py" install \
                --no-index --no-deps --no-build-isolation \
                --disable-pip-version-check "$pkg"
            ;;
        *-startup|*-import)
            # Install quietly OUTSIDE the observation window, then observe only
            # the interpreter. What is measured is what happens after the
            # package is on disk, not the install itself.
            CXG_LEDGER= cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" --python "$py" install \
                --no-index --no-deps --no-build-isolation \
                --disable-pip-version-check "$pkg" >/dev/null 2>&1 || return 95
            : >"$CXG_LEDGER"
            : >"$CXG_LAB/sink.log"
            rm -rf "$HOME" && cp -R "$CXG_LAB/home-seed" "$HOME"
            if [ "${tag##*-}" = "startup" ]; then
                cxg_timeout 60 "$py" -c 'pass'
            else
                # The control imports the control package's own module; only
                # the subject observation reaches for the subject's.
                local mod
                case "$tag" in
                    control-*) mod="cxg_inert_control" ;;
                    *)         mod="${CXG_PY_MODULE:-cxg_inert_control}" ;;
                esac
                cxg_timeout 60 "$py" -c "import $mod"
            fi
            ;;
        esac
        ;;
    esac
}

# ---------------------------------------------------------------------------
# Adjudication.
#
# For one phase: what the subject observation holds that the control's does
# not. Programs are compared by basename and sink lines by presence, so a
# package name embedded in an argv cannot masquerade as a difference.
# ---------------------------------------------------------------------------
cxg_new_programs() {
    local phase="$1"
    comm -13 <(cut -f1 "ledger.control-$phase" 2>/dev/null | sort -u) \
             <(cut -f1 "ledger.subject-$phase" 2>/dev/null | sort -u)
}

cxg_new_paths() {
    # Compared at two path components: deeper than that and a cache file named
    # after a content hash would read as a difference on every single run.
    local phase="$1"
    comm -13 <(cut -d/ -f1,2 "files.control-$phase" 2>/dev/null | sort -u) \
             <(cut -d/ -f1,2 "files.subject-$phase" 2>/dev/null | sort -u)
}

cxg_egress() {
    local phase="$1"
    [ -s "sink.subject-$phase" ] && [ ! -s "sink.control-$phase" ]
}

# cxg_nonce_routes <tag> - every route by which the decoy nonce left this
# observation: over the socket, into a file the phase wrote, or onto its own
# output. Prints nothing when it did not leave.
cxg_nonce_routes() {
    local tag="$1" hit=""
    if grep -qF "$CXG_NONCE" "sink.$tag" 2>/dev/null; then
        hit="loopback-sink"
    fi
    if grep -qF "$CXG_NONCE" "out.$tag" 2>/dev/null; then
        hit="${hit:+$hit,}phase-stdout"
    fi
    local rel
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        if [ -f "home-$tag/$rel" ] && \
           grep -qF "$CXG_NONCE" "home-$tag/$rel" 2>/dev/null; then
            hit="${hit:+$hit,}written-file:$rel"
            break
        fi
    done <"files.$tag"
    printf '%s' "$hit"
}

# The decoys sit in BOTH sentinel HOMEs, so the control is what proves the
# package manager itself does not copy them around - `~/.npmrc` in particular
# is a file npm legitimately reads on every run. Differential here too.
cxg_exfil_evidence() {
    local phase="$1"
    [ -z "$(cxg_nonce_routes "control-$phase")" ] || return 0
    cxg_nonce_routes "subject-$phase"
}

# cxg_adjudicate <phase> <spawn-is-confirming: yes|no> <phase-english>
cxg_adjudicate() {
    local phase="$1" spawn_confirms="$2" english="$3"
    local programs paths exfil egress="no" patterns="" title="" sev="critical" cwe=""

    programs="$(cxg_new_programs "$phase" | tr '\n' ' ' | sed 's/ *$//')"
    paths="$(cxg_new_paths "$phase" | tr '\n' ' ' | sed 's/ *$//')"
    exfil="$(cxg_exfil_evidence "$phase")"
    cxg_egress "$phase" && egress="yes"

    if [ -n "$exfil" ]; then
        patterns="decoy-credential-nonce-observed"
        title="Package read planted decoy credentials during $english"
        cwe="CWE-506,CWE-522,CWE-829"
    fi
    if [ "$egress" = "yes" ]; then
        patterns="${patterns:+$patterns,}loopback-sink-connection"
        [ -n "$title" ] || title="Package opened a network connection during $english"
        cwe="${cwe:-CWE-506,CWE-829,CWE-494}"
    fi
    if [ -n "$paths" ]; then
        patterns="${patterns:+$patterns,}write-outside-install-prefix"
        [ -n "$title" ] || title="Package wrote outside its install prefix during $english"
        cwe="${cwe:-CWE-506,CWE-829,CWE-732}"
    fi
    if [ "$spawn_confirms" = "yes" ] && [ -n "$programs" ]; then
        # A subprocess alone is high, not critical: it proves the phase runs
        # code it should not, without yet showing where that code reached.
        [ -n "$patterns" ] || sev="high"
        patterns="${patterns:+$patterns,}child-process-spawned"
        [ -n "$title" ] || title="Package executed a program during $english"
        cwe="${cwe:-CWE-506,CWE-829}"
    fi

    [ -n "$patterns" ] || return 1

    local desc
    desc="The package under test was installed by $(basename "$CXG_BIN") in a hermetic lab and its $english was observed. Against the identical phase performed on an inert control package by the same package manager, this phase additionally: $(
        [ "$egress" = "yes" ] && printf 'opened a connection to the lab loopback sink (every proxy variable pointed at it, and the control phase opened none); '
        [ -n "$exfil" ] && printf 'emitted the nonce planted in the decoy ~/.ssh/id_ed25519, ~/.aws/credentials and ~/.npmrc, via %s - that value exists nowhere but those decoys; ' "$exfil"
        [ -n "$paths" ] && printf 'created %s under the sentinel HOME, outside any install prefix; ' "$paths"
        { [ "$spawn_confirms" = "yes" ] && [ -n "$programs" ]; } && printf 'executed %s, where the phase is one that must run no subprocess at all; ' "$programs"
        true
    )each of which is a side effect the package produced, not one the package manager produces on its own."

    local findings
    findings="$(cxg_finding "$sev" 95 "$title" "$desc" "$cwe" \
        "$CXG_BIN install <subject> (phase: $english)" \
        "$(head -c 1200 "out.subject-$phase" 2>/dev/null)" \
        "$patterns" \
        "$(CXG_P="$phase" CXG_E="$english" CXG_PROG="$programs" CXG_PATHS="$paths" \
           CXG_EXF="$exfil" CXG_EGR="$egress" CXG_ECOV="$CXG_ECO" \
           CXG_SINKLINE="$(head -c 600 "sink.subject-$phase" 2>/dev/null)" python3 -c '
import json, os
print(json.dumps({
    "oracle": "diff+property+detector",
    "ecosystem": os.environ["CXG_ECOV"],
    "phase": os.environ["CXG_E"],
    "control": "same package manager, same phase, synthesised inert package",
    "new_programs": os.environ["CXG_PROG"].split(),
    "new_home_paths": os.environ["CXG_PATHS"].split(),
    "credential_nonce_route": os.environ["CXG_EXF"],
    "loopback_egress": os.environ["CXG_EGR"] == "yes",
    "sink_first_bytes": os.environ["CXG_SINKLINE"],
}))')")"

    cxg_confirm "oracle=diff(subject-minus-control) phase=$phase observables=$patterns eco=$CXG_ECO" "$findings"
}

# ---------------------------------------------------------------------------
# Run the phases.
# ---------------------------------------------------------------------------
CXG_SUMMARY=""

cxg_run_phase() {
    local phase="$1" spawn_confirms="$2" english="$3"

    case ",$CXG_PHASES," in
        *",$phase,"*) ;;
        *) CXG_SUMMARY="$CXG_SUMMARY $phase(not-selected)"; return 0 ;;
    esac

    cxg_observe "control-$phase" "$CXG_LAB/control"
    local control_rc=$CXG_PHASE_RC
    if [ "$control_rc" -ne 0 ]; then
        cxg_error "control-phase-failed(phase=$phase exit=$control_rc): $(head -c 400 "out.control-$phase" 2>/dev/null)"
    fi

    cxg_observe "subject-$phase" "$CXG_SUBJECT"
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))

    cxg_adjudicate "$phase" "$spawn_confirms" "$english" && return 0

    CXG_SUMMARY="$CXG_SUMMARY $phase(exit=$CXG_PHASE_RC,programs=$(cxg_new_programs "$phase" | wc -l | tr -d ' '))"
    return 0
}

# cxg_python_module - the import name the `import` phase reaches for.
#
# `pip install` prints the DISTRIBUTION name, which is routinely not the import
# name (`cxg-fixture-installhook-flawed` installs `cxg_fixture_installhook`),
# so the name is read off what an install actually put on sys.path. Any venv a
# subject phase already built will do; if none has been built yet - the
# operator selected only the import phase - one throwaway install answers it.
cxg_python_module() {
    local venv
    for venv in venv-subject-import venv-subject-startup venv-subject-install; do
        [ -d "$CXG_LAB/$venv" ] && break
        venv=""
    done
    if [ -z "$venv" ]; then
        venv="venv-probe"
        python3 -m venv "$CXG_LAB/$venv" >/dev/null 2>&1 || return 0
        # Do not leave .pyc litter in the operator's package tree.
        PYTHONDONTWRITEBYTECODE=1 cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" \
            --python "$CXG_LAB/$venv/bin/python" \
            install --no-index --no-deps --no-build-isolation \
            --disable-pip-version-check "$CXG_SUBJECT" >/dev/null 2>&1 || return 0
    fi
    CXG_VENV="$CXG_LAB/$venv" python3 -c '
import glob, os, sys

# A package (a directory with __init__.py) is what an operator would import,
# so it wins over a loose top-level module every time.
packages, modules = set(), set()
for site in glob.glob(os.path.join(os.environ["CXG_VENV"], "lib", "python*",
                                   "site-packages")):
    for entry in os.listdir(site):
        if entry.endswith((".dist-info", ".egg-info", ".pth", "__pycache__")):
            continue
        full = os.path.join(site, entry)
        if os.path.isdir(full) and os.path.exists(os.path.join(full, "__init__.py")):
            packages.add(entry)
        elif entry.endswith(".py"):
            modules.add(entry[:-3])
chosen = sorted(packages) or sorted(modules)
print(chosen[0] if chosen else "")'
}

case "$CXG_ECO" in
npm)
    cxg_run_phase install no "install (npm lifecycle scripts)"
    ;;
pip)
    CXG_PY_MODULE=""
    export CXG_PY_MODULE
    cxg_run_phase install no "install (PEP 517 build and install)"

    cxg_run_phase startup yes "bare interpreter startup (.pth execution, package NOT imported)"

    CXG_PY_MODULE="$(cxg_python_module)"
    export CXG_PY_MODULE
    if [ -n "$CXG_PY_MODULE" ]; then
        cxg_run_phase import yes "first import of the installed package ($CXG_PY_MODULE)"
    else
        CXG_SUMMARY="$CXG_SUMMARY import(skipped:no-importable-module-found)"
    fi
    ;;
esac

cxg_refute "no phase produced egress, a write outside its install prefix, a decoy-credential read, or an unexpected subprocess that its inert control did not also produce.$CXG_SUMMARY eco=$CXG_ECO"

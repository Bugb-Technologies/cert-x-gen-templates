#!/usr/bin/env bash
# @id: supply-chain-install-credential-access
# @name: Supply chain - install-time credential access and workflow planting
# @author: CERT-X-GEN / Bugb Technologies
# @severity: critical
# @description: Installs a package with a real package manager inside a hermetic lab whose sentinel HOME has been seeded with per-file CANARY credentials - ~/.npmrc, ~/.aws/credentials, ~/.config/gh/hosts.yml - and canary credential environment variables, then answers the two questions the Shai-Hulud / CHAINDROP worm mechanic turns on: WHICH secret did the install step read, and did it plant a GitHub Actions workflow. Reads are witnessed by access time against a liveness-tested oracle, workflow planting by a path appearing under .github/workflows outside any install prefix, and exfiltration by a canary value arriving at the lab's loopback sink. Every observation is differential against the same package manager installing a synthesised inert package, so npm reading its own ~/.npmrc can never be the finding. Behavioural, not signature-based: it never looks at the hook's source.
# @tags: supply-chain, tooling, npm, pypi, install-hook, postinstall, credential-theft, worm, shai-hulud, github-actions, behavioural
# @cwe: CWE-522
# @confidence: 95
# @references: https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
# @references: https://www.wiz.io/blog/shai-hulud-second-coming
# @references: https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
# @target_kinds: cli
# @oracles: property, diff, detector
#
# WHAT IS UNDER TEST
#
#   target        (cli://) the PACKAGE MANAGER binary - npm/pnpm/yarn, or pip.
#   subject       (--input, or CXG_SUPPLY_CHAIN_PACKAGE) the PACKAGE whose
#                 install step is under test. Required; without one it skips.
#   observable    something the install step did to a canary the lab planted.
#   oracle        property (post-conditions on the install observation)
#                 diff     (subject install MINUS the same install performed on
#                           a synthesised inert package, so nothing the package
#                           manager does on its own can be reported)
#                 detector (per-file canary nonces that exist nowhere else, an
#                           access-time read witness that is liveness-tested
#                           before it is trusted, and a loopback sink)
#
# THE SIBLING, AND WHY THIS IS NOT IT
#
#   supply-chain-install-hook-behavior asks "does this install spawn something,
#   write outside its prefix, or open a socket?" - the generic question.
#
#   This template asks the worm's specific question. Shai-Hulud (npm, Sep 2025;
#   the "Second Coming" wave, Nov 2025) and the CHAINDROP/TrapDoor family did
#   two things at install time that a build step never does:
#
#     1. read the developer's credential FILES - ~/.npmrc for the registry
#        token that lets it publish the next hop, ~/.aws/credentials, and the
#        gh CLI's ~/.config/gh/hosts.yml for the GitHub token, and
#     2. wrote a GitHub Actions WORKFLOW into the checkout, so the stolen
#        material is re-exfiltrated by CI on every future push, from an
#        identity CI is supposed to have.
#
#   Together those are the propagation engine. A check that reports only "a
#   postinstall ran" cannot tell an operator which token to rotate or which
#   branch to rewrite; that is the gap this fills.
#
# THE FOUR CONFIRMING OBSERVABLES
#
#   canary-read      the access time of a seeded credential file moved during
#                    the subject install and did NOT move during the control
#                    install. Each seeded file is named in the evidence, so the
#                    finding says WHICH secret - and the read witness is
#                    self-tested before the run, so a noatime filesystem
#                    degrades the check to the other three rather than
#                    silently answering "no".
#   workflow-planted a path under .github/workflows appeared outside every
#                    install prefix that the control install did not create.
#                    An install has no business writing CI.
#   canary-egress    a canary value arrived at the lab's loopback sink. Every
#                    proxy variable points at it and the control install sent
#                    nothing, so this is the credential on the wire.
#   canary-retained  a canary value came back out into a file the install
#                    wrote, or onto its own stdout. That value exists nowhere
#                    but the seeded files and the seeded environment, so its
#                    reappearance is proof of a read, not inference.
#
# WHAT IS DELIBERATELY *NOT* CONFIRMING
#
#   A read the control install also performed. `npm` opens ~/.npmrc on every
#   single invocation; reporting that would be reporting npm. It is recorded as
#   a soft observation, named in the finding, and never fires on its own.
#   A connection to the sink carrying no canary - that is the sibling's
#   finding, and it is carried here as an observation only.
#   A subprocess. Honest packages compile things.
#
# ISOLATION - READ THIS BEFORE POINTING IT AT ANYTHING REAL
#
# This template EXECUTES the package's install code. Everything it builds is
# confined to one `mktemp -d` lab - a sentinel HOME and a fresh venv, all removed on exit - and every
# credential it plants is a
# random nonce, never a real one. That confinement is a lab, not a sandbox: a
# hostile package can still reach the real network and the real filesystem. Run
# it against an untrusted package only inside a disposable container or VM with
# no network route. Against the benign fixtures in
# tests/fixtures/tooling/supply-chain-credential-access it is safe anywhere.
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

CXG_LAB=""
CXG_SINK_PORT=""
CXG_SINK_PID=""
CXG_PROBES_DELIVERED=0
CXG_ORIG_PATH="$PATH"
CXG_ATIME_ORACLE="unknown"

# ---------------------------------------------------------------------------
# The JSON contract. Four statuses, and what each one promises:
#
#   confirmed  the install step read a seeded credential, planted a workflow,
#              or put a canary on the wire, and the control install did not.
#   refuted    the install ran, was compared against its control, and touched
#              none of the canaries and wrote no workflow.
#   skipped    the check could not be earned here - wrong target kind, no
#              subject package, an ecosystem this template does not drive.
#   errored    the lab or the control install failed; nothing was learned.
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
# and the template always exits 0: cxg releases up to and including v1.3.0
# discard the stdout of a shell template that exits non-zero whatever
# @allow_nonzero_exit says, which would silently drop every finding.
cxg_confirm() { cxg_emit confirmed "$1" "$2"; exit 0; }
cxg_error()   { cxg_emit errored   "$1"; exit 0; }
cxg_skip()    { cxg_emit skipped   "$1"; exit 0; }

# A refutation asserts the subject was actually installed. A run that never
# delivered the install has not earned one and says so instead.
cxg_refute() {
    if [ "$CXG_PROBES_DELIVERED" -eq 0 ]; then
        cxg_emit skipped "no-install-delivered (nothing was installed, so a refutation would be unearned): $1"
        exit 0
    fi
    cxg_emit refuted "$1"
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
# scheme still attached and no kind at all. Both are a CLI target.
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
CXG_LAB="$(mktemp -d "${TMPDIR:-/tmp}/cxg-credaccess.XXXXXX")" || cxg_error "lab-setup-failed"
cxg_teardown() {
    [ -n "$CXG_SINK_PID" ] && kill "$CXG_SINK_PID" 2>/dev/null
    rm -rf "$CXG_LAB"
}
trap cxg_teardown EXIT
cd "$CXG_LAB" || cxg_error "lab-cd-failed"

# The instant the lab was built. Every canary's access time is backdated to
# 2001 immediately after it is written, so "access time is at or after this
# moment" is exactly "something opened this file during the run".
CXG_T0="$(python3 -c 'import time; print(int(time.time()))')"
CXG_BACKDATE=200101010101

# ---------------------------------------------------------------------------
# The canaries.
#
# One nonce PER SOURCE, not one nonce for the lab. That single decision is what
# lets the finding say "it read the gh CLI token" rather than "it read a
# credential": each nonce can only have come from the one file, or the one
# environment variable, that carries it.
#
# tag <TAB> nonce <TAB> kind <TAB> where it lives
# ---------------------------------------------------------------------------
cxg_nonce() {
    printf 'CXGCANARY%s%s' "$1" \
        "$(od -An -N9 -tx1 /dev/urandom | tr -d ' \n' | tr 'a-f' 'A-F')"
}

CXG_N_NPMRC="$(cxg_nonce NPMRC)"
CXG_N_AWS="$(cxg_nonce AWS)"
CXG_N_GH="$(cxg_nonce GH)"
CXG_N_ENVNPM="$(cxg_nonce ENVNPM)"
CXG_N_ENVAWS="$(cxg_nonce ENVAWS)"
CXG_N_ENVGH="$(cxg_nonce ENVGH)"

# Files, in the order the finding should name them. The relative path is the
# key: it is what the atime witness stats and what the evidence prints.
cat >canaries.tsv <<EOF
npmrc	$CXG_N_NPMRC	file	.npmrc	npm registry auth token
aws	$CXG_N_AWS	file	.aws/credentials	AWS long-lived access key
gh	$CXG_N_GH	file	.config/gh/hosts.yml	GitHub CLI OAuth token
env-npm	$CXG_N_ENVNPM	env	NPM_TOKEN	npm token in the environment
env-aws	$CXG_N_ENVAWS	env	AWS_SECRET_ACCESS_KEY	AWS secret in the environment
env-gh	$CXG_N_ENVGH	env	GH_TOKEN / GITHUB_TOKEN	GitHub token in the environment
EOF

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
            data = conn.recv(8192)
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
# then execs the real binary, resolved once against the ORIGINAL PATH so a shim
# can never re-enter itself. The install still works; it is merely narrated.
# These are evidence, never a verdict - a `cat ~/.aws/credentials` in the
# ledger names the read in the operator's own language, but the atime witness
# is what proves it happened.
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
            base64 xxd openssl gh git crontab; do
    # `cat` is deliberately absent: the shim body itself runs `cat`, and the
    # shim directory is first on PATH inside an observation, so shimming it
    # would make every wrapper recurse into itself.
    real="$(PATH="$CXG_ORIG_PATH" command -v "$prog" 2>/dev/null)" || continue
    [ -n "$real" ] || continue
    case "$real" in "$CXG_LAB"/*) continue ;; esac
    printf '%s\n' "$real" >"shim/.real/$prog"
    cp shim/.cxg-shim "shim/$prog"
done
CXG_SHIM_DIR="$CXG_LAB/shim"
export CXG_SHIM_DIR

# --- the read witness, and its liveness self-test --------------------------
# An access time only answers "was this opened" on a filesystem that maintains
# one. Linux `relatime` refreshes atime when it is older than mtime, which is
# why every canary is backdated and never touched again; `noatime`, and some
# container overlays, maintain nothing at all.
#
# So the witness is TESTED before it is trusted: write a file, backdate it,
# read it, and see whether the access time moved. If it did not, the oracle is
# marked unavailable, `canary-read` is withdrawn as a confirming observable for
# this run, and the metadata says so - rather than a dead sensor quietly
# reporting "no credential was read".
printf 'cxg atime witness\n' >atime-witness
touch -a -t "$CXG_BACKDATE" atime-witness 2>/dev/null
cat atime-witness >/dev/null 2>&1
if CXG_W="$CXG_LAB/atime-witness" CXG_T="$CXG_T0" python3 -c '
import os, sys
sys.exit(0 if os.stat(os.environ["CXG_W"]).st_atime >= float(os.environ["CXG_T"]) else 1)'
then
    CXG_ATIME_ORACLE="live"
else
    CXG_ATIME_ORACLE="unavailable"
fi

# --- the sentinel HOME seed ------------------------------------------------
# The three files the worm family actually goes for, in the shapes their real
# tooling writes, each holding its own nonce. A nonce is a value no correct
# install can produce, so seeing one leave is proof rather than inference.
mkdir -p home-seed/.aws home-seed/.config/gh
printf '//registry.npmjs.org/:_authToken=%s\nregistry=https://registry.npmjs.org/\n' \
    "$CXG_N_NPMRC" >home-seed/.npmrc
printf '[default]\naws_access_key_id = AKIALABCANARYKEYID00\naws_secret_access_key = %s\n' \
    "$CXG_N_AWS" >home-seed/.aws/credentials
chmod 600 home-seed/.aws/credentials
printf 'github.com:\n    oauth_token: %s\n    user: cxg-canary\n    git_protocol: https\n' \
    "$CXG_N_GH" >home-seed/.config/gh/hosts.yml
chmod 600 home-seed/.config/gh/hosts.yml

# --- the seeded checkout ---------------------------------------------------
# The install is run from a directory, and the worm's second stage writes into
# that directory: a checkout is the thing a workflow gets planted in. The seed
# is a plausible one - a git directory, a README, an existing CI workflow for a
# planted file to sit beside - so "a new file under .github/workflows" means
# what it says.
#
# It lives INSIDE the sentinel HOME on purpose. The npm half of this class
# finds the checkout through INIT_CWD; the PyPI half walks $HOME looking for a
# .git directory, because pip hands its build backend no equivalent. One tree
# under one HOME is reachable by both, and is one tree to diff.
CXG_CHECKOUT_REL="src/app"
mkdir -p "home-seed/$CXG_CHECKOUT_REL/.git" "home-seed/$CXG_CHECKOUT_REL/.github/workflows"
printf 'ref: refs/heads/main\n' >"home-seed/$CXG_CHECKOUT_REL/.git/HEAD"
printf '# cxg lab checkout\n' >"home-seed/$CXG_CHECKOUT_REL/README.md"
printf 'name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo build\n' \
    >"home-seed/$CXG_CHECKOUT_REL/.github/workflows/ci.yml"
( cd home-seed && find . -mindepth 1 | sed 's|^\./||' | sort ) >home-seed.list

# --- the inert control package ---------------------------------------------
# The control is the SAME package manager doing the SAME install on a package
# that declares nothing and runs nothing. Everything npm, pip, the venv builder
# and the interpreter do on their own therefore appears in both observations
# and cancels - npm's own read of ~/.npmrc most of all. Only what the subject
# added survives the diff.
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
# Runs one install under full instrumentation and leaves six artefacts named
# after the tag:
#
#   reads.<tag>    canary files whose access time moved
#   files.<tag>    paths the install created anywhere under its sentinel HOME,
#                  the seeded checkout included
#   sink.<tag>     connections that reached the loopback sink
#   ledger.<tag>   programs the install executed, with argv
#   out.<tag>      the install's own stdout and stderr
#
# Both observations get a FRESH copy of the same seed, so their file sets and
# their access times are directly comparable.
# ---------------------------------------------------------------------------
CXG_PHASE_RC=0

# Backdate every canary in one HOME. Directories are left alone: only the files
# are witnesses, and `find` walking the tree afterwards must not disturb them.
cxg_backdate() {
    local home="$1" rel
    while IFS="$(printf '\t')" read -r _tag _nonce kind rel _desc; do
        [ "$kind" = "file" ] || continue
        [ -f "$home/$rel" ] && touch -a -t "$CXG_BACKDATE" "$home/$rel" 2>/dev/null
    done <canaries.tsv
}

# Which canary files were opened. Printed one tag per line, and read BEFORE
# anything else in this template touches the tree.
cxg_record_reads() {
    local home="$1"
    CXG_HOME="$home" CXG_T="$CXG_T0" CXG_MAP="$CXG_LAB/canaries.tsv" python3 -c '
import os, sys
home, floor = os.environ["CXG_HOME"], float(os.environ["CXG_T"])
for line in open(os.environ["CXG_MAP"]):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 4 or parts[2] != "file":
        continue
    path = os.path.join(home, parts[3])
    try:
        if os.stat(path).st_atime >= floor:
            print(parts[0])
    except OSError:
        pass'
}

cxg_observe() {
    local tag="$1" pkg="$2"
    rm -rf "home-$tag" "venv-$tag"
    cp -R home-seed "home-$tag"
    cxg_backdate "$CXG_LAB/home-$tag"
    : >"ledger.$tag"
    : >sink.log

    (
        export HOME="$CXG_LAB/home-$tag"
        cd "$HOME/$CXG_CHECKOUT_REL" || exit 97
        export PATH="$CXG_SHIM_DIR:$CXG_ORIG_PATH"
        export CXG_LEDGER="$CXG_LAB/ledger.$tag"
        export CXG_SHIM_DIR
        # The environment half of the canary set: the same credentials a CI
        # runner would be holding when it installs.
        export NPM_TOKEN="$CXG_N_ENVNPM"
        export AWS_SECRET_ACCESS_KEY="$CXG_N_ENVAWS"
        export AWS_ACCESS_KEY_ID="AKIALABCANARYKEYID00"
        export GH_TOKEN="$CXG_N_ENVGH" GITHUB_TOKEN="$CXG_N_ENVGH"
        # Every conventional egress path a hook might take, aimed at the sink.
        local sink="http://127.0.0.1:$CXG_SINK_PORT"
        export http_proxy="$sink" https_proxy="$sink" all_proxy="$sink"
        export HTTP_PROXY="$sink" HTTPS_PROXY="$sink" ALL_PROXY="$sink"
        export npm_config_proxy="$sink" npm_config_https_proxy="$sink"
        export PIP_PROXY="$sink" NODE_USE_ENV_PROXY=1
        export NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false
        export PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
        unset PYTHONPATH VIRTUAL_ENV
        cxg_install "$tag" "$pkg"
    ) >"out.$tag" 2>&1
    CXG_PHASE_RC=$?

    # Access times first: every command below this line opens files.
    cxg_record_reads "$CXG_LAB/home-$tag" >"reads.$tag"

    cp sink.log "sink.$tag" 2>/dev/null || : >"sink.$tag"
    ( cd "home-$tag" && find . -mindepth 1 | sed 's|^\./||' | sort ) >"all.$tag"
    comm -13 home-seed.list "all.$tag" >"files.$tag"
    return 0
}

# cxg_install <tag> <package-path> - the ecosystem-specific work, run inside
# the instrumented subshell, in the checkout.
cxg_install() {
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
        cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" --python "$py" install \
            --no-index --no-deps --no-build-isolation \
            --disable-pip-version-check "$pkg"
        ;;
    esac
}

# ---------------------------------------------------------------------------
# Adjudication.
# ---------------------------------------------------------------------------

# Canary files the SUBJECT install opened and the control install did not.
cxg_subject_only_reads() {
    comm -13 <(sort -u "reads.control" 2>/dev/null) \
             <(sort -u "reads.subject" 2>/dev/null)
}

# Canary files BOTH installs opened. `npm` reads ~/.npmrc every time it runs,
# so this set is the package manager's own behaviour and is reported as an
# observation the finding names, never as the finding.
cxg_shared_reads() {
    comm -12 <(sort -u "reads.control" 2>/dev/null) \
             <(sort -u "reads.subject" 2>/dev/null)
}

# Every path the subject install created under its sentinel HOME that the
# control install did not. Compared whole, because a planted workflow is
# identified by its full path and nothing else.
cxg_new_paths() {
    comm -13 <(sort -u "files.control" 2>/dev/null) \
             <(sort -u "files.subject" 2>/dev/null)
}

# A planted workflow: a new path under .github/workflows that is NOT inside an
# install prefix. A package that ships its own .github/ directory unpacks it
# into node_modules or site-packages, which is its own tree and not CI - only a
# write into the checkout or the home directory is the worm's second stage.
cxg_planted_workflows() {
    cxg_new_paths \
        | grep -E '(^|/)\.github/workflows/[^/]+' \
        | grep -Ev '(^|/)(node_modules|site-packages|dist-info)(/|$)' \
        | sort -u
}

# cxg_canary_routes <tag> - which canaries came back OUT of this observation,
# and by which route. One line per hit: "<canary-tag>\t<route>".
cxg_canary_routes() {
    local tag="$1" ctag nonce kind rel desc rp
    while IFS="$(printf '\t')" read -r ctag nonce kind rel desc; do
        [ -n "$nonce" ] || continue
        if grep -qF "$nonce" "sink.$tag" 2>/dev/null; then
            printf '%s\tloopback-sink\n' "$ctag"
        fi
        if grep -qF "$nonce" "out.$tag" 2>/dev/null; then
            printf '%s\tinstall-stdout\n' "$ctag"
        fi
        if grep -qF "$nonce" "ledger.$tag" 2>/dev/null; then
            printf '%s\tchild-process-argv\n' "$ctag"
        fi
        while IFS= read -r rp; do
            [ -n "$rp" ] || continue
            # Files the install unpacked into its own prefix are the package
            # under test, not something it wrote; only what landed elsewhere
            # can be a retained credential.
            case "$rp" in
                *node_modules/*|*site-packages/*|*/.git/*) continue ;;
            esac
            [ -f "home-$tag/$rp" ] || continue
            if grep -qF "$nonce" "home-$tag/$rp" 2>/dev/null; then
                printf '%s\twritten-file:~/%s\n' "$ctag" "$rp"
            fi
        done <"files.$tag"
    done <canaries.tsv
}

# Plain egress - a connection with no canary on it. The sibling template's
# finding; here it is context only.
cxg_plain_egress() {
    [ -s "sink.subject" ] && [ ! -s "sink.control" ]
}

# ---------------------------------------------------------------------------
# Run it.
# ---------------------------------------------------------------------------
cxg_observe control "$CXG_LAB/control"
if [ "$CXG_PHASE_RC" -ne 0 ]; then
    cxg_error "control-install-failed(exit=$CXG_PHASE_RC): $(head -c 400 "out.control" 2>/dev/null)"
fi

cxg_observe subject "$CXG_SUBJECT"
CXG_PROBES_DELIVERED=1

CXG_READS="$(cxg_subject_only_reads | tr '\n' ' ' | sed 's/ *$//')"
CXG_SHARED="$(cxg_shared_reads | tr '\n' ' ' | sed 's/ *$//')"
CXG_WORKFLOWS="$(cxg_planted_workflows | tr '\n' ' ' | sed 's/ *$//')"
CXG_ROUTES_SUBJECT="$(cxg_canary_routes subject | sort -u)"
CXG_ROUTES_CONTROL="$(cxg_canary_routes control | sort -u)"
# Differential on the routes too: whatever the package manager itself echoes
# back - npm has been known to print a redacted config - cancels.
CXG_ROUTES="$(comm -13 <(printf '%s\n' "$CXG_ROUTES_CONTROL") \
                       <(printf '%s\n' "$CXG_ROUTES_SUBJECT") | sed '/^$/d')"
CXG_EGRESS_ROUTES="$(printf '%s\n' "$CXG_ROUTES" | grep -c 'loopback-sink' || true)"
CXG_PLAIN_EGRESS="no"; cxg_plain_egress && CXG_PLAIN_EGRESS="yes"
CXG_PROGRAMS="$(comm -13 <(cut -f1 ledger.control 2>/dev/null | sort -u) \
                         <(cut -f1 ledger.subject 2>/dev/null | sort -u) \
                | tr '\n' ' ' | sed 's/ *$//')"

# A read witness that is not live cannot say "no read", so it must not be
# allowed to say "read" either; it is withdrawn from the confirming set and the
# metadata carries the reason.
if [ "$CXG_ATIME_ORACLE" != "live" ]; then
    CXG_READS=""
fi

CXG_PATTERNS=""; CXG_TITLE=""; CXG_SEV="critical"
[ -n "$CXG_READS" ] && {
    CXG_PATTERNS="canary-read"
    CXG_TITLE="Install step read seeded credential files ($CXG_READS)"
}
[ -n "$CXG_WORKFLOWS" ] && {
    CXG_PATTERNS="${CXG_PATTERNS:+$CXG_PATTERNS,}workflow-planted"
    CXG_TITLE="Install step planted a GitHub Actions workflow"
}
[ -n "$CXG_ROUTES" ] && {
    if [ "$CXG_EGRESS_ROUTES" -gt 0 ]; then
        CXG_PATTERNS="${CXG_PATTERNS:+$CXG_PATTERNS,}canary-egress"
        CXG_TITLE="Install step sent seeded credentials to a network sink"
    else
        CXG_PATTERNS="${CXG_PATTERNS:+$CXG_PATTERNS,}canary-retained"
        [ -n "$CXG_TITLE" ] || CXG_TITLE="Install step retained seeded credentials"
    fi
}

if [ -n "$CXG_PATTERNS" ]; then
    # A read alone is high: the install demonstrably opened a secret it has no
    # reason to open, without yet showing that the secret went anywhere.
    case "$CXG_PATTERNS" in
        canary-read) CXG_SEV="high" ;;
    esac

    CXG_DESC="$(basename "$CXG_BIN") installed the package under test in a hermetic lab whose sentinel HOME held canary credentials - a per-file nonce in ~/.npmrc, ~/.aws/credentials and ~/.config/gh/hosts.yml, and further nonces in NPM_TOKEN, AWS_SECRET_ACCESS_KEY and GH_TOKEN - and whose working directory was a seeded checkout. Against the identical install performed on an inert control package by the same package manager, this install additionally: $(
        [ -n "$CXG_READS" ] && printf 'opened the canary credential source(s) %s, which the control install left untouched; ' "$CXG_READS"
        [ -n "$CXG_WORKFLOWS" ] && printf 'created %s - a CI workflow, written by an install, outside every install prefix; ' "$CXG_WORKFLOWS"
        [ -n "$CXG_ROUTES" ] && printf 'emitted canary values by: %s - each of those values existed only in the seeded credential it names; ' "$(printf '%s' "$CXG_ROUTES" | tr '\n' ';' | sed 's/;$//')"
        true
    )Each is a side effect the package produced, not one the package manager produces on its own.${CXG_SHARED:+ Recorded but NOT reported as the finding: both installs read $CXG_SHARED, which is the package manager doing its own configuration handling.}"

    CXG_FINDINGS="$(cxg_finding "$CXG_SEV" 95 "$CXG_TITLE" "$CXG_DESC" \
        "CWE-522,CWE-506,CWE-829,CWE-200" \
        "$CXG_BIN install <subject> (sentinel HOME seeded with per-source canary credentials)" \
        "$(head -c 1200 "out.subject" 2>/dev/null)" \
        "$CXG_PATTERNS" \
        "$(CXG_R="$CXG_READS" CXG_SH="$CXG_SHARED" CXG_W="$CXG_WORKFLOWS" \
           CXG_RT="$CXG_ROUTES" CXG_ECOV="$CXG_ECO" CXG_AT="$CXG_ATIME_ORACLE" \
           CXG_PROG="$CXG_PROGRAMS" CXG_PE="$CXG_PLAIN_EGRESS" \
           CXG_MAP="$CXG_LAB/canaries.tsv" \
           CXG_WFBODY="$(for w in $CXG_WORKFLOWS; do
                             [ -f "$CXG_LAB/home-subject/$w" ] && \
                                 printf '%s:\n%s\n' "$w" "$(head -c 400 "$CXG_LAB/home-subject/$w")"
                         done)" \
           CXG_SINKLINE="$(head -c 800 "sink.subject" 2>/dev/null)" python3 -c '
import json, os

sources = {}
for line in open(os.environ["CXG_MAP"]):
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 5:
        sources[parts[0]] = {"kind": parts[2], "location": parts[3],
                             "what": parts[4]}

routes = []
for line in os.environ["CXG_RT"].splitlines():
    if not line.strip():
        continue
    tag, _, route = line.partition("\t")
    routes.append({"canary": tag, "source": sources.get(tag, {}), "route": route})

print(json.dumps({
    "oracle": "diff(subject-minus-control)+property+detector",
    "ecosystem": os.environ["CXG_ECOV"],
    "read_witness": os.environ["CXG_AT"],
    "credentials_read": [
        {"canary": t, **sources.get(t, {})} for t in os.environ["CXG_R"].split()],
    "credentials_read_by_the_package_manager_too": os.environ["CXG_SH"].split(),
    "workflows_planted": os.environ["CXG_W"].split(),
    "workflow_content": os.environ["CXG_WFBODY"][:1200],
    "canary_exfiltration_routes": routes,
    "sink_first_bytes": os.environ["CXG_SINKLINE"],
    "observations": {
        "new_programs": os.environ["CXG_PROG"].split(),
        "egress_without_a_canary": os.environ["CXG_PE"] == "yes",
    },
}))')")"

    cxg_confirm "oracle=diff(subject-minus-control) eco=$CXG_ECO observables=$CXG_PATTERNS reads='${CXG_READS:-none}' workflows='${CXG_WORKFLOWS:-none}' read-witness=$CXG_ATIME_ORACLE" \
        "$CXG_FINDINGS"
fi

cxg_refute "the install read none of the seeded credential canaries its inert control left untouched, planted no .github/workflows file outside an install prefix, and emitted no canary value. eco=$CXG_ECO read-witness=$CXG_ATIME_ORACLE${CXG_SHARED:+ package-manager-own-reads=$CXG_SHARED} egress-without-canary=$CXG_PLAIN_EGRESS new-programs='${CXG_PROGRAMS:-none}' install-exit=$CXG_PHASE_RC"

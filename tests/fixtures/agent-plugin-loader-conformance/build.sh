#!/usr/bin/env bash
# Materialise the six twins from the single pluginhost.py source.
#
# Agent Plugins 1.0 conformance is four independent normative MUSTs, so a
# flawed/fixed pair would only ever prove the template fires on *something*.
# Each twin below honours a different subset, which lets
# tests/prove-agent-plugin-loader-conformance.sh assert that every arm of the
# check detects its own clause -- and, just as importantly, that it stays quiet
# about the three clauses that twin honours.
#
#   conformant        honours all four        -> REFUTED
#   defective         honours none            -> CONFIRMED, all four arms
#   schema_only       violates Sec 5.2 only   -> CONFIRMED, arm (a) alone
#   namespace_only    violates Sec 8.1 only   -> CONFIRMED, arm (b) alone
#   autostart_only    violates Sec 9.4 only   -> CONFIRMED, arm (d) alone
#   env_leak          violates Sec 9.2 + 9.4  -> CONFIRMED, arms (c) and (d)
#
# Sec 9.2 is only observable through a server that actually starts, so the
# env_leak twin has to give up Sec 9.4 as well; autostart_only is its
# counterpart, starting the same server with the reserved name stripped. The
# pair is what separates "a server was launched" from "the package chose the
# child's PLUGIN_ROOT".
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/pluginhost.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"

emit() {
    variant="$1"; clauses="$2"
    dest="$OUT/pluginhost_${variant}.py"
    sed "s|@@CONFORMANCE@@|${clauses}|" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "^CONFORMANCE = \"${clauses}\"" "$dest" \
        || { echo "build.sh: conformance substitution failed for $variant" >&2; exit 1; }
    printf '%s\n' "$dest"
}

emit conformant     "schema,namespace,env,consent"
emit defective      ""
emit schema_only    "namespace,env,consent"
emit namespace_only "schema,env,consent"
emit autostart_only "schema,namespace,env"
emit env_leak       "schema,namespace"

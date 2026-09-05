#!/usr/bin/env bash
# Materialise the flawed / fixed / nooauth twins from the single
# agent-mcp-client.py source.
#
# One source, three twins. The fixed twin must be the same program with the
# credential store keyed by issuer and the RFC 9207 `iss` checked; the nooauth
# twin the same program with the login surface removed. Anything else that
# differed between them would make the template's REFUTED and SKIP verdicts
# prove only that three files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agent-mcp-client.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in flawed fixed nooauth; do
    dest="$OUT/agent-mcp-client_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' \
    "$OUT/agent-mcp-client_flawed.py" \
    "$OUT/agent-mcp-client_fixed.py" \
    "$OUT/agent-mcp-client_nooauth.py"

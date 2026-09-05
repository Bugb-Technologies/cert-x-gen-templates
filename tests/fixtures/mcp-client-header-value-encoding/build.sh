#!/usr/bin/env bash
# Materialise the flawed / fixed / nohdr twins from the single
# agent-mcp-http-client.py source.
#
# One source, three twins. The fixed twin must be the same program with
# encode_header_value() percent-encoding instead of passing through; the nohdr
# twin the same program with the x-mcp-header extension switched off. Anything
# else that differed between them would make the template's REFUTED and SKIP
# verdicts prove only that three files differ, so the only edit build.sh is
# allowed to make is the VARIANT token, and it checks that afterwards.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agent-mcp-http-client.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in flawed fixed nohdr; do
    dest="$OUT/agent-mcp-http-client_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
    # Normalising the variant token back out must reproduce the source byte for
    # byte: proof that nothing else moved.
    sed "s/VARIANT = \"${variant}\"/VARIANT = \"@@VARIANT@@\"/" "$dest" \
        | diff -q - "$SRC" >/dev/null \
        || { echo "build.sh: $variant differs from the source beyond VARIANT" >&2; exit 1; }
done

printf '%s\n' \
    "$OUT/agent-mcp-http-client_flawed.py" \
    "$OUT/agent-mcp-http-client_fixed.py" \
    "$OUT/agent-mcp-http-client_nohdr.py"

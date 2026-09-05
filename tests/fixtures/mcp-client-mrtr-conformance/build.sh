#!/usr/bin/env bash
# Materialise the flawed / fixed / nomrtr twins from the single
# agent-mcp-mrtr-client.py source.
#
# One source, three twins. The fixed twin must be the same program with the
# provenance boundary present and the `resultType` default correct; the nomrtr
# twin the same program with MRTR support removed. Anything else that differed
# between them would make the template's REFUTED and SKIP verdicts prove only
# that three files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agent-mcp-mrtr-client.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in flawed fixed nomrtr; do
    dest="$OUT/agent-mcp-mrtr-client_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' \
    "$OUT/agent-mcp-mrtr-client_flawed.py" \
    "$OUT/agent-mcp-mrtr-client_fixed.py" \
    "$OUT/agent-mcp-mrtr-client_nomrtr.py"

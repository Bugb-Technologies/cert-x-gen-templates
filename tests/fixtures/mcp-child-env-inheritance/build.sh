#!/usr/bin/env bash
# Materialise the flawed/fixed twin pair from the single mcplaunch.py source.
#
# One source, three twins: the fixed twin must be the same program with the child
# environment scoped to the declared set, or a refutation only proves the two
# files differ. The nodecl twin drops the manifest declaration, which is what
# drives the template's declaration-not-honoured SKIP.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/mcplaunch.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in flawed fixed nodecl; do
    dest="$OUT/mcplaunch_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' "$OUT/mcplaunch_flawed.py" "$OUT/mcplaunch_fixed.py" "$OUT/mcplaunch_nodecl.py"

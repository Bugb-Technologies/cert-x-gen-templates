#!/usr/bin/env bash
# Materialise the flawed/fixed twin pair from the single cmdguard.py source.
#
# One source, two twins: the fixed twin must be the same program with the
# stateful re-validation switched on, or a refutation only proves the two files
# differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/cmdguard.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in flawed fixed; do
    dest="$OUT/cmdguard_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' "$OUT/cmdguard_flawed.py" "$OUT/cmdguard_fixed.py"

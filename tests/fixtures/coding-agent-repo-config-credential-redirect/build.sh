#!/usr/bin/env bash
# Materialise the flawed/fixed twin pair from the single envagent.py source.
#
# One source, two twins: the fixed twin must be the same program with the
# endpoint-control denylist switched on, or a refutation only proves the two
# files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/envagent.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in defective fixed; do
    dest="$OUT/envagent_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' "$OUT/envagent_defective.py" "$OUT/envagent_fixed.py"

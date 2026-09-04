#!/usr/bin/env bash
# Materialise the three twins from the single skillagent.py source.
#
# One source, three twins: the fixed twin must be the same program with the
# approval view switched on and the no-skills twin the same program with the
# surface switched off, or "refuted" and "skipped" only prove that three files
# differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/skillagent.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in flawed fixed noskills; do
    dest="$OUT/skillagent_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' "$OUT/skillagent_flawed.py" "$OUT/skillagent_fixed.py" \
              "$OUT/skillagent_noskills.py"

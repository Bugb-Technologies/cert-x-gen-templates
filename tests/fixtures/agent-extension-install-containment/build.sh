#!/usr/bin/env bash
# Materialise the three twins from the single skillforge.py source.
#
# One source, three twins: the fixed twin must be the same program with
# containment switched on, and the noinstall twin the same program with the
# install verb removed, or a refutation and a skip only prove that three files
# differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/skillforge.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in defective fixed noinstall; do
    dest="$OUT/skillforge_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' "$OUT/skillforge_defective.py" "$OUT/skillforge_fixed.py" \
              "$OUT/skillforge_noinstall.py"

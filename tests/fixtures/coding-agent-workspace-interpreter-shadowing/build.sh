#!/usr/bin/env bash
# Materialise the flawed/fixed twin pair from the single agentstub.py source.
#
# One source, two twins: the fixed twin must be the same program with the
# PYTHONSAFEPATH mitigation switched on, or a refutation only proves the two
# files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agentstub.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in defective fixed; do
    dest="$OUT/agentstub_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' "$OUT/agentstub_defective.py" "$OUT/agentstub_fixed.py"

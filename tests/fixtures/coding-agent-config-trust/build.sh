#!/usr/bin/env bash
# Materialise the flawed/fixed twin pair from the single agentcli.py source.
#
# One source, two twins: the fixed twin must be the same program with the trust
# gate switched on, or a refutation only proves the two files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agentcli.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in defective fixed; do
    dest="$OUT/agentcli_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' "$OUT/agentcli_defective.py" "$OUT/agentcli_fixed.py"

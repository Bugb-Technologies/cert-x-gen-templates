#!/usr/bin/env bash
# Materialise the three twins from the single bleedagent.py source.
#
# One source, three twins driven by two independent switches, so a refutation
# means "the same program with cross-tool discovery and marketplace fan-out
# switched off" rather than "a different program".
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/bleedagent.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"

#            variant     CONFIG_LAYER DISCOVERY FANOUT
for spec in "defective    1            1         1" \
            "fixed        1            0         0" \
            "inert        0            0         0"; do
    # shellcheck disable=SC2086  # deliberate word splitting of the spec row
    set -- $spec
    variant="$1"; layer="$2"; discovery="$3"; fanout="$4"
    dest="$OUT/bleedagent_${variant}.py"
    sed -e "s/@@CONFIG_LAYER@@/${layer}/" \
        -e "s/@@DISCOVERY@@/${discovery}/" \
        -e "s/@@FANOUT@@/${fanout}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "^CONFIG_LAYER = ${layer} " "$dest" \
        || { echo "build.sh: switch substitution failed for $variant" >&2; exit 1; }
    if grep -q '@@' "$dest"; then
        echo "build.sh: unsubstituted placeholder left in $variant" >&2
        exit 1
    fi
done

printf '%s\n' "$OUT/bleedagent_defective.py" "$OUT/bleedagent_fixed.py" "$OUT/bleedagent_inert.py"

#!/usr/bin/env bash
# Materialise the eight twins -- four config shapes x {defective, fixed} --
# from the single agentshape.py source.
#
# One source, two twins per shape: the fixed twin must be the same program with
# the trust gate switched on, or a refutation only proves the two files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agentshape.py"
OUT="${1:-$HERE/build}"
SHAPES="${CXG_FIXTURE_SHAPES:-claudeish cursorish codexish geminiish}"
VARIANTS="${CXG_FIXTURE_VARIANTS:-defective fixed}"

mkdir -p "$OUT"
for shape in $SHAPES; do
    for variant in $VARIANTS; do
        dest="$OUT/${shape}_${variant}.py"
        sed -e "s/@@SHAPE@@/${shape}/" -e "s/@@VARIANT@@/${variant}/" \
            "$SRC" >"$dest"
        chmod +x "$dest"
        grep -q "SHAPE = \"${shape}\"" "$dest" \
            && grep -q "VARIANT = \"${variant}\"" "$dest" \
            || { echo "build.sh: substitution failed for ${shape}/${variant}" >&2
                 exit 1; }
        # A twin that cannot even print its own help is not a target; catching
        # that here beats every probe reporting `errored` one layer up.
        "$dest" version >/dev/null \
            || { echo "build.sh: ${dest} does not run" >&2; exit 1; }
        printf '%s\n' "$dest"
    done
done

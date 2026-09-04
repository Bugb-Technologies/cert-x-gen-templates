#!/usr/bin/env bash
# Materialise the flawed / fixed / nosandbox twins from the single
# sandbox-runner.py source.
#
# One source, three twins: the fixed twin must be the same program with the
# handoff trust-downgrade switched on, and the nosandbox twin the same program
# with confinement switched off, or the template's REFUTED / SKIP verdicts only
# prove that three files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/sandbox-runner.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in flawed fixed nosandbox; do
    dest="$OUT/sandbox-runner_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' \
    "$OUT/sandbox-runner_flawed.py" \
    "$OUT/sandbox-runner_fixed.py" \
    "$OUT/sandbox-runner_nosandbox.py"

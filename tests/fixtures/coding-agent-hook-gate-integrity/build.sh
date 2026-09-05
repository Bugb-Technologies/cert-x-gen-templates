#!/usr/bin/env bash
# Materialise the seven twins from the single agent-host.py source.
#
# One source, seven twins: the honouring twin must be the same program with the
# three flaw switches off, the isolating twins the same program with exactly one
# on, the nohook twin the same program with the gate removed, and the inert twin
# the same program whose gated action is unachievable -- otherwise the driving
# template's REFUTED and SKIP verdicts only prove that seven files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agent-host.py"
OUT="${1:-$HERE/build}"

VARIANTS="flawed fixed ignorehook repodisarm failopen nohook inert"

mkdir -p "$OUT"
for variant in $VARIANTS; do
    dest="$OUT/agent-host_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

for variant in $VARIANTS; do
    printf '%s\n' "$OUT/agent-host_${variant}.py"
done

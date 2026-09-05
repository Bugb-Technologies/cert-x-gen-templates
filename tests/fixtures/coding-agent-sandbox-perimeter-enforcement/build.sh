#!/usr/bin/env bash
# Materialise the flawed / fixed / nosandbox / inert twins from the single
# agent-host.py source.
#
# One source, four twins: the enforcing twin must be the same program with the
# policy injection switched on, the nosandbox twin the same program with the
# confinement control removed, and the inert twin the same program whose
# confinement is not tied to the setting -- otherwise the template's REFUTED and
# SKIP verdicts only prove that four files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agent-host.py"
OUT="${1:-$HERE/build}"

mkdir -p "$OUT"
for variant in flawed fixed nosandbox inert; do
    dest="$OUT/agent-host_${variant}.py"
    sed "s/@@VARIANT@@/${variant}/" "$SRC" >"$dest"
    chmod +x "$dest"
    grep -q "VARIANT = \"${variant}\"" "$dest" \
        || { echo "build.sh: variant substitution failed for $variant" >&2; exit 1; }
done

printf '%s\n' \
    "$OUT/agent-host_flawed.py" \
    "$OUT/agent-host_fixed.py" \
    "$OUT/agent-host_nosandbox.py" \
    "$OUT/agent-host_inert.py"

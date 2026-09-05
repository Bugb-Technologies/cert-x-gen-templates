#!/usr/bin/env bash
# Materialise the nine twins from the single agent-host.py source.
#
# One source, nine twins: the enforcing twin must be the same program with the
# flaw switches off, the isolating twins the same program with exactly one on,
# and the three SKIP twins the same program with a precondition removed --
# otherwise the driving template's REFUTED and SKIP verdicts only prove that
# nine files differ.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agent-host.py"
OUT="${1:-$HERE/build}"

VARIANTS="flawed fixed syntaxonly toctouonly inertrule deadrule nodeny rejects deadchannels"

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

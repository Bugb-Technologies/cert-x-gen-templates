#!/usr/bin/env bash
#
# Proof harness for templates/tooling/supply-chain/supply-chain-install-hook-behavior.sh
#
# A check you cannot make REFUTE is not a check, so every case here is a pair:
# a flawed twin the template must confirm on, and a fixed twin - same shape,
# same active hook, effects confined to its own tree - it must refute on. A
# case that fails either direction fails the run.
#
# It drives the template through `cxg scan` when cxg is on PATH, and through
# the probe-contract environment directly otherwise, so it is runnable with or
# without the engine installed.
#
#   ./tests/prove-supply-chain-install-hook.sh            # every available ecosystem
#   ./tests/prove-supply-chain-install-hook.sh npm        # just npm
#   CXG_PROVE_ENGINE=env ./tests/prove-supply-chain-install-hook.sh
#
# SAFETY: the fixtures are benign synthetic packages that touch only the
# throwaway HOME the template hands them and beacon to a host under .invalid,
# which no resolver answers. Nothing here installs anything from a registry.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$REPO/templates/tooling/supply-chain/supply-chain-install-hook-behavior.sh"
FIXTURES="$REPO/tests/fixtures/tooling/supply-chain"
WANT="${1:-all}"
ENGINE="${CXG_PROVE_ENGINE:-auto}"

PASS=0
FAIL=0
SKIP=0

if [ "$ENGINE" = "auto" ]; then
    if command -v cxg >/dev/null 2>&1; then ENGINE="cxg"; else ENGINE="env"; fi
fi

# run_template <manager> <package> <phases> -> the template's JSON on stdout
run_template() {
    local manager="$1" package="$2" phases="$3"
    if [ "$ENGINE" = "cxg" ] && [ "${FORCE_ENV:-0}" = "0" ]; then
        local out
        out="$(mktemp -d)"
        mkdir -p "$out/home"
        HOME="$out/home" CXG_SUPPLY_CHAIN_PACKAGE="$package" \
        CXG_SUPPLY_CHAIN_PHASES="$phases" \
            cxg --disable-update-check scan \
                --scope "cli://$manager" \
                --templates "$TEMPLATE" \
                --output-format json -o "$out/scan.json" >/dev/null 2>&1
        # cxg reports the findings; the template's own metadata.status is not
        # carried through the scan result, so the verdict is read from whether
        # a finding survived.
        python3 - "$out/scan.json" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        report = json.load(fh)
except (OSError, ValueError):
    print(json.dumps({"status": "errored", "detail": "no scan output", "findings": []}))
    sys.exit(0)
findings = report.get("findings", [])
print(json.dumps({
    "status": "confirmed" if findings else "refuted",
    "detail": "; ".join(f.get("title", "") for f in findings) or "no findings",
    "findings": findings,
}))
PY
        rm -rf "$out"
    else
        local out
        out="$(mktemp -d)"
        mkdir -p "$out/home"
        CERT_X_GEN_MODE=engine \
        CERT_X_GEN_TARGET_KIND=cli \
        CERT_X_GEN_TARGET_HOST="$manager" \
        CERT_X_GEN_INPUT_DIR="$package" \
        CXG_SUPPLY_CHAIN_PHASES="$phases" \
        HOME="$out/home" \
            bash "$TEMPLATE" >"$out/probe.json" 2>/dev/null
        # The template's JSON goes to a FILE and the file is named on argv: a
        # heredoc-supplied python program owns stdin, so a piped payload would
        # never reach it.
        python3 - "$out/probe.json" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        raw = json.loads(fh.readline() or "{}")
except (OSError, ValueError):
    raw = {}
meta = raw.get("metadata", {})
print(json.dumps({"status": meta.get("status", "errored"),
                  "detail": meta.get("detail", ""),
                  "findings": raw.get("findings", [])}))
PY
        rm -rf "$out"
    fi
}

# expect <want> <label> <manager> <package> <phases>
expect() {
    local want="$1" label="$2" manager="$3" package="$4" phases="$5"
    local got detail
    got="$(run_template "$manager" "$package" "$phases")"
    detail="$(printf '%s' "$got" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"]+"|"+d["detail"][:150])')"
    if [ "${detail%%|*}" = "$want" ]; then
        PASS=$((PASS + 1))
        printf 'PASS  %-46s %s\n' "$label" "${detail%%|*}"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL  %-46s wanted %s, got %s\n' "$label" "$want" "$detail"
    fi
}

printf 'proving %s\n' "$(basename "$TEMPLATE")"
printf 'engine: %s\n\n' "$ENGINE"

# --- npm -------------------------------------------------------------------
if [ "$WANT" = "all" ] || [ "$WANT" = "npm" ]; then
    NPM="$(command -v npm)"
    if [ -n "$NPM" ]; then
        expect confirmed "npm install hook, flawed twin" \
            "$NPM" "$FIXTURES/npm/flawed" install
        expect refuted   "npm install hook, fixed twin" \
            "$NPM" "$FIXTURES/npm/fixed"  install
    else
        SKIP=$((SKIP + 1)); printf 'SKIP  %-46s npm not installed\n' "npm"
    fi
fi

# --- pip -------------------------------------------------------------------
# One case per lifecycle phase. A confirmation ends the run at the phase that
# produced it, so proving that all three phases work means selecting them one
# at a time.
if [ "$WANT" = "all" ] || [ "$WANT" = "pip" ]; then
    PIP="$(command -v pip3 || command -v pip)"
    if [ -n "$PIP" ]; then
        for phase in install startup import; do
            expect confirmed "pip $phase, flawed twin" \
                "$PIP" "$FIXTURES/pip/flawed" "$phase"
        done
        expect refuted "pip all phases, fixed twin" \
            "$PIP" "$FIXTURES/pip/fixed" install,startup,import
    else
        SKIP=$((SKIP + 1)); printf 'SKIP  %-46s pip not installed\n' "pip"
    fi
fi

# --- the guards ------------------------------------------------------------
# A template that cannot say "I did not test this" reports a clean bill of
# health it did not earn, so the skip paths are proved too.
if [ "$WANT" = "all" ] || [ "$WANT" = "guards" ]; then
    # Driven through the probe-contract environment rather than `cxg scan`:
    # a scan result carries findings, and "no findings" cannot tell a skip
    # apart from a refutation. Only the template's own metadata.status can,
    # and that distinction is the whole point of these two cases.
    FORCE_ENV=1
    NPM="$(command -v npm)"
    if [ -n "$NPM" ]; then
        expect skipped "no subject package is a skip, not a refutation" \
            "$NPM" "" install
    fi
    if command -v git >/dev/null 2>&1; then
        expect skipped "a binary that is not a package manager is a skip" \
            "$(command -v git)" "$FIXTURES/npm/flawed" install
    fi
fi

FORCE_ENV=0

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]

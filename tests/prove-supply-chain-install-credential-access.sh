#!/usr/bin/env bash
#
# Proof harness for
# templates/tooling/supply-chain/supply-chain-install-credential-access.sh
#
# A check you cannot make REFUTE is not a check, so every case here is a pair:
# a flawed twin the template must confirm on, and a fixed twin - same shape,
# same active install hook, effects confined to its own tree - it must refute
# on. A case that fails either direction fails the run.
#
# It drives the template through `cxg scan` when cxg is on PATH, and through
# the probe-contract environment directly otherwise, so it is runnable with or
# without the engine installed.
#
#   ./tests/prove-supply-chain-install-credential-access.sh          # all
#   ./tests/prove-supply-chain-install-credential-access.sh npm      # just npm
#   CXG_PROVE_ENGINE=env ./tests/prove-supply-chain-install-credential-access.sh
#
# SAFETY: the fixtures are benign synthetic packages. The only credentials they
# can find are the random canary nonces the template plants in a throwaway
# HOME; the workflow they write goes into that HOME's throwaway checkout and
# each fixture refuses outright to write outside a temp directory; and the C2
# host they beacon to is under .invalid (RFC 2606), which no resolver answers.
# Nothing here installs anything from a registry.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$REPO/templates/tooling/supply-chain/supply-chain-install-credential-access.sh"
FIXTURES="$REPO/tests/fixtures/tooling/supply-chain-credential-access"
WANT="${1:-all}"
ENGINE="${CXG_PROVE_ENGINE:-auto}"

PASS=0
FAIL=0
SKIP=0

if [ "$ENGINE" = "auto" ]; then
    if command -v cxg >/dev/null 2>&1; then ENGINE="cxg"; else ENGINE="env"; fi
fi

# run_template <manager> <package> -> a JSON verdict on stdout
run_template() {
    local manager="$1" package="$2"
    local out
    out="$(mktemp -d)"
    mkdir -p "$out/home"
    if [ "$ENGINE" = "cxg" ] && [ "${FORCE_ENV:-0}" = "0" ]; then
        HOME="$out/home" CXG_SUPPLY_CHAIN_PACKAGE="$package" \
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
    else
        CERT_X_GEN_MODE=engine \
        CERT_X_GEN_TARGET_KIND=cli \
        CERT_X_GEN_TARGET_HOST="$manager" \
        CERT_X_GEN_INPUT_DIR="$package" \
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
    fi
    rm -rf "$out"
}

# expect <want> <label> <manager> <package> [<pattern that must appear>]
expect() {
    local want="$1" label="$2" manager="$3" package="$4" needle="${5:-}"
    local got detail
    got="$(run_template "$manager" "$package")"
    detail="$(printf '%s' "$got" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"]+"|"+d["detail"][:200])')"
    if [ "${detail%%|*}" != "$want" ]; then
        FAIL=$((FAIL + 1))
        printf 'FAIL  %-52s wanted %s, got %s\n' "$label" "$want" "$detail"
        return
    fi
    # A confirmation on the right verdict for the wrong reason is not a proof,
    # so the confirming cases also assert WHICH observable fired.
    if [ -n "$needle" ] && ! printf '%s' "$got" | grep -qF "$needle"; then
        FAIL=$((FAIL + 1))
        printf 'FAIL  %-52s %s, but evidence lacked %s\n' "$label" "$want" "$needle"
        return
    fi
    PASS=$((PASS + 1))
    printf 'PASS  %-52s %s\n' "$label" "${detail%%|*}"
}

printf 'proving %s\n' "$(basename "$TEMPLATE")"
printf 'engine: %s\n\n' "$ENGINE"

# --- npm -------------------------------------------------------------------
# The flawed twin must be caught reading the two credential files npm itself
# never opens. ~/.npmrc is deliberately NOT asserted: npm reads it on every
# invocation, the control install proves that, and it is reported as a soft
# observation rather than as the finding.
if [ "$WANT" = "all" ] || [ "$WANT" = "npm" ]; then
    NPM="$(command -v npm)"
    if [ -n "$NPM" ]; then
        expect confirmed "npm postinstall, flawed twin" \
            "$NPM" "$FIXTURES/npm/flawed" "workflow-planted"
        expect confirmed "npm postinstall, flawed twin names the secrets" \
            "$NPM" "$FIXTURES/npm/flawed" ".config/gh/hosts.yml"
        expect refuted   "npm postinstall, fixed twin" \
            "$NPM" "$FIXTURES/npm/fixed"
    else
        SKIP=$((SKIP + 1)); printf 'SKIP  %-52s npm not installed\n' "npm"
    fi
fi

# --- pip -------------------------------------------------------------------
if [ "$WANT" = "all" ] || [ "$WANT" = "pip" ]; then
    PIP="$(command -v pip3 || command -v pip)"
    if [ -n "$PIP" ]; then
        expect confirmed "pip build backend, flawed twin" \
            "$PIP" "$FIXTURES/pip/flawed" "workflow-planted"
        expect confirmed "pip build backend, flawed twin names the secrets" \
            "$PIP" "$FIXTURES/pip/flawed" ".aws/credentials"
        expect refuted   "pip build backend, fixed twin" \
            "$PIP" "$FIXTURES/pip/fixed"
    else
        SKIP=$((SKIP + 1)); printf 'SKIP  %-52s pip not installed\n' "pip"
    fi
fi

# --- the guards ------------------------------------------------------------
# A template that cannot say "I did not test this" reports a clean bill of
# health it did not earn, so the skip paths are proved too. Driven through the
# probe-contract environment rather than `cxg scan`: a scan result carries
# findings, and "no findings" cannot tell a skip apart from a refutation. Only
# the template's own metadata.status can, and that distinction is the whole
# point of these two cases.
if [ "$WANT" = "all" ] || [ "$WANT" = "guards" ]; then
    FORCE_ENV=1
    NPM="$(command -v npm)"
    if [ -n "$NPM" ]; then
        expect skipped "no subject package is a skip, not a refutation" \
            "$NPM" ""
    fi
    if command -v git >/dev/null 2>&1; then
        expect skipped "a binary that is not a package manager is a skip" \
            "$(command -v git)" "$FIXTURES/npm/flawed"
    fi
    FORCE_ENV=0
fi

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]

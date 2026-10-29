#!/usr/bin/env bash
#
# Behavioural proof for templates/web/auth-bypass/traefik-replacepathregex-auth-bypass.py
# (CVE-2026-65600). Not a CI check -- it needs Docker and sends traffic only to a
# loopback lab it builds itself. Run it by hand before changing the template.
#
# It stands up the advisory's vulnerable configuration behind two Traefik builds and
# asserts all three verdicts the template can reach:
#
#   vulnerable (traefik:v3.7.6)  -> CONFIRMED  (a finding; the rewrite reaches /admin)
#   fixed      (traefik:v3.7.7)  -> REFUTED    (no finding; Traefik rejects the rewrite)
#   unrelated  (plain server)    -> no finding (the surface is absent; template skips)
#
# Everything binds to 127.0.0.1. No exploit payload is sent: the probe is a single
# GET whose path carries a literal ".." segment, retrieving a benign marker file.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
LAB="$HERE/fixtures/traefik-replacepathregex"
TEMPLATE_ID="traefik-replacepathregex-auth-bypass"
CTX='{"protected_marker":"CXG-TRAEFIK-LAB-PROTECTED"}'
WORK="$(mktemp -d)"

VULN_IMAGE="traefik:v3.7.6"
FIXED_IMAGE="traefik:v3.7.7"

cleanup() {
  ( cd "$LAB" && TRAEFIK_IMAGE="$VULN_IMAGE" docker compose down -v >/dev/null 2>&1 || true )
  rm -rf "$WORK"
}
trap cleanup EXIT

compose_up() { # image
  ( cd "$LAB" && TRAEFIK_IMAGE="$1" docker compose down >/dev/null 2>&1 || true )
  ( cd "$LAB" && TRAEFIK_IMAGE="$1" docker compose up -d >/dev/null 2>&1 )
}

wait_http() { # url
  for _ in $(seq 1 30); do
    local c; c="$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$1" || true)"
    [ "$c" != "000" ] && return 0
    sleep 1
  done
  return 1
}

# Run the template through the engine and print its inferred status for the one
# execution. An http:// scope is required so the engine probes over HTTP.
engine_status() { # url label
  local url="$1" label="$2" out="$WORK/report-$2"
  ( cd "$REPO_ROOT" && cxg --disable-update-check scan -q \
      --scope "$url" --templates "$TEMPLATE_ID" --context "$CTX" \
      --output "$out" --output-format json >/dev/null 2>&1 )
  python3 - "$out.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
e = d["executions"][0]
print("%s|%d" % (e["status"], len(d["findings"])))
PY
}

pass=0; fail=0
assert() { # description actual expected
  if [ "$2" = "$3" ]; then echo "  [PASS] $1 ($2)"; pass=$((pass+1));
  else echo "  [FAIL] $1 (got '$2', expected '$3')"; fail=$((fail+1)); fi
}

echo "== Arm 1: vulnerable $VULN_IMAGE =="
compose_up "$VULN_IMAGE"
wait_http "http://127.0.0.1:8080/api" || { echo "lab did not come up"; exit 1; }
res="$(engine_status http://127.0.0.1:8080 vuln)"
assert "vulnerable build is CONFIRMED with a finding" "$res" "confirmed|1"

echo "== Arm 2: fixed $FIXED_IMAGE =="
compose_up "$FIXED_IMAGE"
wait_http "http://127.0.0.1:8080/api" || { echo "lab did not come up"; exit 1; }
res="$(engine_status http://127.0.0.1:8080 fixed)"
assert "fixed build is REFUTED with no finding" "$res" "refuted|0"

echo "== Arm 3: unrelated control (plain server, no Traefik) =="
# The control service is already published on 127.0.0.1:8090 by the compose stack.
res="$(engine_status http://127.0.0.1:8090 control)"
# The template emits 'skipped' (no ReplacePathRegex surface); the engine infers
# 'refuted' from the empty findings array. Either way the point is: no finding.
findings="${res##*|}"
assert "unrelated service yields no finding (no misfire)" "$findings" "0"

echo
echo "summary: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

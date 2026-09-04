#!/usr/bin/env python3
r"""
The value-level half of the credential-exposure oracle's proof - issue #32
section 2 turned into assertions.

BENIGN is every string the issue names as ordinary documentation or config
example text that v1's `pass(?:word|wd)?\s*[:=]\s*\S{6,}` reported as a
critical secret. None may produce a secret; each should be recorded as a
`placeholder-assignment` observation instead, so the report still says what was
seen.

LIVE is the other direction: synthetic, obviously-fake-but-structurally-valid
credentials that the template must still read as secrets. Every value here is
invented for this fixture - no real key, account or endpoint is referenced.

    python3 secret_corpus.py       # exit 0 = the oracle holds
"""
import importlib.util
import os
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = pathlib.Path(os.environ.get(
    "CXG_TEMPLATE", REPO / "templates/ai/mcp/mcp-credential-exposure.py"))
spec = importlib.util.spec_from_file_location("mcp_credential_exposure", TEMPLATE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# --- issue #32 section 2, verbatim, plus the rest of a .env.example ---------
BENIGN = [
    ("issue #32: your-password-here", "password: your-password-here"),
    ("issue #32: <redacted>", "password = <redacted>"),
    ("issue #32: asterisks", "password: ********"),
    ("issue #32: ${DB_PASSWORD}", "password: ${DB_PASSWORD}"),
    ("issue #32: changeme", "passwd: changeme"),
    ("issue #32: **REDACTED**", "password: **REDACTED**"),
    ("env var reference", "PGPASSWORD=$PGPASSWORD"),
    ("windows var reference", "password=%PASSWORD%"),
    ("mustache template", "password: {{password}}"),
    ("xxxx mask", "password: xxxxxxxxxxxx"),
    ("dotted mask", "password: ............"),
    ("literal word 'password'", "password: password"),
    ("api_key placeholder", "api_key: your-api-key-here"),
    ("api_key masked", "api_key = XXXXXXXXXXXXXXXX"),
    ("prose about passwords", "Rotate the password every 90 days per policy."),
    ("templated connection string",
     "postgres://app:${DB_PASSWORD}@db.internal:5432/app"),
    ("connection string with mask", "mysql://svc:********@db.internal:3306/app"),
]

# --- synthetic credentials: fake values, real structure --------------------
LIVE = [
    ("aws-access-key", "AWS_ACCESS_KEY_ID=AKIAZZZZFIXTUREZZZZQ"),
    ("openai-style-key", "OPENAI_API_KEY=sk-cxgFIXTUREnotARealKey0123456789"),
    ("google-api-key", "key: AIzaSyCXGFIXTURE_not_a_real_key_000"),
    ("private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n"),
    ("jwt", "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjeGctZml4dHVyZSJ9.c3ludGhldGlj"),
    ("db-connection-string", "postgres://app:R7x-Qv2_Lm9Zt4Wb@db.internal:5432/app"),
    ("password-assignment", "password = R7x-Qv2_Lm9Zt4Wb"),
    ("generic-api-key", "api_key: cxg7Kq2Zt9Lm4Wb0Rv3X"),
]

failed = 0

print("--- benign: no secret, an observation instead (issue #32 section 2) ---")
for label, text in BENIGN:
    secrets, obs = mod.scan_secrets(text)
    if secrets:
        print("FAIL  %-32s reported %s" % (label, [s["type"] for s in secrets]))
        failed = 1
    else:
        note = " (+%d observation)" % len(obs) if obs else ""
        print("ok    %-32s no secret%s" % (label, note))

print("--- synthetic credentials: must still be read as secrets ---")
for expect, text in LIVE:
    secrets, _ = mod.scan_secrets(text)
    types = [s["type"] for s in secrets]
    if expect in types:
        print("ok    %-32s %s" % (expect, types))
    else:
        print("FAIL  %-32s expected %s, got %s" % (expect, expect, types))
        failed = 1

print("CORPUS OK" if not failed else "CORPUS FAILED")
sys.exit(failed)

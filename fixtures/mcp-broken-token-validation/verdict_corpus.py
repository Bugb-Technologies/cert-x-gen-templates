#!/usr/bin/env python3
"""
Precision proof for `response_accepted` in mcp-broken-token-validation.py.

The check is ACTIVE: it sends a forged, never-issued token to a verifier tool
and reports the server as broken only if the verifier ACCEPTS it. The whole
finding therefore rests on reading the verifier's response correctly, and v1's
did not: `{"valid": false}` and "token is not valid" both read as ACCEPTANCES,
because an ACCEPT regex matched `valid` while a REJECT regex keyed on `invalid`
did not match `false` or `not valid`. A correctly-rejecting verifier was
reported as broken authentication - a false positive on the safe case.

REJECTIONS below are the responses a sound verifier returns for a forged token;
none may read as accepted. ACCEPTANCES are the responses a genuinely broken
verifier returns; each must. A structured JSON verdict is read first, then a
negation-aware word scan.

    python3 verdict_corpus.py       # exit 0 = the oracle holds
"""
import importlib.util
import os
import pathlib
import sys

TEMPLATE = pathlib.Path(os.environ.get(
    "CXG_TEMPLATE",
    pathlib.Path(__file__).resolve().parents[2]
    / "templates/ai/mcp/mcp-broken-token-validation.py"))
spec = importlib.util.spec_from_file_location("mcp_btv", TEMPLATE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

REJECTIONS = [
    '{"valid": false}',
    '{"authenticated": false, "reason": "unknown token"}',
    '{"valid": false, "error": "not issued"}',
    '{"error": "token expired"}',
    '{"status": "denied"}',
    '{"valid": true, "expired": true}',   # contradictory but a rejection wins
    "Token is not valid.",
    "The token is not recognized.",
    "Session lookup complete: no active session found.",
    "invalid token",
    "Authentication failed: unrecognized token.",
    "Access denied.",
    "This tool validates a session token and returns its status.",  # desc echo
]

ACCEPTANCES = [
    '{"valid": true}',
    '{"authenticated": true, "user": "alice"}',
    '{"status": "ok"}',
    '{"authorized": true}',
    "Token accepted. Welcome, alice.",
    "The token is valid and the session is active.",
    "Authentication succeeded; access granted.",
]

failed = 0
print("--- rejections: a sound verifier's answer must NOT read as accepted ---")
for text in REJECTIONS:
    if mod.response_accepted(text):
        print("FAIL  read as ACCEPTED: %r" % text)
        failed = 1
    else:
        print("ok    rejected        %r" % text)

print("--- acceptances: a broken verifier's answer MUST read as accepted ---")
for text in ACCEPTANCES:
    if mod.response_accepted(text):
        print("ok    accepted        %r" % text)
    else:
        print("FAIL  missed acceptance: %r" % text)
        failed = 1

print("CORPUS OK" if not failed else "CORPUS FAILED")
sys.exit(failed)

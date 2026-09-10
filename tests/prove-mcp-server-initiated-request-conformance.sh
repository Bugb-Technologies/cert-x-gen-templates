#!/usr/bin/env bash
#
# Proof harness for
# templates/ai/mcp/mcp-server-initiated-request-conformance.py
#
# The twins and every assertion live beside the fixture they drive, the shape
# the other MCP templates use:
#
#     fixtures/mcp-server-initiated-request-conformance/prove.sh
#
# This is the entry point from tests/, so the harness is reachable from where
# the shell-template proofs live too. Every argument and environment variable is
# passed straight through - CXG_MCP_IDLE_WINDOW_SECONDS is the useful one.
#
#   ./tests/prove-mcp-server-initiated-request-conformance.sh
#   CXG_MCP_IDLE_WINDOW_SECONDS=30 ./tests/prove-mcp-server-initiated-request-conformance.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
exec "$REPO/fixtures/mcp-server-initiated-request-conformance/prove.sh" "$@"

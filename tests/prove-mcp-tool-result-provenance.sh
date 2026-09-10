#!/usr/bin/env bash
# Entry point for the proof of templates/ai/mcp/mcp-tool-result-provenance.py.
#
# The harness itself lives beside its synthetic target, at
# fixtures/mcp-tool-result-provenance/prove.sh, because that target is a live
# HTTP MCP server and AGENTS.md puts a template's synthetic target under
# fixtures/<template-id>/. This script is here so `tests/` has one uniform place
# to start every proof from; it delegates rather than duplicating, so there is
# exactly one source of truth for what the twelve directions assert.
#
#   ./tests/prove-mcp-tool-result-provenance.sh    # exit 0 = every direction holds
#
# What it proves, in one line each:
#   CONFIRM  flawed      third-party body re-emitted verbatim, no mark of any kind
#   REFUTE   fixed       wrapped + labelled untrusted + `_meta` provenance
#   REFUTE   attributed  origin named, trust never framed - the near-miss stays soft
#   REFUTE   escaped     the body comes back base64'd, the directive is not prose
#   REFUTE   summarised  fetched, and the body never came back
#   SKIP     nofetch     answers cleanly, never retrieves - no boundary was shown
#   SKIP     notools     no read-type tool with a URL argument - nothing crosses
#   SKIP     unroutable origin, dead port, a cli:// target
#   ERROR    a tool named in CXG_MCP_PROVENANCE_TOOL that the server does not have
#   cxg      the real engine: 1 finding on flawed, 0 on the other six twins
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/../fixtures/mcp-tool-result-provenance/prove.sh" "$@"

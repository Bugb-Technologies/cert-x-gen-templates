#!/usr/bin/env python3
# @id: mcp-invisible-unicode-poisoning
# @name: MCP Invisible-Unicode Tool Poisoning (Approval-View Fidelity Gap)
# @author: Bugb Research
# @severity: high
# @description: Detects MCP servers whose advertised tool, prompt, resource or instructions text carries Unicode that a human approval view never renders but the connected model still reads - TAG-block payloads, zero-width carrier runs, and Trojan-Source bidi controls
# @tags: mcp, ai, agent, tool-poisoning, prompt-injection, unicode, trojan-source, cwe-1427
# @cwe: CWE-1427, CWE-1007
# @cvss: 8.2
# @target_kinds: http
# @oracles: property
# @references: https://arxiv.org/pdf/2607.05744, https://modelcontextprotocol.io/specification, https://cwe.mitre.org/data/definitions/1427.html, https://cwe.mitre.org/data/definitions/1007.html, https://trojansource.codes/
# @confidence: 100
# @version: 1.0.0
"""
MCP invisible-unicode tool poisoning - the approval-view fidelity gap.

An MCP client shows a human the tool's `description` and asks them to approve
it.  The model is handed the same string.  They are not the same string: a
terminal or a chat bubble renders the *visible* characters, and Unicode has
whole planes of characters that render as nothing at all.  Text placed there is
invisible in the approval view and fully legible to the model.

This template reads the invariant, not the intent.  It never asks "does this
description look like an instruction" - that question has no answer a scanner
can get right, and asking it is what makes text-matching MCP checks noisy
(this repo's issue #31).  It asks a structural question instead:

    does this string contain an invisible character in a position where that
    character has no defined text function?

That has exactly one answer, and no correct MCP server produces a `true`.

THE FIVE HARD CLASSES  (any one of these alone is a confirmation)

  H1 tag-block-payload        A character in the Unicode TAG block
                              (U+E0000-U+E007F) outside a well-formed RGI emoji
                              tag sequence.  The block's only living use is the
                              three subdivision flags (U+1F3F4 ... U+E007F).
                              Anywhere else it is a deprecated language tag
                              that renders as nothing and mirrors ASCII
                              one-for-one, so the payload decodes directly.
  H2 zero-width-run           Two or more ADJACENT zero-width format characters
                              from {U+200B U+200C U+200D U+2060 U+FEFF U+00AD}.
                              No script needs two invisible formatters in a
                              row: an emoji ZWJ sequence interleaves ZWJ with
                              pictographs, a joiner in an Indic or Arabic word
                              sits between letters, a BOM is one leading
                              character.  A run is a carrier, usually a binary
                              encoding.
  H3 zero-width-in-ascii-word ZWJ or ZWNJ (U+200D/U+200C) with a Basic-Latin
                              letter or digit on BOTH sides.  Those two
                              characters have a rendering function only for
                              cursive-joining scripts and emoji sequences;
                              between `a` and `b` they change nothing on screen
                              and only break the string for whoever is reading
                              it.
  H4 unbalanced-bidi          A bidi embedding, override or isolate initiator
                              (U+202A U+202B U+202D U+202E U+2066-8) left
                              unterminated within the field.  Trojan Source
                              (CVE-2021-42574): unbalanced controls reorder
                              text past the end of the string they appear in.
  H5 bidi-override-no-rtl     U+202D or U+202E - the two *overrides*, which
                              force direction irrespective of a character's own
                              bidi class - in a field containing no strong-RTL
                              character at all.  An override with nothing to
                              override exists only to reorder the ASCII a
                              human is about to read.

WHAT IS DELIBERATELY *NOT* A CONFIRMATION

Issue #31 is that "a zero-width character is present" is not a finding, because
those characters arrive through mundane routes.  Every route it names is
refuted by construction above, and the residue is reported as an observation in
the evidence and never on its own:

  U+FEFF as a leading BOM            offset 0 is its defined position; only an
                                     INTERIOR one is recorded, and only as an
                                     observation (concatenating two BOM-prefixed
                                     files produces one honestly).
  U+200D inside an emoji sequence    both neighbours are pictographic, so H2 and
                                     H3 cannot fire (family and flag emoji, skin
                                     tone and profession sequences).
  U+200C in Persian/Urdu/Hindi       both neighbours are non-Latin letters, so
                                     H3 cannot fire; a joiner never doubles, so
                                     H2 cannot fire.
  U+FE0F variation selectors         excluded from the zero-width set entirely -
                                     VS16 legitimately abuts a ZWJ in emoji.
  One stray U+200B from a web paste  a single joiner outside an ASCII word is an
                                     observation, not a finding.

A field carrying only observations reports nothing.  This is the whole point:
the check is right by construction rather than right on average.

Transports: streamable HTTP (POST initialize -> tools/list) and legacy HTTP+SSE.

Verdict contract, as the CLI Security Baseline pack states it:
  confirmed  an invisible character was found in a position with no text function
  refuted    the server was enumerated, advertised text was read, and none was
  skipped    no MCP server answered, or it advertised no text to read
  errored    the target could not be reached at all
"""

import json
import os
import queue
import re
import ssl
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timezone

METADATA = {
    "id": "mcp-invisible-unicode-poisoning",
    "name": "MCP Invisible-Unicode Tool Poisoning (Approval-View Fidelity Gap)",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "high",
    "description": (
        "Detects MCP servers advertising tool, prompt, resource or instructions text that carries "
        "Unicode a human approval view never renders but the connected model reads: TAG-block "
        "payloads, zero-width carrier runs, and Trojan-Source bidi controls"
    ),
    "tags": ["mcp", "ai", "agent", "tool-poisoning", "prompt-injection", "unicode",
             "trojan-source", "cwe-1427"],
    "language": "python",
    "confidence": 100,
    "cwe": ["CWE-1427", "CWE-1007"],
    "references": [
        "https://arxiv.org/pdf/2607.05744",
        "https://modelcontextprotocol.io/specification",
        "https://cwe.mitre.org/data/definitions/1427.html",
        "https://cwe.mitre.org/data/definitions/1007.html",
        "https://trojansource.codes/",
    ],
}

MCP_PATHS = ["/mcp", "/", "/rpc"]
PROTO_VERSION = "2024-11-05"

# ---------------------------------------------------------------------------
# The character sets.  Each is a closed list with a stated reason for every
# member, because "which characters count" IS the oracle.
# ---------------------------------------------------------------------------

TAG_LO, TAG_HI = 0xE0000, 0xE007F
TAG_TERMINATOR = 0xE007F          # CANCEL TAG - closes an emoji tag sequence
TAG_ASCII_LO, TAG_ASCII_HI = 0xE0020, 0xE007E   # the ASCII-mirroring subrange
WAVING_BLACK_FLAG = 0x1F3F4       # the only legal base for a tag sequence

# Zero-width formatters.  U+FE0F and the other variation selectors are
# deliberately absent: VS16 legitimately sits next to a ZWJ in emoji, and
# including it would make H2 fire on every waving flag.
ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x00AD: "SOFT HYPHEN",
}
JOINERS = {0x200C, 0x200D}        # the two with a script-dependent function

BIDI_OPEN = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
}
BIDI_OVERRIDES = {0x202D, 0x202E}
BIDI_POP_EMBEDDING = 0x202C       # closes 202A/202B/202D/202E
BIDI_POP_ISOLATE = 0x2069         # closes 2066/2067/2068
BIDI_ALL = set(BIDI_OPEN) | {BIDI_POP_EMBEDDING, BIDI_POP_ISOLATE}

ASCII_WORD = re.compile(r"[A-Za-z0-9]")


def _is_pictographic(ch):
    """True for emoji-ish scalars, so an emoji ZWJ sequence is never a finding.

    Deliberately a codepoint-range test rather than a property lookup: the
    stdlib exposes no Extended_Pictographic, and these ranges are the ones a
    ZWJ or a variation selector legitimately abuts.
    """
    cp = ord(ch)
    return (
        0x1F000 <= cp <= 0x1FAFF          # the emoji planes
        or 0x2600 <= cp <= 0x27BF         # misc symbols + dingbats
        or 0x2190 <= cp <= 0x21FF         # arrows (many are emoji with VS16)
        or 0xFE00 <= cp <= 0xFE0F         # variation selectors
        or 0x1F1E6 <= cp <= 0x1F1FF       # regional indicators
        or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139)
    )


def _codes(text, lo, hi=None):
    """U+XXXX labels for the matching codepoints, for evidence."""
    out = []
    for ch in text:
        cp = ord(ch)
        if (hi is None and cp in lo) or (hi is not None and lo <= cp <= hi):
            label = "U+%04X" % cp
            if label not in out:
                out.append(label)
    return out


def _visible(text, limit=240):
    """Render a field for a report with every invisible character named.

    A report that quoted the raw string would carry the payload into whatever
    reads the report - the same concealment, one hop downstream.
    """
    out = []
    for ch in text[:limit]:
        cp = ord(ch)
        if cp in ZERO_WIDTH or cp in BIDI_ALL or TAG_LO <= cp <= TAG_HI or cp < 0x20:
            out.append("<U+%04X>" % cp)
        else:
            out.append(ch)
    return "".join(out) + ("..." if len(text) > limit else "")


# ---------------------------------------------------------------------------
# The oracle.  analyze() returns (hard, soft): `hard` are structural facts that
# confirm on their own, `soft` are recorded and never sufficient.
# ---------------------------------------------------------------------------

def _tag_sequence_spans(text):
    """Character index ranges covered by well-formed RGI emoji tag sequences.

    U+1F3F4 followed by one or more U+E0020-U+E007E and closed by U+E007F.
    Anything else in the TAG block is outside a legal sequence.
    """
    spans = []
    i = 0
    n = len(text)
    while i < n:
        if ord(text[i]) == WAVING_BLACK_FLAG:
            j = i + 1
            while j < n and TAG_ASCII_LO <= ord(text[j]) <= TAG_ASCII_HI:
                j += 1
            if j > i + 1 and j < n and ord(text[j]) == TAG_TERMINATOR:
                spans.append((i, j))
                i = j + 1
                continue
        i += 1
    return spans


def _decode_tags(text, indices):
    """TAG-block characters mirror ASCII: U+E0041 is 'A'."""
    out = []
    for i in indices:
        cp = ord(text[i])
        if TAG_ASCII_LO <= cp <= TAG_ASCII_HI:
            out.append(chr(cp - 0xE0000))
        else:
            out.append("<U+%04X>" % cp)
    return "".join(out)


def analyze(text):
    """The property oracle.  Returns (hard, soft); both are lists of
    (class, detail) pairs.  A caller confirms on `hard` only."""
    hard, soft = [], []
    if not text or not isinstance(text, str):
        return hard, soft

    # -- H1  TAG-block payload outside an emoji tag sequence ----------------
    legal = _tag_sequence_spans(text)
    stray = [i for i, ch in enumerate(text)
             if TAG_LO <= ord(ch) <= TAG_HI
             and not any(lo < i <= hi for lo, hi in legal)]
    if stray:
        hard.append(("tag-block-payload",
                     "%d TAG-block character(s) outside any emoji tag sequence; "
                     "decodes to: %r" % (len(stray), _decode_tags(text, stray)[:200])))

    # -- H2  a run of two or more adjacent zero-width formatters ------------
    run_start = None
    runs = []
    for i, ch in enumerate(text + "\x00"):
        if ord(ch) in ZERO_WIDTH:
            if run_start is None:
                run_start = i
        else:
            if run_start is not None and i - run_start >= 2:
                runs.append((run_start, i))
            run_start = None
    if runs:
        longest = max(runs, key=lambda r: r[1] - r[0])
        hard.append(("zero-width-run",
                     "%d run(s) of adjacent zero-width formatters, longest %d "
                     "characters (%s) - a carrier, not a joiner"
                     % (len(runs), longest[1] - longest[0],
                        ", ".join(_codes(text[longest[0]:longest[1]], ZERO_WIDTH)))))

    # -- H3  a joiner with Basic-Latin on both sides ------------------------
    ascii_joins = []
    for i, ch in enumerate(text):
        if ord(ch) not in JOINERS:
            continue
        prev_ch = text[i - 1] if i > 0 else ""
        next_ch = text[i + 1] if i + 1 < len(text) else ""
        if (prev_ch and next_ch
                and ASCII_WORD.match(prev_ch) and ASCII_WORD.match(next_ch)
                and not _is_pictographic(prev_ch) and not _is_pictographic(next_ch)):
            ascii_joins.append((i, ord(ch)))
    if ascii_joins:
        hard.append(("zero-width-in-ascii-word",
                     "%d joiner(s) between two Basic-Latin characters (%s) - "
                     "no rendering effect, splits the string only for the reader"
                     % (len(ascii_joins),
                        ", ".join(sorted({"U+%04X" % cp for _, cp in ascii_joins})))))

    # -- H4  unbalanced bidi controls ---------------------------------------
    depth_embed = depth_isolate = 0
    unbalanced = False
    for ch in text:
        cp = ord(ch)
        if cp in BIDI_OPEN:
            if cp in (0x2066, 0x2067, 0x2068):
                depth_isolate += 1
            else:
                depth_embed += 1
        elif cp == BIDI_POP_EMBEDDING:
            if depth_embed == 0:
                unbalanced = True
            depth_embed = max(0, depth_embed - 1)
        elif cp == BIDI_POP_ISOLATE:
            if depth_isolate == 0:
                unbalanced = True
            depth_isolate = max(0, depth_isolate - 1)
    if unbalanced or depth_embed or depth_isolate:
        hard.append(("unbalanced-bidi",
                     "bidi controls do not balance within the field "
                     "(embedding depth %d, isolate depth %d at end%s) - reordering "
                     "escapes the string, which is the Trojan Source shape"
                     % (depth_embed, depth_isolate,
                        ", stray terminator" if unbalanced else "")))

    # -- H5  a direction OVERRIDE in a field with no strong-RTL character ---
    overrides = [ch for ch in text if ord(ch) in BIDI_OVERRIDES]
    if overrides:
        has_rtl = any(unicodedata.bidirectional(ch) in ("R", "AL", "AN")
                      for ch in text)
        if not has_rtl:
            hard.append(("bidi-override-no-rtl",
                         "%s present in a field with no strong right-to-left "
                         "character - an override with nothing to override"
                         % ", ".join(sorted({BIDI_OPEN[ord(c)] for c in overrides}))))

    # -- observations: real, reportable, never sufficient -------------------
    if "\ufeff" in text[1:]:
        soft.append(("interior-byte-order-mark",
                     "U+FEFF at a non-zero offset; a BOM belongs at offset 0, but "
                     "concatenating BOM-prefixed sources produces this honestly"))
    lone = [i for i, ch in enumerate(text)
            if ord(ch) in ZERO_WIDTH
            and not any(lo <= i < hi for lo, hi in runs)
            and ord(ch) != 0xFEFF]
    if lone:
        soft.append(("isolated-zero-width",
                     "%d isolated zero-width character(s) (%s) with a defined text "
                     "function in this position; a web paste produces these"
                     % (len(lone), ", ".join(_codes("".join(text[i] for i in lone),
                                                    ZERO_WIDTH)))))
    return hard, soft


# ---------------------------------------------------------------------------
# Field collection.  Everything below is text the server advertises and the
# client hands to the model, so everything below is in scope.
# ---------------------------------------------------------------------------

TEXT_KEYS = ("name", "title", "description", "instructions", "uri", "uriTemplate", "mimeType")


def _walk_text(node, trail, out, depth=0):
    if depth > 8:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            child = "%s.%s" % (trail, key)
            if isinstance(value, str) and key in TEXT_KEYS:
                out.append((child, value))
            else:
                _walk_text(value, child, out, depth + 1)
    elif isinstance(node, list):
        for i, item in enumerate(node[:64]):
            _walk_text(item, "%s[%d]" % (trail, i), out, depth + 1)


def collect_fields(result):
    """(json-path, text) for every advertised string, schemas included.

    Parameter descriptions inside `inputSchema` reach the model exactly like the
    tool description does, and are a quieter place to hide a payload, so the
    walk is recursive rather than a fixed list of keys.
    """
    fields = []
    info = result.get("serverInfo") or {}
    for key in ("name", "title", "version"):
        if isinstance(info.get(key), str):
            fields.append(("serverInfo.%s" % key, info[key]))
    if isinstance(result.get("instructions"), str):
        fields.append(("instructions", result["instructions"]))
    for coll in ("tools", "prompts", "resources", "resourceTemplates"):
        for i, item in enumerate(result.get(coll) or []):
            _walk_text(item, "%s[%d]" % (coll, i), fields)
    return fields


# ---------------------------------------------------------------------------
# Transport.  Same two dialects as mcp-tool-poisoning.py.
# ---------------------------------------------------------------------------

def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _extract_json(body):
    body = (body or "").strip()
    if not body:
        return None
    if "data:" in body:
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except ValueError:
                    continue
    try:
        return json.loads(body)
    except ValueError:
        return None


def _post(url, payload, timeout, session_id=None):
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if session_id:
        headers["mcp-session-id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=_ctx())
        return r.status, {k.lower(): v for k, v in r.headers.items()}, \
            r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {}, ""
    except Exception:
        return None, {}, ""


def enum_streamable(base, timeout):
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTO_VERSION, "capabilities": {},
                       "clientInfo": {"name": "cxg", "version": "1.0"}}}
    for path in MCP_PATHS:
        url = base + path
        status, headers, body = _post(url, init, timeout)
        if status != 200:
            continue
        obj = _extract_json(body)
        if not obj or "result" not in obj:
            continue
        sid = headers.get("mcp-session-id")
        result = dict(obj["result"] or {})
        _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, sid)
        for method, key in (("tools/list", "tools"),
                            ("prompts/list", "prompts"),
                            ("resources/list", "resources"),
                            ("resources/templates/list", "resourceTemplates")):
            _, _, raw = _post(url, {"jsonrpc": "2.0", "id": 2, "method": method,
                                    "params": {}}, timeout, sid)
            payload = ((_extract_json(raw) or {}).get("result") or {}).get(key)
            if isinstance(payload, list):
                result[key] = payload
        result["transport"] = "streamable-http"
        result["endpoint"] = path
        return result
    return None


def enum_sse(base, timeout):
    responses = queue.Queue()
    endpoint = {}
    stop = threading.Event()

    def reader():
        try:
            resp = urllib.request.urlopen(
                urllib.request.Request(base + "/sse", headers={"Accept": "text/event-stream"}),
                timeout=timeout, context=_ctx())
            event = None
            for raw in resp:
                if stop.is_set():
                    break
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    d = line[5:].strip()
                    if event == "endpoint":
                        endpoint["url"] = d
                    else:
                        try:
                            responses.put(json.loads(d))
                        except ValueError:
                            pass
                elif line == "":
                    event = None
        except Exception:
            pass

    threading.Thread(target=reader, daemon=True).start()
    for _ in range(int(timeout * 10)):
        if "url" in endpoint:
            break
        time.sleep(0.1)
    if "url" not in endpoint:
        stop.set()
        return None
    post_url = base + endpoint["url"]

    def post(p):
        try:
            urllib.request.urlopen(
                urllib.request.Request(post_url, data=json.dumps(p).encode(),
                                       headers={"Content-Type": "application/json"},
                                       method="POST"),
                timeout=timeout, context=_ctx()).read()
        except Exception:
            pass

    post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": PROTO_VERSION, "capabilities": {},
                     "clientInfo": {"name": "cxg", "version": "1.0"}}})
    post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    wanted = {2: ("tools/list", "tools"), 3: ("prompts/list", "prompts"),
              4: ("resources/list", "resources")}
    for rid, (method, _key) in wanted.items():
        post({"jsonrpc": "2.0", "id": rid, "method": method, "params": {}})

    result = {}
    seen = set()
    end = time.time() + min(timeout, 8)
    while time.time() < end and len(seen) < len(wanted) + 1:
        try:
            msg = responses.get(timeout=1)
        except queue.Empty:
            continue
        rid = msg.get("id")
        body = msg.get("result") or {}
        if rid == 1:
            result.update(body)
            seen.add(1)
        elif rid in wanted:
            _method, key = wanted[rid]
            if isinstance(body.get(key), list):
                result[key] = body[key]
            seen.add(rid)
    stop.set()
    if 1 not in seen:
        return None
    result["transport"] = "http+sse"
    result["endpoint"] = "/sse"
    return result


def enumerate_mcp(host, port, timeout=12, scheme="http"):
    base = "%s://%s:%d" % (scheme, host, port)
    return enum_streamable(base, timeout) or enum_sse(base, timeout)


# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------

def emit(status, detail, findings=None):
    meta = dict(METADATA)
    meta["status"] = status
    meta["detail"] = detail
    print(json.dumps({"findings": findings or [], "metadata": meta}, indent=2))


def scan(host, port, timeout=12, scheme="http"):
    result = enumerate_mcp(host, port, timeout, scheme)
    if not result:
        return "skipped", "no-mcp-server-answered(%s://%s:%d)" % (scheme, host, port), []

    base = "%s://%s:%d" % (scheme, host, port)
    endpoint = "%s%s" % (base, result.get("endpoint", ""))
    fields = collect_fields(result)
    if not fields:
        return "skipped", "server-advertised-no-text(nothing to read is not a clean bill of health)", []

    poisoned, observations = [], []
    for path, text in fields:
        hard, soft = analyze(text)
        if hard:
            poisoned.append({"field": path,
                             "classes": [c for c, _ in hard],
                             "details": [d for _, d in hard],
                             "rendered": _visible(text)})
        for cls, detail in soft:
            observations.append({"field": path, "class": cls, "detail": detail})

    info = result.get("serverInfo") or {}
    counts = {c: len(result.get(c) or []) for c in ("tools", "prompts", "resources")}
    surface = "transport=%s fields=%d tools=%d prompts=%d resources=%d" % (
        result.get("transport"), len(fields), counts["tools"], counts["prompts"],
        counts["resources"])

    if not poisoned:
        detail = "no-invisible-character-in-a-position-without-a-text-function (%s)" % surface
        if observations:
            detail += "; %d observation(s) recorded and deliberately not reported: %s" % (
                len(observations), ", ".join(sorted({o["class"] for o in observations})))
        return "refuted", detail, []

    classes = sorted({c for p in poisoned for c in p["classes"]})
    finding = {
        "target": endpoint,
        "template_id": METADATA["id"],
        "severity": METADATA["severity"],
        "confidence": METADATA["confidence"],
        "title": METADATA["name"],
        "description": (
            "MCP server '%s' advertises %d field(s) carrying Unicode that a human approval "
            "view does not render and the connected model does read (%s). The approval a user "
            "gives is therefore not the text the model receives. Fields: %s."
            % (info.get("name", "unknown"), len(poisoned), ", ".join(classes),
               ", ".join(p["field"] for p in poisoned[:8]))),
        "evidence": {
            "request": "%s initialize -> tools/list, prompts/list, resources/list" % result.get("transport"),
            "response": json.dumps({"serverInfo": info,
                                    "poisoned_fields": [p["field"] for p in poisoned]})[:1000],
            "matched_patterns": classes,
            "data": {
                "protocol": scheme,
                "port": port,
                "transport": result.get("transport"),
                "server_name": info.get("name"),
                "fields_read": len(fields),
                "poisoned": poisoned,
                "observations_not_reported": observations,
            },
        },
        "cwe_ids": METADATA["cwe"],
        "tags": METADATA["tags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    detail = "invisible-unicode-in-advertised-text(%s) fields=%d (%s)" % (
        ",".join(classes), len(poisoned), surface)
    return "confirmed", detail, [finding]


def main():
    if os.getenv("CERT_X_GEN_MODE") == "engine":
        host = os.getenv("CERT_X_GEN_TARGET_HOST")
        port = int(os.getenv("CERT_X_GEN_TARGET_PORT", "8000"))
        scheme = os.getenv("CERT_X_GEN_TARGET_PROTOCOL", "http")
        if not host:
            emit("errored", "CERT_X_GEN_TARGET_HOST not set")
            sys.exit(0)
    else:
        if len(sys.argv) < 2:
            emit("errored", "Usage: mcp-invisible-unicode-poisoning.py <host> [port] [scheme]")
            sys.exit(0)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        scheme = sys.argv[3] if len(sys.argv) > 3 else "http"

    status, detail, findings = scan(host, port, scheme=scheme)
    emit(status, detail, findings)


if __name__ == "__main__":
    main()

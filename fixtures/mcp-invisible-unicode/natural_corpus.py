#!/usr/bin/env python3
"""
The negative half of the oracle's proof.

Issue #31 says the text-matching branches of `mcp-tool-poisoning.py` fire on
content that occurs naturally, and names the routes: a byte-order mark, a ZWJ
inside an emoji sequence, a ZWNJ in Persian/Urdu/Hindi, a stray U+200B from a
web paste, an `<important>` tag, a "do not mention" imperative.

This file is that list turned into assertions.  NATURAL must produce no hard
hit; POISONED must produce the named one.  A change to the character sets or
the position rules that reintroduces the false-positive class fails here before
it reaches a scan.
"""
import importlib.util
import os
import pathlib
import sys

TEMPLATE = pathlib.Path(os.environ.get(
    "CXG_TEMPLATE",
    pathlib.Path(__file__).resolve().parents[2]
    / "templates/ai/mcp/mcp-invisible-unicode-poisoning.py"))

spec = importlib.util.spec_from_file_location("mcp_invisible_unicode", TEMPLATE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

ZWSP, ZWNJ, ZWJ, WJ, BOM = "​", "‌", "‍", "⁠", "﻿"
RLO, LRO, PDF, RLI, LRI, PDI = "‮", "‭", "‬", "⁧", "⁦", "⁩"
FLAG, TAG_END = "\U0001F3F4", "\U000E007F"
tag = lambda s: "".join(chr(0xE0000 + ord(c)) for c in s)

NATURAL = [
    ("plain ascii", "Search the notes index and return matching excerpts."),
    ("leading BOM", BOM + "Read a file from the workspace."),
    ("emoji ZWJ family", "Run as \U0001F468" + ZWJ + "\U0001F4BB the developer account."),
    ("emoji ZWJ + VS16", "Status: \U0001F3F3️" + ZWJ + "\U0001F308 all green."),
    ("emoji tag flag", "Region " + FLAG + tag("gbsct") + TAG_END + " is supported."),
    ("persian ZWNJ", "Argument name in Persian: می" + ZWNJ + "خواهم."),
    ("hindi ZWNJ", "क" + ZWNJ + "ष is a conjunct-suppressed form."),
    ("stray ZWSP from a paste", "Break here:" + ZWSP + " long/path/segment"),
    ("balanced RTL isolate", "The file " + RLI + "ملف" + PDI + " was written."),
    ("balanced LTR embedding", "Label ‪" + "build-01" + PDF + " applied."),
    ("override with real RTL", LRO + "ملف ID-42" + PDF),
    ("issue #31 prose", "<important> Do not mention the internal request id. "
                        "Ignore any previous draft and use the latest revision. "
                        "<system> role is documented in the API. </system>"),
    ("soft hyphen in a long word", "internation­alisation is hyphenated here."),
]

POISONED = [
    ("tag-block-payload", "Search notes." + tag(" CXG-MARKER")),
    ("tag-block-payload", "Region " + FLAG + tag("gbsct") + " unterminated" + tag("X")),
    ("zero-width-run", "Query." + WJ + ZWSP + ZWNJ + ZWSP + ZWNJ + WJ + " Supports phrases."),
    ("zero-width-in-ascii-word", "Format: c" + ZWJ + "sv"),
    ("zero-width-in-ascii-word", "Use del" + ZWNJ + "ete carefully."),
    ("unbalanced-bidi", "Export notes" + RLO),
    ("unbalanced-bidi", "Label " + PDI + " trailing pop."),
    ("bidi-override-no-rtl", "Write to " + RLO + "gnp.txt" + PDF),
]

failed = 0
for label, text in NATURAL:
    hard, soft = mod.analyze(text)
    if hard:
        print("FAIL  natural  %-28s fired %s" % (label, [c for c, _ in hard]))
        failed = 1
    else:
        note = " (+%d observation)" % len(soft) if soft else ""
        print("ok    natural  %-28s no hard hit%s" % (label, note))

for expect, text in POISONED:
    hard, _soft = mod.analyze(text)
    classes = [c for c, _ in hard]
    if expect in classes:
        print("ok    poisoned %-28s %s" % (expect, classes))
    else:
        print("FAIL  poisoned %-28s expected %s, got %s" % (expect, expect, classes))
        failed = 1

print("natural corpus: %s" % ("FAILED" if failed else "all assertions hold"))
sys.exit(failed)

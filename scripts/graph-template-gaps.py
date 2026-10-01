#!/usr/bin/env python3
"""
Rank the template gaps that real applications actually expose.

Given code graphs for a set of repositories, this reads two answers from each
graph - the HTTP route table and the ranked attack surface (which sink classes
each route handler reaches through the call graph) - maps every reached sink
and every route framework onto the templates in this repository, and reports
the capabilities and frameworks that NO template covers, ranked by how many of
the repositories reach them and through how many entry points.

The point is to steer template work at exposure that exists in code people
run, instead of at whatever is easiest to write next.

WHERE THE GRAPH COMES FROM
--------------------------
The graph is optional tooling and nothing else in this repository needs it.
`codegraph-mcp` (an MCP server over stdio, shipped in the bravos wheel and
fronted by `bravos graph`) answers the two queries read here,
`codegraph_routes` and `codegraph_attack_surface`. This script never builds a
graph and never installs anything; see docs/graph-template-gaps.md for both.
Discovery order: $CODEGRAPH_MCP (or $CXG_CODEGRAPH_MCP, the variable cert-x-gen
reads), then `codegraph-mcp` on PATH, then `bravos graph`.

THE CONFIDENCE GATE IS NOT OPTIONAL
-----------------------------------
The attack-surface answer carries the graph's own verdict. Only
`sinks_reached` and `no_sinks_reached` are measurements. Under
`insufficient_resolution` the graph resolved too few of the project's calls to
walk, and withholds its ranking on purpose: that repository's sink reach is
UNKNOWN, and it is reported as unknown - never folded into the counts as a
repository that reaches nothing. Graph tooling too old to publish the two
queries is reported the same way. Route frameworks are registration facts that
do not depend on call resolution, so they are still counted below the gate.

EXIT CODES
----------
  0  report written; at least one repository passed the gate
  2  bad arguments or unreadable input
  3  report written, but NO repository passed the gate: there is no result,
     and the report says so rather than listing zero gaps
"""
import argparse
import importlib.util
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_MAP = HERE / "graph-gap-map.json"

TOOL_ROUTES = "codegraph_routes"
TOOL_SURFACE = "codegraph_attack_surface"

# The graph's own caps (routes 5000, ranked entry points 1000), so a large
# application is read whole instead of being cut at the smaller defaults.
ROUTE_LIMIT = 5000
SURFACE_LIMIT = 1000
TIMEOUT_S = 120.0

MEASURED_VERDICTS = ("sinks_reached", "no_sinks_reached")


def _load_generator():
    """scripts/generate-index.py, for engine-parity template discovery."""
    spec = importlib.util.spec_from_file_location("generate_index", HERE / "generate-index.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GEN = _load_generator()


# -- templates ------------------------------------------------------------------

_CWE_RE = re.compile(r"\bCWE-\d+\b", re.I)
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9.+_-]*")


def _split_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip().lower() for v in value if str(v).strip()]
    return [v.strip().lower() for v in str(value).split(",") if v.strip()]


def _words(text):
    return {w.strip(".-_") for w in _WORD_RE.findall(text.lower())} - {""}


def _tokens(*texts):
    out = set()
    for text in texts:
        out |= {t for t in re.split(r"[^a-z0-9.]+", (text or "").lower()) if t}
    return out


def template_index(repo_root):
    """Every runnable template with the terms coverage is matched on.

    A template's terms are its declared tags. One that declares none is read by
    the CWE ids and words of its first 50 lines - the same window the engine
    reads annotations from - so an untagged template is not invisible.
    """
    registry = GEN.scan_templates(Path(repo_root))
    out = []
    for row in registry["templates"]:
        if not row.get("runnable"):
            continue
        path = Path(repo_root) / row["path"]
        head = GEN.read_head(path)
        if row["language"] == "yaml":
            try:
                import yaml
                data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
            except Exception:
                data = {}
            tags = _split_list(data.get("tags") if isinstance(data, dict) else None)
            cwe_raw = data.get("cwe") if isinstance(data, dict) else None
            cwe = {c.upper() for c in _CWE_RE.findall(" ".join(_split_list(cwe_raw)))}
        else:
            tags = _split_list(GEN.annotation(head, "tags"))
            cwe = {c.upper() for c in _CWE_RE.findall(GEN.annotation(head, "cwe") or "")}
        words = set()
        if not tags:
            words = _words(head)
            cwe |= {c.upper() for c in _CWE_RE.findall(head)}
        out.append({
            "id": row["id"],
            "path": row["path"],
            "category": row["category"],
            "tags": set(tags),
            "cwe": cwe,
            "words": words,
            "names": _tokens(row["id"], row.get("name", "")),
        })
    return out


def template_pool(templates, gap_map):
    pool = gap_map.get("template_pool") or {}
    cats = set(pool.get("categories") or [])
    extra = set((pool.get("extra_templates") or {}).keys())
    return [t for t in templates if t["category"] in cats or t["id"] in extra]


def _ecosystems_of(template, gap_map):
    """Ecosystems a template names in its tags, id or name; empty = generic."""
    terms = template["tags"] | template["names"]
    return {eco for eco, spec in (gap_map.get("ecosystems") or {}).items()
            if terms & set(spec.get("terms") or [])}


def _terms_match(template, want_tags, want_cwe):
    if template["tags"]:
        return bool(template["tags"] & want_tags)
    return bool(template["cwe"] & want_cwe) or bool(template["words"] & want_tags)


def covering_templates(cap_id, ecosystem, pool, gap_map):
    """(covering, excluded): template ids that cover ``cap_id`` for ``ecosystem``,
    and the ones whose terms match but that the map rules out, with the reason."""
    cap = gap_map["capabilities"][cap_id]
    pinned = (gap_map.get("pinned") or {}).get(cap_id) or {}
    refused = (gap_map.get("not_coverage") or {}).get(cap_id) or {}
    want_tags = set(cap.get("tags") or [])
    want_cwe = {c.upper() for c in cap.get("cwe") or []}
    covering, excluded = [], []
    for t in pool:
        pin = pinned.get(t["id"])
        if pin is not None:
            ecos = set(pin.get("ecosystems") or [])
            if not cap.get("ecosystem_specific") or not ecos or ecosystem in ecos:
                covering.append(t["id"])
            continue
        if not _terms_match(t, want_tags, want_cwe):
            continue
        if cap.get("ecosystem_specific"):
            ecos = _ecosystems_of(t, gap_map)
            if ecos and ecosystem not in ecos:
                continue
        if t["id"] in refused:
            excluded.append((t["id"], refused[t["id"]]))
            continue
        covering.append(t["id"])
    return sorted(covering), excluded


def framework_templates(fw_id, pool, gap_map):
    fw = (gap_map.get("frameworks") or {}).get(fw_id) or {}
    want = set(fw.get("tags") or [])
    if not want:
        return []
    return sorted(t["id"] for t in pool
                  if ((t["tags"] & want) if t["tags"] else (t["words"] & want)))


# -- reading a graph ------------------------------------------------------------

class Unsupported(Exception):
    """The graph tooling answered but does not publish the queries read here."""


class NoGraph(Exception):
    """The tooling works and no graph has been built for this repository."""


class McpTransport:
    """One codegraph-mcp process per repository: both queries read one graph."""

    def __init__(self, binary):
        self.binary = binary
        self.via = "codegraph-mcp (%s)" % binary

    def query(self, root, calls):
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "graph-template-gaps", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        for i, (tool, args) in enumerate(calls):
            msgs.append({"jsonrpc": "2.0", "id": 3 + i, "method": "tools/call",
                         "params": {"name": tool, "arguments": args}})
        proc = subprocess.Popen([self.binary, "--project-path", str(root)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        lines = queue.Queue()

        def pump():
            for line in proc.stdout:
                lines.put(line)
            lines.put(None)

        threading.Thread(target=pump, daemon=True).start()
        answers, wanted = {}, {2} | {3 + i for i in range(len(calls))}
        try:
            # stdin stays open until every answer is in: the server stops at
            # end of input and would drop requests queued behind the handshake.
            proc.stdin.write("".join(json.dumps(m) + "\n" for m in msgs))
            proc.stdin.flush()
            while not wanted.issubset(answers):
                line = lines.get(timeout=TIMEOUT_S)
                if line is None:
                    break
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if isinstance(msg, dict) and msg.get("id") is not None:
                    answers[msg["id"]] = msg
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if 2 not in answers:
            raise RuntimeError("%s did not answer tools/list" % self.binary)
        names = {t.get("name") for t in answers[2].get("result", {}).get("tools") or []}
        missing = [tool for tool, _ in calls if tool not in names]
        if missing:
            raise Unsupported(", ".join(missing))
        out = []
        for i, (tool, _args) in enumerate(calls):
            msg = answers.get(3 + i)
            if msg is None:
                raise RuntimeError("%s returned no answer" % tool)
            result = msg.get("result") or {}
            body = "".join(c.get("text", "") for c in result.get("content") or [])
            text = body or str((msg.get("error") or {}).get("message") or "")
            if "error" in msg or result.get("isError"):
                if "No CodeGraph" in text:
                    raise NoGraph(text)
                raise RuntimeError(text or "%s failed" % tool)
            out.append(json.loads(body))
        return out


class BravosTransport:
    """`bravos graph <verb> --json`: the same server, launched by the bravos CLI."""

    def __init__(self, binary):
        self.binary = binary
        self.via = "bravos graph"

    def query(self, root, calls):
        out = []
        for tool, args in calls:
            verb = tool[len("codegraph_"):].replace("_", "-")
            argv = [self.binary, "graph", "--repo", str(root), verb, "--json"]
            for key, value in args.items():
                argv += ["--" + key.replace("_", "-"), str(value)]
            proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                                  timeout=TIMEOUT_S)
            said = (proc.stdout or "") + (proc.stderr or "")
            if "has no question called" in said:
                raise Unsupported(tool)
            try:
                doc = json.loads(proc.stdout or "")
            except ValueError:
                doc = None
            if isinstance(doc, dict) and "error" in doc:
                message = str(doc.get("message") or doc.get("error"))
                if "No CodeGraph" in message:
                    raise NoGraph(message)
                raise RuntimeError(message)
            if proc.returncode != 0 or not isinstance(doc, dict) or "result" not in doc:
                raise RuntimeError(said.strip()[:300] or "bravos graph %s failed" % verb)
            out.append(doc["result"])
        return out


def find_transport():
    for var in ("CODEGRAPH_MCP", "CXG_CODEGRAPH_MCP"):
        explicit = (os.environ.get(var) or "").strip()
        if explicit:
            return McpTransport(explicit)
    found = shutil.which("codegraph-mcp")
    if found:
        return McpTransport(found)
    found = shutil.which("bravos")
    if found:
        return BravosTransport(found)
    return None


def query_repo(name, root):
    """Ask the graph of ``root`` for its routes and attack surface. Never raises."""
    base = {"name": name, "root": str(root)}
    transport = find_transport()
    if transport is None:
        return dict(base, status="unavailable",
                    note="no code graph tooling found (codegraph-mcp or bravos on PATH, "
                         "or $CODEGRAPH_MCP)")
    calls = [(TOOL_ROUTES, {"limit": ROUTE_LIMIT}), (TOOL_SURFACE, {"limit": SURFACE_LIMIT})]
    try:
        routes, surface = transport.query(Path(root).resolve(), calls)
    except Unsupported as e:
        return dict(base, status="unsupported", via=transport.via,
                    note="the installed graph tooling predates the queries this needs "
                         "(missing: %s); install a build that publishes them" % e)
    except NoGraph:
        return dict(base, status="no_graph", via=transport.via,
                    note="no code graph has been built for this repository")
    except Exception as e:  # a wedged or malformed server is a status, not a crash
        return dict(base, status="error", via=transport.via,
                    note="graph query failed: %s" % str(e)[:300])
    return dict(base, status="available", via=transport.via,
                routes=routes, attack_surface=surface)


def _unwrap(part):
    """Accept a bare answer or the `bravos graph --json` envelope around one."""
    if isinstance(part, dict) and "result" in part and len(part) <= 3:
        return part["result"]
    return part


def load_answers(path):
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("%s: not a JSON object" % path)
    doc.setdefault("name", Path(path).stem)
    doc.setdefault("root", "")
    if "status" not in doc:
        doc["status"] = "available" if "routes" in doc and "attack_surface" in doc else "error"
        if doc["status"] == "error":
            doc["note"] = "answers file holds neither a status nor both answers"
    if "routes" in doc:
        doc["routes"] = _unwrap(doc["routes"])
    if "attack_surface" in doc:
        doc["attack_surface"] = _unwrap(doc["attack_surface"])
    return doc


# -- one repository ------------------------------------------------------------

def capabilities_for(rule, klass, callee, gap_map):
    """(capability ids, how) for one reached sink: by a callee refinement, by its
    rule, or - for a rule the map does not name yet - by its class fallback."""
    for ref in gap_map.get("callee_refinements") or []:
        if ref.get("class") == klass and re.search(ref["callee"], callee or ""):
            return list(ref["capabilities"]), "refined"
    caps = (gap_map.get("sink_rules") or {}).get(rule)
    if caps:
        return list(caps), "rule"
    return list((gap_map.get("class_fallback") or {}).get(klass) or []), "fallback"


def ecosystem_of_rule(rule, gap_map):
    for prefix, eco in (gap_map.get("rule_ecosystem_prefixes") or {}).items():
        if rule.startswith(prefix):
            return eco
    return None


def summarise_repo(doc, gap_map):
    """What one repository's graph says, with the gate applied."""
    out = {k: doc.get(k) for k in ("name", "root", "status", "via", "note")}
    out.update(frameworks={}, routes_total=0, verdict="", message="", shortfalls=[],
               gate="not_measured", entries_ranked=0, entries_without_sinks=0,
               truncated_entries=0, uncatalogued_languages=[], currency="", reach=[],
               class_weights={}, unmapped_rules=[])
    if doc.get("status") != "available":
        return out
    routes = doc.get("routes") or {}
    surface = doc.get("attack_surface") or {}
    out["frameworks"] = {k: int(v) for k, v in (routes.get("by_framework") or {}).items()}
    out["routes_total"] = int(routes.get("routes_total") or 0)
    out["currency"] = str((routes.get("graph_currency") or {}).get("state") or "")
    out["verdict"] = str(surface.get("verdict") or "")
    out["message"] = str(surface.get("message") or "")
    out["shortfalls"] = list((surface.get("confidence") or {}).get("shortfalls") or [])
    out["class_weights"] = {c.get("id"): float(c.get("weight") or 0.0)
                            for c in (surface.get("catalogue") or {}).get("classes") or []}
    if out["verdict"] in MEASURED_VERDICTS:
        out["gate"] = "passed"
    elif out["verdict"] == "insufficient_resolution":
        out["gate"] = "below"
    else:
        out["gate"] = "no_answer"
        return out
    if out["gate"] != "passed":
        return out
    rows = surface.get("rows") or []
    out["entries_ranked"] = len(rows)
    out["entries_without_sinks"] = int(surface.get("entries_without_sinks") or 0)
    unc, unmapped = set(), set()
    for row in rows:
        if row.get("truncated"):
            out["truncated_entries"] += 1
        unc |= set(row.get("uncatalogued_languages") or [])
        entry = row.get("entry") or {}
        for cls in row.get("classes") or []:
            sink = (cls.get("example") or {}).get("sink") or {}
            rule = str(sink.get("rule") or "")
            caps, how = capabilities_for(rule, cls.get("class"), sink.get("callee"), gap_map)
            if how == "fallback":
                unmapped.add(rule or "(class %s)" % cls.get("class"))
            out["reach"].append({
                "entry": entry.get("id") or "",
                "routes": list(row.get("routes") or []),
                "class": cls.get("class"),
                "sinks": int(cls.get("sinks") or 0),
                "min_depth": cls.get("min_depth"),
                "rule": rule,
                "evidence": sink.get("evidence") or "",
                "example": "%s at %s:%s" % (sink.get("callee"), sink.get("file"), sink.get("line"))
                           if sink.get("callee") else "",
                "ecosystem": ecosystem_of_rule(rule, gap_map),
                "capabilities": caps,
            })
    out["uncatalogued_languages"] = sorted(unc)
    out["unmapped_rules"] = sorted(unmapped)
    return out


# -- across the set --------------------------------------------------------------

def aggregate(repos, pool, gap_map):
    caps = gap_map["capabilities"]
    weights = {}
    for r in repos:
        weights.update(r["class_weights"])
    measured = [r for r in repos if r["gate"] == "passed"]

    found = {}
    for r in measured:
        for hit in r["reach"]:
            for cap_id in hit["capabilities"]:
                if cap_id not in caps:
                    continue
                eco = hit["ecosystem"] if caps[cap_id].get("ecosystem_specific") else None
                key = (cap_id, eco)
                agg = found.setdefault(key, {
                    "capability": cap_id, "label": caps[cap_id]["label"], "ecosystem": eco,
                    "class": hit["class"], "weight": weights.get(hit["class"], 0.0),
                    "repos": {}, "entries": 0, "inferred": 0, "rules": set(), "examples": {}})
                agg["repos"].setdefault(r["name"], 0)
                agg["repos"][r["name"]] += 1
                agg["entries"] += 1
                agg["rules"].add(hit["rule"])
                if hit["evidence"] == "receiver_method":
                    agg["inferred"] += 1
                agg["examples"].setdefault(r["name"], {
                    "route": hit["routes"][0] if hit["routes"] else hit["entry"],
                    "sink": hit["example"], "rule": hit["rule"]})

    rows = []
    for (cap_id, eco), agg in found.items():
        covering, excluded = covering_templates(cap_id, eco, pool, gap_map)
        eco_label = ((gap_map.get("ecosystems") or {}).get(eco) or {}).get("label", eco) if eco else None
        rows.append(dict(agg, rules=sorted(agg["rules"]), ecosystem_label=eco_label,
                         covered_by=covering, not_counted=excluded,
                         cwe=caps[cap_id].get("cwe") or []))
    rows.sort(key=lambda a: (-len(a["repos"]), -a["entries"], -a["weight"],
                             a["capability"], a["ecosystem"] or ""))

    class_totals = {}
    for r in measured:
        seen = {}
        for hit in r["reach"]:
            seen.setdefault(hit["class"], set()).add(hit["entry"])
        for cls, entries in seen.items():
            class_totals.setdefault(cls, {})[r["name"]] = len(entries)

    fws = {}
    for r in repos:
        for fw, n in r["frameworks"].items():
            spec = (gap_map.get("frameworks") or {}).get(fw) or {}
            agg = fws.setdefault(fw, {"framework": fw, "label": spec.get("label", fw),
                                      "would_check": spec.get("would_check", ""),
                                      "known": bool(spec), "repos": {}, "routes": 0})
            agg["repos"][r["name"]] = n
            agg["routes"] += n
    fw_rows = []
    for fw, agg in fws.items():
        fw_rows.append(dict(agg, covered_by=framework_templates(fw, pool, gap_map)))
    fw_rows.sort(key=lambda a: (-len(a["repos"]), -a["routes"], a["framework"]))

    return {
        "repositories": repos,
        "measured": [r["name"] for r in measured],
        "capabilities": rows,
        "gaps": [a for a in rows if not a["covered_by"]],
        "covered": [a for a in rows if a["covered_by"]],
        "class_totals": class_totals,
        "frameworks": fw_rows,
        "framework_gaps": [a for a in fw_rows if not a["covered_by"] and a["framework"] != "unknown"],
        "unmapped_rules": sorted({u for r in measured for u in r["unmapped_rules"]}),
        "pool_size": len(pool),
    }


# -- rendering -------------------------------------------------------------------

def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def _repo_status(r):
    if r["status"] != "available":
        return "**not measured** - %s" % r["note"]
    if r["gate"] == "passed":
        s = "%s; %d entry point(s) ranked" % (r["verdict"], r["entries_ranked"])
        if r["verdict"] == "no_sinks_reached" and r["uncatalogued_languages"]:
            s += "; **blind to %s**" % ", ".join(r["uncatalogued_languages"])
        if r["truncated_entries"]:
            s += "; %d walk(s) truncated (reach is a floor)" % r["truncated_entries"]
        return s
    if r["gate"] == "below":
        return ("**below the confidence gate** (insufficient_resolution): %s - sink reach "
                "UNKNOWN, not clean" % "; ".join(r["shortfalls"] or [r["message"]]))
    return "**no ranking** (%s): %s" % (r["verdict"] or "no verdict", r["message"])


def render_markdown(result, top=None):
    repos = result["repositories"]
    measured = result["measured"]
    lines = ["# Template gaps at reachable exposure", ""]
    lines.append("Generated by `scripts/graph-template-gaps.py` from the code graphs of %d "
                 "repositories, against %d templates in the coverage pool."
                 % (len(repos), result["pool_size"]))
    lines.append("")
    lines += ["## Inputs and the confidence gate", "",
              "| repository | routes (framework) | attack surface |", "|---|---|---|"]
    for r in repos:
        fw = ", ".join("%s %d" % (k, v) for k, v in sorted(r["frameworks"].items())) or "-"
        routes = "%d (%s)" % (r["routes_total"], fw) if r["status"] == "available" else "-"
        stale = " (graph %s against the working tree)" % r["currency"] \
            if r["currency"] and r["currency"] != "current" else ""
        lines.append("| %s | %s | %s%s |" % (_cell(r["name"]), _cell(routes),
                                              _cell(_repo_status(r)), _cell(stale)))
    lines.append("")
    below = [r["name"] for r in repos if r["name"] not in measured]
    if not measured:
        lines += ["> **NO RESULT.** No repository was measured - each is below the graph's "
                  "confidence gate or has no usable graph (see the table) - so no sink reach "
                  "was read and no capability gap can be ranked. This is not a clean result.", ""]
    else:
        lines.append("> %d of %d repositories passed the graph's confidence gate; every "
                     "sink count below is over those %d only (%s)."
                     % (len(measured), len(repos), len(measured), ", ".join(measured)))
        if below:
            lines.append("> Not measured: %s. Their sink reach is unknown, not absent; "
                         "their route frameworks are still counted." % ", ".join(below))
        lines.append("")

    def reach_cells(a):
        repo_cell = "%d/%d (%s)" % (len(a["repos"]), len(measured),
                                    ", ".join(sorted(a["repos"], key=str.lower)))
        ex = next(iter(a["examples"].items()))
        example = "%s: `%s` -> `%s`" % (ex[0], ex[1]["route"], ex[1]["sink"])
        inferred = " (%d of %d inferred)" % (a["inferred"], a["entries"]) if a["inferred"] else ""
        return repo_cell, "%d%s" % (a["entries"], inferred), example

    if measured:
        gaps = result["gaps"][:top] if top else result["gaps"]
        lines += ["## Ranked gaps: reachable sink capabilities with no template", ""]
        if gaps:
            lines += ["| # | capability | ecosystem | repos reaching | entry points | sink rules | example |",
                      "|---|---|---|---|---|---|---|"]
            for i, a in enumerate(gaps, 1):
                repo_cell, entries, example = reach_cells(a)
                lines.append("| %d | %s | %s | %s | %s | %s | %s |" % (
                    i, _cell(a["label"]), _cell(a["ecosystem_label"] or "any"), _cell(repo_cell),
                    _cell(entries), _cell(", ".join(a["rules"])), _cell(example)))
        else:
            lines.append("Every capability the measured repositories reach has at least one template.")
        lines.append("")

    lines += ["## Ranked gaps: route frameworks with no template", ""]
    if not any(r["status"] == "available" for r in repos):
        lines.append("No route table was read, so no framework was seen.")
    elif result["framework_gaps"]:
        lines += ["| # | framework | repos | routes | a framework template would check |",
                  "|---|---|---|---|---|"]
        for i, a in enumerate(result["framework_gaps"], 1):
            lines.append("| %d | %s | %d (%s) | %d | %s |" % (
                i, _cell(a["label"]), len(a["repos"]), _cell(", ".join(sorted(a["repos"], key=str.lower))),
                a["routes"], _cell(a["would_check"] or "-")))
    else:
        lines.append("No uncovered framework among the routes the graphs recognised.")
    lines.append("")

    if measured and result["covered"]:
        lines += ["## Covered: reachable capabilities that already have a template", "",
                  "| capability | ecosystem | repos reaching | entry points | templates |",
                  "|---|---|---|---|---|"]
        for a in result["covered"]:
            repo_cell, entries, _ = reach_cells(a)
            lines.append("| %s | %s | %s | %s | %s |" % (
                _cell(a["label"]), _cell(a["ecosystem_label"] or "any"), _cell(repo_cell),
                _cell(entries), _cell(", ".join(a["covered_by"]))))
        lines.append("")
    covered_fw = [a for a in result["frameworks"] if a["covered_by"]]
    if covered_fw:
        lines += ["Frameworks with a template: " + "; ".join(
            "%s (%s)" % (a["label"], ", ".join(a["covered_by"])) for a in covered_fw), ""]

    lines += ["## Reading these counts", ""]
    if measured:
        lines.append("- **Per sink class the counts are complete; the split into capabilities "
                     "is a floor.** The attack surface gives one example sink per entry point "
                     "and class, so an entry point that reaches both a subprocess call and an "
                     "`eval` is attributed to whichever its example shows. Entry points "
                     "reaching each class, per repository:")
        for cls, per in sorted(result["class_totals"].items()):
            lines.append("  - `%s`: %s" % (cls, ", ".join(
                "%s %d" % (k, v) for k, v in sorted(per.items()))))
        lines.append("- *inferred* counts sinks the graph recognised by a method name in a "
                     "scope that imports the library (`receiver_method` evidence), the weaker "
                     "of its recognition kinds.")
    excluded = sorted({(t, why) for a in result["capabilities"] for t, why in a["not_counted"]})
    for t, why in excluded:
        lines.append("- `%s` matches on its tags but is not counted as coverage: %s" % (t, why))
    if result["unmapped_rules"]:
        lines.append("- Sink rules this map does not name yet (counted under their class "
                     "fallback): %s. Add them to `scripts/graph-gap-map.json`."
                     % ", ".join(result["unmapped_rules"]))
    lines.append("- A route framework the graph does not recognise produces no routes at "
                 "all, so a framework absent here is unseen, not unused.")
    lines.append("")
    return "\n".join(lines)


def to_json(result):
    def clean(o):
        if isinstance(o, set):
            return sorted(o)
        if isinstance(o, tuple):
            return list(o)
        raise TypeError(type(o))
    slim = dict(result)
    slim["repositories"] = [{k: v for k, v in r.items() if k != "reach"} for r in result["repositories"]]
    return json.dumps(slim, indent=2, default=clean, sort_keys=True)


# -- entry point -----------------------------------------------------------------

def parse_repo_arg(value):
    name, sep, path = value.partition("=")
    if not sep:
        path, name = value, Path(value.rstrip("/")).name
    return name, path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", action="append", default=[], metavar="[NAME=]PATH",
                    help="a repository whose code graph has been built; repeatable")
    ap.add_argument("--answers", action="append", default=[], metavar="FILE",
                    help="a saved answers file (see --save-answers); repeatable")
    ap.add_argument("--save-answers", metavar="DIR",
                    help="write each repository's raw graph answers to DIR/<name>.json")
    ap.add_argument("--map", default=str(DEFAULT_MAP), help="capability map (default: %(default)s)")
    ap.add_argument("--templates-root", default=str(REPO_ROOT),
                    help="repository whose templates/ is the coverage pool (default: this one)")
    ap.add_argument("--format", choices=("markdown", "json"), default="markdown")
    ap.add_argument("--top", type=int, default=0, help="show only the first N capability gaps")
    args = ap.parse_args(argv)

    if not args.repo and not args.answers:
        ap.error("give at least one --repo or --answers")
    try:
        gap_map = json.loads(Path(args.map).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print("error: cannot read map %s: %s" % (args.map, e), file=sys.stderr)
        return 2

    docs = []
    for value in args.repo:
        name, path = parse_repo_arg(value)
        if not Path(path).is_dir():
            print("error: --repo %s is not a directory" % path, file=sys.stderr)
            return 2
        docs.append(query_repo(name, path))
    for path in args.answers:
        try:
            docs.append(load_answers(path))
        except (OSError, ValueError) as e:
            print("error: cannot read answers %s: %s" % (path, e), file=sys.stderr)
            return 2

    if args.save_answers:
        out_dir = Path(args.save_answers)
        out_dir.mkdir(parents=True, exist_ok=True)
        for doc in docs:
            (out_dir / ("%s.json" % doc["name"])).write_text(json.dumps(doc, indent=1),
                                                             encoding="utf-8")

    pool = template_pool(template_index(args.templates_root), gap_map)
    repos = [summarise_repo(d, gap_map) for d in docs]
    result = aggregate(repos, pool, gap_map)
    print(to_json(result) if args.format == "json" else render_markdown(result, args.top or None))
    return 0 if result["measured"] else 3


if __name__ == "__main__":
    sys.exit(main())

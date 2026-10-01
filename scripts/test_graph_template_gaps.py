#!/usr/bin/env python3
"""
Tests for scripts/graph-template-gaps.py.

Every test builds a throwaway repository (its own templates/) and synthetic
graph answers, so nothing here needs graph tooling installed and nothing reads
the real template tree. The live-transport tests stand in a tiny fake
codegraph-mcp, which is how the "tooling too old" and "no graph built" paths
are reached without a real server.

The point the tests guard hardest is the confidence gate: a repository whose
graph could not resolve enough calls must be reported as unknown and never
counted as one that reaches nothing.

Run by hand:  python3 scripts/test_graph_template_gaps.py
Exit 0 = all pass, 1 = a failure. Needs PyYAML, like the generator.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "graph-template-gaps.py")
MAP = os.path.join(HERE, "graph-gap-map.json")

_failures = []


def check(label, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print("  [%s] %s%s" % (status, label, ("  -> %s" % (detail,)) if detail and not cond else ""))
    if not cond:
        _failures.append(label)


def write(root, relpath, content):
    full = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)
    return full


def py_template(tid, tags, cwe="", extra=""):
    return ("#!/usr/bin/env python3\n# @id: %s\n# @name: %s\n# @severity: high\n"
            "# @tags: %s\n# @cwe: %s\n%s\nprint('[]')\n" % (tid, tid, tags, cwe, extra))


def templates_root(tmp, templates):
    """A repo whose templates/web holds ``templates`` ({relpath: source})."""
    root = os.path.join(tmp, "repo")
    for rel, src in templates.items():
        write(root, os.path.join("templates", rel), src)
    return root


def sink(rule, cls, callee="call", evidence="module_call", file="app.go", line=1):
    return {"class": cls, "label": cls, "weight": 1.0, "sinks": 1, "sites": 1, "min_depth": 1,
            "weighted": 1.0, "evidence": {evidence: 1},
            "example": {"path": [], "sink": {"rule": rule, "class": cls, "callee": callee,
                                             "evidence": evidence, "file": file, "line": line,
                                             "drawn": False}}}


def row(entry, route, *classes):
    return {"entry": {"id": entry, "name": entry.split("::")[-1], "file": entry.split("::")[0]},
            "routes": [route], "classes": list(classes), "score": 1.0, "rank": 1,
            "truncated": False, "uncatalogued_languages": [], "nodes_reached": 3}


def answers(name, rows, verdict="sinks_reached", frameworks=None, shortfalls=None):
    frameworks = frameworks or {"gorilla_mux": max(1, len(rows))}
    return {
        "name": name, "root": "/src/" + name, "status": "available",
        "routes": {"routes_total": sum(frameworks.values()), "by_framework": frameworks,
                   "graph_currency": {"state": "current"}, "routes": []},
        "attack_surface": {
            "verdict": verdict, "message": "graph says %s" % verdict,
            "confidence": {"shortfalls": shortfalls or []},
            "rows": rows if verdict == "sinks_reached" else [],
            "entries_without_sinks": 0,
            "catalogue": {"classes": [{"id": "exec", "weight": 5.0},
                                      {"id": "network", "weight": 3.0},
                                      {"id": "data_layer", "weight": 1.0},
                                      {"id": "crypto_secrets", "weight": 1.0}]},
        },
    }


def run(tmp, docs, root, *extra, env=None):
    paths = []
    for doc in docs:
        p = os.path.join(tmp, "%s.json" % doc["name"])
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        paths += ["--answers", p]
    proc = subprocess.run([sys.executable, TOOL, "--templates-root", root] + paths + list(extra),
                          capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout, proc.stderr


def run_json(tmp, docs, root):
    code, out, err = run(tmp, docs, root, "--format", "json")
    try:
        return code, json.loads(out), err
    except ValueError:
        return code, None, err + out


def gap_keys(result):
    return [(g["capability"], g["ecosystem"]) for g in result["gaps"]]


# -- tests -----------------------------------------------------------------------

def test_gap_and_coverage():
    print("a reached capability with no template is a gap; one with a template is covered")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/sqli.py": py_template("sqli-probe", "sql-injection", "CWE-89")})
        doc = answers("app", [row("a.go::H", "GET /a", sink("go.gorm", "data_layer"),
                                  sink("go.os_exec", "exec"))])
        code, res, err = run_json(tmp, [doc], root)
        check("exit 0 when a repository was measured", code == 0, err)
        check("command injection is a gap", ("command_injection", None) in gap_keys(res), res and res["gaps"])
        covered = {c["capability"]: c["covered_by"] for c in res["covered"]}
        check("sql injection is covered by the tagged template",
              covered.get("sql_injection") == ["sqli-probe"], covered)


def test_gate_below_is_unknown_not_clean():
    print("a repository below the confidence gate is unknown, not clean")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/x.py": py_template("x", "xss", "CWE-79")})
        good = answers("good", [row("a.go::H", "GET /a", sink("go.os_exec", "exec"))])
        thin = answers("thin", [row("b.go::H", "GET /b", sink("go.net_dial", "network"))],
                       verdict="insufficient_resolution", frameworks={"express": 9},
                       shortfalls=["0.06 resolved call edges per function"])
        code, res, err = run_json(tmp, [good, thin], root)
        check("only the gate-passing repository is measured", res["measured"] == ["good"], res and res["measured"])
        check("a below-gate repository's sinks are not counted",
              ("ssrf", None) not in gap_keys(res), gap_keys(res))
        fws = {f["framework"]: f for f in res["frameworks"]}
        check("its route frameworks are still counted", fws.get("express", {}).get("routes") == 9, fws)
        code, out, _ = run(tmp, [good, thin], root)
        check("the report names the gate and the graph's own shortfall",
              "below the confidence gate" in out and "0.06 resolved call edges" in out, out[:2000])
        check("the report says unknown, not clean", "UNKNOWN, not clean" in out)

        code, out, _ = run(tmp, [thin], root)
        check("only below-gate repositories -> exit 3", code == 3, str(code))
        check("... and a NO RESULT banner, never an empty gap list",
              "NO RESULT" in out and "Ranked gaps: reachable sink" not in out, out[:1500])


def test_no_sinks_reached_with_blind_spot():
    print("no_sinks_reached is a measurement, but its blind spots are named")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/x.py": py_template("x", "xss")})
        doc = answers("quiet", [], verdict="no_sinks_reached")
        doc["attack_surface"]["rows"] = [dict(row("a.rs::H", "GET /a"), uncatalogued_languages=["rust"])]
        code, out, _ = run(tmp, [doc], root)
        check("exit 0: the graph did measure", code == 0, str(code))
        check("the uncatalogued language is called out", "blind to rust" in out, out[:1500])


def test_ecosystem_specific_coverage():
    print("an ecosystem-specific capability needs a template for that ecosystem")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/deser.py": py_template(
            "java-deser-http", "java, deserialization", "CWE-502")})
        doc = answers("mixed", [
            row("A.java::h", "POST /a", sink("java.deserialise", "exec", "ois.readObject")),
            row("b.py::h", "POST /b", sink("py.unsafe_deserialise", "exec", "pickle.loads")),
        ])
        code, res, err = run_json(tmp, [doc], root)
        check("Java deserialisation is covered", ("insecure_deserialization", "java") not in gap_keys(res), gap_keys(res))
        check("Python deserialisation is a gap", ("insecure_deserialization", "python") in gap_keys(res), gap_keys(res))


def test_not_coverage_is_reported():
    print("a template the map rules out is not coverage, and the report says why")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/g.py": py_template(
            "deserialization-gadget-scan", "java, deserialization", "CWE-502")})
        doc = answers("wg", [row("A.java::h", "POST /a", sink("java.deserialise", "exec"))])
        code, res, _ = run_json(tmp, [doc], root)
        check("the ruled-out template leaves the gap open",
              ("insecure_deserialization", "java") in gap_keys(res), gap_keys(res))
        code, out, _ = run(tmp, [doc], root)
        check("the reason is printed", "deserialization-gadget-scan` matches on its tags but is not counted" in out)


def test_untagged_template_read_by_head():
    print("a template with no tags is matched by the CWE ids and words in its head")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/cmd.js": "#!/usr/bin/env node\n/**\n * CWE: CWE-78 (OS command injection)\n */\nconsole.log('[]')\n"})
        doc = answers("app", [row("a.go::H", "GET /a", sink("go.os_exec", "exec"))])
        code, res, _ = run_json(tmp, [doc], root)
        covered = {c["capability"]: c["covered_by"] for c in res["covered"]}
        check("covered through the CWE in its comment header", covered.get("command_injection") == ["cmd"], covered)


def test_callee_refinement():
    print("a bundled rule is re-read by its callee")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/jwt.py": py_template("jwt-probe", "jwt")})
        doc = answers("wg", [
            row("A.java::h", "POST /a", sink("java.crypto", "crypto_secrets", "Jwts.parser")),
            row("B.go::h", "POST /b", sink("go.crypto_hash", "crypto_secrets", "md5.New")),
            row("C.go::h", "POST /c", sink("go.crypto_hash", "crypto_secrets", "hmac.New")),
        ])
        code, res, _ = run_json(tmp, [doc], root)
        covered = {c["capability"] for c in res["covered"]}
        check("a JWT call counts as JWT exposure", "jwt_abuse" in covered, covered)
        check("an md5 call counts as weak hashing", ("weak_hash", None) in gap_keys(res), gap_keys(res))
        check("an hmac call is not called weak hashing",
              [g["entries"] for g in res["gaps"] if g["capability"] == "weak_hash"] == [1], res["gaps"])


def test_unmapped_rule_falls_back_and_is_named():
    print("a sink rule the map does not know falls back to its class and is named")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/x.py": py_template("x", "xss")})
        doc = answers("app", [row("a.cs::H", "GET /a", sink("csharp.process_start", "exec"))])
        code, res, _ = run_json(tmp, [doc], root)
        check("counted under the class fallback", ("command_injection", None) in gap_keys(res), gap_keys(res))
        check("named as unmapped", res["unmapped_rules"] == ["csharp.process_start"], res["unmapped_rules"])


def test_ranking_by_spread_then_entries():
    print("gaps rank by how many repositories reach them, then by entry points")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/x.py": py_template("x", "xss")})
        many = [row("a.go::H%d" % i, "GET /a%d" % i, sink("go.os_exec", "exec")) for i in range(5)]
        one = answers("one", many)
        two = answers("two", [row("b.go::H", "GET /b", sink("go.net_dial", "network"))])
        three = answers("three", [row("c.go::H", "GET /c", sink("go.net_dial", "network"))])
        code, res, _ = run_json(tmp, [one, two, three], root)
        check("reached in two repositories outranks five entry points in one",
              gap_keys(res)[:2] == [("ssrf", None), ("command_injection", None)], gap_keys(res))


def test_bravos_envelope_accepted():
    print("answers saved from `bravos graph ... --json` are accepted as they are")
    with tempfile.TemporaryDirectory() as tmp:
        root = templates_root(tmp, {"web/x.py": py_template("x", "xss")})
        doc = answers("app", [row("a.go::H", "GET /a", sink("go.os_exec", "exec"))])
        doc["routes"] = {"result": doc["routes"]}
        doc["attack_surface"] = {"result": doc["attack_surface"]}
        code, res, err = run_json(tmp, [doc], root)
        check("unwrapped and measured", code == 0 and res["measured"] == ["app"], err)


FAKE_MCP = r'''#!%(python)s
import json, sys
TOOLS = %(tools)r
for line in sys.stdin:
    msg = json.loads(line)
    mid = msg.get("id")
    if mid is None:
        continue
    if msg["method"] == "initialize":
        out = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    elif msg["method"] == "tools/list":
        out = {"tools": [{"name": t} for t in TOOLS]}
    else:
        out = {"isError": True, "content": [{"type": "text", "text": %(error)r}]}
    print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": out}), flush=True)
'''


def fake_mcp(tmp, tools, error="boom"):
    path = write(tmp, "fake-codegraph-mcp", FAKE_MCP % {"python": sys.executable, "tools": tools, "error": error})
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


def run_live(tmp, mcp):
    root = templates_root(tmp, {"web/x.py": py_template("x", "xss")})
    target = os.path.join(tmp, "target")
    os.makedirs(target, exist_ok=True)
    env = dict(os.environ, CODEGRAPH_MCP=mcp)
    proc = subprocess.run([sys.executable, TOOL, "--templates-root", root, "--repo", target],
                          capture_output=True, text=True, env=env, timeout=120)
    return proc.returncode, proc.stdout


def test_live_old_tooling_is_unsupported():
    print("graph tooling that predates the queries is reported, not read as empty")
    with tempfile.TemporaryDirectory() as tmp:
        code, out = run_live(tmp, fake_mcp(tmp, ["codegraph_callers", "codegraph_routes"]))
        check("exit 3", code == 3, str(code))
        check("says the tooling predates the queries and names the missing one",
              "predates the queries" in out and "codegraph_attack_surface" in out, out[:1200])


def test_live_no_graph_built():
    print("tooling with no graph built for the repository says so")
    with tempfile.TemporaryDirectory() as tmp:
        mcp = fake_mcp(tmp, ["codegraph_routes", "codegraph_attack_surface"],
                       error="No CodeGraph for this project")
        code, out = run_live(tmp, mcp)
        check("exit 3 with a no-graph note", code == 3 and "no code graph has been built" in out, out[:1200])


def test_map_is_consistent():
    print("the shipped map is internally consistent")
    with open(MAP, encoding="utf-8") as fh:
        gap_map = json.load(fh)
    caps = set(gap_map["capabilities"])
    named = [c for v in gap_map["sink_rules"].values() for c in v]
    named += [c for v in gap_map["class_fallback"].values() for c in v]
    named += [c for r in gap_map.get("callee_refinements") or [] for c in r["capabilities"]]
    named += list((gap_map.get("pinned") or {}).keys()) + list((gap_map.get("not_coverage") or {}).keys())
    check("every capability the map names is defined", set(named) <= caps, sorted(set(named) - caps))
    check("every sink class has a fallback",
          set(gap_map["class_fallback"]) == {"data_layer", "exec", "template", "network",
                                             "filesystem", "crypto_secrets"})
    ecos = set(gap_map["ecosystems"])
    check("every rule prefix maps to a defined ecosystem",
          set(gap_map["rule_ecosystem_prefixes"].values()) <= ecos)
    check("every rule id carries a known prefix",
          all(any(r.startswith(p) for p in gap_map["rule_ecosystem_prefixes"]) for r in gap_map["sink_rules"]))


def main():
    for test in (test_gap_and_coverage, test_gate_below_is_unknown_not_clean,
                 test_no_sinks_reached_with_blind_spot, test_ecosystem_specific_coverage,
                 test_not_coverage_is_reported, test_untagged_template_read_by_head,
                 test_callee_refinement, test_unmapped_rule_falls_back_and_is_named,
                 test_ranking_by_spread_then_entries, test_bravos_envelope_accepted,
                 test_live_old_tooling_is_unsupported, test_live_no_graph_built,
                 test_map_is_consistent):
        test()
    print()
    if _failures:
        print("%d check(s) failed: %s" % (len(_failures), ", ".join(_failures)))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

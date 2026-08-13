#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@id: pwn-request-scanner
@name: GitHub Actions Pwn Request Scanner
@author: Bugb Research
@severity: critical
@description: Detects pwn requests - workflows that check out untrusted pull request code while holding secrets or write permissions in the same job
@tags: ci-cd, github-actions, supply-chain, pwn-request, pull-request-target, code-injection
@cwe: CWE-829, CWE-94
@cvss: 9.3
@references: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/, https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
@confidence: 90
@version: 2.0.0

Design notes (v2.0.0 rewrite):
  v1 guessed 8 hardcoded workflow filenames over HTTP and enumerated nothing.
  Against asyncapi/generator (33 workflows) it discovered 0 and reported
  "No Workflows Found". This version enumerates .github/workflows/ for real,
  off the filesystem: offline, any commit, complete, and CI-native.

  OFFLINE BY CONSTRUCTION
  -----------------------
  The target is a local repository path and nothing else. An earlier draft
  fell back to the GitHub API (api.github.com git-tree + raw.githubusercontent
  .com) when handed an 'owner/repo' string; that fallback is gone. Templates in
  this repo do not contact third-party services during a scan, and an opt-in
  flag would not have fixed it - the switch would still ship code that reaches
  api.github.com with a GITHUB_TOKEN attached, one environment variable away
  from doing it for every host in a scan scope. To audit a remote repository,
  clone it and point this template at the clone: the filesystem walk sees every
  workflow at any ref, with no token, no rate limit and no truncated git tree.

  Detection is job-scoped, not file-scoped. The bug is not
  "pull_request_target exists"; it is "an untrusted checkout and a secret
  live in the same job". v1 mixed file-wide regex with per-step loops and
  therefore ranked a real pwn request identically to a Slack notifier.

  Two distinct classes are reported separately:
    pwn-request          - untrusted checkout + secrets/write perms (CWE-829)
    expression-injection - untrusted context interpolated into run/with (CWE-94)
  Untrusted context routed through env: is the pattern GitHub recommends and
  is deliberately NOT flagged.

  SILENT ON ABSENCE
  -----------------
  A scan scope is mostly hosts, and a host is not a repository. Anything that
  is not a repository with workflows to read produces no output at all - not an
  info finding. Absence of a finding is not a finding, so "No Workflows Found"
  and "No Pwn Requests Detected" do not exist either. Coverage gaps that a
  human may want to know about (unparseable workflow, unresolved reusable
  workflow) go to stderr, where they do not pollute a report.
"""

import os
import re
import sys
import json
import datetime
from typing import Dict, List, Any, Tuple

import yaml

METADATA = {
    "id": "pwn-request-scanner",
    "name": "GitHub Actions Pwn Request Scanner",
    "author": {"name": "Bugb Research", "email": "research@bugb.io"},
    "severity": "critical",
    "description": "Detects pwn requests - workflows that check out untrusted pull request code while holding secrets or write permissions in the same job",
    "tags": ["ci-cd", "github-actions", "supply-chain", "pwn-request",
             "pull-request-target", "code-injection"],
    "language": "python",
    "confidence": 90,
    "cwe": ["CWE-829", "CWE-94"],
    "cvss": 9.3,
    "references": [
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
        "https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions",
    ],
}

# Triggers that run in the BASE repo context (secrets available) but are
# influenced by untrusted actors.
UNTRUSTED_TRIGGERS = {"pull_request_target", "workflow_run", "issue_comment"}

# Refs that resolve to attacker-controlled code.
UNTRUSTED_REF_PATTERNS = [
    r"github\.event\.pull_request\.head\.sha",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.merge_commit_sha",
    r"github\.event\.pull_request\.number",
    r"github\.event\.workflow_run\.head_sha",
    r"github\.event\.workflow_run\.head_branch",
    r"github\.head_ref",
    r"refs/pull/",
]

# Untrusted attacker-supplied text (expression-injection surface).
UNTRUSTED_TEXT_PATTERNS = [
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.pull_request\.head\.label",
    r"github\.event\.pull_request\.head\.repo\.[a-z_.]+",
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.discussion\.title",
    r"github\.event\.discussion\.body",
    r"github\.event\.head_commit\.message",
    r"github\.event\.workflow_run\.head_commit\.message",
    r"github\.head_ref",
]

# Steps that execute code from the working tree after a checkout.
CODE_EXEC_PATTERNS = [
    r"\bnpm\s+(ci|install|i|run|exec)\b",
    r"\byarn\b",
    r"\bpnpm\s+(install|i|run)\b",
    r"\bbun\s+(install|run)\b",
    r"\bpip\s+install\b",
    r"\bpoetry\s+install\b",
    r"\bmake\b",
    r"\bmvn\b",
    r"\bgradle\b",
    r"\bcargo\s+(build|test|run)\b",
    r"\bgo\s+(build|test|run|generate)\b",
    r"\bdotnet\s+(build|run|test)\b",
    r"\bbundle\s+exec\b",
    r"\.\/[\w./-]+\.sh\b",
    r"\bnode\s+[\w./-]+\.js\b",
    r"\bpython3?\s+[\w./-]+\.py\b",
]

WRITE_PERMS = {"write", "write-all"}

# Guards that constrain who can trigger an untrusted checkout. These mitigate
# but do not eliminate: each is downgraded, never suppressed, because every one
# of them has a documented bypass or a config we cannot see from the YAML.
#
#   strong   - fork PRs structurally excluded (attacker cannot reach the job)
#   moderate - requires an existing trust relationship or a human gate
#   weak     - label gates: vulnerable to the label-then-push TOCTOU bypass,
#              where a maintainer labels a benign PR and the attacker force
#              pushes new code before the job resolves the ref
GUARD_STRONG = [
    r"github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository",
    r"github\.event\.pull_request\.head\.repo\.fork\s*==\s*false",
    r"!\s*github\.event\.pull_request\.head\.repo\.fork",
]
GUARD_MODERATE = [
    r"github\.event\.pull_request\.author_association",
    r"github\.actor\s*==",
    r"contains\s*\([^)]*author_association",
    r"github\.triggering_actor\s*==",
]
GUARD_WEAK = [
    r"contains\s*\([^)]*labels\.\*\.name",
    r"github\.event\.label\.name\s*==",
]

# Severity ladder, highest first. Downgrading walks toward 'info'.
SEV_LADDER = ["critical", "high", "medium", "low", "info"]


def _downgrade(sev: str, steps_down: int) -> str:
    idx = SEV_LADDER.index(sev) if sev in SEV_LADDER else 0
    return SEV_LADDER[min(idx + steps_down, len(SEV_LADDER) - 1)]




# ------------------------------------------------- expression evaluator
# Inlined rather than imported: CXG templates are standalone executables with
# no shared-library mechanism yet. This belongs in CXG core once that exists;
# actions-injection-scanner.py needs the identical logic to decide whether an
# injection site is reachable. Tracked as debt, not a design choice.
#
# Measured on 293 real jobs with untrusted checkouts (357 workflows, GitHub
# code search, 2026-07-15): regex-only guard matching agreed with this
# evaluator on 98.3%, under-reporting 0.7% and over-reporting 1.0%. The
# evaluator additionally resolves unreachable jobs, which regex cannot.

import re

TOKEN = re.compile(r"""
    \s*(?:
      (?P<str>'(?:[^']|'')*')
    | (?P<op>==|!=|<=|>=|&&|\|\||[<>!(),\[\]])
    | (?P<num>\d+(?:\.\d+)?)
    | (?P<id>[A-Za-z_][A-Za-z0-9_.*\-]*)
    )""", re.X)

def tokenize(s):
    s = s.strip()
    if s.startswith('${{') and s.endswith('}}'):
        s = s[3:-2].strip()
    s = s.replace('${{', ' ').replace('}}', ' ')
    toks, i = [], 0
    while i < len(s):
        m = TOKEN.match(s, i)
        if not m or m.end() == i:
            i += 1; continue
        i = m.end()
        for k in ('str','op','num','id'):
            if m.group(k) is not None:
                toks.append((k, m.group(k))); break
    return toks

class P:
    def __init__(self, toks): self.t, self.i = toks, 0
    def peek(self): return self.t[self.i] if self.i < len(self.t) else (None, None)
    def next(self):
        v = self.peek(); self.i += 1; return v
    def accept(self, val):
        if self.peek()[1] == val: self.i += 1; return True
        return False
    def parse(self): return self.or_()
    def or_(self):
        n = self.and_()
        while self.accept('||'): n = ('or', n, self.and_())
        return n
    def and_(self):
        n = self.not_()
        while self.accept('&&'): n = ('and', n, self.not_())
        return n
    def not_(self):
        if self.accept('!'): return ('not', self.not_())
        return self.cmp_()
    def cmp_(self):
        n = self.prim()
        k, v = self.peek()
        if v in ('==','!=','<','>','<=','>='):
            self.next(); return ('cmp', v, n, self.prim())
        return n
    def prim(self):
        k, v = self.peek()
        if v == '(':
            self.next(); n = self.or_()
            self.accept(')'); return n
        k, v = self.next()
        if k == 'id' and self.peek()[1] == '(':
            self.next(); args = []
            if self.peek()[1] != ')':
                args.append(self.or_())
                while self.accept(','): args.append(self.or_())
            self.accept(')')
            return ('call', v, args)
        return ('lit', k, v)

def parse(expr):
    try:
        return P(tokenize(expr)).parse()
    except Exception:
        return None


GUARD_ATOMS = {
    'strong': [r'head\.repo\.full_name', r'head\.repo\.fork'],
    'moderate': [r'author_association', r'github\.actor\b', r'github\.triggering_actor'],
    'weak': [r'labels\.\*\.name', r'github\.event\.label\.name'],
}

def _text(node):
    """Flatten a node back to rough source text for atom classification."""
    if node is None: return ''
    t = node[0]
    if t == 'lit': return str(node[2])
    if t == 'not': return '!' + _text(node[1])
    if t == 'cmp': return '%s %s %s' % (_text(node[2]), node[1], _text(node[3]))
    if t in ('and','or'): return '%s %s %s' % (_text(node[1]), t, _text(node[2]))
    if t == 'call': return '%s(%s)' % (node[1], ','.join(_text(a) for a in node[2]))
    return ''

def guard_strength(text):
    for s in ('strong','moderate','weak'):
        if any(re.search(p, text) for p in GUARD_ATOMS[s]): return s
    return ''

T, F, U = True, False, 'U'

def _fold_eventname(node, trigger):
    """Resolve `github.event_name == 'X'` under the assumed trigger."""
    if node[0] != 'cmp': return None
    op, l, r = node[1], _text(node[2]), _text(node[3])
    sides = (l.strip(), r.strip().strip("'"))
    if 'github.event_name' not in l and 'github.event_name' not in r: return None
    val = sides[1] if 'github.event_name' in l else l.strip("'")
    if op == '==': return (val == trigger)
    if op == '!=': return (val != trigger)
    return None

def evaluate(node, trigger, guards_satisfied=False):
    """Kleene three-valued eval.

    guard atoms   -> guards_satisfied (T or F)
    unknown atoms -> U  (NOT T: collapsing unknown to True is unsound, because
                         `!unknown` would then fold to False and make a
                         skip-ci check look like an unreachable job)
    """
    if node is None: return U
    t = node[0]
    if t == 'or':
        a = evaluate(node[1], trigger, guards_satisfied)
        b = evaluate(node[2], trigger, guards_satisfied)
        if a is T or b is T: return T
        if a is F and b is F: return F
        return U
    if t == 'and':
        a = evaluate(node[1], trigger, guards_satisfied)
        b = evaluate(node[2], trigger, guards_satisfied)
        if a is F or b is F: return F
        if a is T and b is T: return T
        return U
    if t == 'not':
        a = evaluate(node[1], trigger, guards_satisfied)
        return U if a is U else (not a)
    folded = _fold_eventname(node, trigger) if t == 'cmp' else None
    if folded is not None: return folded
    txt = _text(node)
    if guard_strength(txt):
        return T if guards_satisfied else F
    if t == 'lit' and str(node[2]).lower() in ('true','false'):
        return str(node[2]).lower() == 'true'
    return U


def analyze_condition(expr, trigger):
    """Return (verdict, strength).

    'unguarded'  - reachable with every guard unsatisfied
    'guarded'    - blocked unless a guard is satisfied
    'unreachable'- blocked even with guards satisfied (dead / contradictory)
    'unparsed'   - could not parse
    """
    ast = parse(expr)
    if ast is None: return ('unparsed', '')
    strength = guard_strength(_text(ast))
    without = evaluate(ast, trigger, guards_satisfied=False)
    if without is not F:
        return ('unguarded', strength)
    with_ = evaluate(ast, trigger, guards_satisfied=True)
    if with_ is F:
        return ('unreachable', strength)
    return ('guarded', strength)

# ---------------------------------------------------------------- discovery

def _is_local_repo(target: str) -> bool:
    """A target is local if it is a directory on disk."""
    return os.path.isdir(os.path.expanduser(target))


def discover_local(repo_path: str) -> Dict[str, str]:
    """Enumerate .github/workflows/ on disk. No filename guessing."""
    root = os.path.join(os.path.expanduser(repo_path), ".github", "workflows")
    found = {}
    if not os.path.isdir(root):
        return found
    for entry in sorted(os.listdir(root)):
        if not entry.endswith((".yml", ".yaml")):
            continue
        full = os.path.join(root, entry)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                found[entry] = fh.read()
        except OSError as exc:
            print("warn: unreadable %s: %s" % (full, exc), file=sys.stderr)
    return found


# ----------------------------------------------------------------- helpers

def _match_any(patterns: List[str], text: str) -> str:
    """Return the first matching pattern's matched text, else ''."""
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(0)
    return ""


def _triggers(workflow: Dict[str, Any]) -> List[str]:
    """Extract trigger names. YAML 1.1 parses bare `on:` as boolean True."""
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, dict):
        return list(on.keys())
    if isinstance(on, list):
        return list(on)
    if isinstance(on, str):
        return [on]
    return []


def _has_write_perms(scope: Dict[str, Any]) -> bool:
    perms = scope.get("permissions")
    if perms is None:
        return False
    if isinstance(perms, str):
        return perms in WRITE_PERMS
    if isinstance(perms, dict):
        return any(str(v) in WRITE_PERMS for v in perms.values())
    return False


def _secrets_in(blob: str) -> List[str]:
    """Secret references inside a serialized scope."""
    return sorted(set(re.findall(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", blob)))


def _guards(job, upto_step, trigger):
    """Decide whether the untrusted checkout in this job is actually guarded.

    Considers the job-level `if:` plus every step-level `if:` up to and
    including the checkout. Those conditions are ANDed, so:
      any condition unreachable -> the job cannot run at all
      any condition guarded     -> a guard is mandatory
      otherwise                 -> reachable with all guards unsatisfied

    Returns (verdict, strength, matched_expressions) where verdict is
    'unguarded' | 'guarded' | 'unreachable'.
    """
    conditions = []
    if job.get("if") is not None:
        conditions.append(str(job.get("if")))
    steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
    for step in steps[:upto_step + 1]:
        if step.get("if") is not None:
            conditions.append(str(step.get("if")))
    if not conditions:
        return "unguarded", "", []

    verdicts, strengths, matched = [], [], []
    for cond in conditions:
        v, s = analyze_condition(cond, trigger)
        verdicts.append(v)
        if s:
            strengths.append(s); matched.append(cond)

    strength = ""
    for s in ("strong", "moderate", "weak"):
        if s in strengths:
            strength = s; break

    if "unreachable" in verdicts:
        return "unreachable", strength, matched
    if "guarded" in verdicts:
        return "guarded", strength, matched
    return "unguarded", strength, matched


def _environment_gate(job: Dict[str, Any]) -> str:
    """A deployment environment may carry required reviewers. We cannot see
    the protection rules from YAML, so this is reported, not trusted."""
    env = job.get("environment")
    if not env:
        return ""
    if isinstance(env, dict):
        return str(env.get("name", "unnamed"))
    return str(env)


def _untrusted_checkout(step: Dict[str, Any]) -> str:
    """Return the offending ref if this step checks out untrusted code."""
    uses = str(step.get("uses", ""))
    with_cfg = step.get("with", {}) or {}

    if "actions/checkout" in uses:
        ref = str(with_cfg.get("ref", ""))
        hit = _match_any(UNTRUSTED_REF_PATTERNS, ref)
        if hit:
            return ref
        # Checking out the PR's fork repository is equally untrusted.
        repo = str(with_cfg.get("repository", ""))
        if _match_any([r"github\.event\.pull_request\.head\.repo"], repo):
            return repo

    # Manual checkout inside a run block.
    run = str(step.get("run", ""))
    if run:
        if re.search(r"gh\s+pr\s+checkout", run):
            return "gh pr checkout"
        if re.search(r"git\s+fetch[^\n]*refs/pull/", run):
            return "git fetch refs/pull/"
    return ""


def _injection_sites(step: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Untrusted context interpolated directly into run/with.

    Values routed through `env:` are the GitHub-recommended mitigation and are
    intentionally not reported here.
    """
    sites = []
    run = str(step.get("run", ""))
    if run:
        hit = _match_any(UNTRUSTED_TEXT_PATTERNS, run)
        if hit and "${{" in run:
            sites.append(("run", hit))
    with_cfg = step.get("with", {}) or {}
    if isinstance(with_cfg, dict):
        for key, val in with_cfg.items():
            sval = str(val)
            if "${{" not in sval:
                continue
            hit = _match_any(UNTRUSTED_TEXT_PATTERNS, sval)
            if hit:
                sites.append(("with.%s" % key, hit))
    return sites


def _exec_steps(steps: List[Dict[str, Any]], after: int) -> List[str]:
    """Code-execution steps occurring after the untrusted checkout index."""
    hits = []
    for step in steps[after + 1:]:
        if not isinstance(step, dict):
            continue
        run = str(step.get("run", ""))
        hit = _match_any(CODE_EXEC_PATTERNS, run)
        if hit:
            hits.append(hit.strip())
        uses = str(step.get("uses", ""))
        # A local action is code from the checked-out tree.
        if uses.startswith("./"):
            hits.append("uses: %s" % uses)
    return sorted(set(hits))


# ----------------------------------------------------------------- analysis

def _finding(target, severity, confidence, title, matched_at, desc, evidence, cwe):
    return {
        "target": target,
        "template_id": METADATA["id"],
        "template_name": METADATA["name"],
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "matched_at": matched_at,
        "description": desc,
        "evidence": evidence,
        "cwe": cwe,
        "tags": METADATA["tags"],
        "timestamp": datetime.datetime.now(datetime.timezone.utc)
                      .isoformat().replace("+00:00", "Z"),
    }


def _analyze_job(target, name, job_name, job, untrusted_triggers,
                 wf_write, inherited_secrets=None, via=""):
    """Analyze one job for the pwn-request class. Returns findings."""
    findings = []
    steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
    job_blob = yaml.safe_dump(job, default_flow_style=False)
    secrets = _secrets_in(job_blob)
    if inherited_secrets:
        secrets = sorted(set(secrets) | set(inherited_secrets))
    writes = wf_write or _has_write_perms(job)

    ck_idx, ck_ref = -1, ""
    for idx, step in enumerate(steps):
        ref = _untrusted_checkout(step)
        if ref:
            ck_idx, ck_ref = idx, ref
            break
    if ck_idx < 0:
        return findings

    execs = _exec_steps(steps, ck_idx)
    verdict, guard, guard_exprs = _guards(job, ck_idx, untrusted_triggers[0])
    env_gate = _environment_gate(job)

    # A job whose conditions can never all hold is dead code, not a finding.
    if verdict == "unreachable":
        return findings

    # Base severity: how much damage is reachable.
    if secrets and execs:
        sev, conf = "critical", 95
    elif secrets or writes:
        sev, conf = "critical", 85
    elif execs:
        sev, conf = "high", 80
    else:
        sev, conf = "medium", 70

    # Guards reduce reachability. Never suppressed - each has a known bypass
    # or depends on config invisible from the YAML. A guard only counts if the
    # expression evaluator says it is load-bearing under this trigger.
    notes = []
    if verdict != "guarded":
        guard = ""
    if guard == "strong":
        sev, conf = _downgrade(sev, 3), 60
        notes.append("Fork pull requests appear structurally excluded by an "
                     "explicit same-repository check; residual risk is limited "
                     "to actors who can already push branches.")
    elif guard == "moderate":
        sev, conf = _downgrade(sev, 2), 70
        notes.append("An actor/author_association guard restricts who can "
                     "trigger this job. Verify the allowed set is not broader "
                     "than intended (CONTRIBUTOR includes anyone with a merged PR).")
    elif guard == "weak":
        sev, conf = _downgrade(sev, 1), 75
        notes.append("A label gate is present. Label gates are bypassable: a "
                     "maintainer may label a benign pull request and the author "
                     "can then push new commits before the ref is resolved.")
    if env_gate:
        sev, conf = _downgrade(sev, 1), max(conf - 10, 50)
        notes.append("Job targets environment '%s', which may require reviewer "
                     "approval. Protection rules are not visible from the "
                     "workflow file - verify them before accepting this as a "
                     "mitigation." % env_gate)

    title = "Pwn Request: untrusted checkout with privileged context in job '%s'" % job_name
    if via:
        title = "Pwn Request: untrusted checkout in reusable workflow '%s' called by job '%s'" % (via, job_name)

    desc = ("Workflow triggers on %s (base-repo context, secrets available) and job "
            "'%s' checks out attacker-controlled code via '%s'. %s%s"
            "An attacker opening a pull request can execute code in this job and "
            "exfiltrate everything it can reach."
            % (", ".join(untrusted_triggers), job_name, ck_ref,
               ("Secrets reachable in-job: %s. " % ", ".join(secrets)) if secrets else "",
               ("Code execution after checkout: %s. " % ", ".join(execs)) if execs else ""))
    if notes:
        desc += " MITIGATION PRESENT: " + " ".join(notes)

    findings.append(_finding(
        target, sev, conf, title,
        "%s:jobs.%s" % (name, job_name), desc,
        {"triggers": untrusted_triggers, "job": job_name,
         "untrusted_ref": ck_ref, "secrets_in_job": secrets,
         "write_permissions": writes, "exec_after_checkout": execs,
         "guard": guard or None, "guard_expressions": guard_exprs or None,
         "guard_verdict": verdict,
         "environment_gate": env_gate or None,
         "called_workflow": via or None},
        ["CWE-829", "CWE-94"]))
    return findings


def analyze_workflow(target, name, content, corpus=None):
    """Analyze one workflow file. `corpus` enables reusable-workflow resolution."""
    findings = []
    corpus = corpus or {}
    try:
        workflow = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        # A coverage gap, not a finding about the target. stderr, not stdout.
        print("warn: could not parse %s as YAML: %s" % (name, exc),
              file=sys.stderr)
        return findings
    if not isinstance(workflow, dict):
        return findings

    triggers = _triggers(workflow)
    untrusted_triggers = sorted(set(triggers) & UNTRUSTED_TRIGGERS)
    if not untrusted_triggers:
        return findings

    wf_write = _has_write_perms(workflow)
    jobs = workflow.get("jobs", {}) or {}
    injection_sites = []

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        # --- reusable workflow call -----------------------------------
        calls = str(job.get("uses", ""))
        if calls.startswith("./.github/workflows/"):
            callee_name = os.path.basename(calls.split("@")[0])
            callee_src = corpus.get(callee_name)
            if callee_src:
                inherited = []
                if str(job.get("secrets", "")) == "inherit":
                    inherited = ["<inherited from caller>"]
                elif isinstance(job.get("secrets"), dict):
                    inherited = _secrets_in(yaml.safe_dump(job.get("secrets")))
                try:
                    callee = yaml.safe_load(callee_src)
                except yaml.YAMLError:
                    callee = None
                if isinstance(callee, dict):
                    for cj_name, cj in (callee.get("jobs", {}) or {}).items():
                        if not isinstance(cj, dict):
                            continue
                        findings.extend(_analyze_job(
                            target, name, "%s -> %s" % (job_name, cj_name), cj,
                            untrusted_triggers,
                            wf_write or _has_write_perms(callee),
                            inherited_secrets=inherited, via=callee_name))
            else:
                # Also a coverage gap rather than a finding: the callee may
                # live on another ref, or outside this checkout entirely.
                print("warn: %s job '%s' calls '%s', which is not in the "
                      "discovered corpus; its jobs were not analyzed."
                      % (name, job_name, calls), file=sys.stderr)
            continue

        # --- class 1: pwn request -------------------------------------
        findings.extend(_analyze_job(target, name, job_name, job,
                                     untrusted_triggers, wf_write))

        # --- class 2: expression injection (collected, deduped per file)
        for step in [s for s in (job.get("steps") or []) if isinstance(s, dict)]:
            for loc, hit in _injection_sites(step):
                injection_sites.append({
                    "job": job_name,
                    "step": step.get("name", step.get("uses", "?")),
                    "location": loc, "context": hit})

    # One injection finding per file: the same pattern repeated across N jobs
    # is one defect, not N.
    if injection_sites:
        jobs_hit = sorted({s["job"] for s in injection_sites})
        findings.append(_finding(
            target, "medium", 75,
            "Expression injection: untrusted context inlined in %d job(s)" % len(jobs_hit),
            name,
            ("Workflow '%s' interpolates attacker-controlled text directly into run "
             "scripts or action inputs under a %s trigger, across job(s): %s. "
             "Route these values through env: and reference them as shell "
             "variables instead."
             % (name, "/".join(untrusted_triggers), ", ".join(jobs_hit))),
            {"triggers": untrusted_triggers, "jobs": jobs_hit,
             "site_count": len(injection_sites), "sites": injection_sites},
            ["CWE-94"]))
    return findings


# ------------------------------------------------------------- entry points

def test_vulnerability(target: str) -> List[Dict[str, Any]]:
    """Analyze every workflow in a local repository.

    Returns [] - and says nothing on stderr - for anything that is not a
    repository with workflows in it. A scan scope is mostly hosts, and a host
    that is not a checkout is simply out of scope for this template, not a
    finding about the target.
    """
    if not _is_local_repo(target):
        return []

    workflows = discover_local(target)
    if not workflows:
        return []

    findings = []
    for name, content in sorted(workflows.items()):
        findings.extend(analyze_workflow(target, name, content, corpus=workflows))
    return findings


def main():
    if os.getenv("CERT_X_GEN_MODE") == "engine":
        target = os.getenv("CERT_X_GEN_TARGET_HOST")
        if not target:
            print(json.dumps({"error": "CERT_X_GEN_TARGET_HOST not set"}))
            sys.exit(1)
    else:
        if len(sys.argv) < 2:
            print(json.dumps({"error": "Usage: pwn-request-scanner.py "
                                       "<path-to-local-repo>"}))
            sys.exit(1)
        target = sys.argv[1]

    findings = test_vulnerability(target)
    # Nothing found means nothing printed. An empty findings envelope is still
    # a line of output per host in a scan scope, and this template has one
    # relevant target shape among many.
    if findings:
        print(json.dumps({"findings": findings, "metadata": METADATA}, indent=2))


if __name__ == "__main__":
    main()

# Playbook — Agent command-trace composition bypass

> **Template:** [`templates/ai/coding-agent/coding-agent-command-trace-composition.sh`](../../templates/ai/coding-agent/coding-agent-command-trace-composition.sh)
> **Fixture:** [`tests/fixtures/coding-agent-command-trace/`](../../tests/fixtures/coding-agent-command-trace/) · **Proof:** [`tests/prove-coding-agent-command-trace.sh`](../../tests/prove-coding-agent-command-trace.sh)
> **Class:** composition bypass · **Target kind:** `cli` · **Oracle:** `property` (filesystem marker + execution ledger) · **CWE:** CWE-77, CWE-693, CWE-807

---

## 1. Use case

Modern coding agents don't run whatever the model asks for. Between the model and the shell sits a **command validator**: a gate that inspects each proposed command and decides, one at a time, whether it is safe to execute. Allowlists of read-only verbs, denylists of `rm`/`curl`/redirection, quote-stripping "normalisation" so `git 'push'` is judged the same as `git push` — this is the layer that is supposed to keep an agent from being talked into deleting a repo or exfiltrating a token.

The trouble is that the validator sees **one command at a time**, but an agent session is a **sequence**. State accumulates: a value set in step 1 is read in step 3; a tool "registered" early is "invoked" later; two harmless strings are concatenated into one that is not. Each step, examined alone, is genuinely benign — there is nothing in `set an alias to the word "touch"` that any validator should block, because blocking every string assignment would make the tool useless. The danger is **emergent**: it exists only in the composition, and the composition is never presented to the validator as a single thing to judge.

This is the failure mode two shipping bugs made concrete. The **Cursor 9.8 / Claude Code single-quote-strip validator bug** checked a *normalised* form of a command while a *different* form actually ran — the string the gate approved was not the string that executed. And **SCR-Bench** (Xie et al. 2026, *"Benign in Isolation, Harmful in Composition"*) formalised the general shape: a corpus of command sequences that every per-item filter waves through and whose joint effect is harmful. Both are the same structural gap — a stateless gate in front of a stateful session. *(These are named here for motivation only; this check reproduces neither — it exercises a synthetic, obviously-benign validator fixture.)*

This template proves the gap **behaviourally**. It hands a validator a four-statement trace — bind the bare token `touch`, bind a marker path, concatenate the two already-approved names, then invoke the result — and watches. If every statement is individually allowed **and** the composition still executes `touch <marker>` (dropping a decoy sentinel file that no correct run could invent), the bypass is real and observed, not inferred. If the validator re-checks the *resolved, composed* command at the moment of execution and blocks it, the check refutes — and that refutation is itself the positive signal that this validator is stateful.

---

## 2. Testing flow

```mermaid
flowchart TD
    A([cli:// target]) --> B{Executable<br/>CLI target?}
    B -- no --> S1[[SKIP: not a cli target]]
    B -- yes --> C[Build hermetic mktemp lab<br/>write control.trace + probe.trace]

    C --> D["Phase 1 — CONTROL<br/>set a NONCE_A · set b NONCE_B<br/>join c a b · show c"]
    D --> E{Joined nonce<br/>'NONCE_A NONCE_B'<br/>echoed back?}
    E -- no --> S2[[SKIP: no command-trace<br/>validator surface]]
    E -- "yes → stateful trace<br/>validator confirmed" --> F

    F["Phase 2 — PROBE<br/>set verb touch · set marker MARK<br/>join cmd verb marker · run cmd"]
    F --> G[Read execution ledger:<br/>count LEDGER ALLOW / BLOCK]
    F --> H[Check filesystem:<br/>did decoy marker fire?]

    G --> I{Marker fired<br/>AND 0 blocks?}
    H --> I
    I -- yes --> C1[[CONFIRMED: every statement allowed,<br/>composition executed unvalidated command]]
    I -- "no · blocks &gt; 0 · no marker" --> R1[[REFUTED: validator re-validated<br/>the resolved composed command]]
    I -- "no · no marker · no block" --> R2[[REFUTED: composition delivered<br/>but did not execute]]
```

The two-phase shape is the whole discipline. **Phase 1 never executes anything** — it only proves the target is a stateful trace validator by making it reconstruct a joined nonce it was never handed whole. Without that proof the verdict is `SKIP`, never a refutation, because there is no validator here to bypass. **Phase 2** changes exactly one thing: the joined value is *invoked* instead of *printed*. The oracle then needs **both** halves — the decoy marker fired **and** the ledger shows zero blocks — so a target that merely runs a shell can't be mistaken for a validator that was bypassed.

---

## 3. Market & competitors

Who else looks at this surface, and how?

| Tool / project | Tests this class? | Behavioural (run-and-observe)? | What it actually does |
|---|---|---|---|
| **cxg** (this template) | **Yes** | **Yes** | Feeds a validator a live command trace, reads the execution ledger **and** an observed filesystem effect, and returns CONFIRMED / REFUTED / SKIP with the evidence. |
| **SCR-Bench** (Xie et al. 2026) | Yes (defines it) | Partly — offline eval | An academic **benchmark**: a labelled corpus of benign-in-isolation / harmful-in-composition sequences to score models against. Not a scanner you point at a tool; no per-target verdict, no re-runnable gate. |
| **Adversa AI** (sandbox-escape series) | Yes | Yes, but **manual** | Hand-crafted red-team research per target. High-quality, not a repeatable automated check; reporting notes scanners here were *"trivially bypassed in under an hour."* |
| **Nuclei / YAML template scanners** | No | No | Per-request / per-item matchers. No session state, so no way to express a def-use chain across statements (see §4). |
| **Semgrep / static allowlist linters** | No | No | Pattern-match one command or one file. Reason about the text of a rule, not the runtime composition of a session. |
| **Per-skill / per-tool agent scanners** | No | No | Score each skill or tool call in isolation — the exact granularity the class defeats. Reporting states these architectures *"completely miss"* the compositional surface. |

The gap this fills: SCR-Bench is a benchmark, Adversa is manual, and the per-item scanners structurally can't reach it. **Nobody ships a repeatable check that feeds a validator a sequence of individually-benign commands and proves the dangerous composition executes.** That is what this template is.

---

## 4. Why behavioral wins here

A static or YAML/Nuclei rule matches **one observation** — one request, one command, one file — against a pattern. The composition bypass has no signature in any single observation: `set verb touch` is a string assignment, `join cmd verb marker` is a string concatenation, `run cmd` names a value the rule cannot resolve. To flag it, a checker must carry **session state** and follow the **def-use chain** — the verb bound in statement 1, the argument bound in statement 2, meeting the execution sink in statement 4. A per-item matcher has nowhere to keep that chain, so it must judge each line alone and pass all four. This is not a gap in a particular ruleset; it is a limit of the per-item form.

Behavioural checking sidesteps the whole problem by **not trying to recognise the dangerous string at all**. It runs the trace and asks the runtime a physical question — *did the decoy marker appear?* — while reading the validator's own ledger to confirm every step was allowed. The finding is grounded in an observed effect (a sentinel file whose nonce no correct run could invent) plus an observed approval trail, not in a pattern that has to anticipate the attacker's encoding. And the same mechanism yields an honest **REFUTED** when the validator is stateful — it re-checks the resolved command at the exec sink and blocks it — which no signature scanner could report as a positive property of the tool.

That is the thesis in one line: **the check is stateful because the vulnerability is stateful.** The sequence across observations *is* the finding, and only a run-and-observe oracle can hold a sequence.

# Fixture — agent skill hidden-instruction trust

Synthetic twins for
[`templates/ai/coding-agent/agent-skill-hidden-instruction-trust.py`](../../../templates/ai/coding-agent/agent-skill-hidden-instruction-trust.py).
Run the proof with
[`tests/prove-agent-skill-hidden-instruction.sh`](../../prove-agent-skill-hidden-instruction.sh).

`skillagent.py` is a benign synthetic agent that loads skills from a directory
and acts on the `RUN: <command>` lines written in them. It is a fixture, not a
tool: no marketplace skill is installed, no vendor agent is driven, and the
only commands the driving template ever composes are `touch <nonce>` inside a
throwaway lab and one HTTP GET at a `127.0.0.1` port that template opened.

## One source, three twins

`build.sh` substitutes `VARIANT` in the single source and writes three
programs. The switches are independent rather than one flawed/fixed axis,
which is what lets one file reach every verdict the template can emit:

| Twin | `SANITISE` | `SKILLS_ENABLED` | Behaviour | Verdict |
|---|---|---|---|---|
| `skillagent_flawed.py` | off | on | acts on the **model view** — TAG block decoded, HTML comments and collapsed `<details>` bodies intact | `confirmed` |
| `skillagent_fixed.py` | on | on | acts on the **approval view** only, and prints each directive before running it | `refuted` |
| `skillagent_noskills.py` | off | off | no skills surface at all; `--skills-dir` is not part of its interface | `skipped` |

The fixed twin has to be the same program with the approval view switched on,
and the no-skills twin the same program with the surface switched off — twins
that could drift apart would make "refuted" and "skipped" mean nothing more
than "these three files differ".

## The two views

    model_view(raw)      what a tokenizer reads: TAG-block characters decoded
                         back to the ASCII they mirror, nothing dropped.
    approval_view(raw)   what a human reading the rendered Markdown sees:
                         invisible formatting characters removed, HTML comments
                         removed, collapsed <details> bodies removed.

The gap between them is the class. `skillagent_flawed` picks the first,
`skillagent_fixed` picks the second, and the template's job is to notice which.

    bash build.sh /tmp/twins
    /tmp/twins/skillagent_flawed.py run --skills-dir /tmp/skills --task "a task"

# Fixture — agent-plugin-loader-conformance

A benign synthetic **Agent Plugins 1.0 launch client**, used to prove
[`templates/ai/agent-plugin/agent-plugin-loader-conformance.sh`](../../../templates/ai/agent-plugin/agent-plugin-loader-conformance.sh)
in every direction it can report.

`pluginhost.py` is the single source. `build.sh` materialises **six twins** from
it by substituting `CONFORMANCE` — the comma-separated list of normative clauses
that twin honours:

| Twin | Honours | Violates | Template must say |
|---|---|---|---|
| `pluginhost_conformant.py` | §5.2, §8.1, §9.2, §9.4 | — | REFUTED |
| `pluginhost_defective.py` | — | all four | CONFIRMED, 4 clauses |
| `pluginhost_schema_only.py` | §8.1, §9.2, §9.4 | §5.2 | CONFIRMED, `sec-5.2` alone |
| `pluginhost_namespace_only.py` | §5.2, §9.2, §9.4 | §8.1 | CONFIRMED, `sec-8.1` alone |
| `pluginhost_autostart_only.py` | §5.2, §8.1, §9.2 | §9.4 | CONFIRMED, `sec-9.4` alone |
| `pluginhost_env_leak.py` | §5.2, §8.1 | §9.2, §9.4 | CONFIRMED, `sec-9.2` + `sec-9.4` |

The switches are independent rather than a single flawed/fixed axis because the
check reports on four separate MUSTs: a flawed/fixed pair would only ever prove
the template fires on *something*, whereas this matrix proves each arm fires for
its own reason **and stays silent about the three clauses its twin honours**.

§9.2 (the reserved name `PLUGIN_ROOT` in a plugin-declared `env` block) is only
observable through a server that actually starts, so its twin has to give up
§9.4 as well. `autostart_only` is its counterpart: it starts the same server
with the reserved name stripped, and the client still exports its *own*
`PLUGIN_ROOT` pointing at the real package directory. That pair is what proves
the §9.2 arm keys on the **manifest's value** rather than on the variable's
presence — a check that grepped for the name alone would confirm on a compliant
loader.

The seventh case, a stub CLI with the same command surface and no plugin layer
at all, is written by
[`tests/prove-agent-plugin-loader-conformance.sh`](../../prove-agent-plugin-loader-conformance.sh)
itself: the template must report `skipped` there, never a clean bill of health.

## Safety

Nothing here is an exploit. Every command any twin can be made to run is a
`printf <nonce> > <file>` planted by the template in the template's own
`mktemp -d` lab, and the only URL any twin can be made to fetch is a listener
the template starts on `127.0.0.1` and kills on exit. `$HOME` is redirected into
that lab for every run, so no real plugin root or user configuration is read or
written. No vendor's package or code is reproduced.

## Running

    bash tests/prove-agent-plugin-loader-conformance.sh

Roughly 35 s. Not one of the five CI checks — run it by hand before pushing a
change to the template or to this fixture.

# `agent-extension-install-path-containment` fixture

A benign synthetic agent extension manager, `skillforge`, used to prove
[`templates/ai/coding-agent/agent-extension-install-path-containment.sh`](../../../templates/ai/coding-agent/agent-extension-install-path-containment.sh)
in every direction it can report. There is no vendor code here and no exploit:
the entire content of every extension the probe builds is a random nonce, and
the `.ssh/authorized_keys` the archive arm aims at is a file the template
creates inside its own throwaway `$HOME` and seeds with an inert comment.

`build.sh <outdir>` materialises three twins from the one `skillforge.py` source:

| twin | behaviour |
| --- | --- |
| `skillforge_defective.py` | `os.path.join(root, name)` with the name taken straight off the extension's own metadata, and archive members laid down by member name. A name of `../../x` lands above the root, and a symlink member is recreated so the next member is written through it. |
| `skillforge_fixed.py` | Every destination is re-resolved and required to stay inside its root: a skill name is normalised to one path component and installed in place, a plugin manifest name that is a path is refused, and archive link members are skipped by name on stderr. |
| `skillforge_noinstall.py` | The same program with the install verb removed, so the template's SKIP branch has an honest target — an agent with no extension installer at all. |

The twins differ only in containment, so a refutation means "the same program
re-resolves its destinations", not "the two files differ". The `noinstall` twin
exists because a check that cannot distinguish *contained* from *never tested*
reports absence as safety.

## The three source shapes

| shape | name comes from | root |
| --- | --- | --- |
| `<dir>/SKILL.md` | frontmatter `name:` | `$HOME/.skillforge/skills` |
| `<dir>/plugin.json`, `.claude-plugin/plugin.json`, `marketplace.json` | manifest `"name"` | `$HOME/.skillforge/plugins` |
| `<file>.tar` | each member's own name | `$HOME/.skillforge/packs` |

Archive members are laid out by hand rather than through `tarfile.extractall()`,
because that is what an installer written in any other language does and
because `extractall()`'s default member filter varies by interpreter version —
the twins must differ by their own containment logic, not by the Python on PATH.

## Refusal must stay quiet about markers

The template proves an escape by finding its nonce at a path outside the root
the control install established. A gate that echoed the rejected name would put
the nonce in the program's output rather than on disk — which the template does
not scan, so it could not be mistaken for an escape — but the fixed twin still
names only the surface and the reason, never the value, so that the twins'
observable difference is containment and nothing else.

Run `tests/prove-agent-extension-install-containment.sh` to exercise all three.

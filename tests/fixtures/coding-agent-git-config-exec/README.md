# Fixture — GitSpawn (`coding-agent-git-config-exec`)

Synthetic twin pair for
[`templates/ai/coding-agent/coding-agent-git-config-exec.sh`](../../../templates/ai/coding-agent/coding-agent-git-config-exec.sh).

- **`gitagent.py`** — one source, benign. A synthetic coding-agent CLI whose
  `open` / `session` / `context` subcommands gather repository context by
  shelling out to `git` (`git status`, `git diff`, `git ls-remote`) — exactly
  the unattended startup calls that make git execute a workspace's own
  `.git/config` (`core.fsmonitor`, clean/smudge filters, `core.sshCommand`,
  `core.hooksPath`). This is the faithful reproduction of the **GitSpawn**
  mechanism; nothing here is a real exploit — the only commands git ever runs
  are `printf <nonce> > <lab-file>` the template planted in its own scratch dir.
- **`build.sh`** — materialises two twins from that one source via `@@VARIANT@@`:
  - `gitagent_defective.py` — shells out to git **raw**; git honours the
    malicious `.git/config`. → **CONFIRMED**.
  - `gitagent_fixed.py` — same program, git-config trust gate on: it refuses to
    run git in a workspace whose `.git/config` carries exec-bearing directives
    unless the user approved the path, and hardens the calls it does make
    (`git -c core.fsmonitor= -c core.hooksPath= -c core.sshCommand= …`).
    → **REFUTED**.

The proof driver [`tests/prove-coding-agent-git-config-exec.sh`](../../prove-coding-agent-git-config-exec.sh)
adds a third `nogitcli` stub that gathers context without git at all (→ **SKIP**)
and runs a real `cxg scan` against both twins, not just the raw probe contract.

```sh
tests/prove-coding-agent-git-config-exec.sh
```

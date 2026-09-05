# Supply-chain install-hook behavioural probes

Two checks, same lab, two different questions.

| Template | Asks | Playbook |
|---|---|---|
| [`supply-chain-install-hook-behavior`](./supply-chain-install-hook-behavior.sh) | does installing this package **do something it should not**, at the moment it is installed, started or first imported? | — |
| [`supply-chain-install-credential-access`](./supply-chain-install-credential-access.sh) | **which secret** does the install step read, and does it **plant a GitHub Actions workflow**? | [playbook](../../../docs/playbooks/supply-chain-install-credential-access.md) |

The second is the Shai-Hulud / CHAINDROP worm mechanic stated as a behaviour:
per-source canary credentials in `~/.npmrc`, `~/.aws/credentials` and
`~/.config/gh/hosts.yml`, an access-time read witness that is liveness-tested
before it is trusted, and a seeded checkout for a planted workflow to appear in.
Where the first template says *a package is misbehaving*, it says **which token
to rotate and which branch to rewrite**. It has its own fixtures
(`tests/fixtures/tooling/supply-chain-credential-access/`) and its own proof
harness (`tests/prove-supply-chain-install-credential-access.sh`); everything
below describes the first template.

---

## `supply-chain-install-hook-behavior`

One check: **does installing this package do something it should not, at the
moment it is installed, started or first imported?**

Not "does its `postinstall` line match a bad pattern" — the template never
reads the hook's source. It installs the package with a real package manager
in a hermetic lab, watches the lifecycle happen, and reports the side effects
it can see.

```bash
cxg scan --scope cli:///usr/local/bin/npm \
         --templates templates/tooling/supply-chain/supply-chain-install-hook-behavior.sh \
         --input ./some-package
```

`--input` is the probe-input flag of cxg ≥ the release that carries
`CERT_X_GEN_INPUT_DIR`. On an older cxg, pass the package as
`CXG_SUPPLY_CHAIN_PACKAGE=./some-package` instead; the template reads both.

## What it observes

| Observable | How it is seen | Why a positive is a fact |
|---|---|---|
| `loopback-sink-connection` | every proxy variable in the lab points at a listener on `127.0.0.1:<random>`; the listener logs whatever arrives | the install is offline and the control phase connects to nothing, so a connection is the package reaching for a network |
| `decoy-credential-nonce-observed` | a random nonce is planted in decoy `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.npmrc` and `~/.config/gcloud/credentials.json`; the nonce is then looked for in the sink's bytes, in files the phase wrote, and on its stdout | that value exists nowhere but those decoys. Seeing it leave means something read them |
| `write-outside-install-prefix` | the phase's sentinel `HOME` is diffed against the control phase's | build work belongs in the package's own tree. `~/.ssh`, `~/.cursorrules`, `~/.aws` do not |
| `child-process-spawned` | transparent PATH shims record every capability program the phase executed | **only confirming for the startup and import phases** — see below |

## The control, and why there is one

Every observation is taken twice: once on the package under test, and once on a
package the template synthesises on the spot that declares nothing and does
nothing. Same package manager, same phase, same lab. Whatever npm, pip, the
venv builder and the interpreter do on their own therefore appears in both and
cancels; only what the subject *added* survives.

That is the whole reason this can be precise. `npm install` runs `sh` for every
package that has a lifecycle script, and pip writes into `~/.cache`. Without a
control those are noise you either report (false positives) or suppress by
hand (a list that rots). With one they subtract.

## Phases

| Ecosystem | Phase | What is running | `child-process-spawned` confirms? |
|---|---|---|---|
| npm / pnpm / yarn | `install` | `preinstall`/`install`/`postinstall` lifecycle scripts | no |
| pip | `install` | the PEP 517 build backend — the modern `setup.py` | no |
| pip | `startup` | `python -c pass`. The package is **not** imported | **yes** |
| pip | `import` | `python -c "import <pkg>"`, the first import | **yes** |

The split in that last column is the precision claim. A subprocess during
an install is ordinary: thousands of honest packages compile something. A
subprocess during a *bare interpreter start*, with the package never imported,
is the `.pth` mechanism and nothing else — `site.py` executes an `import` line
in a `.pth` file on every Python start, which is how LiteLLM 1.82.8 ran on
hosts that never used LiteLLM. A subprocess during a first `import` is the
LiteLLM 1.82.7 shape.

Select phases with `CXG_SUPPLY_CHAIN_PHASES=install,startup,import` (the
default). A confirmation ends the run at the phase that produced it.

## Isolation — the part that is not optional

This template **executes the package's install and import code**. Everything it
creates lives in one `mktemp -d` lab — a sentinel `HOME`, a fresh project
directory and a fresh venv per phase, all removed on exit — and the decoys it
plants are random nonces, never real credentials.

That is a **lab, not a sandbox**. A hostile package can still reach the real
network and the real filesystem; the lab only makes its effects *visible*.
Point this at an untrusted package **only inside a disposable container or VM
with no network route**. Against the fixtures below it is safe anywhere.

## Proving it both ways

```bash
./tests/prove-supply-chain-install-hook.sh
```

Eight cases, all of which must pass: the flawed twin confirms in every phase,
the fixed twin refutes in every phase, and the two guard cases prove the
template says `skipped` — never `refuted` — when it was handed no package or a
binary that is not a package manager.

```
PASS  npm install hook, flawed twin                  confirmed
PASS  npm install hook, fixed twin                   refuted
PASS  pip install, flawed twin                       confirmed
PASS  pip startup, flawed twin                       confirmed
PASS  pip import, flawed twin                        confirmed
PASS  pip all phases, fixed twin                     refuted
PASS  no subject package is a skip, not a refutation skipped
PASS  a binary that is not a package manager is a skip skipped
```

The fixtures are in `tests/fixtures/tooling/supply-chain/`. Both twins are
**benign synthetic packages**, and the fixed twin is deliberately not inert —
it runs at install time, spawns a shell, and generates a file — because a probe
that confirmed on it would be reporting "this package has a hook", which is not
a finding.

The flawed twin's "exfiltration" is a `curl` to `cxg-fixture-c2.invalid`.
`.invalid` is reserved by RFC 2606 and no resolver will ever answer it, so
outside the template's own loopback proxy the beacon cannot leave the machine
at all.

## The class

- npm `postinstall` droppers: `axios@1.14.1` / `axios@0.30.4` pulling
  `plain-crypto-js`, whose `postinstall` fetched a platform payload from a C2
  and then rewrote its own `package.json` clean —
  [Zscaler ThreatLabz, Mar 2026](https://www.zscaler.com/blogs/security-research/supply-chain-attacks-surge-march-2026).
- PyPI import-time and `.pth` execution: `litellm@1.82.7` (base64 payload in
  `proxy_server.py`, runs on import) and `litellm@1.82.8` (a `.pth` that runs
  on *any* Python start), harvesting AWS/GCP/Azure tokens, SSH keys and
  Kubernetes credentials — same report.
- Cross-ecosystem, npm + PyPI + crates.io, exploiting `postinstall`, Python
  import behaviour and `build.rs` alike, and planting `CLAUDE.md` /
  `.cursorrules` outside the package to poison coding agents —
  [TrapDoor (Socket, May 2026)](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates).

Signature lists chase each of those after the fact. The behaviour — egress,
credential read, escape from the install prefix, code at interpreter start —
is what they all have in common, and it is what this template reads.

## Not yet covered

`build.rs` (crates.io) is the third leg of the TrapDoor class and is not
implemented here. `cargo build` runs `build.rs` with the same shape of side
effects, and the observation harness in this template is ecosystem-agnostic —
adding it is a `cxg_phase` branch, not a redesign.

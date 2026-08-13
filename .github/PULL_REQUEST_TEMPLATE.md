## What this changes

<!-- One or two lines. Which template(s), and what they detect. -->

## Checklist

- [ ] **Category** — the template is under one of `ai`, `databases`, `devops`,
      `messaging`, `monitoring`, `network`, `recon`, `tooling`, `web`, in the
      one that matches what it audits.
- [ ] **Annotations** — full set present, and `@id` is unique across the repo.
      A duplicate `@id` is not a warning: the engine keeps one template per id
      and silently drops the rest, so both templates stop running.
- [ ] **It loads** — `cxg --disable-update-check -vv template list` from the
      repo root reports no `WARN` for your file. The engine, not
      `cxg template validate`; the two disagree and the engine is what runs.
- [ ] **Registry regenerated** — ran `python3 scripts/generate-index.py` and
      committed the resulting `TEMPLATE_REGISTRY.json`.
- [ ] **Terminology** — the template describes an audit and what it exposes.
      Not exploit, manipulation, or confusion.
- [ ] **No third-party traffic** — a scan touches the target and nothing else.
      No calls out to external services, callback hosts, or public resolvers.
- [ ] **Detection is specific** — it fires on a unique, verifiable signal the
      template put there or can attribute to the finding. Not on a string,
      status code, or banner that occurs naturally in an ordinary response.

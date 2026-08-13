# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-08-13

**162 templates**, all of which load through the engine and hold a unique id.
That is the first release where those two things are true and are checked
automatically: `files_on_disk == loadable == runnable == engine_registered == 162`.

Minor, not major: no template was removed from the library's detection surface
and no consumer-visible format changed. `TEMPLATE_REGISTRY.json` gained fields
and kept the ones it had, and the library gained templates.

### Added

- **6 MCP security templates** in `templates/ai/mcp/`, covering the Model
  Context Protocol attack surface end to end:
  - `mcp-unauthenticated` — MCP server reachable with no authentication (CWE-306)
  - `mcp-tool-poisoning` — tool/prompt/resource descriptions carrying
    instructions aimed at the connected model (CWE-1427)
  - `mcp-excessive-tool-permissions` — tools advertising capability far beyond
    their stated purpose (CWE-250)
  - `mcp-credential-exposure` — credentials readable through MCP resources (CWE-522)
  - `mcp-broken-token-validation` — token validation that accepts what it
    should reject (CWE-287)
  - `mcp-rug-pull-detection` — tool definitions that change after approval
    (CWE-345, stateful)
- **10 auth-context parameterised templates** in `templates/web/`, the first
  wave using the `auth-context` batch group: forced browse, mass assignment,
  vertical privilege escalation, horizontal IDOR/BOLA, JWT algorithm confusion,
  JWT role tampering, logout token reuse, password reset enumeration, auth rate
  limiting, and session fixation.
- **Continuous integration.** `.github/workflows/ci.yml` runs on every pull
  request and on push to `main`, gating four things that were previously only
  detectable by hand:
  - every template loads through the **engine loader** at `-vv` — failing on any
    `WARN`, on the loaded count not matching the file count, and on a
    `Deduplicated templates` line, which means an id collision silently dropped
    a template. The engine, not `cxg template validate`: the two disagree about
    validity, and the loader is what decides which templates actually run.
  - `TEMPLATE_REGISTRY.json` is regenerated and diffed, so a template cannot be
    added or edited without the registry following it
  - the generator's guard tests
  - hygiene: no absolute paths or empty names in the registry, and no template
    outside the nine valid categories
  - cxg is pinned to a specific release and checksum-verified, so a cxg release
    cannot silently change what this repo considers a valid template
- **Guard tests for the registry generator** (`scripts/test_generate_index.py`).
  A clean template tree exercises neither the collision guard nor the
  zero-template guard, so both were about to rot untested. The tests build
  throwaway fixture trees and assert that a duplicate id exits 2 with both
  members recorded `runnable=false`, and that an empty tree exits 1 leaving the
  registry byte-identical.
- **`.github/PULL_REQUEST_TEMPLATE.md`** — a short contributor checklist:
  category placement, full annotations with a unique `@id`, loads through the
  engine, registry regenerated, audit/exposure terminology, no third-party
  traffic during a scan, and detection gated on a unique verifiable signal.
- **`pwn-request-scanner` rewritten** (`templates/devops/github/`). The previous
  version guessed 8 hardcoded workflow filenames over HTTP; against a repository
  with 33 workflows it discovered none and reported "No Workflows Found". It now
  walks `.github/workflows/` on the filesystem, scopes analysis per job rather
  than per file, parses `if:` conditions with a guard-strength ladder, and
  separates pwn-request (CWE-829) from expression injection (CWE-94). Untrusted
  context routed through `env:` is GitHub's own recommended pattern and is
  deliberately not flagged. It runs entirely offline and stays silent on targets
  that are not repositories.

### Fixed

- **4 templates that never loaded.** The engine warns once and continues, so
  each was silently absent from every scan it was supposed to run in:
  - `devops/etcd/which-runs-etcdctl-command.yaml` — used `ports:` (a list) and
    `inputs:`, both unknown keys the engine drops, leaving the required `port`
    absent and the probe payload unsent
  - `web/injection/timing-attack-detection.yaml` — four `dsl:` matchers; there
    is no `dsl` matcher in the engine's set
  - `web/cache/response-manipulation-detection.yaml` — same unsupported `dsl`
    matcher
  - `network/http/http-service-responding.yaml` — `author` given as a plain
    string where the schema requires an object
- **5 duplicate template ids.** The engine keeps exactly one template per id and
  drops the rest, decided by directory walk order, so one of each pair never ran
  no matter how valid it was: `cadvisor-exposed`, `node-exporter-exposed`,
  `prometheus-server-exposed`, `redis-exporter-exposed`, and the ollama pair.
- **The registry generator** (`scripts/generate-index.py`). It walked
  `templates/<language>/`, a layout that no longer exists. Against the current
  tree it discovered 0 templates and wrote the empty result out, so running it
  destroyed the registry. Rebuilt to walk by category and to mirror the engine's
  own discovery and parsing rules — the 50-line annotation window, the `#`,
  `//`, `//!` and `*` comment prefixes, the silent `medium` severity default,
  and the `.cc`/`.cxx`/`.bash` extensions — so the registry cannot drift from
  what cxg actually loads.
- **`TEMPLATE_REGISTRY.json`.** It carried absolute paths from a developer's
  home directory into a public repository, had empty `name` fields, was dated
  2025-10-30, and claimed `total_templates: 32` over a 21-entry array.

### Changed

- **The registry reports four counts instead of one.** A single total hid two
  different kinds of breakage, so each is now separate and every row carries its
  own status:
  - `files_on_disk` — every template file the engine would discover
  - `loadable` — files that survive the engine's parse/deserialize step
  - `runnable` — loadable and holding an id no other template claims
  - `engine_registered` — what the engine reports after dropping one file per
    collided id, which is higher than `runnable` because it counts an arbitrary
    survivor per collision
  `runnable` is the number reproducible from the source tree; the gap between it
  and `engine_registered` is exactly the number of collisions left to fix.
- **Multi-language template pairs now carry distinct ids**, using the library's
  pre-existing `<base-id>-<language>` convention (as in `redis-unauthenticated.*`):
  `cadvisor-exposed`, `node-exporter-exposed` and `prometheus-server-exposed` are
  suffixed `-python` / `-javascript`; `redis-exporter-exposed.py` becomes
  `-python` while the `.yaml` keeps the base id as the externally referenced
  canonical member. Runtime `id:` fields were synced so emitted findings match.

### Removed

- `templates/ai/ollama/detect_ollama.yaml` — a verbatim duplicate of
  `detect-exposed-ollama-sending.yaml` (byte-identical but for a trailing
  newline) sharing its id, so the engine was already dropping one of the two. It
  also broke the directory's kebab-case convention. No detection coverage was
  lost.

## [1.1.0] - 2025-03-04

### Changed
- **BREAKING:** Restructured template directory from language-based (`python/`, `go/`, `yaml/`) to purpose-based categories (`databases/`, `devops/`, `network/`, `web/`, `ai/`, etc.)
- Templates are now grouped by what they detect, not what language they're written in
- CXG CLI discovers templates via recursive directory walk + file extension detection, so this change is transparent to the scanner engine

### Added

#### New Categories
- `ai/` — AI/LLM security templates (15 templates)
- `databases/` — Database vulnerability detection (26 templates)
- `devops/` — DevOps platform security (26 templates)
- `messaging/` — Message broker security (7 templates)
- `monitoring/` — Observability stack exposure (16 templates)
- `network/` — Network service probes and attacks (34 templates)
- `web/` — Web application vulnerabilities (22 templates)
- `recon/` — Reconnaissance and enumeration (1 template)
- 23 security assessment playbooks (published on [BugB Blog](https://bugb.io/blogs))

#### AI / LLM Security (15 new templates)
- Claude Code sed DSL bypass detection (CVE-2025-64755)
- Copilot YOLO autoApprove risk detection
- Cursor MCP poisoning config risk
- Flowise CustomMCP command injection and JS eval exposure
- InvokeAI model install endpoint exposure
- TorchServe and Triton model control API exposure
- Torch unsafe load and unsafe deserialization in ML pipelines
- AI-assisted fuzzing SQLi seed corpus generation

#### Network Service Probes (25+ new templates)
- ADB, Cisco Smart Install, DHCPv6, DNS UDP, Echo, EPMD, Finger
- HTTP service responding, Ident, mDNS, NBNS, NDMP, NTP
- ICMP echo reachability, rsync banner, SOCKS5 no auth
- SSDP M-SEARCH, TACACS, TFTP, Whois, WSD probes
- TCP banner probe and TCP port reachability scanners

#### DevOps & Cloud (13 new templates)
- GitHub Actions injection scanner, pwn request scanner, runner token detection
- GHES version fingerprint, GitLab version fingerprint, SAML SSO bypass
- Kubernetes RBAC misconfiguration, kubelet API exposure, service account token abuse, Helm chart secrets leak
- Istio pilot misconfiguration, Git history secret scan, CI variable exposure

#### Database Security (4 new templates)
- ClickHouse auth bypass, Elasticsearch query injection
- MongoDB injection deep, PostgreSQL extension RCE, Redis cluster takeover

#### Web Application (10 new templates)
- HTTP/2 Rapid Reset, prototype pollution, server-side JS injection
- SSTI engine fingerprint, Spring4Shell detection, deserialization gadget scan
- HTTP header injection, GraphQL user enumeration
- Password reset takeover, race condition exploit

#### Messaging & Monitoring (7 new templates)
- Kafka unauthenticated access (Python), MQTT unauthenticated, NATS unauthenticated banner
- RabbitMQ management exposed, InfluxDB health exposed
- Kibana API status exposed, Splunk web login and splunkd server info exposed

#### Playbooks (23 — published on [BugB Blog](https://bugb.io/blogs))
- Detailed security assessment playbooks moved from repository to blog for better discoverability and richer presentation
- Topics include: ClickHouse auth bypass, deserialization gadget scan, DNS rebinding, Elasticsearch query injection, GHES SAML encrypted assertions, Git history secret scan, GraphQL batching DoS, gRPC reflection abuse, HTTP/2 rapid reset, Istio pilot misconfiguration, JWT algorithm confusion, K8s RBAC misconfiguration, kubelet API exposure, MongoDB injection deep, OAuth state confusion, OAuth state parameter audit, race condition exploit, Redis cluster takeover, RMI service enumeration, service account token abuse, Spring4Shell detection, SSTI engine fingerprint, TLS certificate deep analysis

### Documentation
- Added CONTRIBUTORS.md
- Added docs/TEMPLATE_GUIDE.md with template authoring documentation
- Regenerated TEMPLATE_REGISTRY.md for new directory structure with full inventory

### Removed
- Removed stale `templates/yaml/` directory (templates relocated to purpose-based categories)
- Removed `Cargo.lock` from repository (build artifact)
- Cleaned up test artifacts (`scan.json`, `scan-results.json`)

### Contributors
- Shahid — Directory restructuring, 50+ new templates (network probes, AI security, monitoring)
- Ashish — 19 templates (DevOps, web injection, CI/CD), 10 playbooks
- Feature branch contributors — 13 templates with playbooks across databases, network, web, DevOps

## [1.0.0] - 2025-10-30

### Added
- Initial release of CERT-X-GEN templates
- 45 network service templates
- 78 web vulnerability templates  
- 52 CVE templates
- 18 cloud misconfiguration templates
- 12 default credential templates
- Support for 12 programming languages
- Documentation and examples
- CI/CD pipeline for validation
- Template validation scripts

### Template Categories
- **YAML:** 150 templates (http, network)
- **Python:** 25 templates
- **JavaScript:** 12 templates
- **C:** 8 templates
- **Rust:** 5 templates
- **Shell:** 5 templates

[Unreleased]: https://github.com/Bugb-Technologies/cert-x-gen-templates/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/Bugb-Technologies/cert-x-gen-templates/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Bugb-Technologies/cert-x-gen-templates/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Bugb-Technologies/cert-x-gen-templates/releases/tag/v1.0.0
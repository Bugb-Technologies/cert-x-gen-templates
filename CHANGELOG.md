# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Bugb-Technologies/cert-x-gen-templates/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Bugb-Technologies/cert-x-gen-templates/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Bugb-Technologies/cert-x-gen-templates/releases/tag/v1.0.0
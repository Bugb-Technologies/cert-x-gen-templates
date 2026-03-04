<h1 align="center">CERT-X-GEN Templates</h1>
<h4 align="center">Polyglot Security Templates for the CERT-X-GEN Execution Engine</h4>

<p align="center">
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates/releases"><img src="https://img.shields.io/badge/version-1.1.0-blue?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates"><img src="https://img.shields.io/badge/templates-147-orange?style=flat-square"></a>
<a href="#supported-languages"><img src="https://img.shields.io/badge/languages-12-purple?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen?style=flat-square"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-template-overview">Overview</a> •
  <a href="#-polyglot-showcase">Showcase</a> •
  <a href="#-documentation">Docs</a> •
  <a href="#-contributing">Contributing</a> •
  <a href="#-community">Community</a>
</p>

---

Templates are the core of the [CERT-X-GEN](https://github.com/Bugb-Technologies/cert-x-gen) — a next-generation execution engine for cybersecurity that executes templates written in **real programming languages**, not just YAML.

This repository contains security scanning templates contributed by the CERT-X-GEN team and the security community. We encourage you to contribute by submitting templates via **pull requests** or [GitHub Issues](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues/new).


## 🚀 Quick Start

```bash
# Templates auto-download on first scan
cxg scan --scope example.com

# Update to latest templates
cxg template update

# List all available templates
cxg template list

# Scan with specific template
cxg scan --scope 192.168.1.100:5432 --templates postgresql-default-credentials.go

# Scan with multiple templates
cxg scan --scope targets.txt --templates redis*.py,docker*.go
```

## 📊 Template Overview

An overview of the CERT-X-GEN template repository, including statistics by language, severity, and category.

| Language | Templates | Description |
|----------|-----------|-------------|
| **Python** | 48 | Database auth, DevOps tools, AI/ML security, network probes |
| **YAML** | 50 | HTTP checks, service detection, network probes |
| **Go** | 16 | High-performance scanning, binary protocols, K8s security |
| **JavaScript** | 7 | Monitoring exporters, web injection, WebSocket fuzzing |
| **Shell** | 8 | System checks, native tool integration |
| **Rust** | 5 | Async operations, memory-safe scanning |
| **C** | 5 | Low-level protocols, web vulnerability detection |
| **Java** | 4 | Deserialization, RMI enumeration, Spring4Shell |
| **C++** | 1 | Redis protocol implementation |
| **Ruby** | 1 | Redis unauthenticated access |
| **Perl** | 1 | Redis unauthenticated access |
| **PHP** | 1 | Redis unauthenticated access |
| **Total** | **147** | |

<details>
<summary>📁 Directory Structure</summary>

```
templates/
├── ai/                 # AI/LLM security
│   ├── ollama/         # Ollama endpoint exposure
│   ├── flowise/        # Flowise MCP injection
│   ├── claude/         # Claude Code bypass detection
│   ├── ml/             # ML pipeline unsafe deserialization
│   └── ...
├── databases/          # Database vulnerabilities
│   ├── redis/          # Redis unauth (12 languages)
│   ├── mysql/          # MySQL default credentials
│   ├── postgresql/     # PostgreSQL default creds & RCE
│   ├── mongodb/        # MongoDB unauth & injection
│   └── ...
├── devops/             # DevOps & platform security
│   ├── docker/         # Docker API & registry
│   ├── kubernetes/     # K8s API, RBAC, kubelet, Helm
│   ├── github/         # GHES, Actions injection, runner tokens
│   ├── gitlab/         # GitLab fingerprint, SAML bypass
│   ├── jenkins/        # Jenkins unauth RCE
│   └── ...
├── messaging/          # Message broker security
│   ├── kafka/          # Kafka unauthenticated
│   ├── rabbitmq/       # RabbitMQ default creds & mgmt
│   └── ...
├── monitoring/         # Observability stack exposure
│   ├── prometheus/     # Prometheus server exposed
│   ├── exporters/      # Redis, MySQL, Node, PostgreSQL exporters
│   ├── splunk/         # Splunk web & API exposure
│   └── ...
├── network/            # Network service probes
│   ├── dns/            # DNS zone transfer, rebinding, probes
│   ├── scanning/       # Port scanner, TCP probes
│   ├── tls/            # TLS certificate deep analysis
│   └── ...             # ADB, Cisco, SNMP, VNC, gRPC, RMI, ...
├── web/                # Web application vulnerabilities
│   ├── injection/      # SQLi, XSS, SSTI, Spring4Shell, prototype pollution
│   ├── auth-bypass/    # Auth bypass, password reset takeover
│   ├── deserialization/ # Java deserialization gadget scan
│   └── ...
├── recon/              # Reconnaissance
│   └── system/         # System context recon
└── skeleton/           # Template boilerplate (12 languages)
```

</details>


## ⚡ Polyglot Showcase

CERT-X-GEN's unique strength is executing templates in **real programming languages**. These showcase templates demonstrate capabilities that declarative formats cannot achieve:

### 🔐 Stateful Protocol Authentication

| Template | Language | Capability |
|----------|----------|------------|
| [`smtp-open-relay.py`](templates/network/smtp/smtp-open-relay.py) | Python | Multi-step SMTP conversation: `EHLO` → `MAIL FROM` → `RCPT TO` → `DATA` with branching logic |
| [`postgresql-default-credentials.go`](templates/databases/postgresql/postgresql-default-credentials.go) | Go | PostgreSQL wire protocol + MD5 challenge-response authentication |
| [`mysql-default-credentials.py`](templates/databases/mysql/mysql-default-credentials.py) | Python | MySQL handshake protocol + native password authentication |
| [`mongodb-unauthenticated.py`](templates/databases/mongodb/mongodb-unauthenticated.py) | Python | MongoDB BSON wire protocol parsing + database enumeration |

### 🛠️ Native Tool Integration

| Template | Language | Capability |
|----------|----------|------------|
| [`snmp-default-community.sh`](templates/network/snmp/snmp-default-community.sh) | Shell | Native `snmpwalk` integration for community string testing |
| [`system-context-recon.sh`](templates/recon/system/system-context-recon.sh) | Shell | OS detection, user enumeration, installed packages |

### 🎯 Binary Protocol Analysis

| Template | Language | Capability |
|----------|----------|------------|
| [`vnc-no-auth.c`](templates/network/vnc/vnc-no-auth.c) | C | RFB (Remote Framebuffer) binary protocol handshake |
| [`port-scanner-async.rs`](templates/network/scanning/port-scanner-async.rs) | Rust | High-speed async TCP port scanning with service detection |

### ☁️ Cloud & Container Security

| Template | Language | Capability |
|----------|----------|------------|
| [`docker-api-unauth.go`](templates/devops/docker/docker-api-unauth.go) | Go | Docker Engine API access + container enumeration |
| [`k8s-etcd-exposed.go`](templates/devops/etcd/k8s-etcd-exposed.go) | Go | Kubernetes etcd key-value extraction |
| [`jenkins-unauth-rce.go`](templates/devops/jenkins/jenkins-unauth-rce.go) | Go | Jenkins Script Console command execution |
| [`jupyter-unauth-rce.py`](templates/devops/jupyter/jupyter-unauth-rce.py) | Python | Jupyter Notebook kernel code execution |


## 📂 Template Categories

<table>
<tr>
<td>

### Databases
- Redis unauthenticated (12 languages)
- Redis cluster takeover
- MongoDB unauthenticated & injection
- MySQL default credentials
- PostgreSQL default creds & RCE
- Elasticsearch unauth, data exposure & injection
- CouchDB default credentials
- CockroachDB unauthenticated
- ClickHouse auth bypass
- Memcached unauthenticated
- InfluxDB health exposed

</td>
<td>

### DevOps & CI/CD
- Docker API & registry unauthenticated
- Kubernetes API, RBAC, kubelet, Helm secrets
- Service account token abuse
- Jenkins Script Console RCE
- Jupyter Notebook RCE
- etcd key exposure
- GitHub Actions injection, pwn request, runner tokens
- GHES version fingerprint
- GitLab version fingerprint, SAML bypass
- Istio pilot misconfiguration
- Git history secret scan

</td>
<td>

### AI / LLM Security
- Ollama endpoint exposure (4 checks)
- Flowise MCP command injection
- Claude Code sed bypass (CVE-2025-64755)
- Copilot YOLO autoApprove
- Cursor MCP poisoning
- TorchServe & Triton model API exposure
- ML unsafe deserialization & torch load
- AI-assisted fuzzing seed corpus

</td>
</tr>
<tr>
<td>

### Web Vulnerabilities
- SQL injection detection
- XSS detection
- SSTI engine fingerprint
- Spring4Shell detection
- Prototype pollution
- Server-side JS injection
- HTTP header injection
- Deserialization gadget scan
- Directory traversal & listing
- Auth bypass & password reset takeover
- Race condition exploit
- HTTP/2 Rapid Reset
- Log4Shell detection

</td>
<td>

### Monitoring & Messaging
- Prometheus server & exporter exposed
- Node, Redis, MySQL, PostgreSQL exporters
- cAdvisor exposed
- Kibana API status exposed
- Splunk web & splunkd exposure
- RabbitMQ default creds & management
- Kafka unauthenticated
- MQTT unauthenticated
- NATS unauthenticated
- ZooKeeper unauthenticated

</td>
<td>

### Network Services
- DNS zone transfer & rebinding
- FTP anonymous access
- SMTP open relay
- SNMP default community
- VNC no authentication
- gRPC reflection abuse
- RMI service enumeration
- TLS certificate deep analysis
- 25+ service probes (ADB, Cisco, SOCKS5, NTP, mDNS, SSDP, ...)
- Async port scanner
- TCP banner & reachability probes

</td>
</tr>
</table>


## 📖 Documentation

Please refer to the [CERT-X-GEN documentation](https://github.com/Bugb-Technologies/cert-x-gen) for detailed guides on:

- **Writing Templates** — Create custom security checks in any supported language
- **Template Specification** — Required metadata, output format, environment variables
- **Language Guides** — Best practices for Python, Go, C, Rust, Shell, and YAML templates
- **Security Playbooks** — Detailed walkthroughs and learning content on the [BugB Blog](https://bugb.io/blogs)

### Template Skeletons

Get started quickly with our template skeletons:

```bash
# Skeletons are installed with templates
ls ~/.cert-x-gen/templates/official/templates/skeleton/

# Available skeletons:
# - python-template-skeleton.py
# - go-template-skeleton.go
# - shell-template-skeleton.sh
# - yaml-template-skeleton.yaml
```

## 🤝 Contributing

CERT-X-GEN templates are powered by contributions from the security community.

**[Template Contributions](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues/new?template=submit-template.md)** • **[Feature Requests](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues/new?template=feature_request.md)** • **[Bug Reports](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues/new?template=bug_report.md)**

### Contribution Guidelines

1. **Fork** this repository
2. **Create** your template in the appropriate category directory (e.g., `databases/redis/`, `web/injection/`)
3. **Follow** the template skeleton structure
4. **Validate** your template:
   ```bash
   cxg template validate path/to/your-template.py
   ```
5. **Test** against a local target or test environment
6. **Submit** a Pull Request

### Template Requirements

All templates must:

- ✅ Output valid JSON with a findings array
- ✅ Handle `CERT_X_GEN_TARGET_HOST` and `CERT_X_GEN_TARGET_PORT` environment variables
- ✅ Include metadata comments (`@id`, `@name`, `@severity`, `@description`, etc.)
- ✅ Handle errors gracefully (return empty array `[]`, never crash)
- ✅ Follow the [Code of Conduct](CODE_OF_CONDUCT.md)


## 💬 Community

Have questions, ideas, or want to discuss security automation?

- **[GitHub Discussions](https://github.com/Bugb-Technologies/cert-x-gen/discussions)** — Ask questions, share ideas
- **[GitHub Issues](https://github.com/Bugb-Technologies/cert-x-gen-templates/issues)** — Report bugs, request features

## 🔒 Security

Found a security vulnerability in a template? Please report it responsibly:

- **Email:** security@bugb.io
- **See:** [SECURITY.md](SECURITY.md)

## 📝 License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Bugb-Technologies">BugB Technologies</a> and the security community</b>
</p>

<p align="center">
  <a href="https://github.com/Bugb-Technologies/cert-x-gen">CERT-X-GEN Scanner</a> •
  <a href="https://github.com/Bugb-Technologies/cert-x-gen-templates">Templates</a> •
  <a href="https://github.com/Bugb-Technologies/cert-x-gen/discussions">Discussions</a>
</p>

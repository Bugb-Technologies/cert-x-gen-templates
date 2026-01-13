<h1 align="center">CERT-X-GEN Templates</h1>
<h4 align="center">Polyglot Security Templates for the CERT-X-GEN Execution Engine</h4>

<p align="center">
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates/releases"><img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates"><img src="https://img.shields.io/badge/templates-58-orange?style=flat-square"></a>
<a href="#supported-languages"><img src="https://img.shields.io/badge/languages-6-purple?style=flat-square"></a>
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
| **Python** | 15 | Database auth, DevOps tools, stateful protocols |
| **YAML** | 24 | HTTP checks, simple network probes |
| **Go** | 5 | High-performance scanning, binary protocols |
| **C** | 5 | Low-level protocols, web vulnerability detection |
| **Shell** | 5 | System checks, native tool integration |
| **Rust** | 4 | Async operations, memory-safe scanning |
| **Total** | **58** | |

<details>
<summary>📁 Directory Structure</summary>

```
templates/
├── c/                  # C templates
│   ├── vnc-no-auth.c
│   ├── sql-injection-detection.c
│   └── ...
├── go/                 # Go templates  
│   ├── postgresql-default-credentials.go
│   ├── docker-api-unauth.go
│   └── ...
├── python/             # Python templates
│   ├── smtp-open-relay.py
│   ├── mysql-default-credentials.py
│   └── ...
├── rust/               # Rust templates
│   ├── port-scanner-async.rs
│   └── ...
├── shell/              # Shell templates
│   ├── snmp-default-community.sh
│   └── ...
└── yaml/               # YAML templates
    ├── http/
    └── network/
```

</details>


## ⚡ Polyglot Showcase

CERT-X-GEN's unique strength is executing templates in **real programming languages**. These showcase templates demonstrate capabilities that declarative formats cannot achieve:

### 🔐 Stateful Protocol Authentication

| Template | Language | Capability |
|----------|----------|------------|
| [`smtp-open-relay.py`](templates/python/smtp-open-relay.py) | Python | Multi-step SMTP conversation: `EHLO` → `MAIL FROM` → `RCPT TO` → `DATA` with branching logic |
| [`postgresql-default-credentials.go`](templates/go/postgresql-default-credentials.go) | Go | PostgreSQL wire protocol + MD5 challenge-response authentication |
| [`mysql-default-credentials.py`](templates/python/mysql-default-credentials.py) | Python | MySQL handshake protocol + native password authentication |
| [`mongodb-unauthenticated.py`](templates/python/mongodb-unauthenticated.py) | Python | MongoDB BSON wire protocol parsing + database enumeration |

### 🛠️ Native Tool Integration

| Template | Language | Capability |
|----------|----------|------------|
| [`snmp-default-community.sh`](templates/shell/snmp-default-community.sh) | Shell | Native `snmpwalk` integration for community string testing |
| [`system-context-recon.sh`](templates/shell/system-context-recon.sh) | Shell | OS detection, user enumeration, installed packages |

### 🎯 Binary Protocol Analysis

| Template | Language | Capability |
|----------|----------|------------|
| [`vnc-no-auth.c`](templates/c/vnc-no-auth.c) | C | RFB (Remote Framebuffer) binary protocol handshake |
| [`port-scanner-async.rs`](templates/rust/port-scanner-async.rs) | Rust | High-speed async TCP port scanning with service detection |

### ☁️ Cloud & Container Security

| Template | Language | Capability |
|----------|----------|------------|
| [`docker-api-unauth.go`](templates/go/docker-api-unauth.go) | Go | Docker Engine API access + container enumeration |
| [`k8s-etcd-exposed.go`](templates/go/k8s-etcd-exposed.go) | Go | Kubernetes etcd key-value extraction |
| [`jenkins-unauth-rce.go`](templates/go/jenkins-unauth-rce.go) | Go | Jenkins Script Console command execution |
| [`jupyter-unauth-rce.py`](templates/python/jupyter-unauth-rce.py) | Python | Jupyter Notebook kernel code execution |


## 📂 Template Categories

<table>
<tr>
<td>

### Databases
- Redis unauthenticated access
- MongoDB unauthenticated access  
- MySQL default credentials
- PostgreSQL default credentials
- Elasticsearch data exposure
- CouchDB default credentials
- Memcached unauthenticated
- Zookeeper unauthenticated

</td>
<td>

### DevOps & CI/CD
- Jenkins Script Console RCE
- Jupyter Notebook RCE
- Docker API unauthenticated
- Kubernetes API exposed
- etcd key exposure
- Prometheus metrics exposed
- Kafka unauthenticated

</td>
<td>

### Network Services
- SMTP open relay
- FTP anonymous access
- SNMP default community
- VNC no authentication
- RabbitMQ default creds

</td>
</tr>
<tr>
<td>

### Web Vulnerabilities
- SQL injection detection
- XSS detection
- Directory traversal
- Authentication bypass

</td>
<td>

### Cloud Exporters
- Prometheus exporters
- Node exporter exposed
- Redis exporter exposed
- MySQL exporter exposed

</td>
<td>

### Reconnaissance
- Port scanning
- Service detection
- System context recon

</td>
</tr>
</table>


## 📖 Documentation

Please refer to the [CERT-X-GEN documentation](https://github.com/Bugb-Technologies/cert-x-gen) for detailed guides on:

- **Writing Templates** — Create custom security checks in any supported language
- **Template Specification** — Required metadata, output format, environment variables
- **Language Guides** — Best practices for Python, Go, C, Rust, Shell, and YAML templates

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
2. **Create** your template in the appropriate language directory
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

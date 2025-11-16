# CERT-X-GEN Templates

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](VERSION)
[![Templates](https://img.shields.io/badge/templates-200+-orange.svg)](TEMPLATE_REGISTRY.json)
[![Languages](https://img.shields.io/badge/languages-12-purple.svg)](#supported-languages)

Official security scanning templates for [CERT-X-GEN](https://github.com/BugB-Tech/cert-x-gen-cli-v2) - A next-generation polyglot security scanning engine.

## 🚀 Quick Start

### Using with CERT-X-GEN CLI

```bash
# Install CERT-X-GEN CLI first
# See: https://github.com/BugB-Tech/cert-x-gen-cli-v2

# Templates are automatically downloaded on first run
cert-x-gen template update

# List available templates
cert-x-gen template list

# Run a scan with templates
cert-x-gen scan --target example.com
```

### Manual Installation

```bash
# Clone this repository
git clone https://github.com/BugB-Tech/cert-x-gen-templates.git

# Use with CERT-X-GEN
cert-x-gen scan --template-dir ./cert-x-gen-templates --target example.com
```

## 📚 What's Inside

This repository contains **200+ security scanning templates** across:

- **Network Services:** Redis, Memcached, MongoDB, MySQL, PostgreSQL, Elasticsearch, etc.
- **Web Applications:** SQL Injection, XSS, SSRF, Authentication bypass, etc.
- **Cloud Services:** S3 buckets, Azure storage, GCP misconfigurations
- **CVEs:** Latest CVE templates for known vulnerabilities
- **Misconfigurations:** Default credentials, open ports, exposed services

## 🛠️ Supported Languages

Templates can be written in **12 programming languages**:

### Interpreted Languages
- 🐍 **Python** - Rich ecosystem, fast development
- 🟨 **JavaScript** (Node.js) - Async operations, web testing
- 💎 **Ruby** - Elegant syntax, great for scripting
- 🐪 **Perl** - Text processing, legacy systems
- 🐘 **PHP** - Web-focused testing
- 🐚 **Shell** - System-level checks

### Compiled Languages
- 🦀 **Rust** - High performance, memory safe
- ⚙️ **C** - Maximum performance, low-level access
- ➕ **C++** - OOP with performance
- ☕ **Java** - Enterprise environment testing
- 🔷 **Go** - Concurrent operations, networking

### Declarative
- 📄 **YAML** - Simple, human-readable templates

## 📂 Repository Structure

```
templates/
├── yaml/           # YAML templates (recommended for beginners)
│   ├── http/       # Web application checks
│   └── network/    # Network service checks
├── python/         # Python templates
├── javascript/     # JavaScript templates
├── rust/           # Rust templates
├── c/              # C templates
├── shell/          # Shell script templates
└── ...             # Other languages
```

## 📖 Documentation

- **[Template Guide](docs/TEMPLATE_GUIDE.md)** - How to write templates
- **[Template Specification](docs/TEMPLATE_SPEC.md)** - Format reference
- **[Language Guides](docs/LANGUAGES.md)** - Language-specific examples
- **[Examples](docs/EXAMPLES.md)** - Annotated template examples

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Guide

1. Fork this repository
2. Create a new branch: `git checkout -b feature/new-template`
3. Add your template in the appropriate language directory
4. Validate: `./scripts/validate.sh your-template.yaml`
5. Commit: `git commit -m "Add template for XYZ vulnerability"`
6. Push: `git push origin feature/new-template`
7. Open a Pull Request

## 🔒 Security

Found a security vulnerability in a template? Please report it privately to security@bugb.tech or see [SECURITY.md](SECURITY.md).

## 📊 Template Statistics

| Category | Count | Status |
|----------|-------|--------|
| Network Services | 45 | ✅ Stable |
| Web Vulnerabilities | 78 | ✅ Stable |
| CVE Templates | 52 | 🔄 Updated Weekly |
| Cloud Checks | 18 | 🆕 New |
| Misconfigurations | 12 | ✅ Stable |

**Total:** 205 templates across 12 languages

## 📝 License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=BugB-Tech/cert-x-gen-templates&type=Date)](https://star-history.com/#BugB-Tech/cert-x-gen-templates&Date)


## 📞 Support

- **Documentation:** [docs.cert-x-gen.com](https://docs.cert-x-gen.com)
- **Discord:** [Join our community](https://discord.gg/cert-x-gen)
- **Issues:** [GitHub Issues](https://github.com/BugB-Tech/cert-x-gen-templates/issues)
- **Email:** support@bugb.tech

## 🙏 Acknowledgments

Templates contributed by the security community. See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the full list.

---

[![GitHub Stars](https://img.shields.io/github/stars/BugB-Tech/cert-x-gen-templates?style=social)](https://github.com/BugB-Tech/cert-x-gen-templates/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/BugB-Tech/cert-x-gen-templates?style=social)](https://github.com/BugB-Tech/cert-x-gen-templates/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/BugB-Tech/cert-x-gen-templates)](https://github.com/BugB-Tech/cert-x-gen-templates/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/BugB-Tech/cert-x-gen-templates)](https://github.com/BugB-Tech/cert-x-gen-templates/pulls)
[![CI](https://github.com/BugB-Tech/cert-x-gen-templates/workflows/Validate%20Templates/badge.svg)](https://github.com/BugB-Tech/cert-x-gen-templates/actions)

**Made with ❤️ by the BugB-Tech team and contributors**
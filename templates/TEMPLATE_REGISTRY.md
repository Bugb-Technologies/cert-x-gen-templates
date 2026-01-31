# CERT-X-GEN Template Registry

This document provides a registry of all available templates organized by purpose-based folders.

## Template Categories

### 1. AI / LLM Services
- **Ollama Unauthenticated /api/generate Access** (`ai/ollama/detect-unauthenticated-access-apigenerate.yaml`)
- **Ollama Unauthorized /api/pull Access (CVE-2024-37032)** (`ai/ollama/apipull-access-sending-post.yaml`)
- **Ollama Exposed Endpoint Detection** (`ai/ollama/detect-exposed-ollama-sending.yaml`)
- **Ollama Detection** (`ai/ollama/detect_ollama.yaml`)

### 2. Databases
- **Redis Unauthenticated (multi-language)**
  - `databases/redis/redis-unauthenticated.c`
  - `databases/redis/redis-unauthenticated.cpp`
  - `databases/redis/redis-unauthenticated.go`
  - `databases/redis/redis-unauthenticated.js`
  - `databases/redis/redis-unauthenticated.php`
  - `databases/redis/redis-unauthenticated.pl`
  - `databases/redis/redis-unauthenticated.py`
  - `databases/redis/redis-unauthenticated.rb`
  - `databases/redis/redis-unauthenticated.rs`
  - `databases/redis/redis-unauthenticated.sh`
  - `databases/redis/redis-unauthenticated.yaml`
  - `databases/redis/RedisUnauthenticated.java`
- **MySQL Default Credentials** (`databases/mysql/mysql-default-credentials.py`)
- **PostgreSQL Default Credentials** (`databases/postgresql/postgresql-default-credentials.go`)
- **MongoDB Unauthenticated** (`databases/mongodb/mongodb-unauthenticated.py`)
- **Elasticsearch Unauthenticated** (`databases/elasticsearch/elasticsearch_unauthenticated.rs`)
- **Elasticsearch Data Exposure** (`databases/elasticsearch/elasticsearch-data-exposure.py`)
- **CouchDB Default Credentials** (`databases/couchdb/couchdb_default_creds.rs`)
- **CockroachDB Unauthenticated** (`databases/cockroachdb/cockroachdb-unauthenticated.yaml`)
- **Memcached Unauthenticated** (`databases/memcached/memcached-unauthenticated.yaml`)

### 3. DevOps / Platform
- **Docker API Unauthenticated** (`devops/docker/docker-api-unauth.go`)
- **Docker Registry Unauthenticated** (`devops/docker/docker-registry-unauthenticated.sh`)
- **Etcd Unauthenticated (shell)** (`devops/etcd/etcd-unauthenticated.sh`)
- **Etcd Unauthenticated (HTTP checks)**
  - `devops/etcd/think-wrong-able-validate.yaml`
  - `devops/etcd/etcd-instead-http-request.yaml`
  - `devops/etcd/etcd-think-path-wrong.yaml`
  - `devops/etcd/new-etcd-vulnerable-unauthenticated.yaml`
  - `devops/etcd/which-runs-etcdctl-command.yaml`
- **Etcd Unauthenticated Port Check** (`devops/etcd/etcd-running-unauthenticated-port.sh`)
- **K8s Etcd Exposed** (`devops/etcd/k8s-etcd-exposed.go`)
- **Jenkins Unauthenticated RCE** (`devops/jenkins/jenkins-unauth-rce.go`)
- **Kubernetes API Unauthenticated** (`devops/kubernetes/kubernetes-api-unauthenticated-default.yaml`)
- **Jupyter Unauthenticated RCE** (`devops/jupyter/jupyter-unauth-rce.py`)

### 4. Monitoring & Observability
- **Prometheus Server Exposed**
  - `monitoring/prometheus/prometheus-server-exposed.py`
  - `monitoring/prometheus/prometheus-server-exposed.js`
  - `monitoring/prometheus/prometheus-server-exposed-https.py`
- **cAdvisor Exposed**
  - `monitoring/cadvisor/cadvisor-exposed.py`
  - `monitoring/cadvisor/cadvisor-exposed.js`
- **Metrics Endpoint Exposure** (`monitoring/metrics/which-checks-metrics-available.yaml`)
- **Exporters**
  - Redis Exporter Exposed: `monitoring/exporters/redis/redis-exporter-exposed.py`, `monitoring/exporters/redis/redis-exporter-exposed.yaml`
  - MySQL Exporter Exposed: `monitoring/exporters/mysql/mysql-exporter-exposed.py`
  - PostgreSQL Exporter Exposed: `monitoring/exporters/postgresql/postgresql-exporter-exposed.py`
  - Node Exporter Exposed: `monitoring/exporters/node/node-exporter-exposed.py`, `monitoring/exporters/node/node-exporter-exposed.js`, `monitoring/exporters/node/prometheus-node-exporter-exposed.yaml`

### 5. Messaging
- **RabbitMQ Default Credentials** (`messaging/rabbitmq/rabbitmq-default-credentials.py`)
- **Kafka Unauthenticated** (`messaging/kafka/kafka-unauthenticated.sh`)
- **Zookeeper Unauthenticated** (`messaging/zookeeper/zookeeper-unauthenticated.yaml`)

### 6. Network Services
- **FTP Anonymous Access** (`network/ftp/ftp-anonymous-access.py`)
- **SMTP Open Relay** (`network/smtp/smtp-open-relay.py`)
- **SNMP Default Community** (`network/snmp/snmp-default-community.sh`)
- **VNC No Auth** (`network/vnc/vnc-no-auth.c`)
- **Port Scanner (Async)** (`network/scanning/port-scanner-async.rs`)
- **DNS Zone Transfer** (`network/dns/dns-zone-transfer.py`)

### 7. Web Application Security
- **SQL Injection Detection** (`web/injection/sql-injection-detection.c`, `web/injection/sql-injection-detection.yaml`)
- **Blind SQL Injection (Time-Based)** (`web/injection/timing-attack-detection.yaml`)
- **Response Manipulation / Cache Poisoning** (`web/cache/response-manipulation-detection.yaml`)
- **XSS Detection** (`web/xss/xss-detection.c`)
- **Directory Traversal** (`web/traversal/directory-traversal.c`)
- **Auth Bypass Flow** (`web/auth-bypass/auth-bypass-flow.yaml`)
- **Sensitive Data Exposure** (`web/sensitive-data/sensitive-data-exposure.yaml`)
- **HTTP Detection Examples** (`web/http/http-detection.yaml`, `web/http/example-http-check.yaml`)
- **Log4Shell Check** (`web/log4shell/are-vulnerable-log4shell.sh`)

### 8. Reconnaissance
- **System Context Recon** (`recon/system/system-context-recon.sh`)

## Template Execution

### Running All Templates
```bash
# Test all templates across all languages
./test-all-templates.sh

# Test with specific target
./test-all-templates.sh -t 192.168.1.100 -p 8080

# Verbose output
./test-all-templates.sh -v

# JSON output
./test-all-templates.sh -j
```

### Running Templates by Language
```bash
# C templates only
cert-x-gen scan --target example.com --template-language c

# Go templates only
cert-x-gen scan --target example.com --template-language go

# Python templates only
cert-x-gen scan --target example.com --template-language python

# Multiple languages
cert-x-gen scan --target example.com --template-language c,go,python
```

### Running Templates by Category
```bash
# Database services
cert-x-gen scan --target example.com --tags database

# Web vulnerabilities
cert-x-gen scan --target example.com --tags injection

# Cloud services
cert-x-gen scan --target example.com --tags cloud

# Container services
cert-x-gen scan --target example.com --tags container
```

## Template Development

### Skeleton Templates
Each language has a skeleton template in `templates/skeleton/`:
- `c-template-skeleton.c`
- `cpp-template-skeleton.cpp`
- `java-template-skeleton.java`
- `go-template-skeleton.go`
- `python-template-skeleton.py`
- `javascript-template-skeleton.js`
- `rust-template-skeleton.rs`
- `shell-template-skeleton.sh`
- `ruby-template-skeleton.rb`
- `perl-template-skeleton.pl`
- `php-template-skeleton.php`
- `yaml-template-skeleton.yaml`

### Template Structure
All templates follow the same structure:
1. **Metadata**: Template ID, name, author, severity, tags, CWE
2. **Environment Variables**: CERT_X_GEN_* variables for configuration
3. **Port Configuration**: Support for ADD_PORTS and OVERRIDE_PORTS
4. **HTTP Requests**: Service-specific testing logic
5. **JSON Output**: Standardized finding format
6. **Error Handling**: Graceful failure handling

### Adding New Templates
1. Choose appropriate language based on service type
2. Copy skeleton template
3. Implement service-specific logic
4. Add to appropriate purpose-based category directory
5. Update this registry
6. Test with `test-all-templates.sh`

## Quality Assurance

### Testing
- All templates are tested with `test-all-templates.sh`
- Compilation testing for compiled languages
- Runtime testing for all languages
- JSON output validation
- Error handling verification

### Validation
- Template metadata validation
- Port configuration testing
- Environment variable handling
- Output format compliance
- Performance testing

### Maintenance
- Regular template updates
- Security patch testing
- Performance optimization
- Documentation updates
- Community contributions

## Contributing

1. Fork the repository
2. Create feature branch
3. Add new templates following the structure
4. Test with `test-all-templates.sh`
5. Update documentation
6. Submit pull request

## Support

For questions or issues:
- Check existing templates for examples
- Review skeleton templates
- Test with `test-all-templates.sh`
- Submit issues on GitHub
- Join the community discussions

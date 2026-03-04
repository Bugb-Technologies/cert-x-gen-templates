# CERT-X-GEN Template Registry

This document provides a complete registry of all available templates organized by purpose-based categories.

> **Total templates:** 147 | **Languages:** 12 | **Categories:** 9
>
> **Playbooks & learning content:** Published on the [BugB Blog](https://bugb.io/blogs)

---

## 1. AI / LLM Security (`ai/`)

### Ollama
- **Ollama Unauthenticated /api/generate Access** — `ai/ollama/detect-unauthenticated-access-apigenerate.yaml`
- **Ollama Unauthorized /api/pull Access (CVE-2024-37032)** — `ai/ollama/apipull-access-sending-post.yaml`
- **Ollama Exposed Endpoint Detection** — `ai/ollama/detect-exposed-ollama-sending.yaml`
- **Ollama Detection** — `ai/ollama/detect_ollama.yaml`

### Flowise
- **Flowise CustomMCP Command Endpoint Exposed** — `ai/flowise/flowise-custommcp-command-endpoint-exposed.yaml`
- **Flowise CustomMCP JS Eval Exposed** — `ai/flowise/flowise-custommcp-js-eval-exposed.yaml`

### ML / Model Security
- **Torch Unsafe Load Usage** — `ai/ml/torch-unsafe-load-usage.py`
- **Unsafe Deserialization Usage** — `ai/ml/unsafe-deserialization-usage.py`
- **AI-Assisted Fuzzing SQLi Seed Corpus** — `ai/ai-assisted-fuzzing/ai-assisted-fuzzing-sqli-seed-corpus.py`

### Model Serving
- **TorchServe Management API Exposed** — `ai/torchserve/torchserve-management-api-exposed.yaml`
- **Triton Model Control Exposed** — `ai/triton/triton-model-control-exposed.yaml`
- **InvokeAI Model Install Exposed** — `ai/invokeai/invokeai-model-install-exposed.yaml`

### AI IDE / Agent Security
- **Claude Code sed Bypass Usage (CVE-2025-64755)** — `ai/claude/claude-code-sed-bypass-usage.py`
- **Copilot YOLO AutoApprove Enabled** — `ai/copilot/copilot-yolo-autoapprove-enabled.py`
- **Cursor MCP Poisoning Config Risk** — `ai/cursor/cursor-mcpoison-config-risk.py`

---

## 2. Databases (`databases/`)

### Redis (Polyglot — 12 languages)
- `databases/redis/redis-unauthenticated.py`
- `databases/redis/redis-unauthenticated.go`
- `databases/redis/redis-unauthenticated.rs`
- `databases/redis/redis-unauthenticated.js`
- `databases/redis/redis-unauthenticated.c`
- `databases/redis/redis-unauthenticated.cpp`
- `databases/redis/RedisUnauthenticated.java`
- `databases/redis/redis-unauthenticated.rb`
- `databases/redis/redis-unauthenticated.pl`
- `databases/redis/redis-unauthenticated.php`
- `databases/redis/redis-unauthenticated.sh`
- `databases/redis/redis-unauthenticated.yaml`
- **Redis Cluster Takeover** — `databases/redis/redis-cluster-takeover.go`

### MySQL
- **MySQL Default Credentials** — `databases/mysql/mysql-default-credentials.py`

### PostgreSQL
- **PostgreSQL Default Credentials** — `databases/postgresql/postgresql-default-credentials.go`
- **PostgreSQL Extension RCE** — `databases/postgresql/postgresql-extension-rce.py`

### MongoDB
- **MongoDB Unauthenticated** — `databases/mongodb/mongodb-unauthenticated.py`
- **MongoDB Injection Deep** — `databases/mongodb/mongodb-injection-deep.py`

### Elasticsearch
- **Elasticsearch Unauthenticated** — `databases/elasticsearch/elasticsearch_unauthenticated.rs`
- **Elasticsearch Data Exposure** — `databases/elasticsearch/elasticsearch-data-exposure.py`
- **Elasticsearch Query Injection** — `databases/elasticsearch/elasticsearch-query-injection.py`

### ClickHouse
- **ClickHouse Auth Bypass** — `databases/clickhouse/clickhouse-auth-bypass.py`

### CouchDB
- **CouchDB Default Credentials** — `databases/couchdb/couchdb_default_creds.rs`

### CockroachDB
- **CockroachDB Unauthenticated** — `databases/cockroachdb/cockroachdb-unauthenticated.yaml`

### Memcached
- **Memcached Unauthenticated** — `databases/memcached/memcached-unauthenticated.yaml`

### InfluxDB
- **InfluxDB Health Exposed** — `databases/influxdb/influxdb-health-exposed.yaml`

---

## 3. DevOps / Platform (`devops/`)

### Docker
- **Docker API Unauthenticated** — `devops/docker/docker-api-unauth.go`
- **Docker Registry Unauthenticated** — `devops/docker/docker-registry-unauthenticated.sh`

### Etcd
- **Etcd Unauthenticated (Shell)** — `devops/etcd/etcd-unauthenticated.sh`
- **Etcd Unauthenticated Port Check** — `devops/etcd/etcd-running-unauthenticated-port.sh`
- **K8s Etcd Exposed** — `devops/etcd/k8s-etcd-exposed.go`
- **Etcd HTTP Checks** — `devops/etcd/etcd-instead-http-request.yaml`, `devops/etcd/etcd-think-path-wrong.yaml`, `devops/etcd/new-etcd-vulnerable-unauthenticated.yaml`, `devops/etcd/think-wrong-able-validate.yaml`, `devops/etcd/which-runs-etcdctl-command.yaml`

### Jenkins
- **Jenkins Unauthenticated RCE** — `devops/jenkins/jenkins-unauth-rce.go`

### Jupyter
- **Jupyter Unauthenticated RCE** — `devops/jupyter/jupyter-unauth-rce.py`

### Kubernetes
- **Kubernetes API Unauthenticated** — `devops/kubernetes/kubernetes-api-unauthenticated-default.yaml`
- **K8s RBAC Misconfiguration** — `devops/kubernetes/k8s-rbac-misconfiguration.go`
- **Kubelet API Exposure** — `devops/kubernetes/kubelet-api-exposure.go`
- **Service Account Token Abuse** — `devops/kubernetes/service-account-token-abuse.go`
- **Helm Chart Secrets Leak** — `devops/kubernetes/helm-chart-secrets-leak.py`

### GitHub / GitHub Enterprise
- **GHES Version Fingerprint** — `devops/github/ghes-version-fingerprint.py`
- **Actions Injection Scanner** — `devops/github/actions-injection-scanner.py`
- **Pwn Request Scanner** — `devops/github/pwn-request-scanner.py`
- **Runner Token Detection** — `devops/github/runner-token-detection.go`

### GitLab
- **GitLab Version Fingerprint** — `devops/gitlab/gitlab-version-fingerprint.py`
- **SAML SSO Bypass GitLab** — `devops/gitlab/saml-sso-bypass-gitlab.py`

### Git
- **Git History Secret Scan** — `devops/git/git-history-secret-scan.go`

### Istio
- **Istio Pilot Misconfiguration** — `devops/istio/istio-pilot-misconfiguration.go`

### CI/CD
- **CI Variable Exposure** — `devops/ci/ci-variable-exposure.py`

---

## 4. Messaging (`messaging/`)

### RabbitMQ
- **RabbitMQ Default Credentials** — `messaging/rabbitmq/rabbitmq-default-credentials.py`
- **RabbitMQ Management Exposed** — `messaging/rabbitmq/rabbitmq-management-exposed.yaml`

### Kafka
- **Kafka Unauthenticated** — `messaging/kafka/kafka-unauthenticated.sh`
- **Kafka Unauthenticated Access** — `messaging/kafka/kafka-unauthenticated-access.py`

### ZooKeeper
- **ZooKeeper Unauthenticated** — `messaging/zookeeper/zookeeper-unauthenticated.yaml`

### MQTT
- **MQTT Unauthenticated** — `messaging/mqtt/mqtt-unauthenticated.yaml`

### NATS
- **NATS Unauthenticated Banner** — `messaging/nats/nats-unauthenticated-banner.yaml`

---

## 5. Monitoring & Observability (`monitoring/`)

### Prometheus
- **Prometheus Server Exposed** — `monitoring/prometheus/prometheus-server-exposed.py`
- **Prometheus Server Exposed (JS)** — `monitoring/prometheus/prometheus-server-exposed.js`
- **Prometheus Server Exposed HTTPS** — `monitoring/prometheus/prometheus-server-exposed-https.py`

### cAdvisor
- **cAdvisor Exposed (Python)** — `monitoring/cadvisor/cadvisor-exposed.py`
- **cAdvisor Exposed (JS)** — `monitoring/cadvisor/cadvisor-exposed.js`

### Exporters
- **Redis Exporter Exposed** — `monitoring/exporters/redis/redis-exporter-exposed.py`, `monitoring/exporters/redis/redis-exporter-exposed.yaml`
- **MySQL Exporter Exposed** — `monitoring/exporters/mysql/mysql-exporter-exposed.py`
- **PostgreSQL Exporter Exposed** — `monitoring/exporters/postgresql/postgresql-exporter-exposed.py`
- **Node Exporter Exposed** — `monitoring/exporters/node/node-exporter-exposed.py`, `monitoring/exporters/node/node-exporter-exposed.js`, `monitoring/exporters/node/prometheus-node-exporter-exposed.yaml`

### Metrics
- **Metrics Endpoint Exposure** — `monitoring/metrics/which-checks-metrics-available.yaml`

### Kibana
- **Kibana API Status Exposed** — `monitoring/kibana/kibana-api-status-exposed.yaml`

### Splunk
- **Splunk Web Login Exposed** — `monitoring/splunk/splunk-web-login-exposed.yaml`
- **Splunkd Server Info Exposed** — `monitoring/splunk/splunkd-server-info-exposed.yaml`

---

## 6. Network Services (`network/`)

### DNS
- **DNS Zone Transfer** — `network/dns/dns-zone-transfer.py`
- **DNS UDP Service Probe** — `network/dns/dns-udp-service-probe.py`
- **DNS Rebinding Attack** — `network/dns/dns-rebinding-attack.go`

### FTP
- **FTP Anonymous Access** — `network/ftp/ftp-anonymous-access.py`

### SMTP
- **SMTP Open Relay** — `network/smtp/smtp-open-relay.py`

### SNMP
- **SNMP Default Community** — `network/snmp/snmp-default-community.sh`

### VNC
- **VNC No Auth** — `network/vnc/vnc-no-auth.c`

### gRPC
- **gRPC Reflection Abuse** — `network/grpc/grpc-reflection-abuse.go`

### RMI
- **RMI Service Enumeration** — `network/rmi/RmiServiceEnumeration.java`

### TLS
- **TLS Certificate Deep Analysis** — `network/tls/src/main.rs`

### WebSocket
- **WebSocket Message Fuzzer** — `network/websocket/websocket-message-fuzzer.js`

### Scanning & Recon
- **Port Scanner (Async)** — `network/scanning/port-scanner-async.rs`
- **TCP Banner Probe** — `network/scanning/tcp-banner-probe.py`
- **TCP Port Reachability** — `network/scanning/tcp-port-reachability.py`
- **ICMP Echo Reachable** — `network/recon/icmp-echo-reachable.py`

### Service Probes (YAML)
- **ADB Exposed** — `network/adb/adb-exposed.yaml`
- **Cisco Smart Install Exposed** — `network/cisco/smart-install-exposed.yaml`
- **Echo Service Exposed** — `network/echo/echo-service-exposed.yaml`
- **EPMD Node List Exposed** — `network/epmd/epmd-node-list-exposed.yaml`
- **Finger Service Exposed** — `network/finger/finger-service-exposed.yaml`
- **HTTP Service Responding** — `network/http/http-service-responding.yaml`
- **Ident Exposed** — `network/ident/ident-exposed.yaml`
- **NDMP Service Exposed** — `network/ndmp/ndmp-service-exposed.yaml`
- **rsync Banner Exposed** — `network/rsync/rsync-banner-exposed.yaml`
- **SOCKS5 No Auth** — `network/socks/socks5-no-auth.yaml`
- **TACACS Service Exposed** — `network/tacacs/tacacs-service-exposed.yaml`
- **TFTP Service Exposed** — `network/tftp/tftp-service-exposed.yaml`
- **Whois Service Exposed** — `network/whois/whois-service-exposed.yaml`

### UDP Service Probes (Python)
- **DHCPv6 Solicit Response** — `network/dhcpv6/dhcpv6-solicit-response.py`
- **mDNS Service Discovery Probe** — `network/mdns/mdns-service-discovery-probe.py`
- **NBNS Name Query Probe** — `network/nbns/nbns-name-query-probe.py`
- **NTP UDP Service Probe** — `network/ntp/ntp-udp-service-probe.py`
- **SSDP M-SEARCH Response** — `network/ssdp/ssdp-msearch-response.py`
- **WSD Probe Response** — `network/wsd/wsd-probe-response.py`

---

## 7. Web Application (`web/`)

### Authentication
- **Auth Bypass Flow** — `web/auth-bypass/auth-bypass-flow.yaml`
- **Password Reset Takeover** — `web/auth-bypass/password-reset-takeover.py`

### Injection
- **SQL Injection Detection (C)** — `web/injection/sql-injection-detection.c`
- **SQL Injection Detection (YAML)** — `web/injection/sql-injection-detection.yaml`
- **Timing Attack Detection** — `web/injection/timing-attack-detection.yaml`
- **HTTP Header Injection** — `web/injection/http-header-injection.py`
- **Prototype Pollution** — `web/injection/prototype-pollution.js`
- **Server-Side JS Injection** — `web/injection/server-side-js-injection.js`
- **SSTI Engine Fingerprint** — `web/injection/ssti-engine-fingerprint.py`
- **Spring4Shell Detection** — `web/injection/Spring4ShellDetection.java`

### Deserialization
- **Deserialization Gadget Scan** — `web/deserialization/DeserializationGadgetScan.java`

### GraphQL
- **GraphQL User Enumeration** — `web/graphql/graphql-user-enumeration.py`

### HTTP
- **HTTP Detection** — `web/http/http-detection.yaml`
- **Example HTTP Check** — `web/http/example-http-check.yaml`
- **HTTP/2 Rapid Reset** — `web/http/http2-rapid-reset.go`

### Other Web
- **XSS Detection** — `web/xss/xss-detection.c`
- **Directory Traversal** — `web/traversal/directory-traversal.c`
- **Directory Listing Common Paths** — `web/directory-listing/directory-listing-common-paths.yaml`
- **Sensitive Data Exposure** — `web/sensitive-data/sensitive-data-exposure.yaml`
- **Response Manipulation Detection** — `web/cache/response-manipulation-detection.yaml`
- **Log4Shell Detection** — `web/log4shell/are-vulnerable-log4shell.sh`
- **Race Condition Exploit** — `web/race-condition/race-condition-exploit.go`

---

## 8. Recon (`recon/`)

- **System Context Recon** — `recon/system/system-context-recon.sh`

---

## 9. Skeleton Templates (`skeleton/`)

Boilerplate templates and AI-assisted authoring notes for all 12 supported languages:

| Language | Skeleton | AI Notes |
|---|---|---|
| C | `skeleton/c-template-skeleton.c` | `skeleton/c-template-ai-notes.md` |
| C++ | `skeleton/cpp-template-skeleton.cpp` | `skeleton/cpp-template-ai-notes.md` |
| Go | `skeleton/go-template-skeleton.go` | `skeleton/go-template-ai-notes.md` |
| Java | `skeleton/java-template-skeleton.java` | `skeleton/java-template-ai-notes.md` |
| JavaScript | `skeleton/javascript-template-skeleton.js` | `skeleton/javascript-template-ai-notes.md` |
| Perl | `skeleton/perl-template-skeleton.pl` | `skeleton/perl-template-ai-notes.md` |
| PHP | `skeleton/php-template-skeleton.php` | `skeleton/php-template-ai-notes.md` |
| Python | `skeleton/python-template-skeleton.py` | `skeleton/python-template-ai-notes.md` |
| Ruby | `skeleton/ruby-template-skeleton.rb` | `skeleton/ruby-template-ai-notes.md` |
| Rust | `skeleton/rust-template-skeleton.rs` | `skeleton/rust-template-ai-notes.md` |
| Shell | `skeleton/shell-template-skeleton.sh` | `skeleton/shell-template-ai-notes.md` |
| YAML | `skeleton/yaml-template-skeleton.yaml` | `skeleton/yaml-template-ai-notes.md` |

---

## Playbooks & Learning Content

Detailed security assessment playbooks, walkthroughs, and learning content for templates are published on the **[BugB Blog](https://bugb.io/blogs)**.

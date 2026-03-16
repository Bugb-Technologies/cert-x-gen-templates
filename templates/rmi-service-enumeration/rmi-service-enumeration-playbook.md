# RMI Service Enumeration

<div align="center">

![CERT-X-GEN](https://img.shields.io/badge/CERT--X--GEN-Playbook-blue?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-High-orange?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Java-red?style=for-the-badge)
![CVSS](https://img.shields.io/badge/CVSS-8.1-high?style=for-the-badge)

**Detecting exposed Java RMI registries and enumerating bound services via native protocol**

*Why YAML scanners miss this entirely and how CERT-X-GEN's Java template nails it*

</div>

---

## 📖 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Understanding the Vulnerability](#understanding-the-vulnerability)
3. [Why Traditional Scanners Fail](#why-traditional-scanners-fail)
4. [The CERT-X-GEN Approach](#the-cert-x-gen-approach)
5. [Attack Flow Visualization](#attack-flow-visualization)
6. [Template Deep Dive](#template-deep-dive)
7. [Usage Guide](#usage-guide)
8. [Real-World Test Results](#real-world-test-results)
9. [Defense & Remediation](#defense--remediation)
10. [Extending the Template](#extending-the-template)
11. [References](#references)

---

## Executive Summary

Java RMI (Remote Method Invocation) is a native Java protocol enabling distributed object communication. When an RMI registry is exposed to untrusted networks without authentication, any client can call `registry.list()` to enumerate all bound service names — revealing internal service topology and providing a direct attack surface for Java deserialization exploits via ysoserial gadget chains.

**The result?** An attacker can map an organization's internal Java service architecture, identify high-value targets (JMX connectors, EJB services, custom business logic), and deliver serialized payloads through the RMI stub invocation path — all without credentials.

> 💡 **Key Insight**: RMI speaks a binary Java serialization protocol. You cannot detect it with HTTP matchers or regex patterns. You need a JVM. CERT-X-GEN's Java templates speak the same language as the target.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 8.1 (High) |
| **CWE** | CWE-306 (Missing Authentication), CWE-502 (Deserialization) |
| **Default Port** | 1099 (also 1098, 2099, 9010) |
| **Protocol** | Java RMI / Java Object Serialization |
| **Detection Complexity** | High (requires JVM + RMI protocol knowledge) |
| **Attack Potential** | Pre-condition for ysoserial RCE chains |

---

## Understanding the Vulnerability

### How Java RMI Works

RMI allows Java objects to invoke methods on remote objects as if they were local. The **RMI Registry** acts as a naming service — services bind themselves under a name, and clients look them up.

```
┌─────────────────────────────────────────────────────────────────┐
│                     JAVA RMI ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  RMI Registry (port 1099)                                        │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  "HelloService"       → stub → HelloServiceImpl         │    │
│  │  "InternalDataService"→ stub → InternalDataServiceImpl  │    │
│  │  "JMXConnector"       → stub → RMIConnectorServer       │    │
│  └─────────────────────────────────────────────────────────┘    │
│          ↑ list() returns all bound names                        │
│          ↑ lookup("name") returns serialized stub                │
│                                                                  │
│  Client ──────────────► registry.list()    → ["HelloService"...] │
│  Client ──────────────► registry.lookup()  → RemoteStub (serial) │
│  Attacker ─────────────► stub.method(payload) → RCE via deser   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### The Attack Chain

An exposed RMI registry is dangerous in two distinct ways:

**1. Information Disclosure** — `list()` reveals internal service names, which often encode technology stack, versions, and architecture patterns (e.g., `jmxrmi`, `RMI_SERVER`, `EJBFactory_v2`).

**2. Deserialization Attack Surface** — RMI stubs accept serialized Java objects. Combined with a ysoserial gadget chain (Commons Collections, Spring, etc.), an attacker can achieve Remote Code Execution by sending a malicious serialized object through the stub invocation path.

```
┌─────────────────────────────────────────────────────────────────┐
│                    DESERIALIZATION ATTACK PATH                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Attacker calls registry.list()                               │
│             → discovers "DataProcessor" service                  │
│                                                                  │
│  2. Attacker calls registry.lookup("DataProcessor")              │
│             → receives serialized RemoteStub                     │
│                                                                  │
│  3. Attacker crafts ysoserial payload (e.g. CommonsCollections1) │
│             → java -jar ysoserial.jar CommonsCollections1 "cmd"  │
│                                                                  │
│  4. Attacker invokes stub method with malicious payload          │
│             → JVM deserializes object → RCE 💥                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### DGC: The Hidden Attack Surface

Every RMI registry also exposes a **Distributed Garbage Collector (DGC)** endpoint on the same port. The DGC `dirty()` and `clean()` methods accept serialized `Lease` and `ObjID` objects — making them a classic ysoserial delivery vector that requires **zero knowledge of registered service names**.

---

## Why Traditional Scanners Fail

### The YAML Limitation

YAML-based scanners communicate over HTTP. Java RMI speaks an entirely different binary protocol:

```
# What a YAML scanner sees on port 1099:
GET / HTTP/1.1
Host: target:1099

# Response: Connection reset / garbage bytes
# Result: ❌ Cannot detect anything
```

| Capability | YAML/HTTP Scanner | CERT-X-GEN Java |
|------------|-------------------|-----------------|
| Connect to RMI port | ❌ Protocol mismatch | ✅ Native socket |
| Send JRMI handshake | ❌ Impossible | ✅ Raw bytes |
| Call `registry.list()` | ❌ Impossible | ✅ JDK `LocateRegistry` |
| Parse serialized response | ❌ Impossible | ✅ Native Java |
| Probe DGC endpoint | ❌ Impossible | ✅ Binary probe |
| Enumerate service names | ❌ | ✅ |
| **Confidence Level** | 0% | **95%** |

---

## The CERT-X-GEN Approach

The template uses a four-phase detection strategy combining raw socket probes for fingerprinting and JDK RMI APIs for reliable service enumeration.

### Detection Strategy

```
┌──────────────────────────────────────────────────────────────────┐
│                    CERT-X-GEN DETECTION FLOW                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Phase 1: TCP Probe                                               │
│  Scanner ──────► connect(host, 1099)                             │
│     │  success? → continue   failure? → scan alt ports           │
│     ▼                                                            │
│  Phase 2: RMI Handshake Fingerprint                              │
│  Scanner ──────► send JRMI header (raw socket)                   │
│     │  0x4e ProtocolAck? → confirmed RMI registry                │
│     │  0xaced? → Java serialization stream (old registry/DGC)    │
│     │  no response? → not RMI                                    │
│     ▼                                                            │
│  Phase 3: Registry list() Enumeration                            │
│  Scanner ──────► LocateRegistry.getRegistry(host, port).list()   │
│     │  names returned? → HIGH finding + service inventory        │
│     │  empty/blocked? → MEDIUM finding (exposure still exists)   │
│     ▼                                                            │
│  Phase 4: DGC Endpoint Probe                                     │
│  Scanner ──────► send DGC dirty() probe bytes (raw socket)       │
│     │  any response? → HIGH finding (deser attack surface)       │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Why Two Different Approaches (Raw Socket + JDK API)?

- **Raw socket** for handshake and DGC: gives us byte-level control to fingerprint the protocol and probe the DGC without triggering full RMI connection setup
- **JDK `LocateRegistry`** for `list()`: the most reliable cross-version approach — it speaks the exact wire format the target expects, handles all JDK version quirks internally, and returns a clean `String[]`

---

## Attack Flow Visualization

### Complete Detection Chain

**Phase 1: Connectivity**
- 🔌 TCP connect to port 1099
- 🔍 Check alternate ports (1098, 2099, 9010) on failure

**Phase 2: Protocol Fingerprint**
- 📡 Send `JRMI\x00\x02\x4b` header
- 🔬 Classify response: ProtocolAck / SerializationStream / Unknown

**Phase 3: Service Enumeration**
- 📋 Call `registry.list()` via JDK RMI client
- 📦 Collect bound service names

**Phase 4: DGC Attack Surface**
- ⚡ Send DGC `dirty()` probe bytes
- 🚨 Flag deserialization delivery vector

### RMI Wire Protocol (Simplified)

```
┌─────────────────────────────────────────────────────────────────┐
│                    RMI WIRE EXCHANGE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Client → Server:  4a 52 4d 49 00 02 4b    ("JRMI" v2 Single)  │
│  Server → Client:  4e [port] [hostname]    (ProtocolAck)        │
│                                                                  │
│  Client → Server:  50 aced 0005 ...        (Call: list() op)    │
│  Server → Client:  51 aced 0005 ...        (ReturnData: String[])│
│                    74 00 0c "HelloService"  (TC_STRING entries)  │
│                    74 00 13 "InternalData.."                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Phase 2: RMI Handshake Probe

```java
static byte[] rmiHandshake(String host, int port) {
    try (Socket s = new Socket()) {
        s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
        s.setSoTimeout(TIMEOUT_MS);
        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        out.write(RMI_TRANSPORT_HEADER);  // "JRMI" + version 2 + SingleOpProtocol
        out.flush();

        InputStream in = s.getInputStream();
        byte[] buf = new byte[256];
        int read = in.read(buf, 0, buf.length);
        return Arrays.copyOf(buf, read);
    }
}
```

Response classification:
- `0x4e` → `rmi_protocol_ack` (standard registry)
- `0xaced` → `java_serialization_stream` (old registry / DGC direct)
- `0x4f` → `rmi_protocol_ack_compressed`

### Phase 3: Registry Enumeration

```java
static List<String> registryList(String host, int port) {
    List<String> names = new ArrayList<>();
    try {
        // JDK built-in RMI client - handles all wire protocol details internally
        java.rmi.registry.Registry reg =
            java.rmi.registry.LocateRegistry.getRegistry(host, port);
        String[] bound = reg.list();
        for (String n : bound) names.add(n);
    } catch (Exception e) {
        System.err.println("[rmi] list() error: " + e.getMessage());
    }
    return names;
}
```

### Phase 4: DGC Probe

```java
// DGC dirty() probe - detects deserialization attack surface
// Uses raw bytes: JRMI header + Call(0x50) + DGC ObjID + dirty() op hash
byte[] dgcDirtyProbe = new byte[] {
    0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b,   // JRMI header
    0x50,                                           // Call message
    (byte)0xac, (byte)0xed, 0x00, 0x05,           // Java stream magic
    0x77, 0x22,                                     // TC_BLOCKDATA
    // DGC ObjID (all zeros + space=2)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02,
    // dirty() operation hash
    (byte)0xf6, (byte)0xb6, (byte)0x89, (byte)0x8d,
    (byte)0x8b, (byte)0xf2, (byte)0x86, 0x43,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
// Any response byte ≥ 0 = DGC reachable
```

---

## Usage Guide

### Basic Usage

```bash
# Scan default RMI port
cxg scan --scope target.example.com --template rmi-service-enumeration/RmiServiceEnumeration.java

# Explicit port
cxg scan --scope target.example.com:1099 --template rmi-service-enumeration/RmiServiceEnumeration.java

# JSON output with verbose logging
cxg scan --scope target.example.com --template rmi-service-enumeration/RmiServiceEnumeration.java \
  --output-format json --timeout 30s -vv

# Scan multiple targets from file
cxg scan --scope @targets.txt --template rmi-service-enumeration/RmiServiceEnumeration.java \
  --output-format json --timeout 30s
```

### Direct Execution

```bash
# Compile
javac RmiServiceEnumeration.java

# Run directly
java -cp . RmiServiceEnumeration --target 192.168.1.10 --port 1099

# JSON mode
java -cp . RmiServiceEnumeration --target 192.168.1.10 --port 1099 --json
```

### Expected Output — Vulnerable (Services Enumerated)

```json
[
  {
    "template_id": "rmi-service-enumeration",
    "severity": "high",
    "confidence": 95,
    "title": "Exposed RMI Registry with Unauthenticated Service Enumeration",
    "evidence": {
      "handshake_type": "rmi_protocol_ack",
      "registry_list_success": "true",
      "bound_service_count": "2",
      "bound_services": "InternalDataService, HelloService",
      "dgc_reachable": "true"
    },
    "cvss_score": 8.1
  },
  {
    "template_id": "rmi-service-enumeration",
    "severity": "high",
    "confidence": 85,
    "title": "RMI Distributed Garbage Collector (DGC) Endpoint Exposed",
    "evidence": {
      "dgc_reachable": "true",
      "attack_vector": "DGC dirty()/clean() deserialization"
    },
    "cvss_score": 8.1
  }
]
```

### Expected Output — Port Closed

```json
[{
  "severity": "info",
  "title": "RMI: No RMI Registry Detected - Port Closed or Filtered",
  "evidence": { "tcp_open": "false" }
}]
```

---

## Real-World Test Results

The template was tested against a Docker-based RMI registry (`eclipse-temurin:11-jdk-jammy`) with two bound services.

| Target | Port | TCP Open | Handshake | list() | Services Found | DGC | Finding |
|--------|------|----------|-----------|--------|----------------|-----|---------|
| 127.0.0.1 (Docker) | 1099 | ✅ | `rmi_protocol_ack` | ✅ | `HelloService`, `InternalDataService` | ✅ | 2× HIGH |
| 127.0.0.1:80 (nginx) | 80 | ✅ | `no_response` | N/A | N/A | N/A | INFO |

**Key findings from testing:**

1. ✅ RMI handshake fingerprinting correctly identifies protocol acknowledgement byte `0x4e`
2. ✅ `registry.list()` via JDK `LocateRegistry` reliably enumerates all bound names
3. ✅ DGC probe correctly identifies deserialization attack surface on same port
4. ✅ Non-RMI port (80) handled gracefully with INFO finding — zero false positives
5. ✅ Full execution time: ~1.1s via `cxg` engine
6. ✅ Engine correctly reported 2 HIGH findings with full JSON evidence

---

## Defense & Remediation

### Immediate Actions

**1. Bind registry to localhost only**

```java
// ❌ VULNERABLE: listens on all interfaces
Registry reg = LocateRegistry.createRegistry(1099);

// ✅ SECURE: localhost only
System.setProperty("java.rmi.server.hostname", "127.0.0.1");
Registry reg = LocateRegistry.createRegistry(1099,
    new SslRMIClientSocketFactory(),
    new SslRMIServerSocketFactory());
```

**2. Apply JEP 290 Deserialization Filters (JDK 9+)**

```java
// Global filter - allowlist approach
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.*;java.lang.*;java.util.*;!*"
);
ObjectInputFilter.Config.setSerialFilter(filter);
```

**3. RMI over SSL**

```java
// Server
Registry reg = LocateRegistry.createRegistry(1099,
    new SslRMIClientSocketFactory(),
    new SslRMIServerSocketFactory(null, null, true)); // needClientAuth=true

// Client
Registry reg = LocateRegistry.getRegistry(host, 1099,
    new SslRMIClientSocketFactory());
```

### Defense Checklist

**Network Controls:**
- ✅ Firewall port 1099 (and 1098, 2099, 9010) from untrusted networks
- ✅ Use network segmentation — RMI should never be internet-facing
- ✅ Monitor for unexpected connections to RMI ports

**JVM Hardening:**
- ✅ Set `-Djava.rmi.server.hostname=127.0.0.1`
- ✅ Enable JEP 290 deserialization filters
- ✅ Use serialization allowlists (not denylists)
- ✅ Upgrade to JDK 17+ (stronger default filters)

**Architecture:**
- ✅ Replace RMI with gRPC or REST for new services
- ✅ Migrate JMX-over-RMI to JMX-over-JMXMP with authentication
- ✅ Audit all services bound to the registry — remove unused bindings

### Severity Matrix

| Condition | Severity | CVSS |
|-----------|----------|------|
| `list()` succeeds + DGC reachable | HIGH | 8.1 |
| `list()` succeeds only | HIGH | 8.1 |
| Handshake only (list blocked) + DGC | HIGH | 7.5 |
| Handshake confirmed, list empty | MEDIUM | 5.3 |
| Port open, no RMI protocol | INFO | 0.0 |

---

## Extending the Template

### Add lookup() Stub Type Detection

```java
// After list() - attempt lookup to identify stub class names
for (String name : serviceNames) {
    try {
        Remote stub = reg.lookup(name);
        evidence.put("stub_class_" + name, stub.getClass().getName());
    } catch (Exception e) { /* skip */ }
}
```

### Scan Additional RMI Ports

```java
// Add to findAlternatePort() common ports array
int[] common = {1099, 1098, 1097, 2099, 4000, 9010, 8888, 8009,
                44444, 10999, 1100, 1101};
```

### JMX-over-RMI Detection

```java
// JMX connector URL pattern in bound names
for (String name : serviceNames) {
    if (name.equals("jmxrmi") || name.startsWith("JMX")) {
        // Flag as JMX connector - additional attack surface
        evidence.put("jmx_connector_exposed", "true");
    }
}
```

### Integration with ysoserial

```bash
# Manual post-exploitation (after template confirms exposure)
# DO NOT automate - requires explicit authorization
java -jar ysoserial.jar CommonsCollections1 "id" | \
  java -cp . RmiExploit 192.168.1.10 1099 HelloService
```

---

## References

### CVEs Involving Exposed RMI

| CVE | Product | Description |
|-----|---------|-------------|
| CVE-2017-1000353 | Jenkins | Unauthenticated RMI → RCE via deserialization |
| CVE-2019-2725 | Oracle WebLogic | RMI/T3 deserialization RCE |
| CVE-2016-3427 | JMX/RMI | DGC deserialization chain |
| CVE-2011-3556 | Oracle WebLogic | RMI registry exposure |

### Tools & Resources

- [ysoserial](https://github.com/frohoff/ysoserial) — Java deserialization payload generator
- [rmiscout](https://github.com/mogwailabs/rmiscout) — RMI service enumeration and brute-forcing
- [barmie](https://github.com/NickstaDB/BaRMIe) — Java RMI enumeration and attack tool
- [JEP 290](https://openjdk.org/jeps/290) — Filter Incoming Serialization Data
- [Attacking Java RMI after JEP 290](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/) — MogWai Labs research

---

<div align="center">

## 🚀 Ready to Hunt?

```bash
cxg scan --scope your-target.com --template rmi-service-enumeration/RmiServiceEnumeration.java \
  --output-format json --timeout 30s -vv
```

**Found exposed RMI registries using this template?**
Tag `@BugB-Tech` on Twitter with `#CERTXGEN`

---

*This playbook is part of the CERT-X-GEN Security Scanner documentation.*
*Licensed under Apache 2.0. Contributions welcome!*

[GitHub](https://github.com/Bugb-Technologies/cert-x-gen) • [Templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) • [DeepWiki](https://deepwiki.com/Bugb-Technologies/cert-x-gen)

</div>

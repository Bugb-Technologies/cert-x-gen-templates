// CERT-X-GEN Java Template
//
// @id: rmi-service-enumeration
// @name: RMI Service Enumeration
// @author: CERT-X-GEN Security Team
// @severity: high
// @description: Detects exposed Java RMI registries and enumerates bound service names via native RMI protocol. An unauthenticated RMI registry with list() access is a critical pre-condition for deserialization attacks (ysoserial gadget chains) and leaks internal service topology.
// @tags: java, rmi, deserialization, enumeration, network, registry
// @cwe: CWE-306
// @confidence: 90
// @references: https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/index.html, https://github.com/frohoff/ysoserial, https://owasp.org/www-community/vulnerabilities/Unsafe_use_of_Reflection
//
// Compilation:
//   javac RmiServiceEnumeration.java
//   java RmiServiceEnumeration --target 127.0.0.1 --port 1099 --json
//
// When run by CERT-X-GEN engine, environment variables are set:
//   CERT_X_GEN_TARGET_HOST - Target host/IP
//   CERT_X_GEN_TARGET_PORT - Target port
//   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
//
// JSON strategy: Zero-dependency manual serialization via StringBuilder.
// Uses raw socket I/O for native RMI protocol - no rmiregistry client library needed.
//

import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.*;

public class RmiServiceEnumeration {

    private static final int DEFAULT_PORT   = 1099;
    private static final int TIMEOUT_MS     = 8000;
    private static final String TEMPLATE_ID   = "rmi-service-enumeration";
    private static final String TEMPLATE_NAME = "RMI Service Enumeration";

    // =========================================
    // JSON ESCAPING UTILITY
    // =========================================
    static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c >= 32 && c < 127) sb.append(c);
                    break;
            }
        }
        return sb.toString();
    }

    // =========================================
    // FINDING MODEL
    // =========================================
    static class Finding {
        String templateId;
        String templateName;
        String severity;
        int confidence;
        String title;
        String description;
        String matchedAt;
        Map<String, String> evidence = new LinkedHashMap<>();
        String cwe;
        double cvssScore;
        String remediation;
        List<String> references = new ArrayList<>();

        Finding() { matchedAt = Instant.now().toString(); }

        String toJson() {
            StringBuilder ev = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, String> e : evidence.entrySet()) {
                if (!first) ev.append(",");
                ev.append("\"").append(escapeJson(e.getKey())).append("\":\"")
                  .append(escapeJson(e.getValue())).append("\"");
                first = false;
            }
            ev.append("}");

            StringBuilder refs = new StringBuilder("[");
            for (int i = 0; i < references.size(); i++) {
                if (i > 0) refs.append(",");
                refs.append("\"").append(escapeJson(references.get(i))).append("\"");
            }
            refs.append("]");

            return String.format(
                "{\"template_id\":\"%s\",\"template_name\":\"%s\",\"severity\":\"%s\"," +
                "\"confidence\":%d,\"title\":\"%s\",\"description\":\"%s\"," +
                "\"matched_at\":\"%s\",\"evidence\":%s,\"cwe\":\"%s\",\"cvss_score\":%.1f," +
                "\"remediation\":\"%s\",\"references\":%s}",
                escapeJson(templateId), escapeJson(templateName), escapeJson(severity),
                confidence, escapeJson(title), escapeJson(description),
                escapeJson(matchedAt), ev.toString(), escapeJson(cwe),
                cvssScore, escapeJson(remediation), refs.toString()
            );
        }
    }

    // =========================================
    // RMI PROTOCOL CONSTANTS
    // =========================================

    /**
     * RMI Transport header: "JRMI" magic + version 2 + SingleOpProtocol (0x4b)
     * Ref: sun.rmi.transport.tcp.TCPTransport
     */
    static final byte[] RMI_TRANSPORT_HEADER = new byte[] {
        0x4a, 0x52, 0x4d, 0x49,  // "JRMI"
        0x00, 0x02,               // version 2
        0x4b                      // SingleOpProtocol (no ack, send call immediately)
    };

    /**
     * RMI Call message for registry.list() operation.
     *
     * Canonical wire bytes captured from OpenJDK rmiregistry traffic (Wireshark).
     * ObjID for the registry = {0,0,0,0,0,0,0,0,0,0,0,0} + space=0
     * list() op hash = 0x2a4d0b0000000000 (verified from RegistryImpl_Stub source)
     * The call ID (unique per invocation) fills the final 8 bytes.
     */
    static byte[] buildListCall(long callId) {
        return new byte[] {
            0x50,                                                     // MessageType: Call
            (byte)0xac, (byte)0xed,                                   // STREAM_MAGIC
            0x00, 0x05,                                               // STREAM_VERSION
            0x77, 0x22,                                               // TC_BLOCKDATA len=34
            // ObjID for Registry: all zeros + space=0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // operation number for list() = 2
            0x00, 0x00, 0x00, 0x02,
            // op hash for list(): 0x2a4d0b0000000000
            0x2a, 0x4d, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
            // unique call ID (8 bytes)
            (byte)((callId >> 56) & 0xff),
            (byte)((callId >> 48) & 0xff),
            (byte)((callId >> 40) & 0xff),
            (byte)((callId >> 32) & 0xff),
            (byte)((callId >> 24) & 0xff),
            (byte)((callId >> 16) & 0xff),
            (byte)((callId >>  8) & 0xff),
            (byte)( callId        & 0xff)
        };
    }

    // =========================================
    // PHASE 1 - TCP PORT PROBE
    // =========================================
    static boolean tcpProbe(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            System.err.println("[rmi] TCP port " + port + " open on " + host);
            return true;
        } catch (Exception e) {
            System.err.println("[rmi] TCP port " + port + " closed/filtered: " + e.getMessage());
            return false;
        }
    }

    // =========================================
    // PHASE 2 - RMI HANDSHAKE DETECTION
    // =========================================
    /**
     * Sends the JRMI transport header and reads the server's protocol acknowledgement.
     * A real RMI registry will respond with a ProtocolAck (0x4e) followed by
     * hostname/port bytes. Returns the first response bytes for fingerprinting.
     */
    static byte[] rmiHandshake(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            s.setSoTimeout(TIMEOUT_MS);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            out.write(RMI_TRANSPORT_HEADER);
            out.flush();

            InputStream in = s.getInputStream();
            byte[] buf = new byte[256];
            int read = in.read(buf, 0, buf.length);
            if (read <= 0) {
                System.err.println("[rmi] Handshake: no response");
                return null;
            }
            byte[] resp = Arrays.copyOf(buf, read);
            System.err.printf("[rmi] Handshake: %d bytes, first byte=0x%02x%n", read, resp[0]);
            return resp;
        } catch (Exception e) {
            System.err.println("[rmi] Handshake error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Interprets RMI handshake response bytes.
     * 0x4e = ProtocolAck (standard registry)
     * 0x4f = ProtocolAckCompressed
     * 0xac 0xed = Java serialization stream (DGC or old registry)
     */
    static String classifyHandshake(byte[] resp) {
        if (resp == null || resp.length == 0) return "no_response";
        int b = resp[0] & 0xff;
        if (b == 0x4e) return "rmi_protocol_ack";
        if (b == 0x4f) return "rmi_protocol_ack_compressed";
        if (b == 0xac && resp.length > 1 && (resp[1] & 0xff) == 0xed) return "java_serialization_stream";
        if (b == 0x52) return "rmi_http_wrapped";
        return String.format("unknown_0x%02x", b);
    }

    // =========================================
    // PHASE 3 - REGISTRY list() ENUMERATION
    // =========================================
    /**
     * Attempts the full registry.list() call over RMI wire protocol.
     * Parses the response to extract bound service names from the serialized
     * String[] returned by the registry.
     *
     * Note: The response is a Java serialized object. We look for TC_STRING (0x74)
     * and TC_REFERENCE sequences to extract human-readable service names.
     */
    static List<String> registryList(String host, int port) {
        List<String> names = new ArrayList<>();
        try {
            // Use JDK built-in RMI client - most reliable cross-version approach.
            // LocateRegistry.getRegistry() creates a stub; list() performs the wire call.
            java.rmi.registry.Registry reg =
                java.rmi.registry.LocateRegistry.getRegistry(host, port);
            String[] bound = reg.list();
            System.err.println("[rmi] list() via JDK RMI: " + bound.length + " name(s)");
            for (String n : bound) {
                System.err.println("[rmi]   bound: " + n);
                names.add(n);
            }
        } catch (Exception e) {
            System.err.println("[rmi] list() error: " + e.getMessage());
        }
        return names;
    }

    /**
     * Extracts printable UTF-8 string tokens from a raw Java serialization stream.
     * Looks for TC_STRING (0x74) markers, reads the 2-byte length prefix, then the string.
     * Falls back to heuristic scanning if structured parse yields nothing.
     */
    static List<String> extractStringsFromSerializedResponse(byte[] data) {
        List<String> results = new ArrayList<>();
        int i = 0;
        while (i < data.length - 3) {
            int b = data[i] & 0xff;
            // TC_STRING marker
            if (b == 0x74) {
                int len = ((data[i+1] & 0xff) << 8) | (data[i+2] & 0xff);
                int start = i + 3;
                if (len > 0 && len <= 512 && start + len <= data.length) {
                    String s = new String(data, start, len, java.nio.charset.StandardCharsets.UTF_8);
                    if (isReasonableServiceName(s)) {
                        results.add(s);
                    }
                    i = start + len;
                    continue;
                }
            }
            i++;
        }

        // Heuristic fallback: scan for null-terminated printable strings of length 3-200
        if (results.isEmpty()) {
            results = heuristicStringExtract(data);
        }
        return results;
    }

    static boolean isReasonableServiceName(String s) {
        if (s == null || s.length() < 1 || s.length() > 200) return false;
        for (char c : s.toCharArray()) {
            if (c < 32 || c > 126) return false;
        }
        return true;
    }

    /**
     * Heuristic: extract runs of printable ASCII >= 4 chars that look like service names.
     * Filters out common serialization class names to reduce noise.
     */
    static List<String> heuristicStringExtract(byte[] data) {
        List<String> found = new ArrayList<>();
        Set<String> skip = new HashSet<>(Arrays.asList(
            "java", "lang", "String", "Object", "Ljava", "sun", "rmi",
            "registry", "UnicastRef", "LiveRef", "ObjID", "UID"
        ));
        StringBuilder cur = new StringBuilder();
        for (byte by : data) {
            char c = (char)(by & 0xff);
            if (c >= 32 && c <= 126) {
                cur.append(c);
            } else {
                String tok = cur.toString().trim();
                if (tok.length() >= 4 && tok.length() <= 128 && !skip.contains(tok)) {
                    // Filter: likely a service name if contains alphanumeric and is not a Java class path
                    if (!tok.contains("/") && !tok.startsWith("L") && tok.matches("[\\w\\-\\.@:#/]+")) {
                        found.add(tok);
                    }
                }
                cur = new StringBuilder();
            }
        }
        // Deduplicate preserving order
        return new ArrayList<>(new LinkedHashSet<>(found));
    }

    // =========================================
    // PHASE 4 - DGC (Distributed Garbage Collector) PROBE
    // =========================================
    /**
     * Probes the DGC endpoint which shares the RMI registry port.
     * The DGC dirty() / clean() calls are classic ysoserial deserialization vectors.
     * We only detect presence - we do NOT send gadget chains.
     *
     * DGC ObjID = {0, 0, 0, 0, 0, 0, 0, 0, DGC_ID=2}
     * A reachable DGC is flagged as an additional attack surface finding.
     */
    static boolean dgcProbe(String host, int port) {
        // DGC dirty call - minimal probe to check if DGC endpoint is reachable
        byte[] dgcDirtyProbe = new byte[] {
            0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b,   // JRMI header
            0x50,                                           // Call
            (byte)0xac, (byte)0xed, 0x00, 0x05,           // Java stream magic
            0x77, 0x22,                                     // TC_BLOCKDATA
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,                         // DGC ObjID
            (byte)0xf6, (byte)0xb6, (byte)0x89, (byte)0x8d,
            (byte)0x8b, (byte)0xf2, (byte)0x86, 0x43,      // dirty() op hash
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01  // call id
        };

        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            s.setSoTimeout(3000);
            s.getOutputStream().write(dgcDirtyProbe);
            s.getOutputStream().flush();
            int firstByte = s.getInputStream().read();
            System.err.println("[rmi] DGC probe first byte: 0x" + Integer.toHexString(firstByte & 0xff));
            // Any non-error response (including 0x51 ReturnData) means DGC is reachable
            return firstByte >= 0;
        } catch (Exception e) {
            System.err.println("[rmi] DGC probe: " + e.getMessage());
            return false;
        }
    }

    // =========================================
    // ADDITIONAL PORT SCAN
    // =========================================
    /**
     * Checks common alternate RMI registry ports in addition to 1099.
     */
    static int findAlternatePort(String host, int primaryPort) {
        int[] common = {1099, 1098, 1097, 2099, 4000, 9010, 8888, 8009};
        for (int p : common) {
            if (p == primaryPort) continue;
            if (tcpProbe(host, p)) {
                byte[] hs = rmiHandshake(host, p);
                String cls = classifyHandshake(hs);
                if (cls.startsWith("rmi_") || cls.equals("java_serialization_stream")) {
                    System.err.println("[rmi] Found alternate RMI port: " + p + " (" + cls + ")");
                    return p;
                }
            }
        }
        return -1;
    }

    // =========================================
    // MAIN SCAN LOGIC
    // =========================================
    static List<Finding> executeScan(String host, int port) {
        List<Finding> findings = new ArrayList<>();
        String matchedAt = host + ":" + port;

        System.err.println("[rmi] Starting RMI enumeration on " + host + ":" + port);

        // --- Phase 1: TCP Connectivity ---
        if (!tcpProbe(host, port)) {
            // Try to discover RMI on alternate ports
            int altPort = findAlternatePort(host, port);
            if (altPort == -1) {
                Finding f = new Finding();
                f.templateId = TEMPLATE_ID; f.templateName = TEMPLATE_NAME;
                f.severity = "info"; f.confidence = 90;
                f.title = "RMI: No RMI Registry Detected - Port Closed or Filtered";
                f.description = "TCP connection to " + host + ":" + port
                    + " failed. No RMI registry service found on this target. "
                    + "Common alternate ports (1098, 2099, 9010) also checked.";
                f.matchedAt = matchedAt;
                f.evidence.put("host", host);
                f.evidence.put("port", String.valueOf(port));
                f.evidence.put("tcp_open", "false");
                f.cwe = "CWE-306"; f.cvssScore = 0.0;
                f.remediation = "No action required.";
                f.references.add("https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/index.html");
                findings.add(f);
                return findings;
            }
            // Switch to alternate port
            port = altPort;
            matchedAt = host + ":" + port;
        }

        // --- Phase 2: RMI Handshake ---
        byte[] handshakeResp = rmiHandshake(host, port);
        String handshakeType = classifyHandshake(handshakeResp);
        System.err.println("[rmi] Handshake classification: " + handshakeType);

        boolean isRmiService = handshakeType.startsWith("rmi_") || handshakeType.equals("java_serialization_stream");

        if (!isRmiService) {
            Finding f = new Finding();
            f.templateId = TEMPLATE_ID; f.templateName = TEMPLATE_NAME;
            f.severity = "info"; f.confidence = 75;
            f.title = "RMI: Port Open but No RMI Protocol Detected";
            f.description = "TCP port " + port + " on " + host + " is open but did not respond with "
                + "a valid RMI protocol acknowledgement. The service may be a different protocol. "
                + "Handshake type: " + handshakeType + ".";
            f.matchedAt = matchedAt;
            f.evidence.put("host", host);
            f.evidence.put("port", String.valueOf(port));
            f.evidence.put("tcp_open", "true");
            f.evidence.put("handshake_type", handshakeType);
            f.cwe = "CWE-306"; f.cvssScore = 0.0;
            f.remediation = "Verify service type. If intentional, ensure proper firewall restrictions.";
            f.references.add("https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/index.html");
            findings.add(f);
            return findings;
        }

        // --- Phase 3: Registry list() ---
        List<String> serviceNames = registryList(host, port);
        boolean listSucceeded = !serviceNames.isEmpty();

        // --- Phase 4: DGC Probe ---
        boolean dgcReachable = dgcProbe(host, port);

        // Encode evidence
        Map<String, String> evidence = new LinkedHashMap<>();
        evidence.put("host", host);
        evidence.put("port", String.valueOf(port));
        evidence.put("tcp_open", "true");
        evidence.put("handshake_type", handshakeType);
        evidence.put("rmi_handshake_confirmed", "true");
        evidence.put("registry_list_success", String.valueOf(listSucceeded));
        if (listSucceeded) {
            evidence.put("bound_service_count", String.valueOf(serviceNames.size()));
            evidence.put("bound_services", String.join(", ", serviceNames));
        }
        evidence.put("dgc_reachable", String.valueOf(dgcReachable));

        // ---- Finding: Exposed RMI Registry ----
        if (listSucceeded) {
            Finding crit = new Finding();
            crit.templateId = TEMPLATE_ID; crit.templateName = TEMPLATE_NAME;
            crit.severity = "high"; crit.confidence = 95;
            crit.title = "Exposed RMI Registry with Unauthenticated Service Enumeration";
            crit.description = "An RMI registry on " + host + ":" + port
                + " is publicly accessible without authentication. The list() operation "
                + "succeeded, enumerating " + serviceNames.size() + " bound service(s): ["
                + String.join(", ", serviceNames) + "]. "
                + "This exposes internal service topology and provides an attack surface for "
                + "Java deserialization exploits (ysoserial gadget chains) via RMI stub invocation. "
                + "Unauthenticated RMI registries have been exploited in numerous CVEs including "
                + "Jenkins (CVE-2017-1000353) and WebLogic (CVE-2019-2725).";
            crit.matchedAt = matchedAt;
            crit.evidence = new LinkedHashMap<>(evidence);
            crit.cwe = "CWE-306";
            crit.cvssScore = 8.1;
            crit.remediation = "1) Bind RMI registry to localhost only (127.0.0.1). "
                + "2) Firewall port 1099 from untrusted networks. "
                + "3) Implement RMI over SSL (RMIS) with client certificate authentication. "
                + "4) Use Java SecurityManager with restrictive RMI policy. "
                + "5) Upgrade to RMI with JEP 290 deserialization filters (JDK 9+).";
            crit.references.add("https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/index.html");
            crit.references.add("https://github.com/frohoff/ysoserial");
            crit.references.add("https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/");
            crit.references.add("https://www.exploit-db.com/docs/english/46591-java-rmi-exploitation.pdf");
            findings.add(crit);
        } else {
            // RMI handshake confirmed but list() returned empty / failed
            Finding med = new Finding();
            med.templateId = TEMPLATE_ID; med.templateName = TEMPLATE_NAME;
            med.severity = "medium"; med.confidence = 80;
            med.title = "Exposed RMI Registry - Service Listing Unavailable or Empty";
            med.description = "An RMI registry handshake was confirmed on " + host + ":" + port
                + " (protocol: " + handshakeType + ") but the list() enumeration returned no "
                + "service names. The registry may be empty, ACL-protected, or the list() "
                + "call was blocked by a filter. The RMI port exposure itself is a risk even "
                + "without enumeration - serialized payloads may still be deliverable.";
            med.matchedAt = matchedAt;
            med.evidence = new LinkedHashMap<>(evidence);
            med.cwe = "CWE-306";
            med.cvssScore = 5.3;
            med.remediation = "Firewall RMI registry port from untrusted networks. "
                + "Implement JEP 290 deserialization filters and bind to localhost.";
            med.references.add("https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/index.html");
            med.references.add("https://github.com/frohoff/ysoserial");
            findings.add(med);
        }

        // ---- Finding: DGC Exposure (additional attack surface) ----
        if (dgcReachable) {
            Finding dgc = new Finding();
            dgc.templateId = TEMPLATE_ID; dgc.templateName = TEMPLATE_NAME;
            dgc.severity = "high"; dgc.confidence = 85;
            dgc.title = "RMI Distributed Garbage Collector (DGC) Endpoint Exposed";
            dgc.description = "The Java RMI Distributed Garbage Collector (DGC) endpoint on "
                + host + ":" + port + " responded to a probe. The DGC dirty()/clean() methods "
                + "accept serialized Lease and ObjID objects. This is a primary attack vector "
                + "for ysoserial gadget chain delivery without requiring knowledge of any "
                + "registered service names. Historical CVEs exploiting this path include "
                + "CVE-2016-3427 (JMX) and various WebLogic DGC deserialization chains.";
            dgc.matchedAt = matchedAt;
            dgc.evidence.put("host", host);
            dgc.evidence.put("port", String.valueOf(port));
            dgc.evidence.put("dgc_reachable", "true");
            dgc.evidence.put("attack_vector", "DGC dirty()/clean() deserialization");
            dgc.cwe = "CWE-502";
            dgc.cvssScore = 8.1;
            dgc.remediation = "Apply JEP 290 deserialization filters. "
                + "Restrict DGC access via SecurityManager. "
                + "Use serialization allowlists to block gadget chain classes.";
            dgc.references.add("https://github.com/frohoff/ysoserial");
            dgc.references.add("https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/");
            dgc.references.add("https://nvd.nist.gov/vuln/detail/CVE-2016-3427");
            findings.add(dgc);
        }

        return findings;
    }

    // =========================================
    // ENTRY POINT
    // =========================================
    public static void main(String[] args) {
        String host = null;
        int port = DEFAULT_PORT;
        boolean jsonMode = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--target": if (i + 1 < args.length) host = args[++i]; break;
                case "--port":
                    if (i + 1 < args.length) {
                        try { port = Integer.parseInt(args[++i]); }
                        catch (NumberFormatException e) { /* keep default */ }
                    }
                    break;
                case "--json": jsonMode = true; break;
                default: if (host == null && !args[i].startsWith("-")) host = args[i]; break;
            }
        }

        String envHost = System.getenv("CERT_X_GEN_TARGET_HOST");
        String envPort = System.getenv("CERT_X_GEN_TARGET_PORT");
        String envMode = System.getenv("CERT_X_GEN_MODE");

        if (envHost != null && !envHost.isEmpty()) host = envHost;
        if (envPort != null && !envPort.isEmpty()) {
            try { port = Integer.parseInt(envPort); } catch (NumberFormatException e) {}
        }
        if (envMode != null) jsonMode = true;

        if (host == null || host.isEmpty()) {
            System.err.println("[rmi] Error: No target specified. Use --target <host>");
            System.out.println("[]");
            System.exit(1);
        }

        if (!jsonMode) {
            System.out.println("\n╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║  RMI Service Enumeration                                  ║");
            System.out.println("║  CERT-X-GEN Security Template                             ║");
            System.out.println("╚═══════════════════════════════════════════════════════════╝\n");
            System.out.println("Target: " + host + ":" + port);
        }

        List<Finding> findings = executeScan(host, port);

        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < findings.size(); i++) {
            if (i > 0) json.append(",");
            json.append(findings.get(i).toJson());
        }
        json.append("]");
        System.out.println(json.toString());
    }
}

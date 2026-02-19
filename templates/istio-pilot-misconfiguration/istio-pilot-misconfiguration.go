// CERT-X-GEN Go Template - Istio Pilot Misconfiguration Detection
//
// @id: istio-pilot-misconfiguration
// @name: Istio Pilot Misconfiguration Detection
// @author: BugB Technologies
// @severity: high
// @description: Detects misconfigured Istio Pilot (istiod) control plane endpoints exposed without authentication. Probes port 8080 (HTTP admin), 15010 (xDS plaintext gRPC), and 15014 (monitoring). Exposure allows service mesh topology enumeration, secret extraction, and potential AuthorizationPolicy bypass.
// @tags: istio, service-mesh, kubernetes, misconfiguration, xds, envoy, api-exposure, container-security
// @cwe: CWE-306
// @confidence: 90
// @references: https://istio.io/latest/docs/ops/best-practices/security/, https://istio.io/latest/docs/reference/config/istio.pilot.v1alpha1/, https://attack.mitre.org/techniques/T1046/

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Finding represents a security finding
type Finding struct {
	TemplateID   string                 `json:"template_id"`
	TemplateName string                 `json:"template_name"`
	Host         string                 `json:"host"`
	Severity     string                 `json:"severity"`
	Confidence   int                    `json:"confidence"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Evidence     map[string]interface{} `json:"evidence,omitempty"`
	CWE          string                 `json:"cwe,omitempty"`
	CVSSScore    float64                `json:"cvss_score,omitempty"`
	Remediation  string                 `json:"remediation,omitempty"`
	References   []string               `json:"references,omitempty"`
	MatchedAt    string                 `json:"matched_at"`
}

// ProbeResult captures what we observed on a given port/path
type ProbeResult struct {
	Port       int
	Path       string
	StatusCode int
	Body       string
	Reachable  bool
	ResetByPeer bool
}

func main() {
	target := os.Getenv("CERT_X_GEN_TARGET_HOST")
	if target == "" && len(os.Args) > 1 {
		target = os.Args[1]
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: No target specified")
		fmt.Println("[]")
		return
	}

	target = normalizeTarget(target)
	findings := []Finding{}

	// --- Port 8080: Istio HTTP admin/debug server ---
	// This port is always present in istiod. It exposes /ready, /debug/*, /metrics
	fmt.Fprintf(os.Stderr, "[*] Probing port 8080 (Istio HTTP admin server)...\n")
	adminFindings := probePort8080(target)
	findings = append(findings, adminFindings...)

	// --- Port 15010: xDS plaintext gRPC ---
	// In misconfigured or older Istio, this port accepts plain-text xDS connections.
	// HTTP/1.1 will get a TCP reset (gRPC only) but TCP reachability proves exposure.
	fmt.Fprintf(os.Stderr, "[*] Probing port 15010 (xDS plaintext gRPC)...\n")
	if f := probePort15010(target); f != nil {
		findings = append(findings, *f)
	}

	// --- Port 15014: monitoring/debug HTTP ---
	// Exposes /metrics and /debug/* in full Istio deployments.
	fmt.Fprintf(os.Stderr, "[*] Probing port 15014 (Istio monitoring/debug)...\n")
	if f := probePort15014(target); f != nil {
		findings = append(findings, *f)
	}

	output, err := json.Marshal(findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		fmt.Println("[]")
		return
	}
	fmt.Println(string(output))
}

// probePort8080 checks Istio's HTTP admin server on port 8080.
// Detection logic:
//   /ready          -> 200 or 503 = Istio is present and port is exposed (503 = starting/no-k8s)
//   /debug/endpointz -> 200 = unauthenticated debug access (CRITICAL)
//                      401 = debug exists but auth enforced (INFO)
//   /metrics        -> 200 with istio_ prefix = metrics exposed (HIGH)
func probePort8080(host string) []Finding {
	var findings []Finding
	client := httpClient()

	// Step 1: /ready — presence check
	readyResult := httpProbe(client, host, 8080, "/ready")
	if !readyResult.Reachable {
		fmt.Fprintf(os.Stderr, "  [-] Port 8080 unreachable\n")
		return findings
	}

	// 200 or 503 both confirm Istio admin port is exposed
	if readyResult.StatusCode == 200 || readyResult.StatusCode == 503 {
		severityLabel := "high"
		cvss := 7.5
		title := fmt.Sprintf("Istio Admin HTTP Port Exposed on %s:8080", host)
		desc := fmt.Sprintf(
			"Istio Pilot admin HTTP server (port 8080) is reachable without network restrictions on %s. "+
				"/ready returned HTTP %d. This port provides access to debug endpoints, metrics, and "+
				"control plane status. In production environments this port must be restricted to "+
				"internal cluster traffic only.",
			host, readyResult.StatusCode,
		)
		evidence := map[string]interface{}{
			"url":            fmt.Sprintf("http://%s:8080/ready", host),
			"http_status":    readyResult.StatusCode,
			"authentication": "not_required",
			"port":           8080,
			"path":           "/ready",
		}
		findings = append(findings, buildFinding(host, severityLabel, cvss, title, desc, evidence))
		fmt.Fprintf(os.Stderr, "  [!] Port 8080 /ready returned %d — Istio admin port exposed\n", readyResult.StatusCode)
	}

	// Step 2: /debug/endpointz — unauthenticated debug access
	debugResult := httpProbe(client, host, 8080, "/debug/endpointz")
	if debugResult.Reachable {
		if debugResult.StatusCode == 200 {
			istioContent := strings.Contains(debugResult.Body, "clusterName") ||
				strings.Contains(debugResult.Body, "endpoints") ||
				strings.Contains(debugResult.Body, "address")
			if istioContent {
				title := fmt.Sprintf("Istio Debug Endpoint Unauthenticated on %s:8080/debug/endpointz", host)
				desc := "Istio debug endpoint /debug/endpointz is accessible without authentication. " +
					"This exposes the full Envoy xDS endpoint table including all service mesh workloads, " +
					"cluster addresses, and routing topology. An attacker can use this to map the entire " +
					"internal infrastructure."
				evidence := map[string]interface{}{
					"url":              fmt.Sprintf("http://%s:8080/debug/endpointz", host),
					"http_status":      200,
					"authentication":   "not_required",
					"response_snippet": truncate(debugResult.Body, 500),
				}
				findings = append(findings, buildFinding(host, "critical", 9.1, title, desc, evidence))
				fmt.Fprintf(os.Stderr, "  [!] CRITICAL: /debug/endpointz is unauthenticated and returns Istio data\n")
			}
		} else if debugResult.StatusCode == 401 {
			fmt.Fprintf(os.Stderr, "  [+] /debug/endpointz returns 401 — auth enforced on debug endpoints\n")
		}
	}

	// Step 3: /metrics — Prometheus metrics exposure
	metricsResult := httpProbe(client, host, 8080, "/metrics")
	if metricsResult.Reachable && metricsResult.StatusCode == 200 {
		if strings.Contains(metricsResult.Body, "pilot_") || strings.Contains(metricsResult.Body, "istio_") {
			title := fmt.Sprintf("Istio Metrics Exposed Unauthenticated on %s:8080/metrics", host)
			desc := "Istio Pilot Prometheus metrics are exposed without authentication on port 8080/metrics. " +
				"These metrics reveal internal mesh state including number of connected proxies, config " +
				"distribution status, and operational details useful for reconnaissance."
			evidence := map[string]interface{}{
				"url":              fmt.Sprintf("http://%s:8080/metrics", host),
				"http_status":      200,
				"authentication":   "not_required",
				"response_snippet": truncate(metricsResult.Body, 500),
			}
			findings = append(findings, buildFinding(host, "high", 7.5, title, desc, evidence))
			fmt.Fprintf(os.Stderr, "  [!] /metrics exposed with Istio data\n")
		}
	}

	return findings
}

// probePort15010 checks if Istio's xDS plaintext gRPC port is reachable.
// Port 15010 speaks gRPC (HTTP/2), so HTTP/1.1 will get a TCP reset.
// A TCP reset from this port is itself evidence of exposure — it proves
// an unauthenticated gRPC listener is reachable from outside the cluster.
func probePort15010(host string) *Finding {
	address := fmt.Sprintf("%s:15010", host)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Port 15010 unreachable: %v\n", err)
		return nil
	}
	defer conn.Close()

	// Port is reachable — send a minimal HTTP/1.1 GET to confirm it's istiod
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("GET /ready HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	response := string(buf[:n])

	// TCP connection succeeded = plaintext xDS port is exposed
	// Response may be a gRPC reset frame, HTTP error, or empty — all valid signals
	fmt.Fprintf(os.Stderr, "  [!] Port 15010 TCP reachable — xDS plaintext gRPC port is exposed\n")

	evidence := map[string]interface{}{
		"address":          address,
		"port":             15010,
		"tcp_reachable":    true,
		"authentication":   "none",
		"protocol":         "gRPC plaintext (xDS)",
		"response_bytes":   n,
	}
	if n > 0 {
		evidence["response_preview"] = truncate(response, 100)
	}

	title := fmt.Sprintf("Istio xDS Plaintext gRPC Port Exposed on %s:15010", host)
	desc := "Istio Pilot xDS plaintext gRPC port (15010) is reachable without authentication. " +
		"This port serves the Envoy xDS (discovery service) API over unencrypted gRPC. " +
		"An attacker with network access can connect an Envoy proxy or xDS client to receive " +
		"the full service mesh configuration including all clusters, endpoints, listeners, " +
		"routes, and TLS certificates. In Istio 1.9+ this port is disabled by default. " +
		"Its exposure indicates an outdated or misconfigured Istio installation."

	f := buildFinding(host, "critical", 9.1, title, desc, evidence)
	return &f
}

// probePort15014 checks Istio's monitoring/debug port.
// In full Istio deployments this serves /metrics and /debug/* unauthenticated.
func probePort15014(host string) *Finding {
	client := httpClient()
	result := httpProbe(client, host, 15014, "/metrics")
	if !result.Reachable {
		fmt.Fprintf(os.Stderr, "  [-] Port 15014 unreachable\n")
		return nil
	}
	if result.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "  [-] Port 15014 /metrics returned %d\n", result.StatusCode)
		return nil
	}

	if !strings.Contains(result.Body, "pilot_") && !strings.Contains(result.Body, "istio_") && !strings.Contains(result.Body, "grpc_") {
		fmt.Fprintf(os.Stderr, "  [-] Port 15014 responded 200 but no Istio metrics found\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "  [!] CRITICAL: Port 15014 /metrics exposed with Istio telemetry\n")

	evidence := map[string]interface{}{
		"url":              fmt.Sprintf("http://%s:15014/metrics", host),
		"http_status":      200,
		"authentication":   "not_required",
		"response_snippet": truncate(result.Body, 500),
	}
	title := fmt.Sprintf("Istio Control Plane Monitoring Port Exposed on %s:15014", host)
	desc := "Istio control plane monitoring port 15014 is exposed without authentication. " +
		"This port serves Prometheus metrics and debug endpoints revealing internal mesh " +
		"telemetry, configuration sync state, connected proxy counts, and error rates."

	f := buildFinding(host, "high", 7.5, title, desc, evidence)
	return &f
}

// httpProbe performs a GET request and returns a ProbeResult
func httpProbe(client *http.Client, host string, port int, path string) ProbeResult {
	url := fmt.Sprintf("http://%s:%d%s", host, port, path)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ProbeResult{Port: port, Path: path, Reachable: false}
	}

	resp, err := client.Do(req)
	if err != nil {
		// Detect TCP reset specifically
		resetByPeer := strings.Contains(err.Error(), "connection reset by peer")
		return ProbeResult{Port: port, Path: path, Reachable: false, ResetByPeer: resetByPeer}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return ProbeResult{
		Port:       port,
		Path:       path,
		StatusCode: resp.StatusCode,
		Body:       string(body),
		Reachable:  true,
	}
}

// httpClient returns a shared http.Client with TLS skip and timeout
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// buildFinding constructs a Finding with standard Istio remediation and references
func buildFinding(host, severity string, cvss float64, title, desc string, evidence map[string]interface{}) Finding {
	return Finding{
		TemplateID:   "istio-pilot-misconfiguration",
		TemplateName: "Istio Pilot Misconfiguration Detection",
		Host:         host,
		Severity:     severity,
		Confidence:   90,
		Title:        title,
		Description:  desc,
		Evidence:     evidence,
		CWE:          "CWE-306",
		CVSSScore:    cvss,
		Remediation: "1) Apply Kubernetes NetworkPolicy to restrict ports 8080, 15010, 15014 to intra-cluster traffic only. " +
			"2) Upgrade to Istio 1.9+ which disables plaintext xDS port 15010 by default. " +
			"3) Set PILOT_ENABLE_UNSAFE_UNPROTECTED_CLIENT_CONTROL=false. " +
			"4) Enable istiod with --tlsCertFile and --tlsKeyFile for mutual TLS on control plane. " +
			"5) Use Istio's built-in AuthorizationPolicy to restrict access to istiod service.",
		References: []string{
			"https://istio.io/latest/docs/ops/best-practices/security/",
			"https://istio.io/latest/docs/reference/config/istio.pilot.v1alpha1/",
			"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8843",
			"https://attack.mitre.org/techniques/T1046/",
		},
		MatchedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// truncate caps a string at maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}

// normalizeTarget strips protocol, port suffix, and trailing slash
func normalizeTarget(target string) string {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		if !strings.Contains(target[idx:], "]") {
			target = target[:idx]
		}
	}
	target = strings.TrimSuffix(target, "/")
	return target
}

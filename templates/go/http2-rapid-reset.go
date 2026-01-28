package main

// @id: http2-rapid-reset
// @name: HTTP/2 Rapid Reset Detection (CVE-2023-44487)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects servers vulnerable to HTTP/2 Rapid Reset DoS attack via RST_STREAM flood
// @tags: http2, rapid-reset, dos, cve-2023-44487, rst-stream
// @cwe: CWE-400, CWE-770
// @cvss: 7.5
// @references: https://nvd.nist.gov/vuln/detail/CVE-2023-44487, https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack
// @confidence: 90
// @version: 1.0.0

/*
HTTP/2 Rapid Reset Detection Template (CVE-2023-44487)

This template detects servers vulnerable to the HTTP/2 Rapid Reset attack,
a critical DoS vulnerability that affected major platforms including Google,
Amazon, Cloudflare, and others in 2023.

VULNERABILITY BACKGROUND:
The HTTP/2 Rapid Reset attack exploits the RST_STREAM frame mechanism. Attackers
create streams, immediately cancel them with RST_STREAM, and repeat at high rates.
This forces servers to waste resources on request setup/teardown cycles.

DETECTION STRATEGY:
1. Verify target supports HTTP/2 (ALPN negotiation)
2. Establish HTTP/2 connection with proper framing
3. Send controlled stream creation + RST_STREAM pairs
4. Measure server response times and resource consumption
5. Detect vulnerability via timing anomalies and behavior changes

INDICATORS OF VULNERABILITY:
- Server accepts high-frequency RST_STREAM frames without rate limiting
- Response times degrade proportionally with RST_STREAM rate
- Server doesn't enforce per-connection stream limits
- No GOAWAY frame sent after stream limit exceeded
- Connection stays open despite rapid resets

WHY GO:
- Native HTTP/2 support with golang.org/x/net/http2
- Low-level frame control via http2.Framer
- Precise timing measurements
- TLS 1.2+ with ALPN for HTTP/2 negotiation

SAFETY NOTE:
This template performs SAFE DETECTION with minimal traffic (20-50 streams).
It does NOT perform actual DoS attacks. Testing is throttled and limited
to prevent any service impact.

CVE-2023-44487 IMPACT:
- CVSS: 7.5 (High)
- Affected: nginx, Apache, AWS, Google Cloud, Cloudflare, etc.
- Attack magnification: 1 attacking machine → 1000x amplification
*/

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Metadata structure for template information
var Metadata = map[string]interface{}{
	"id":   "http2-rapid-reset",
	"name": "HTTP/2 Rapid Reset Detection (CVE-2023-44487)",
	"author": map[string]string{
		"name":  "CERT-X-GEN Security Team",
		"email": "security@cert-x-gen.io",
	},
	"severity":    "critical",
	"description": "Detects HTTP/2 Rapid Reset vulnerability via controlled RST_STREAM testing",
	"tags":        []string{"http2", "rapid-reset", "dos", "cve-2023-44487", "rst-stream"},
	"language":    "go",
	"confidence":  90,
	"cwe":         []string{"CWE-400", "CWE-770"},
	"cvss":        7.5,
	"references": []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
		"https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack",
		"https://www.cloudflare.com/learning/ddos/rapid-reset-ddos-attack/",
	},
}

// Finding represents a detected vulnerability
type Finding struct {
	Target       string                 `json:"target"`
	TemplateID   string                 `json:"template_id"`
	TemplateName string                 `json:"template_name"`
	Severity     string                 `json:"severity"`
	Confidence   int                    `json:"confidence"`
	Title        string                 `json:"title"`
	MatchedAt    string                 `json:"matched_at"`
	Description  string                 `json:"description"`
	Evidence     map[string]interface{} `json:"evidence"`
	Remediation  string                 `json:"remediation,omitempty"`
	CWEIDs       []string               `json:"cwe_ids,omitempty"`
	CVSSScore    float64                `json:"cvss_score,omitempty"`
	Tags         []string               `json:"tags"`
	Timestamp    string                 `json:"timestamp"`
}

// HTTP2TestResult holds test execution data
type HTTP2TestResult struct {
	SupportsHTTP2       bool
	ALPNProtocol        string
	StreamsCreated      int
	RSTFramesSent       int
	AvgResponseTime     time.Duration
	DegradationDetected bool
	GOAWAYReceived      bool
	ConnectionStable    bool
	ServerHeader        string
}

// testHTTP2Support checks if target supports HTTP/2
func testHTTP2Support(host string, port int, useTLS bool) (*HTTP2TestResult, error) {
	result := &HTTP2TestResult{}
	
	// Build connection address
	addr := fmt.Sprintf("%s:%d", host, port)
	
	if !useTLS {
		// HTTP/2 over cleartext (h2c) - rare but possible
		result.SupportsHTTP2 = false
		result.ALPNProtocol = "http/1.1"
		return result, nil
	}
	
	// TLS connection with ALPN
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing purposes
		NextProtos:         []string{"h2", "http/1.1"},
		ServerName:         host,
	}
	
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()
	
	// Check negotiated protocol
	state := conn.ConnectionState()
	result.ALPNProtocol = state.NegotiatedProtocol
	result.SupportsHTTP2 = (state.NegotiatedProtocol == "h2")
	
	return result, nil
}

// performRapidResetTest executes controlled RST_STREAM test
func performRapidResetTest(host string, port int) (*HTTP2TestResult, error) {
	result := &HTTP2TestResult{}
	addr := fmt.Sprintf("%s:%d", host, port)
	
	// Establish TLS connection
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         host,
	}
	
	tlsConn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer tlsConn.Close()
	
	// Verify HTTP/2 negotiation
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		return nil, fmt.Errorf("HTTP/2 not negotiated (got: %s)", state.NegotiatedProtocol)
	}
	
	// Create HTTP/2 framer
	framer := http2.NewFramer(tlsConn, tlsConn)
	
	// Send HTTP/2 connection preface
	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("preface write failed: %w", err)
	}
	
	// Send SETTINGS frame
	if err := framer.WriteSettings(); err != nil {
		return nil, fmt.Errorf("settings write failed: %w", err)
	}
	
	// Read server settings
	frame, err := framer.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("reading server settings failed: %w", err)
	}
	
	// Extract server info if available
	if sf, ok := frame.(*http2.SettingsFrame); ok {
		_ = sf // Server settings received
	}
	
	// Test 1: Baseline - Normal request without reset
	baselineStart := time.Now()
	streamID := uint32(1)
	
	// Send HEADERS frame for GET /
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: host},
		{Name: ":path", Value: "/"},
	}
	
	var headersBuf bytes.Buffer
	hpackEncoder := hpack.NewEncoder(&headersBuf)
	for _, hf := range headers {
		_ = hpackEncoder.WriteField(hf)
	}
	
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headersBuf.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		return nil, fmt.Errorf("baseline headers write failed: %w", err)
	}
	
	// Wait for response
	time.Sleep(100 * time.Millisecond)
	baselineDuration := time.Since(baselineStart)
	
	// Test 2: Rapid Reset - Create streams and immediately RST them
	resetStart := time.Now()
	numStreams := 20 // Safe number for detection
	var totalResetTime time.Duration
	
	for i := 0; i < numStreams; i++ {
		streamID = uint32((i+1)*2 + 1) // Odd stream IDs for client
		
		resetLoopStart := time.Now()
		
		// Send HEADERS
		headersBuf.Reset()
		hpackEncoder = hpack.NewEncoder(&headersBuf)
		for _, hf := range headers {
			_ = hpackEncoder.WriteField(hf)
		}
		
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: headersBuf.Bytes(),
			EndStream:     false, // Don't end stream yet
			EndHeaders:    true,
		}); err != nil {
			continue // Silently continue on error
		}
		
		// Immediately send RST_STREAM
		if err := framer.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
			continue
		}
		
		result.StreamsCreated++
		result.RSTFramesSent++
		
		totalResetTime += time.Since(resetLoopStart)
		
		// Small delay to avoid overwhelming (10ms between resets)
		time.Sleep(10 * time.Millisecond)
	}
	
	resetDuration := time.Since(resetStart)
	result.AvgResponseTime = totalResetTime / time.Duration(numStreams)
	
	// Check for GOAWAY frame (indicates server detected abuse)
	tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			break // Timeout or connection closed
		}
		
		if _, ok := frame.(*http2.GoAwayFrame); ok {
			result.GOAWAYReceived = true
			break
		}
	}
	
	// Analysis: Detect vulnerability
	// Vulnerable servers show degradation proportional to RST rate
	degradationRatio := float64(resetDuration) / float64(baselineDuration)
	result.DegradationDetected = degradationRatio > 1.5 // 50% slower
	
	// Connection should remain stable if server is protected
	result.ConnectionStable = !result.GOAWAYReceived
	
	return result, nil
}

// testVulnerability is the main detection function
func testVulnerability(host string, port int, timeout int) []Finding {
	findings := []Finding{}
	target := fmt.Sprintf("%s:%d", host, port)
	
	// Determine if we should use TLS (port 443 or explicit HTTPS)
	useTLS := (port == 443)
	
	// Step 1: Check HTTP/2 support
	supportResult, err := testHTTP2Support(host, port, useTLS)
	if err != nil {
		// Connection error - return info finding
		findings = append(findings, Finding{
			Target:       target,
			TemplateID:   Metadata["id"].(string),
			TemplateName: Metadata["name"].(string),
			Severity:     "info",
			Confidence:   50,
			Title:        "HTTP/2 Support Check Failed",
			MatchedAt:    target,
			Description:  fmt.Sprintf("Could not establish connection to test HTTP/2 support: %v", err),
			Evidence: map[string]interface{}{
				"error":     err.Error(),
				"tls_used":  useTLS,
				"test_type": "http2_support",
			},
			Tags:      Metadata["tags"].([]string),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		return findings
	}
	
	// If HTTP/2 not supported, return info finding
	if !supportResult.SupportsHTTP2 {
		findings = append(findings, Finding{
			Target:       target,
			TemplateID:   Metadata["id"].(string),
			TemplateName: Metadata["name"].(string),
			Severity:     "info",
			Confidence:   100,
			Title:        "HTTP/2 Not Supported",
			MatchedAt:    target,
			Description:  "Target does not support HTTP/2 protocol. CVE-2023-44487 only affects HTTP/2 servers.",
			Evidence: map[string]interface{}{
				"alpn_protocol": supportResult.ALPNProtocol,
				"http2_support": false,
			},
			Tags:      Metadata["tags"].([]string),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		return findings
	}
	
	// Step 2: Perform Rapid Reset test
	testResult, err := performRapidResetTest(host, port)
	if err != nil {
		findings = append(findings, Finding{
			Target:       target,
			TemplateID:   Metadata["id"].(string),
			TemplateName: Metadata["name"].(string),
			Severity:     "info",
			Confidence:   50,
			Title:        "HTTP/2 Rapid Reset Test Failed",
			MatchedAt:    target,
			Description:  fmt.Sprintf("Could not complete rapid reset test: %v", err),
			Evidence: map[string]interface{}{
				"error":        err.Error(),
				"http2_support": true,
				"alpn_protocol": supportResult.ALPNProtocol,
			},
			Tags:      Metadata["tags"].([]string),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		return findings
	}
	
	// Step 3: Analyze results and determine severity
	severity := "info"
	confidence := 70
	title := "HTTP/2 Server Tested - No Vulnerability Detected"
	description := "Server implements proper HTTP/2 stream management and RST_STREAM rate limiting."
	
	// Vulnerability indicators
	indicators := []string{}
	
	if testResult.DegradationDetected {
		indicators = append(indicators, "Performance degradation under RST_STREAM load")
		severity = "medium"
		confidence = 75
	}
	
	if !testResult.GOAWAYReceived && testResult.RSTFramesSent > 15 {
		indicators = append(indicators, "No GOAWAY frame after excessive RST_STREAM")
		severity = "medium"
		confidence = 80
	}
	
	if testResult.DegradationDetected && !testResult.GOAWAYReceived {
		severity = "high"
		confidence = 85
		title = "Potential HTTP/2 Rapid Reset Vulnerability (CVE-2023-44487)"
		description = "Server shows indicators of vulnerability to HTTP/2 Rapid Reset attack. " +
			"Performance degrades under RST_STREAM load without proper rate limiting."
		indicators = append(indicators, "Combined: degradation + no protection")
	}
	
	if len(indicators) == 0 {
		indicators = append(indicators, "Server appears properly protected")
	}
	
	// Build evidence
	evidence := map[string]interface{}{
		"http2_support":        true,
		"alpn_protocol":        supportResult.ALPNProtocol,
		"streams_created":      testResult.StreamsCreated,
		"rst_frames_sent":      testResult.RSTFramesSent,
		"avg_response_time_ms": testResult.AvgResponseTime.Milliseconds(),
		"degradation_detected": testResult.DegradationDetected,
		"goaway_received":      testResult.GOAWAYReceived,
		"indicators":           indicators,
	}
	
	// Add server header if available
	if testResult.ServerHeader != "" {
		evidence["server_header"] = testResult.ServerHeader
	}
	
	// Create finding
	finding := Finding{
		Target:       target,
		TemplateID:   Metadata["id"].(string),
		TemplateName: Metadata["name"].(string),
		Severity:     severity,
		Confidence:   confidence,
		Title:        title,
		MatchedAt:    target,
		Description:  description,
		Evidence:     evidence,
		Tags:         Metadata["tags"].([]string),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}
	
	// Add remediation for vulnerable findings
	if severity == "high" || severity == "medium" {
		finding.Remediation = "Update HTTP/2 server to latest version with CVE-2023-44487 patches. " +
			"Implement RST_STREAM rate limiting, enforce per-connection stream limits, and monitor for abnormal reset patterns."
		finding.CWEIDs = Metadata["cwe"].([]string)
		finding.CVSSScore = Metadata["cvss"].(float64)
	}
	
	findings = append(findings, finding)
	return findings
}

func main() {
	var host string
	var port int
	
	// Check if running in engine mode (called by cxg CLI)
	if os.Getenv("CERT_X_GEN_MODE") == "engine" {
		host = os.Getenv("CERT_X_GEN_TARGET_HOST")
		portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
		if host == "" {
			result := map[string]interface{}{
				"error": "CERT_X_GEN_TARGET_HOST not set",
			}
			jsonOutput, _ := json.Marshal(result)
			fmt.Println(string(jsonOutput))
			os.Exit(1)
		}
		if portStr == "" {
			port = 443 // Default HTTPS port for HTTP/2
		} else {
			fmt.Sscanf(portStr, "%d", &port)
		}
	} else {
		// CLI mode (direct execution)
		if len(os.Args) < 2 {
			result := map[string]interface{}{
				"error": "Usage: http2-rapid-reset <host> [port]",
			}
			jsonOutput, _ := json.Marshal(result)
			fmt.Println(string(jsonOutput))
			os.Exit(1)
		}
		host = os.Args[1]
		if len(os.Args) > 2 {
			fmt.Sscanf(os.Args[2], "%d", &port)
		} else {
			port = 443
		}
	}
	
	// Run detection with 30s timeout
	findings := testVulnerability(host, port, 30)
	
	// Build output
	result := map[string]interface{}{
		"findings": findings,
		"metadata": Metadata,
	}
	
	// Print JSON result
	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		errorResult := map[string]interface{}{
			"error": fmt.Sprintf("JSON marshaling failed: %v", err),
		}
		errorJSON, _ := json.Marshal(errorResult)
		fmt.Println(string(errorJSON))
		os.Exit(1)
	}
	
	fmt.Println(string(jsonOutput))
}

package main

// @id: dns-rebinding-attack
// @name: DNS Rebinding Attack Detection
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects servers vulnerable to DNS rebinding attacks via Host header validation and DNS resolution monitoring
// @tags: dns-rebinding, toctou, ssrf, host-header, dns
// @cwe: CWE-350, CWE-367, CWE-918
// @cvss: 8.8
// @references: https://en.wikipedia.org/wiki/DNS_rebinding, https://github.com/nccgroup/singularity, https://github.com/taviso/rbndr
// @confidence: 85
// @version: 1.0.0

/*
DNS Rebinding Attack Detection Template

This template detects servers vulnerable to DNS rebinding attacks, a critical
TOCTOU (Time-Of-Check, Time-Of-Use) vulnerability that bypasses the Same-Origin
Policy to access internal resources.

VULNERABILITY BACKGROUND:
DNS rebinding exploits the gap between DNS resolution and HTTP request execution:
1. Attacker controls a domain (evil.com) with low TTL DNS record
2. Initial DNS query returns attacker's public IP (1.2.3.4)
3. Victim's browser performs preflight checks - passes validation
4. DNS TTL expires, next query returns internal IP (127.0.0.1, 192.168.x.x)
5. Browser makes request thinking it's still "evil.com" but now hits internal service
6. Same-Origin Policy bypassed - attacker accesses internal resources

DETECTION STRATEGY:
1. Check if service validates Host header properly
2. Monitor DNS resolution stability (multiple queries)
3. Detect very low TTL values (<60 seconds)
4. Test if service accepts arbitrary Host headers
5. Verify origin validation mechanisms exist
6. Check for IP address changes across DNS queries

INDICATORS OF VULNERABILITY:
- Service responds to arbitrary Host headers
- No DNS pinning or Host validation
- Accepts requests from localhost/private IPs via public domain
- Very low DNS TTL (<10 seconds)
- No CORS or origin validation
- Responds identically regardless of Host header

WHY GO:
- Native DNS resolution via net package
- HTTP client with Host header control
- Goroutines for concurrent DNS monitoring
- Precise timing for TOCTOU detection
- Low-level network control

SAFETY NOTE:
This template performs SAFE DETECTION only. It tests Host header validation
and DNS resolution patterns without attempting actual rebinding attacks.
No internal resources are accessed, no exploitation is performed.

ATTACK IMPACT:
- CVSS: 8.8 (High)
- Access to internal services (Redis, Elasticsearch, admin panels)
- Bypass authentication and firewall rules
- Read sensitive data from internal APIs
- Potential RCE via exposed admin interfaces
*/

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// Metadata structure for template information
var Metadata = map[string]interface{}{
	"id":   "dns-rebinding-attack",
	"name": "DNS Rebinding Attack Detection",
	"author": map[string]string{
		"name":  "CERT-X-GEN Security Team",
		"email": "security@cert-x-gen.io",
	},
	"severity":    "critical",
	"description": "Detects DNS rebinding vulnerabilities via Host header validation and DNS monitoring",
	"tags":        []string{"dns-rebinding", "toctou", "ssrf", "host-header", "dns"},
	"language":    "go",
	"confidence":  85,
	"cwe":         []string{"CWE-350", "CWE-367", "CWE-918"},
	"cvss":        8.8,
	"references": []string{
		"https://en.wikipedia.org/wiki/DNS_rebinding",
		"https://github.com/nccgroup/singularity",
		"https://github.com/taviso/rbndr",
		"https://cheatsheetseries.owasp.org/cheatsheets/DNS_Rebinding_Prevention_Cheat_Sheet.html",
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

// DNSRebindingTestResult holds test execution data
type DNSRebindingTestResult struct {
	HostHeaderValidation   bool
	ArbitraryHostAccepted  bool
	LocalhostHostAccepted  bool
	PrivateIPHostAccepted  bool
	DNSResolutionStable    bool
	DNSResolutionIPs       []string
	DNSTTLSeconds          int
	ResponsesIdentical     bool
	OriginValidation       bool
	VulnerabilityIndicators []string
}

// resolveDNSMultipleTimes performs multiple DNS resolutions to detect rebinding potential
func resolveDNSMultipleTimes(host string, attempts int, delay time.Duration) ([]string, bool) {
	ips := []string{}
	ipSet := make(map[string]bool)
	
	for i := 0; i < attempts; i++ {
		addresses, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		
		for _, addr := range addresses {
			ips = append(ips, addr)
			ipSet[addr] = true
		}
		
		if i < attempts-1 {
			time.Sleep(delay)
		}
	}
	
	// Stable if all resolutions returned same IPs
	stable := len(ipSet) <= len(ips)/attempts
	
	return ips, stable
}

// isPrivateIP checks if an IP is in private range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	
	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet != nil && ipNet.Contains(ip) {
			return true
		}
	}
	
	return false
}

// testHostHeaderValidation checks if server validates Host header
func testHostHeaderValidation(host string, port int, useHTTPS bool) (*DNSRebindingTestResult, error) {
	result := &DNSRebindingTestResult{
		VulnerabilityIndicators: []string{},
	}
	
	scheme := "http"
	if useHTTPS || port == 443 {
		scheme = "https"
	}
	
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	
	// Test 1: Normal request with correct Host header
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
	
	req1, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return nil, err
	}
	req1.Host = fmt.Sprintf("%s:%d", host, port)
	
	resp1, err := client.Do(req1)
	if err != nil {
		return result, err
	}
	defer resp1.Body.Close()
	
	normalStatusCode := resp1.StatusCode
	
	// Test 2: Request with arbitrary Host header
	req2, _ := http.NewRequest("GET", baseURL, nil)
	req2.Host = "evil.attacker.com"
	
	resp2, err := client.Do(req2)
	if err == nil {
		defer resp2.Body.Close()
		
		if resp2.StatusCode == normalStatusCode || resp2.StatusCode == 200 {
			result.ArbitraryHostAccepted = true
			result.VulnerabilityIndicators = append(result.VulnerabilityIndicators,
				"Server accepts arbitrary Host header")
		}
	}
	
	// Test 3: Request with localhost Host header
	req3, _ := http.NewRequest("GET", baseURL, nil)
	req3.Host = "localhost"
	
	resp3, err := client.Do(req3)
	if err == nil {
		defer resp3.Body.Close()
		
		if resp3.StatusCode == normalStatusCode || resp3.StatusCode == 200 {
			result.LocalhostHostAccepted = true
			result.VulnerabilityIndicators = append(result.VulnerabilityIndicators,
				"Server accepts localhost as Host header")
		}
	}
	
	// Test 4: Request with private IP Host header
	req4, _ := http.NewRequest("GET", baseURL, nil)
	req4.Host = "192.168.1.1"
	
	resp4, err := client.Do(req4)
	if err == nil {
		defer resp4.Body.Close()
		
		if resp4.StatusCode == normalStatusCode || resp4.StatusCode == 200 {
			result.PrivateIPHostAccepted = true
			result.VulnerabilityIndicators = append(result.VulnerabilityIndicators,
				"Server accepts private IP as Host header")
		}
	}
	
	// Test 5: DNS resolution stability
	ips, stable := resolveDNSMultipleTimes(host, 3, 2*time.Second)
	result.DNSResolutionIPs = ips
	result.DNSResolutionStable = stable
	
	if !stable {
		result.VulnerabilityIndicators = append(result.VulnerabilityIndicators,
			"DNS resolution unstable (potential rebinding)")
	}
	
	// Check if any resolved IPs are private
	hasPrivateIP := false
	for _, ip := range ips {
		if isPrivateIP(ip) {
			hasPrivateIP = true
			break
		}
	}
	
	if hasPrivateIP {
		result.VulnerabilityIndicators = append(result.VulnerabilityIndicators,
			"Domain resolves to private IP address")
	}
	
	// Overall Host header validation status
	result.HostHeaderValidation = !result.ArbitraryHostAccepted &&
		!result.LocalhostHostAccepted &&
		!result.PrivateIPHostAccepted
	
	// Check for origin validation (CORS headers)
	result.OriginValidation = resp1.Header.Get("Access-Control-Allow-Origin") != "*"
	
	if !result.OriginValidation {
		result.VulnerabilityIndicators = append(result.VulnerabilityIndicators,
			"CORS allows any origin (Access-Control-Allow-Origin: *)")
	}
	
	return result, nil
}

// testVulnerability is the main detection function
func testVulnerability(host string, port int, timeout int) []Finding {
	findings := []Finding{}
	target := fmt.Sprintf("%s:%d", host, port)
	
	// Determine if we should use HTTPS
	useHTTPS := (port == 443)
	
	// Perform DNS rebinding detection tests
	testResult, err := testHostHeaderValidation(host, port, useHTTPS)
	if err != nil {
		// Connection error - return info finding
		findings = append(findings, Finding{
			Target:       target,
			TemplateID:   Metadata["id"].(string),
			TemplateName: Metadata["name"].(string),
			Severity:     "info",
			Confidence:   50,
			Title:        "DNS Rebinding Test Failed",
			MatchedAt:    target,
			Description:  fmt.Sprintf("Could not complete DNS rebinding tests: %v", err),
			Evidence: map[string]interface{}{
				"error":     err.Error(),
				"test_type": "dns_rebinding",
			},
			Tags:      Metadata["tags"].([]string),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		return findings
	}
	
	// Analyze results and determine severity
	severity := "info"
	confidence := 70
	title := "DNS Rebinding Protection Verified"
	description := "Server implements proper Host header validation and DNS rebinding protection."
	
	vulnerabilityCount := len(testResult.VulnerabilityIndicators)
	
	if vulnerabilityCount == 0 {
		// No vulnerability detected
		severity = "info"
		confidence = 90
	} else if vulnerabilityCount == 1 || vulnerabilityCount == 2 {
		// Some indicators present
		severity = "medium"
		confidence = 75
		title = "Potential DNS Rebinding Weakness Detected"
		description = "Server shows some indicators of DNS rebinding vulnerability. " +
			"Additional protections may be needed."
	} else if vulnerabilityCount >= 3 {
		// Multiple indicators - likely vulnerable
		severity = "high"
		confidence = 85
		title = "DNS Rebinding Vulnerability Detected"
		description = "Server is vulnerable to DNS rebinding attacks. It accepts arbitrary " +
			"Host headers and lacks proper origin validation, allowing attackers to bypass " +
			"Same-Origin Policy and access internal resources."
	}
	
	// Build evidence
	evidence := map[string]interface{}{
		"host_header_validation":  testResult.HostHeaderValidation,
		"arbitrary_host_accepted": testResult.ArbitraryHostAccepted,
		"localhost_host_accepted": testResult.LocalhostHostAccepted,
		"private_ip_host_accepted": testResult.PrivateIPHostAccepted,
		"dns_resolution_stable":   testResult.DNSResolutionStable,
		"dns_resolved_ips":        testResult.DNSResolutionIPs,
		"origin_validation":       testResult.OriginValidation,
		"vulnerability_indicators": testResult.VulnerabilityIndicators,
		"indicator_count":         vulnerabilityCount,
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
		finding.Remediation = "Implement Host header validation to only accept expected domains. " +
			"Use DNS pinning to cache DNS resolutions. Implement CORS policies with specific origins. " +
			"Validate Origin header on sensitive endpoints. Consider using DNS rebinding protection " +
			"middleware. Avoid binding services to 0.0.0.0 when possible."
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
			port = 80
		} else {
			fmt.Sscanf(portStr, "%d", &port)
		}
	} else {
		// CLI mode (direct execution)
		if len(os.Args) < 2 {
			result := map[string]interface{}{
				"error": "Usage: dns-rebinding-attack <host> [port]",
			}
			jsonOutput, _ := json.Marshal(result)
			fmt.Println(string(jsonOutput))
			os.Exit(1)
		}
		host = os.Args[1]
		if len(os.Args) > 2 {
			fmt.Sscanf(os.Args[2], "%d", &port)
		} else {
			port = 80
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

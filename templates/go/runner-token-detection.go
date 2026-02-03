package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Template: Runner Token Detection
// Purpose: Detects exposed CI/CD runner tokens (GitLab, GitHub Actions, Jenkins)
// Severity: CRITICAL
// CWE: CWE-522 (Insufficiently Protected Credentials)

type Finding struct {
	Severity     string   `json:"severity"`
	Confidence   int      `json:"confidence"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	CWE          string   `json:"cwe,omitempty"`
	Remediation  string   `json:"remediation"`
	References   []string `json:"references,omitempty"`
}

type Metadata struct {
	HTTPAccessible   bool     `json:"http_accessible"`
	EndpointsTested  int      `json:"endpoints_tested"`
	TokensFound      int      `json:"tokens_found"`
	TokenTypes       []string `json:"token_types"`
}

type ScanResult struct {
	Template  string    `json:"template"`
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	Timestamp string    `json:"timestamp"`
	Findings  []Finding `json:"findings"`
	Metadata  Metadata  `json:"metadata"`
}

type RunnerTokenDetector struct {
	target  string
	port    int
	timeout time.Duration
	client  *http.Client
}

func NewRunnerTokenDetector(target string, port int) *RunnerTokenDetector {
	return &RunnerTokenDetector{
		target:  target,
		port:    port,
		timeout: 10 * time.Second,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (d *RunnerTokenDetector) Scan() ScanResult {
	result := ScanResult{
		Template:  "runner-token-detection",
		Target:    d.target,
		Port:      d.port,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Metadata: Metadata{
			HTTPAccessible: false,
			EndpointsTested: 0,
			TokensFound:    0,
			TokenTypes:     []string{},
		},
	}

	// Check HTTP accessibility
	if !d.checkHTTPAccessible() {
		result.Findings = append(result.Findings, Finding{
			Severity:    "info",
			Confidence:  100,
			Title:       "HTTP Service Not Accessible",
			Description: fmt.Sprintf("HTTP service not accessible on %s:%d", d.target, d.port),
			Remediation: "Verify target is running an HTTP server",
		})
		return result
	}

	result.Metadata.HTTPAccessible = true

	// Test various endpoints for token exposure
	endpoints := d.getTestEndpoints()
	result.Metadata.EndpointsTested = len(endpoints)

	vulnerabilities := d.testTokenExposure(endpoints)
	
	if len(vulnerabilities) > 0 {
		result.Findings = append(result.Findings, vulnerabilities...)
		result.Metadata.TokensFound = len(vulnerabilities)
		
		// Extract token types
		tokenTypes := make(map[string]bool)
		for _, vuln := range vulnerabilities {
			if strings.Contains(vuln.Title, "GitLab") {
				tokenTypes["GitLab Runner"] = true
			} else if strings.Contains(vuln.Title, "GitHub") {
				tokenTypes["GitHub Actions"] = true
			} else if strings.Contains(vuln.Title, "Jenkins") {
				tokenTypes["Jenkins"] = true
			}
		}
		for tokenType := range tokenTypes {
			result.Metadata.TokenTypes = append(result.Metadata.TokenTypes, tokenType)
		}
	} else {
		result.Findings = append(result.Findings, Finding{
			Severity:    "info",
			Confidence:  80,
			Title:       "No Exposed Runner Tokens Detected",
			Description: fmt.Sprintf("Tested %d endpoints - no runner tokens found", result.Metadata.EndpointsTested),
			Remediation: "Continue following CI/CD security best practices",
		})
	}

	return result
}

func (d *RunnerTokenDetector) checkHTTPAccessible() bool {
	scheme := "http"
	if d.port == 443 {
		scheme = "https"
	}
	
	url := fmt.Sprintf("%s://%s:%d/", scheme, d.target, d.port)
	resp, err := d.client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return true
}

func (d *RunnerTokenDetector) getTestEndpoints() []string {
	return []string{
		"/.gitlab-runner",
		"/.gitlab-ci.yml",
		"/admin/runners",
		"/api/v4/runners",
		"/runners",
		"/.github/workflows",
		"/actions/runners",
		"/.env",
		"/config.toml",
		"/runner-config.toml",
		"/ci/config",
		"/jenkins/credentials",
		"/credentials.xml",
	}
}

func (d *RunnerTokenDetector) testTokenExposure(endpoints []string) []Finding {
	var findings []Finding
	foundTokens := make(map[string]bool)

	scheme := "http"
	if d.port == 443 {
		scheme = "https"
	}

	for _, endpoint := range endpoints {
		url := fmt.Sprintf("%s://%s:%d%s", scheme, d.target, d.port, endpoint)
		
		resp, err := d.client.Get(url)
		if err != nil {
			continue
		}
		
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if err != nil {
			continue
		}

		bodyStr := string(body)
		
		// Check for GitLab runner tokens
		if d.containsGitLabToken(bodyStr) {
			tokenKey := "gitlab-" + endpoint
			if !foundTokens[tokenKey] {
				foundTokens[tokenKey] = true
				findings = append(findings, Finding{
					Severity:    "critical",
					Confidence:  90,
					Title:       "GitLab Runner Token Exposed",
					Description: fmt.Sprintf("Endpoint '%s' exposes GitLab runner token. This allows attackers to register malicious runners and execute code in your CI/CD pipeline.", endpoint),
					CWE:         "CWE-522",
					Remediation: "1. Immediately revoke exposed runner token\n2. Register new runner with fresh token\n3. Restrict access to runner configuration files\n4. Use environment variables for sensitive data\n5. Implement proper access controls on CI/CD endpoints\n6. Enable audit logging for runner registration",
					References: []string{
						"https://docs.gitlab.com/runner/security/",
						"https://about.gitlab.com/blog/2021/04/28/devops-platform-supply-chain-attacks/",
					},
				})
			}
		}

		// Check for GitHub Actions tokens
		if d.containsGitHubToken(bodyStr) {
			tokenKey := "github-" + endpoint
			if !foundTokens[tokenKey] {
				foundTokens[tokenKey] = true
				findings = append(findings, Finding{
					Severity:    "critical",
					Confidence:  85,
					Title:       "GitHub Actions Token Exposed",
					Description: fmt.Sprintf("Endpoint '%s' exposes GitHub Actions runner token. Attackers can use this to register malicious self-hosted runners.", endpoint),
					CWE:         "CWE-522",
					Remediation: "1. Revoke exposed runner token immediately\n2. Remove and re-register self-hosted runners\n3. Use GitHub Secrets for sensitive data\n4. Enable runner group access controls\n5. Implement IP allowlisting for runners\n6. Monitor runner activity logs",
					References: []string{
						"https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners",
						"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
					},
				})
			}
		}

		// Check for Jenkins credentials
		if d.containsJenkinsToken(bodyStr) {
			tokenKey := "jenkins-" + endpoint
			if !foundTokens[tokenKey] {
				foundTokens[tokenKey] = true
				findings = append(findings, Finding{
					Severity:    "critical",
					Confidence:  85,
					Title:       "Jenkins Credentials Exposed",
					Description: fmt.Sprintf("Endpoint '%s' exposes Jenkins credentials or agent tokens. This allows unauthorized access to Jenkins build environment.", endpoint),
					CWE:         "CWE-522",
					Remediation: "1. Rotate all exposed Jenkins credentials\n2. Restrict access to credentials.xml\n3. Use Jenkins Credentials Plugin properly\n4. Enable Matrix Authorization Strategy\n5. Implement CSRF protection\n6. Use SSH keys instead of passwords",
					References: []string{
						"https://www.jenkins.io/doc/book/security/",
						"https://www.jenkins.io/doc/book/using/using-credentials/",
					},
				})
			}
		}

		// Check for generic runner tokens in config files
		if resp.StatusCode == 200 && (strings.Contains(endpoint, "config") || strings.Contains(endpoint, ".env")) {
			if d.containsGenericToken(bodyStr) {
				tokenKey := "generic-" + endpoint
				if !foundTokens[tokenKey] {
					foundTokens[tokenKey] = true
					findings = append(findings, Finding{
						Severity:    "high",
						Confidence:  75,
						Title:       "Potential Runner Token in Configuration File",
						Description: fmt.Sprintf("Endpoint '%s' contains what appears to be a runner token or credential in a configuration file.", endpoint),
						CWE:         "CWE-522",
						Remediation: "1. Review exposed configuration for sensitive data\n2. Use secret management solutions\n3. Never commit tokens to version control\n4. Rotate any potentially exposed credentials",
					})
				}
			}
		}
	}

	return findings
}

func (d *RunnerTokenDetector) containsGitLabToken(content string) bool {
	// GitLab runner tokens typically start with specific prefixes
	indicators := []string{
		"token =",
		"registration_token",
		"runner-token",
		"glrt-",
		"GR1348941",
		"gitlab-runner",
	}
	
	contentLower := strings.ToLower(content)
	for _, indicator := range indicators {
		if strings.Contains(contentLower, strings.ToLower(indicator)) {
			// Check if it looks like an actual token (not just the word)
			if strings.Contains(content, "glrt-") || 
			   (strings.Contains(contentLower, "token") && len(content) > 100) {
				return true
			}
		}
	}
	return false
}

func (d *RunnerTokenDetector) containsGitHubToken(content string) bool {
	indicators := []string{
		"ACTIONS_RUNNER_TOKEN",
		"RUNNER_TOKEN",
		"github_token",
		"runner registration token",
	}
	
	contentLower := strings.ToLower(content)
	for _, indicator := range indicators {
		if strings.Contains(contentLower, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}

func (d *RunnerTokenDetector) containsJenkinsToken(content string) bool {
	indicators := []string{
		"<secret>",
		"<privateKey>",
		"jenkins.security",
		"credentials.xml",
		"apiToken",
	}
	
	for _, indicator := range indicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

func (d *RunnerTokenDetector) containsGenericToken(content string) bool {
	// Look for token-like patterns
	indicators := []string{
		"token",
		"secret",
		"password",
		"api_key",
		"private_key",
	}
	
	contentLower := strings.ToLower(content)
	
	// Check if content has token indicators and looks like config
	hasIndicator := false
	for _, indicator := range indicators {
		if strings.Contains(contentLower, indicator) {
			hasIndicator = true
			break
		}
	}
	
	// Also check for base64-like or long alphanumeric strings
	hasLongString := strings.Contains(content, "=") && len(content) > 200
	
	return hasIndicator && hasLongString
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: runner-token-detection <target> <port>\n")
		os.Exit(1)
	}

	target := os.Args[1]
	var port int
	if _, err := fmt.Sscanf(os.Args[2], "%d", &port); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Port must be an integer\n")
		os.Exit(1)
	}

	detector := NewRunnerTokenDetector(target, port)
	result := detector.Scan()

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating output: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}

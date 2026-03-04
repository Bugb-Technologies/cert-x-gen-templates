// CERT-X-GEN Go Template - Git History Secret Scan
//
// @id: git-history-secret-scan
// @name: Git History Secret Scan
// @author: BugB Technologies
// @severity: critical
// @description: Detects exposed .git directories on web servers that allow reconstruction of repository history and extraction of credentials, API keys, tokens, and other secrets from commit history and configuration files.
// @tags: git, secret-exposure, credential-leak, misconfiguration, source-code-disclosure, devops
// @cwe: CWE-312
// @confidence: 95
// @references: https://cwe.mitre.org/data/definitions/312.html, https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces, https://nvd.nist.gov/vuln/search/results?query=git+exposure

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
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

// SecretPattern holds a regex pattern and its classification
type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Redact  bool // if true, mask the matched value in evidence
}

// secretPatterns is the list of credential/secret regexes to scan for
var secretPatterns = []SecretPattern{
	{Name: "AWS Access Key ID", Pattern: regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), Redact: true},
	{Name: "AWS Secret Key", Pattern: regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['":\s=][A-Za-z0-9/+]{40}`), Redact: true},
	{Name: "Generic API Key", Pattern: regexp.MustCompile(`(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:'"]+\s*([A-Za-z0-9\-_]{16,64})`), Redact: true},
	{Name: "Generic Password", Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:'"]+\s*([^\s'"&]{8,64})`), Redact: true},
	{Name: "Database URL with Credentials", Pattern: regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis|amqp|ftp)://[^:]+:[^@\s]+@`), Redact: true},
	{Name: "Private Key Header", Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`), Redact: false},
	{Name: "GitHub Token", Pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`), Redact: true},
	{Name: "Generic Bearer Token", Pattern: regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,500}`), Redact: true},
	{Name: "Slack Webhook", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), Redact: true},
	{Name: "Stripe Key", Pattern: regexp.MustCompile(`(?:r|s)k_(live|test)_[A-Za-z0-9]{24,}`), Redact: true},
	{Name: "Google API Key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Redact: true},
	{Name: "Twilio Key", Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Redact: true},
	{Name: "Credentials in URL", Pattern: regexp.MustCompile(`https?://[^:]+:[^@\s]{4,}@[a-zA-Z0-9\-_.]+`), Redact: true},
}

// newHTTPClient returns an http.Client with TLS verification disabled and a
// given timeout. Many self-signed deployments reject strict TLS, so we skip
// verification for detection purposes only.
func newHTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - intentional for scanning
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		// Do NOT follow redirects automatically – a redirect away from /.git/
		// means the path is protected or not present.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// fetchGitFile fetches a file from the target's .git directory.
// Returns (body, statusCode, error).
func fetchGitFile(ctx context.Context, client *http.Client, baseURL, gitPath string) (string, int, error) {
	url := fmt.Sprintf("%s/.git/%s", strings.TrimRight(baseURL, "/"), gitPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; cert-x-gen-scanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	// Read up to 64 KB to prevent memory exhaustion on honeypots
	limitedReader := io.LimitReader(resp.Body, 64*1024)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", resp.StatusCode, err
	}

	return string(body), resp.StatusCode, nil
}

// isGitHeadResponse returns true if the body looks like a real .git/HEAD file.
func isGitHeadResponse(body string) bool {
	body = strings.TrimSpace(body)
	return strings.HasPrefix(body, "ref: refs/heads/") ||
		(len(body) == 40 && isHexString(body))
}

// isHexString checks if s is a 40-char hex string (detached HEAD SHA).
func isHexString(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// scanForSecrets scans content for all secret patterns.
// Returns a slice of matched evidence items (with redaction).
type secretMatch struct {
	PatternName string `json:"pattern_name"`
	Preview     string `json:"preview"` // redacted if Redact=true
}

func scanForSecrets(content string) []secretMatch {
	var matches []secretMatch
	seen := make(map[string]bool)

	for _, sp := range secretPatterns {
		found := sp.Pattern.FindAllString(content, -1)
		for _, match := range found {
			key := sp.Name + ":" + match
			if seen[key] {
				continue
			}
			seen[key] = true

			preview := match
			if sp.Redact && len(preview) > 12 {
				// Show first 4 + last 4 chars with asterisks in between
				preview = preview[:4] + strings.Repeat("*", len(preview)-8) + preview[len(preview)-4:]
			}
			matches = append(matches, secretMatch{
				PatternName: sp.Name,
				Preview:     preview,
			})
		}
	}
	return matches
}

// extractRemoteURL extracts the [remote "origin"] url from .git/config
func extractRemoteURL(configContent string) string {
	lines := strings.Split(configContent, "\n")
	inRemote := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[remote") {
			inRemote = true
			continue
		}
		if inRemote && strings.HasPrefix(trimmed, "[") {
			inRemote = false
		}
		if inRemote && strings.HasPrefix(trimmed, "url") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// normalizeTarget builds candidate base URLs for the target given an explicit port.
// port=0 means "unknown – try both 80 and 443".
// port=443 means HTTPS only.
// Any other port means http://host:port first, https://host:port as fallback.
func normalizeTarget(host string, port int) []string {
	host = strings.TrimSpace(host)
	// Strip any existing scheme
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimRight(host, "/")

	// If host already contains a port (e.g. "localhost:8765"), split it out
	// and prefer that over the port argument (which defaults to 80 from the engine
	// when no port is set in the scope file).
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		possiblePort := host[colonIdx+1:]
		allDigits := true
		for _, c := range possiblePort {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(possiblePort) > 0 {
			if parsed, err := strconv.Atoi(possiblePort); err == nil {
				host = host[:colonIdx]
				port = parsed
			}
		}
	}

	switch {
	case port == 443:
		return []string{"https://" + host}
	case port == 80 || port == 0:
		// Try HTTP first; template will fall through to HTTPS if 0 findings
		return []string{"http://" + host, "https://" + host}
	default:
		// Non-standard port: construct explicit host:port URLs
		// Try HTTP first, then HTTPS on the same port
		return []string{
			fmt.Sprintf("http://%s:%d", host, port),
			fmt.Sprintf("https://%s:%d", host, port),
		}
	}
}

// cvssScore maps severity to a numeric CVSS approximation.
func cvssScore(severity string) float64 {
	switch severity {
	case "critical":
		return 9.8
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 3.0
	default:
		return 0.0
	}
}

// runChecks performs the full git-exposure check against a single base URL.
// Returns a slice of findings (may be empty).
func runChecks(baseURL, host string) []Finding {
	var findings []Finding

	client := newHTTPClient(10 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ── Check 1: .git/HEAD ────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "[*] [%s] Check 1/3 – Testing /.git/HEAD existence...\n", baseURL)
	headBody, headStatus, headErr := fetchGitFile(ctx, client, baseURL, "HEAD")
	if headErr != nil || headStatus != 200 || !isGitHeadResponse(headBody) {
		fmt.Fprintf(os.Stderr, "[-] [%s] /.git/HEAD not accessible (status=%d)\n", baseURL, headStatus)
		return findings
	}

	branchRef := strings.TrimSpace(headBody)
	fmt.Fprintf(os.Stderr, "[+] [%s] /.git/HEAD accessible – %s\n", baseURL, branchRef)

	// HEAD is accessible → at minimum an INFO finding
	gitDirFinding := Finding{
		TemplateID:   "git-history-secret-scan",
		TemplateName: "Git History Secret Scan",
		Host:         host,
		Severity:     "medium",
		Confidence:   90,
		Title:        "Exposed .git Directory Detected",
		Description:  fmt.Sprintf("The .git directory is publicly accessible on %s. This exposes version control metadata and potentially source code and secrets.", baseURL),
		CWE:          "CWE-312",
		CVSSScore:    cvssScore("medium"),
		Remediation:  "Deny access to /.git/ in your web server configuration (e.g., 'location /.git { deny all; }' in nginx or 'RedirectMatch 404 /\\.git' in Apache).",
		References: []string{
			"https://cwe.mitre.org/data/definitions/312.html",
			"https://owasp.org/www-community/attacks/git_exposure",
		},
		MatchedAt: fmt.Sprintf("%s/.git/HEAD", baseURL),
		Evidence: map[string]interface{}{
			"head_content": branchRef,
			"head_url":     fmt.Sprintf("%s/.git/HEAD", baseURL),
		},
	}

	// ── Check 2: .git/config ─────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "[*] [%s] Check 2/3 – Fetching /.git/config...\n", baseURL)
	configBody, configStatus, configErr := fetchGitFile(ctx, client, baseURL, "config")
	if configErr == nil && configStatus == 200 && strings.Contains(configBody, "[core]") {
		remoteURL := extractRemoteURL(configBody)
		configEvidence := map[string]interface{}{
			"config_url":    fmt.Sprintf("%s/.git/config", baseURL),
			"config_status": configStatus,
		}
		if remoteURL != "" {
			configEvidence["remote_origin_url"] = remoteURL
			fmt.Fprintf(os.Stderr, "[+] [%s] Remote URL: %s\n", baseURL, remoteURL)
		}

		// Check if remote URL itself contains credentials (e.g. https://user:pass@github.com)
		credInURL := regexp.MustCompile(`https?://[^:]+:[^@\s]+@`).FindString(remoteURL)
		if credInURL != "" {
			configEvidence["credentials_in_remote_url"] = true
			gitDirFinding.Severity = "critical"
			gitDirFinding.CVSSScore = cvssScore("critical")
			gitDirFinding.Title = "Git Config Exposes Credentials in Remote URL"
			gitDirFinding.Description = fmt.Sprintf(
				"The .git/config file on %s contains a remote URL with embedded credentials. Attackers can extract these credentials directly without reconstructing the git history.",
				baseURL,
			)
		}

		gitDirFinding.Evidence["git_config"] = configEvidence
		fmt.Fprintf(os.Stderr, "[+] [%s] /.git/config fetched successfully\n", baseURL)
	} else {
		fmt.Fprintf(os.Stderr, "[-] [%s] /.git/config not accessible (status=%d)\n", baseURL, configStatus)
	}

	// ── Check 3: Secret scanning across key git files ─────────────────────────
	fmt.Fprintf(os.Stderr, "[*] [%s] Check 3/3 – Scanning git files for secrets...\n", baseURL)

	secretScanFiles := []string{
		"COMMIT_EDITMSG",
		"logs/HEAD",
		"logs/refs/heads/main",
		"logs/refs/heads/master",
		"refs/heads/main",
		"refs/heads/master",
		"config",
	}

	allSecretMatches := []secretMatch{}
	secretSourceFiles := []string{}

	for _, gitFile := range secretScanFiles {
		body, status, err := fetchGitFile(ctx, client, baseURL, gitFile)
		if err != nil || status != 200 || len(body) == 0 {
			continue
		}
		matches := scanForSecrets(body)
		if len(matches) > 0 {
			fmt.Fprintf(os.Stderr, "[+] [%s] Found %d secret(s) in /.git/%s\n", baseURL, len(matches), gitFile)
			allSecretMatches = append(allSecretMatches, matches...)
			secretSourceFiles = append(secretSourceFiles, gitFile)
		}
	}

	if len(allSecretMatches) > 0 {
		// Upgrade to a separate CRITICAL finding for the secrets
		secretFinding := Finding{
			TemplateID:   "git-history-secret-scan",
			TemplateName: "Git History Secret Scan",
			Host:         host,
			Severity:     "critical",
			Confidence:   95,
			Title:        fmt.Sprintf("Secrets Found in Exposed Git History (%d pattern(s) matched)", len(allSecretMatches)),
			Description: fmt.Sprintf(
				"The exposed .git directory on %s contains files with secret credential patterns. "+
					"%d secret(s) matched across %d git file(s): %s. "+
					"Attackers can reconstruct the full commit history and extract all credentials ever committed.",
				baseURL,
				len(allSecretMatches),
				len(secretSourceFiles),
				strings.Join(secretSourceFiles, ", "),
			),
			CWE:       "CWE-312",
			CVSSScore: cvssScore("critical"),
			Remediation: "1. Immediately rotate ALL credentials found in the repository history. " +
				"2. Use 'git-filter-repo' or BFG Repo Cleaner to purge secrets from history. " +
				"3. Block /.git/ access at the web server level. " +
				"4. Implement pre-commit hooks (e.g., Gitleaks, Trufflehog) to prevent future commits of secrets.",
			References: []string{
				"https://cwe.mitre.org/data/definitions/312.html",
				"https://owasp.org/www-community/attacks/git_exposure",
				"https://github.com/gitleaks/gitleaks",
			},
			MatchedAt: fmt.Sprintf("%s/.git/", baseURL),
			Evidence: map[string]interface{}{
				"secret_matches":    allSecretMatches,
				"affected_git_files": secretSourceFiles,
				"total_secrets":     len(allSecretMatches),
			},
		}
		findings = append(findings, secretFinding)
		// Also upgrade the base finding severity
		gitDirFinding.Severity = "critical"
		gitDirFinding.CVSSScore = cvssScore("critical")
	} else {
		fmt.Fprintf(os.Stderr, "[-] [%s] No secret patterns found in accessible git files\n", baseURL)
	}

	// Always emit the base git-directory exposure finding
	findings = append(findings, gitDirFinding)
	return findings
}

func main() {
	host := os.Getenv("CERT_X_GEN_TARGET_HOST")
	port := 0 // 0 = unknown, will try both http and https on port 80/443

	// Read port from environment (set by cxg engine from the scope file entry)
	if portStr := os.Getenv("CERT_X_GEN_TARGET_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// CLI fallback for direct execution
	if host == "" && len(os.Args) > 1 {
		for i := 1; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--target":
				if i+1 < len(os.Args) {
					host = os.Args[i+1]
					i++
				}
			case "--port":
				if i+1 < len(os.Args) {
					if p, err := strconv.Atoi(os.Args[i+1]); err == nil {
						port = p
					}
					i++
				}
			default:
				if !strings.HasPrefix(os.Args[i], "--") && host == "" {
					host = os.Args[i]
				}
			}
		}
	}

	if host == "" {
		fmt.Fprintln(os.Stderr, "Error: No target specified. Set CERT_X_GEN_TARGET_HOST or pass --target <host>")
		fmt.Println("[]")
		os.Exit(1)
	}

	// normalizeTarget handles host:port notation in the host string itself,
	// and builds the correct list of base URLs to try (http/https, with port).
	candidates := normalizeTarget(host, port)

	allFindings := []Finding{}
	for _, baseURL := range candidates {
		findings := runChecks(baseURL, host)
		if len(findings) > 0 {
			allFindings = append(allFindings, findings...)
			// Stop trying further candidates once we have a confirmed exposure
			break
		}
	}

	output, err := json.Marshal(allFindings)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error marshalling output:", err)
		fmt.Println("[]")
		os.Exit(1)
	}
	fmt.Println(string(output))
}

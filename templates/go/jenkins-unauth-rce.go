// @id: jenkins-unauth-rce
// @name: Jenkins Unauthenticated Script Console RCE
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Jenkins instances with unauthenticated access to Script Console enabling Remote Code Execution
// @tags: jenkins, ci-cd, devops, rce, misconfig, groovy
// @cwe: CWE-306, CWE-94
// @cvss: 9.8
// @references: https://www.jenkins.io/doc/book/security/, https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/jenkins
// @confidence: 95
// @version: 1.0.0
//
// WHY GO?
// Jenkins API is REST/JSON based. Go provides:
// - Excellent HTTP client libraries
// - Clean JSON marshaling
// - Goroutines for concurrent endpoint checking
// - No external dependencies needed

package main

import (
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
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Severity    string                 `json:"severity"`
	Confidence  int                    `json:"confidence"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Remediation string                 `json:"remediation"`
	CWE         []string               `json:"cwe,omitempty"`
	CVSSScore   float64                `json:"cvss_score,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Timestamp   string                 `json:"timestamp,omitempty"`
}

// Result is the output structure
type Result struct {
	Findings []Finding `json:"findings"`
}

// JenkinsScanner scans for Jenkins vulnerabilities
type JenkinsScanner struct {
	host     string
	port     int
	client   *http.Client
	evidence map[string]interface{}
	baseURL  string
}

// NewJenkinsScanner creates a new scanner
func NewJenkinsScanner(host string, port int) *JenkinsScanner {
	return &JenkinsScanner{
		host: host,
		port: port,
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		evidence: make(map[string]interface{}),
		baseURL:  fmt.Sprintf("http://%s:%d", host, port),
	}
}

// Get performs HTTP GET and returns status, body, and headers
func (j *JenkinsScanner) Get(path string) (int, string, http.Header, error) {
	req, err := http.NewRequest("GET", j.baseURL+path, nil)
	if err != nil {
		return 0, "", nil, err
	}

	req.Header.Set("User-Agent", "CERT-X-GEN/1.0")
	req.Header.Set("Accept", "text/html,application/json,*/*")

	resp, err := j.client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", resp.Header, err
	}

	return resp.StatusCode, string(body), resp.Header, nil
}

// CheckJenkins verifies this is a Jenkins instance
func (j *JenkinsScanner) CheckJenkins() bool {
	status, body, headers, err := j.Get("/")
	if err != nil {
		return false
	}

	// Check for Jenkins header
	jenkinsVersion := headers.Get("X-Jenkins")
	if jenkinsVersion != "" {
		j.evidence["version"] = jenkinsVersion
		return true
	}

	// Check body for Jenkins indicators
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "jenkins") {
		// Try to extract version from page
		versionRegex := regexp.MustCompile(`Jenkins\s+ver\.\s*([\d.]+)`)
		if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
			j.evidence["version"] = matches[1]
		}
		return true
	}

	// Check for redirect to login (still Jenkins)
	if status == 302 || status == 301 {
		location := headers.Get("Location")
		if strings.Contains(location, "login") || strings.Contains(location, "jenkins") {
			return true
		}
	}

	return false
}

// CheckAuthRequired determines if authentication is needed
func (j *JenkinsScanner) CheckAuthRequired() bool {
	status, body, _, _ := j.Get("/")

	if status == 403 {
		return true
	}

	if status == 200 {
		bodyLower := strings.ToLower(body)
		// Check for login form
		if strings.Contains(bodyLower, "j_username") || strings.Contains(bodyLower, "password") {
			if strings.Contains(bodyLower, `type="password"`) || strings.Contains(bodyLower, `name="j_password"`) {
				return true
			}
		}
	}

	return false
}

// CheckCriticalEndpoints checks for accessible dangerous endpoints
func (j *JenkinsScanner) CheckCriticalEndpoints() {
	endpoints := []struct {
		Path        string
		Name        string
		Critical    bool
		RCEPossible bool
	}{
		{"/script", "Script Console", true, true},
		{"/scriptText", "Script Text API", true, true},
		{"/manage", "Manage Jenkins", true, false},
		{"/credentials", "Credentials Store", true, false},
		{"/configureSecurity", "Security Configuration", true, false},
		{"/api/json", "API Access", false, false},
		{"/computer", "Build Nodes", false, false},
		{"/asynchPeople", "User List", false, false},
		{"/systemInfo", "System Information", false, false},
		{"/log", "System Log", false, false},
		{"/pluginManager", "Plugin Manager", false, false},
	}

	accessible := []string{}
	j.evidence["rce_possible"] = false

	for _, ep := range endpoints {
		status, body, _, err := j.Get(ep.Path)
		if err != nil {
			continue
		}

		if status == 200 {
			accessible = append(accessible, ep.Name)

			if ep.RCEPossible {
				// Verify Script Console is actually usable
				if strings.Contains(body, "textarea") || strings.Contains(body, "script") {
					j.evidence["rce_possible"] = true
					j.evidence["script_console_accessible"] = true
				}
			}

			// Check for exposed credentials
			if ep.Path == "/credentials" {
				if strings.Contains(strings.ToLower(body), "credential") {
					j.evidence["credentials_accessible"] = true
				}
			}
		}
	}

	j.evidence["accessible_endpoints"] = accessible
}

// CheckAPIAccess checks what's available via the JSON API
func (j *JenkinsScanner) CheckAPIAccess() {
	status, body, _, err := j.Get("/api/json?tree=jobs[name,url,color],views[name]")
	if err != nil || status != 200 {
		return
	}

	var apiData struct {
		Jobs []struct {
			Name  string `json:"name"`
			URL   string `json:"url"`
			Color string `json:"color"`
		} `json:"jobs"`
		Views []struct {
			Name string `json:"name"`
		} `json:"views"`
	}

	if err := json.Unmarshal([]byte(body), &apiData); err != nil {
		return
	}

	j.evidence["job_count"] = len(apiData.Jobs)

	jobNames := []string{}
	for i, job := range apiData.Jobs {
		if i >= 10 {
			break
		}
		jobNames = append(jobNames, job.Name)
	}
	j.evidence["jobs"] = jobNames
}

// CheckBuildLogs checks for exposed build logs with potential secrets
func (j *JenkinsScanner) CheckBuildLogs() {
	jobs, ok := j.evidence["jobs"].([]string)
	if !ok || len(jobs) == 0 {
		return
	}

	// Try first job
	jobName := jobs[0]
	status, body, _, err := j.Get(fmt.Sprintf("/job/%s/lastBuild/consoleText", jobName))
	if err != nil || status != 200 {
		return
	}

	j.evidence["build_logs_accessible"] = true

	// Check for secrets in logs
	secretPatterns := []string{
		`(?i)password\s*[=:]\s*\S+`,
		`(?i)api[_-]?key\s*[=:]\s*\S+`,
		`(?i)secret\s*[=:]\s*\S+`,
		`(?i)token\s*[=:]\s*\S+`,
		`AWS_SECRET`,
		`PRIVATE_KEY`,
	}

	secretsFound := []string{}
	for _, pattern := range secretPatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			// Extract pattern name
			name := strings.Split(pattern, `\s`)[0]
			name = strings.TrimPrefix(name, "(?i)")
			secretsFound = append(secretsFound, name)
		}
	}

	if len(secretsFound) > 0 {
		j.evidence["potential_secrets_in_logs"] = secretsFound
	}
}

// Scan performs the complete scan
func (j *JenkinsScanner) Scan() []Finding {
	findings := []Finding{}

	// Step 1: Verify Jenkins
	if !j.CheckJenkins() {
		return findings
	}

	j.evidence["jenkins_detected"] = true

	// Step 2: Check if auth required
	authRequired := j.CheckAuthRequired()
	j.evidence["auth_required"] = authRequired

	// Step 3: Check critical endpoints
	j.CheckCriticalEndpoints()

	// Step 4: Check API
	j.CheckAPIAccess()

	// Step 5: Check build logs
	j.CheckBuildLogs()

	// Build findings
	accessible, _ := j.evidence["accessible_endpoints"].([]string)
	rcePossible, _ := j.evidence["rce_possible"].(bool)

	if !authRequired && len(accessible) > 0 {
		severity := "high"
		if rcePossible {
			severity = "critical"
		}

		desc := fmt.Sprintf("Jenkins on %s:%d ", j.host, j.port)

		if rcePossible {
			desc += "has Script Console accessible without authentication (REMOTE CODE EXECUTION POSSIBLE). "
		} else {
			desc += "is accessible without authentication. "
		}

		if version, ok := j.evidence["version"].(string); ok {
			desc += fmt.Sprintf("Version: %s. ", version)
		}

		desc += fmt.Sprintf("Accessible endpoints: %s. ", strings.Join(accessible, ", "))

		if j.evidence["credentials_accessible"] == true {
			desc += "Credentials store is accessible. "
		}

		if secrets, ok := j.evidence["potential_secrets_in_logs"].([]string); ok && len(secrets) > 0 {
			desc += fmt.Sprintf("Build logs may contain secrets (%s). ", strings.Join(secrets, ", "))
		}

		if rcePossible {
			desc += "Attackers can execute arbitrary Groovy code on the Jenkins server, leading to complete system compromise."
		}

		findings = append(findings, Finding{
			ID:          "jenkins-unauth-rce",
			Name:        "Jenkins Unauthenticated Script Console RCE",
			Severity:    severity,
			Confidence:  95,
			Description: desc,
			Evidence:    j.evidence,
			Remediation: "Enable Jenkins security. Configure authentication (LDAP/SAML/local). Disable Script Console or restrict to admins only. Use Role-Based Access Control. Never expose Jenkins to the internet without authentication.",
			CWE:         []string{"CWE-306", "CWE-94"},
			CVSSScore:   9.8,
			Tags:        []string{"jenkins", "ci-cd", "rce"},
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		})
	} else if j.evidence["jenkins_detected"] == true && authRequired {
		findings = append(findings, Finding{
			ID:          "jenkins-exposed",
			Name:        "Jenkins Exposed (Auth Required)",
			Severity:    "medium",
			Confidence:  85,
			Description: fmt.Sprintf("Jenkins detected on %s:%d but authentication is required. Version: %v.", j.host, j.port, j.evidence["version"]),
			Evidence:    map[string]interface{}{"version": j.evidence["version"]},
			Remediation: "Restrict access via firewall or VPN.",
			Tags:        []string{"jenkins", "exposed"},
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		})
	}

	return findings
}

func main() {
	host := os.Getenv("CERT_X_GEN_TARGET_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
	port := 8080
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		if p, err := strconv.Atoi(os.Args[2]); err == nil {
			port = p
		}
	}

	scanner := NewJenkinsScanner(host, port)
	findings := scanner.Scan()

	result := Result{Findings: findings}
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}

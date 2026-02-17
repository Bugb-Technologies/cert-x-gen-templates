// CERT-X-GEN Go Template - Kubernetes RBAC Misconfiguration Detection
//
// @id: k8s-rbac-misconfiguration
// @name: Kubernetes RBAC Misconfiguration Detection
// @author: BugB Technologies
// @severity: critical
// @description: Detects Kubernetes RBAC misconfigurations including unauthenticated API server access on insecure port 8080, anonymous authentication on port 6443 with strict TLS, dangerous ClusterRoleBindings enabling privilege escalation to cluster-admin, and exposed Kubernetes Dashboard on port 8001 or 443.
// @tags: kubernetes, rbac, privilege-escalation, misconfiguration, anonymous-auth, cluster-admin, api-server, dashboard, k8s
// @cwe: CWE-269
// @confidence: 95
// @references: https://kubernetes.io/docs/reference/access-authn-authz/rbac/, https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests, https://attack.mitre.org/techniques/T1078/, https://github.com/kubernetes/dashboard

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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

// APIVersions is a minimal K8s APIVersions response
type APIVersions struct {
	Kind     string   `json:"kind"`
	Versions []string `json:"versions"`
}

// ClusterRoleBindingList is a minimal K8s ClusterRoleBindingList response
type ClusterRoleBindingList struct {
	Kind  string `json:"kind"`
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		RoleRef struct {
			Name string `json:"name"`
		} `json:"roleRef"`
		Subjects []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"subjects"`
	} `json:"items"`
}

func main() {
	target := os.Getenv("CERT_X_GEN_TARGET_HOST")
	if target == "" && len(os.Args) > 1 {
		target = os.Args[1]
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: No target specified")
		fmt.Println("[]")
		os.Exit(1)
	}

	target = normalizeTarget(target)
	findings := []Finding{}

	// Check 1: Unauthenticated insecure port 8080 (pre-1.20 K8s insecure API, no TLS, no auth)
	fmt.Fprintf(os.Stderr, "[*] Check 1/3 - Testing Kubernetes insecure API port 8080...\n")
	if f := testInsecurePort(target, 8080); f != nil {
		findings = append(findings, *f)
	}

	// Check 2: Anonymous access on HTTPS port 6443 (strict TLS verification)
	fmt.Fprintf(os.Stderr, "[*] Check 2/3 - Testing Kubernetes API server port 6443 (strict TLS)...\n")
	if f := testAnonymousAccess(target, 6443); f != nil {
		findings = append(findings, *f)
	}

	// Check 3: Kubernetes Dashboard exposure on port 8001 (kubectl proxy) and 443
	fmt.Fprintf(os.Stderr, "[*] Check 3/3 - Testing Kubernetes Dashboard exposure on ports 8001 and 443...\n")
	if f := testDashboardExposure(target); f != nil {
		findings = append(findings, *f)
	}

	output, err := json.Marshal(findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		fmt.Println("[]")
		os.Exit(1)
	}
	fmt.Println(string(output))
}

// testInsecurePort tests for Kubernetes insecure port 8080 (unauthenticated plain-HTTP API)
func testInsecurePort(host string, port int) *Finding {
	baseURL := fmt.Sprintf("http://%s:%d", host, port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Plain HTTP client — no TLS needed on insecure port
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Port %d: Failed to build request: %v\n", port, err)
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Port %d: Connection failed (not exposed): %v\n", port, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "[-] Port %d: Non-200 response (%d) — not a K8s insecure port\n", port, resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Port %d: Failed to read response: %v\n", port, err)
		return nil
	}
	bodyStr := string(body)

	// Confirm it is the K8s API by looking for canonical response fields
	if !strings.Contains(bodyStr, "APIVersions") && !strings.Contains(bodyStr, "apiVersion") {
		fmt.Fprintf(os.Stderr, "[-] Port %d: Response does not look like Kubernetes API\n", port)
		return nil
	}

	fmt.Fprintf(os.Stderr, "[!] Port %d: CRITICAL — Kubernetes insecure API port is OPEN!\n", port)

	// Attempt namespace enumeration to gauge impact depth
	namespaceNames := []string{}
	nsCtx, nsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer nsCancel()
	nsReq, nsErr := http.NewRequestWithContext(nsCtx, "GET", baseURL+"/api/v1/namespaces", nil)
	if nsErr == nil {
		nsResp, nsDoErr := client.Do(nsReq)
		if nsDoErr == nil {
			defer nsResp.Body.Close()
			if nsResp.StatusCode == 200 {
				nsBody, nsReadErr := io.ReadAll(io.LimitReader(nsResp.Body, 16384))
				if nsReadErr == nil {
					namespaceNames = extractNamespaceNames(string(nsBody))
				}
			}
		}
	}

	evidence := map[string]interface{}{
		"port":              port,
		"protocol":          "http",
		"endpoint":          baseURL + "/api",
		"authentication":    "not_required",
		"tls":               false,
		"status":            "exposed",
		"response_snippet":  truncate(bodyStr, 300),
		"namespaces_found":  namespaceNames,
		"namespace_count":   len(namespaceNames),
		"vulnerability":     "--insecure-port=8080 enabled; full unauthenticated, unencrypted API access",
	}

	return &Finding{
		TemplateID:   "k8s-rbac-misconfiguration",
		TemplateName: "Kubernetes RBAC Misconfiguration Detection",
		Host:         host,
		Severity:     "CRITICAL",
		Confidence:   98,
		Title:        fmt.Sprintf("Kubernetes Insecure API Port Exposed on %s:%d — Full Unauthenticated Access", host, port),
		Description:  "The Kubernetes API server is running with --insecure-port=8080 enabled. This port accepts ALL requests without authentication or TLS, granting any network-adjacent attacker full cluster-admin level control. This feature was deprecated in Kubernetes 1.13 and removed in 1.20.",
		Evidence:     evidence,
		CWE:          "CWE-269",
		CVSSScore:    10.0,
		Remediation:  "Set --insecure-port=0 in the kube-apiserver manifest to disable the insecure port. Ensure --secure-port=6443 is configured with valid TLS certificates and RBAC is enabled with --authorization-mode=Node,RBAC.",
		References: []string{
			"https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/",
			"https://kubernetes.io/docs/concepts/security/hardening-guide/",
			"https://attack.mitre.org/techniques/T1078/",
		},
		MatchedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// testAnonymousAccess tests for anonymous authentication on HTTPS port 6443
// Uses STRICT TLS verification — connection errors mean the cert is invalid/untrusted
func testAnonymousAccess(host string, port int) *Finding {
	baseURL := fmt.Sprintf("https://%s:%d", host, port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Strict TLS — no InsecureSkipVerify
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Port %d: Failed to build request: %v\n", port, err)
		return nil
	}
	// No Authorization header — testing anonymous access path

	resp, err := client.Do(req)
	if err != nil {
		// TLS errors or connection refused mean we cannot determine state — skip gracefully
		fmt.Fprintf(os.Stderr, "[-] Port %d: Connection/TLS failed — skipping (cert may be self-signed or host unreachable): %v\n", port, err)
		return nil
	}
	defer resp.Body.Close()

	// 401/403 = properly secured with authentication requirement
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		fmt.Fprintf(os.Stderr, "[+] Port %d: Authentication required (properly secured) — HTTP %d\n", port, resp.StatusCode)
		return createSecuredFinding(host, port)
	}

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "[-] Port %d: Unexpected status %d — not conclusive, skipping\n", port, resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Port %d: Failed to read response body: %v\n", port, err)
		return nil
	}
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "APIVersions") && !strings.Contains(bodyStr, "apiVersion") {
		fmt.Fprintf(os.Stderr, "[-] Port %d: Response does not look like Kubernetes API\n", port)
		return nil
	}

	fmt.Fprintf(os.Stderr, "[!] Port %d: Anonymous access ENABLED on Kubernetes API server!\n", port)

	// Enumerate ClusterRoleBindings to find dangerous privilege escalation paths
	dangerousBindings, rbacEvidence := enumerateRBAC(ctx, client, baseURL)

	severity := "HIGH"
	cvssScore := 8.8
	title := fmt.Sprintf("Kubernetes API Server Anonymous Access Enabled on %s:%d", host, port)
	description := "The Kubernetes API server responds to unauthenticated requests (no bearer token). Anonymous access allows any network actor to enumerate cluster resources including namespaces, pods, secrets, and service accounts."

	if len(dangerousBindings) > 0 {
		severity = "CRITICAL"
		cvssScore = 9.8
		title = fmt.Sprintf("Kubernetes RBAC Privilege Escalation via Anonymous Access on %s:%d", host, port)
		description = fmt.Sprintf(
			"Critical: Anonymous access is enabled AND %d dangerous ClusterRoleBinding(s) were found. "+
				"Unauthenticated principals have been granted cluster-admin or wildcard privileges, "+
				"enabling full cluster takeover without any credentials.",
			len(dangerousBindings),
		)
	}

	evidence := map[string]interface{}{
		"port":               port,
		"protocol":           "https",
		"tls_verification":   "strict",
		"endpoint":           baseURL + "/api",
		"authentication":     "not_required",
		"anonymous_access":   true,
		"response_snippet":   truncate(bodyStr, 300),
		"dangerous_bindings": dangerousBindings,
	}
	for k, v := range rbacEvidence {
		evidence[k] = v
	}

	return &Finding{
		TemplateID:   "k8s-rbac-misconfiguration",
		TemplateName: "Kubernetes RBAC Misconfiguration Detection",
		Host:         host,
		Severity:     severity,
		Confidence:   95,
		Title:        title,
		Description:  description,
		Evidence:     evidence,
		CWE:          "CWE-269",
		CVSSScore:    cvssScore,
		Remediation: "1. Disable anonymous authentication: set --anonymous-auth=false on kube-apiserver.\n" +
			"2. Audit all ClusterRoleBindings: kubectl get clusterrolebindings -o wide\n" +
			"3. Remove bindings granting cluster-admin or wildcard verbs to system:anonymous or system:unauthenticated.\n" +
			"4. Enable audit logging: --audit-log-path and --audit-policy-file.\n" +
			"5. Restrict API server network access via firewall or NetworkPolicy.",
		References: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
			"https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests",
			"https://attack.mitre.org/techniques/T1078/",
			"https://www.cncf.io/blog/2020/12/16/kubernetes-security-best-practices/",
		},
		MatchedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// testDashboardExposure checks for an unauthenticated Kubernetes Dashboard
// on port 8001 (kubectl proxy default) and port 443 (common ingress exposure)
func testDashboardExposure(host string) *Finding {
	type dashboardProbe struct {
		url      string
		scheme   string
		port     int
		skipTLS  bool
	}

	probes := []dashboardProbe{
		// kubectl proxy — HTTP, no TLS, no auth bypass needed
		{url: fmt.Sprintf("http://%s:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/", host), scheme: "http", port: 8001, skipTLS: false},
		{url: fmt.Sprintf("http://%s:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/", host), scheme: "http", port: 8001, skipTLS: false},
		// HTTPS dashboard directly (skip TLS for dashboard-specific probe only)
		{url: fmt.Sprintf("https://%s:443/", host), scheme: "https", port: 443, skipTLS: true},
	}

	dashboardSignals := []string{
		"kubernetes-dashboard",
		"Kubernetes Dashboard",
		"kube-dashboard",
		"<title>Kubernetes</title>",
	}

	for _, probe := range probes {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: probe.skipTLS},
		}
		client := &http.Client{Timeout: 8 * time.Second, Transport: transport}

		req, err := http.NewRequestWithContext(ctx, "GET", probe.url, nil)
		if err != nil {
			cancel()
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Dashboard probe %s: connection failed: %v\n", probe.url, err)
			cancel()
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		cancel()

		if readErr != nil {
			continue
		}

		bodyStr := string(body)
		serverHeader := resp.Header.Get("Server")

		// Check for dashboard signals in body or server header
		isDashboard := false
		for _, signal := range dashboardSignals {
			if strings.Contains(bodyStr, signal) || strings.Contains(serverHeader, signal) {
				isDashboard = true
				break
			}
		}

		if !isDashboard {
			continue
		}

		// Found a dashboard — determine if it requires login
		requiresAuth := strings.Contains(bodyStr, "login") ||
			strings.Contains(bodyStr, "token") ||
			resp.StatusCode == 401 ||
			resp.StatusCode == 403

		severity := "CRITICAL"
		cvssScore := 9.6
		accessStatus := "unauthenticated"
		titleSuffix := "Unauthenticated Access — Full Cluster Control"
		desc := fmt.Sprintf(
			"The Kubernetes Dashboard is publicly accessible on %s (port %d) without requiring authentication. "+
				"The Dashboard has full cluster-admin rights by default in many installations. "+
				"An attacker can create pods, read secrets, exec into containers, and pivot to full cluster compromise.",
			probe.url, probe.port,
		)

		if requiresAuth {
			severity = "HIGH"
			cvssScore = 7.5
			accessStatus = "login_page_exposed"
			titleSuffix = "Login Page Exposed"
			desc = fmt.Sprintf(
				"The Kubernetes Dashboard login page is publicly exposed on %s (port %d). "+
					"While authentication is present, the Dashboard itself should never be publicly accessible. "+
					"Brute-force and token theft attacks are possible from the internet.",
				probe.url, probe.port,
			)
		}

		fmt.Fprintf(os.Stderr, "[!] Dashboard: FOUND on %s (status=%d, auth=%s)\n", probe.url, resp.StatusCode, accessStatus)

		return &Finding{
			TemplateID:   "k8s-rbac-misconfiguration",
			TemplateName: "Kubernetes RBAC Misconfiguration Detection",
			Host:         host,
			Severity:     severity,
			Confidence:   90,
			Title:        fmt.Sprintf("Kubernetes Dashboard Exposed on %s:%d — %s", host, probe.port, titleSuffix),
			Description:  desc,
			Evidence: map[string]interface{}{
				"port":            probe.port,
				"scheme":          probe.scheme,
				"url":             probe.url,
				"http_status":     resp.StatusCode,
				"server_header":   serverHeader,
				"requires_auth":   requiresAuth,
				"access_status":   accessStatus,
				"response_snippet": truncate(bodyStr, 400),
			},
			CWE:      "CWE-269",
			CVSSScore: cvssScore,
			Remediation: "1. Never expose the Kubernetes Dashboard to the internet.\n" +
				"2. Disable kubectl proxy for remote access; use kubectl port-forward locally.\n" +
				"3. Require authentication: --authentication-mode=token and --auto-generate-certificates.\n" +
				"4. Bind the Dashboard to localhost only (127.0.0.1).\n" +
				"5. Use RBAC to restrict the Dashboard service account to read-only namespaced permissions.\n" +
				"6. Deploy Dashboard behind a VPN or SSO proxy (e.g., oauth2-proxy).",
			References: []string{
				"https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/README.md",
				"https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/",
				"https://attack.mitre.org/techniques/T1078/",
				"https://www.cvedetails.com/vulnerability-list/vendor_id-15867/product_id-34016/Kubernetes-Dashboard.html",
			},
			MatchedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	fmt.Fprintf(os.Stderr, "[-] Dashboard: Not detected on ports 8001 or 443\n")
	return nil
}

// enumerateRBAC fetches ClusterRoleBindings anonymously and flags dangerous patterns
func enumerateRBAC(ctx context.Context, client *http.Client, baseURL string) ([]string, map[string]interface{}) {
	dangerousBindings := []string{}
	evidence := map[string]interface{}{}

	dangerousPrincipals := map[string]bool{
		"system:anonymous":       true,
		"system:unauthenticated": true,
	}
	dangerousRoles := map[string]bool{
		"cluster-admin":  true,
		"system:masters": true,
	}

	crbURL := baseURL + "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
	req, err := http.NewRequestWithContext(ctx, "GET", crbURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] RBAC: Failed to build ClusterRoleBindings request: %v\n", err)
		return dangerousBindings, evidence
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] RBAC: ClusterRoleBindings request failed: %v\n", err)
		return dangerousBindings, evidence
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "[-] RBAC: ClusterRoleBindings returned HTTP %d — enumeration not permitted\n", resp.StatusCode)
		evidence["rbac_enumeration"] = fmt.Sprintf("blocked_status_%d", resp.StatusCode)
		return dangerousBindings, evidence
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] RBAC: Failed to read ClusterRoleBindings body: %v\n", err)
		return dangerousBindings, evidence
	}

	var crbList ClusterRoleBindingList
	if err := json.Unmarshal(body, &crbList); err != nil {
		fmt.Fprintf(os.Stderr, "[!] RBAC: Failed to parse ClusterRoleBindings JSON: %v\n", err)
		evidence["rbac_parse_error"] = err.Error()
		return dangerousBindings, evidence
	}

	evidence["clusterrolebindings_total"] = len(crbList.Items)
	fmt.Fprintf(os.Stderr, "[+] RBAC: Enumerated %d ClusterRoleBindings\n", len(crbList.Items))

	for _, crb := range crbList.Items {
		for _, subject := range crb.Subjects {
			isPrincipalDangerous := dangerousPrincipals[subject.Name] || dangerousPrincipals[strings.ToLower(subject.Name)]
			isRoleDangerous := dangerousRoles[crb.RoleRef.Name]

			if isPrincipalDangerous || isRoleDangerous {
				binding := fmt.Sprintf(
					"ClusterRoleBinding '%s': role='%s' granted to %s '%s'",
					crb.Metadata.Name, crb.RoleRef.Name, subject.Kind, subject.Name,
				)
				dangerousBindings = append(dangerousBindings, binding)
				fmt.Fprintf(os.Stderr, "[!] DANGEROUS RBAC: %s\n", binding)
			}
		}
	}

	evidence["dangerous_binding_count"] = len(dangerousBindings)
	return dangerousBindings, evidence
}

// createSecuredFinding returns an INFO finding when the API server requires auth
func createSecuredFinding(host string, port int) *Finding {
	return &Finding{
		TemplateID:   "k8s-rbac-misconfiguration",
		TemplateName: "Kubernetes RBAC Misconfiguration Detection",
		Host:         host,
		Severity:     "INFO",
		Confidence:   100,
		Title:        fmt.Sprintf("Kubernetes API Server Properly Secured on %s:%d", host, port),
		Description:  fmt.Sprintf("Kubernetes API server on port %d requires authentication (401/403 received without bearer token). Anonymous access is not enabled. This is the expected secure configuration.", port),
		Evidence: map[string]interface{}{
			"port":             port,
			"protocol":         "https",
			"tls_verification": "strict",
			"authentication":   "required",
			"anonymous_access": false,
		},
		MatchedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func normalizeTarget(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		if !strings.Contains(target[idx:], "]") {
			target = target[:idx]
		}
	}
	return strings.TrimSuffix(target, "/")
}

// extractNamespaceNames parses a /api/v1/namespaces JSON body for namespace names
func extractNamespaceNames(body string) []string {
	names := []string{}
	parts := strings.Split(body, "\"name\":")
	for i, part := range parts {
		if i == 0 {
			continue
		}
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, "\"") {
			end := strings.Index(trimmed[1:], "\"")
			if end > 0 {
				name := trimmed[1 : end+1]
				if name != "" && !strings.Contains(name, "/") {
					names = append(names, name)
				}
			}
		}
		if len(names) >= 20 {
			break
		}
	}
	return names
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

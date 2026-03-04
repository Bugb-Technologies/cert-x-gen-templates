// CERT-X-GEN Go Template - Kubelet API Exposure Detection
//
// @id: kubelet-api-exposure
// @name: Kubelet API Exposure Detection
// @author: BugB Technologies
// @severity: critical
// @description: Detects exposed Kubelet API endpoints that allow unauthenticated access to pod information and potential container execution. Exposed Kubelet APIs can lead to node-level compromise, secret extraction, and container escape.
// @tags: kubernetes, kubelet, api-exposure, container-escape, node-compromise, misconfiguration
// @cwe: CWE-306
// @confidence: 95
// @references: https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-authentication-authorization/, https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-1, https://attack.mitre.org/techniques/T1552/007/

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

// PodList represents a simplified Kubernetes pod list response
type PodList struct {
	Kind  string `json:"kind"`
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	} `json:"items"`
}

func main() {
	// Get target from environment
	target := os.Getenv("CERT_X_GEN_TARGET_HOST")
	if target == "" && len(os.Args) > 1 {
		target = os.Args[1]
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: No target specified")
		fmt.Println("[]")
		return
	}

	// Normalize target (remove protocol, port, trailing slash)
	target = normalizeTarget(target)

	findings := []Finding{}

	// Test port 10250 (HTTPS - full Kubelet API)
	fmt.Fprintf(os.Stderr, "[*] Testing Kubelet HTTPS API on port 10250...\n")
	if finding := testKubeletPort(target, 10250, "https"); finding != nil {
		findings = append(findings, *finding)
	}

	// Test port 10255 (HTTP - deprecated read-only API)
	fmt.Fprintf(os.Stderr, "[*] Testing Kubelet read-only HTTP API on port 10255...\n")
	if finding := testKubeletPort(target, 10255, "http"); finding != nil {
		findings = append(findings, *finding)
	}

	// Marshal findings to JSON
	output, err := json.Marshal(findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		fmt.Println("[]")
		return
	}
	fmt.Println(string(output))
}

func testKubeletPort(host string, port int, scheme string) *Finding {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testURL := fmt.Sprintf("%s://%s:%d/pods", scheme, host, port)
	
	status, pods, version, err := testKubeletEndpoint(ctx, testURL, scheme == "https")
	
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Port %d (%s): Connection failed: %v\n", port, scheme, err)
		return nil
	}

	// If authentication is required, return INFO finding
	if status == "authenticated" {
		fmt.Fprintf(os.Stderr, "[+] Port %d (%s): Authentication required (properly secured)\n", port, scheme)
		return createAuthRequiredFinding(host, port, scheme)
	}

	// If accessible without authentication, create vulnerability finding
	if status == "accessible" {
		fmt.Fprintf(os.Stderr, "[!] Port %d (%s): EXPOSED - Unauthenticated access allowed!\n", port, scheme)
		
		// Determine severity based on port
		severity := "CRITICAL"
		if port == 10255 {
			severity = "HIGH" // Read-only is still serious but less critical
		}

		evidence := make(map[string]interface{})
		evidence["port"] = port
		evidence["protocol"] = scheme
		evidence["endpoint"] = testURL
		evidence["authentication"] = "not_required"
		evidence["status"] = "exposed"
		evidence["pods_found"] = len(pods)

		if version != "" {
			evidence["kubernetes_version"] = version
		}

		// Extract namespace information
		if len(pods) > 0 {
			namespaces := make(map[string]bool)
			for _, pod := range pods {
				namespaces[pod.Metadata.Namespace] = true
			}
			var nsList []string
			for ns := range namespaces {
				nsList = append(nsList, ns)
			}
			evidence["namespaces"] = nsList

			// Sample first 3 pods
			samplePods := make([]string, 0)
			for i, pod := range pods {
				if i >= 3 {
					break
				}
				samplePods = append(samplePods, fmt.Sprintf("%s/%s", pod.Metadata.Namespace, pod.Metadata.Name))
			}
			evidence["sample_pods"] = samplePods
		}

		var title, description, vulnerability string
		if port == 10250 {
			title = fmt.Sprintf("Critical Kubelet API Exposure on %s:%d", host, port)
			description = "Kubelet full API exposed without authentication on port 10250. This allows unauthenticated access to pod inspection, container execution (/exec), and potential node-level compromise."
			vulnerability = "Full Kubelet API exposed - allows pod inspection and container execution"
		} else {
			title = fmt.Sprintf("Kubelet Read-Only API Exposure on %s:%d", host, port)
			description = "Kubelet read-only API exposed without authentication on port 10255 (deprecated). This allows unauthenticated pod enumeration and information disclosure."
			vulnerability = "Read-only Kubelet API exposed (deprecated port 10255)"
		}

		evidence["vulnerability"] = vulnerability

		return &Finding{
			TemplateID:   "kubelet-api-exposure",
			TemplateName: "Kubelet API Exposure Detection",
			Host:         host,
			Severity:     severity,
			Confidence:   95,
			Title:        title,
			Description:  description,
			Evidence:     evidence,
			CWE:          "CWE-306",
			CVSSScore:    9.8,
			Remediation:  "Enable Kubelet authentication and authorization. Set --anonymous-auth=false and configure proper RBAC policies. Disable port 10255 (read-only port is deprecated).",
			References: []string{
				"https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-authentication-authorization/",
				"https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-1",
			},
			MatchedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	return nil
}

func testKubeletEndpoint(ctx context.Context, url string, skipTLS bool) (string, []struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
}, string, error) {
	
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLS,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "error", nil, "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "unreachable", nil, "", err
	}
	defer resp.Body.Close()

	// Check for authentication requirement
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return "authenticated", nil, "", nil
	}

	// Check for successful response
	if resp.StatusCode != 200 {
		return "error", nil, "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Extract version from headers
	version := ""
	if v := resp.Header.Get("X-Kubernetes-Version"); v != "" {
		version = v
	}

	// Parse response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "accessible", nil, version, fmt.Errorf("failed to read response: %v", err)
	}

	var podList PodList
	if err := json.Unmarshal(body, &podList); err != nil {
		return "accessible", nil, version, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return "accessible", podList.Items, version, nil
}

func createAuthRequiredFinding(host string, port int, scheme string) *Finding {
	evidence := make(map[string]interface{})
	evidence["port"] = port
	evidence["protocol"] = scheme
	evidence["authentication"] = "required"
	evidence["status"] = "secured"

	return &Finding{
		TemplateID:   "kubelet-api-exposure",
		TemplateName: "Kubelet API Exposure Detection",
		Host:         host,
		Severity:     "INFO",
		Confidence:   100,
		Title:        fmt.Sprintf("Kubelet API Properly Secured on %s:%d", host, port),
		Description:  fmt.Sprintf("Kubelet API on port %d requires authentication. This is the expected secure configuration.", port),
		Evidence:     evidence,
		MatchedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

func normalizeTarget(target string) string {
	// Remove protocol if present
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	
	// Remove port if present
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		// Check if it's actually a port (not IPv6)
		if !strings.Contains(target[idx:], "]") {
			target = target[:idx]
		}
	}
	
	// Remove trailing slash
	target = strings.TrimSuffix(target, "/")
	
	return target
}

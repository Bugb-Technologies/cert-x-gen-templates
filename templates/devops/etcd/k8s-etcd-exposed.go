// @id: k8s-etcd-exposed
// @name: Kubernetes etcd Secrets Exposure
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects exposed Kubernetes etcd databases leaking cluster secrets, tokens, and certificates
// @tags: kubernetes, etcd, secrets, cloud, k8s, misconfiguration
// @cwe: CWE-200, CWE-306
// @cvss: 9.8
// @references: https://kubernetes.io/docs/concepts/configuration/secret/, https://etcd.io/docs/v3.5/op-guide/security/
// @confidence: 95
// @version: 1.0.0
//
// WHY GO?
// Kubernetes and etcd are written in Go. This provides:
// - Native understanding of etcd API patterns
// - Same JSON/protobuf handling as Kubernetes
// - Goroutines for concurrent key enumeration
// - Familiar ecosystem tooling

package main

import (
	"encoding/base64"
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

// EtcdResponse represents etcd v2 API response
type EtcdResponse struct {
	Action string    `json:"action"`
	Node   *EtcdNode `json:"node"`
}

// EtcdNode represents a node in etcd
type EtcdNode struct {
	Key           string      `json:"key"`
	Value         string      `json:"value,omitempty"`
	Dir           bool        `json:"dir,omitempty"`
	Nodes         []*EtcdNode `json:"nodes,omitempty"`
	ModifiedIndex int64       `json:"modifiedIndex"`
	CreatedIndex  int64       `json:"createdIndex"`
}

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
}

// Result is the output structure
type Result struct {
	Findings []Finding `json:"findings"`
}

// EtcdClient wraps HTTP client for etcd API
type EtcdClient struct {
	baseURL string
	client  *http.Client
	version string
}

// NewEtcdClient creates a new etcd API client
func NewEtcdClient(host string, port int) *EtcdClient {
	return &EtcdClient{
		baseURL: fmt.Sprintf("http://%s:%d", host, port),
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Get performs a GET request
func (e *EtcdClient) Get(path string) ([]byte, int, error) {
	resp, err := e.client.Get(e.baseURL + path)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}

// CheckVersion determines etcd version and accessibility
func (e *EtcdClient) CheckVersion() (bool, error) {
	body, status, err := e.Get("/version")
	if err != nil {
		return false, err
	}

	if status == 200 {
		if strings.Contains(string(body), "etcdserver") || strings.Contains(string(body), "etcdcluster") {
			e.version = "v3"
			return true, nil
		}
	}

	// Try v2 keys endpoint
	body, status, err = e.Get("/v2/keys/")
	if err != nil {
		return false, err
	}

	if status == 200 {
		e.version = "v2"
		return true, nil
	}

	return false, nil
}

// ListKeysV2 lists keys using v2 API
func (e *EtcdClient) ListKeysV2(path string, recursive bool) (*EtcdResponse, error) {
	url := fmt.Sprintf("/v2/keys%s", path)
	if recursive {
		url += "?recursive=true"
	}

	body, status, err := e.Get(url)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("status %d", status)
	}

	var response EtcdResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// FindSecrets traverses etcd and finds Kubernetes secrets
func (e *EtcdClient) FindSecrets() ([]string, map[string]bool, []string) {
	secretPaths := []string{}
	namespaces := make(map[string]bool)
	sensitiveKeys := []string{}

	// Common Kubernetes registry paths
	searchPaths := []string{
		"/registry/secrets",
		"/registry/serviceaccounts",
		"/registry/configmaps",
		"/registry/pods",
		"/registry/deployments",
	}

	for _, basePath := range searchPaths {
		resp, err := e.ListKeysV2(basePath, true)
		if err != nil {
			continue
		}

		if resp.Node != nil {
			e.walkNodes(resp.Node, &secretPaths, namespaces, &sensitiveKeys)
		}
	}

	// Also try root enumeration
	resp, err := e.ListKeysV2("/", true)
	if err == nil && resp.Node != nil {
		e.walkNodes(resp.Node, &secretPaths, namespaces, &sensitiveKeys)
	}

	return secretPaths, namespaces, sensitiveKeys
}

// walkNodes recursively walks etcd nodes
func (e *EtcdClient) walkNodes(node *EtcdNode, secrets *[]string, namespaces map[string]bool, sensitive *[]string) {
	if node == nil {
		return
	}

	key := node.Key

	// Check for secrets paths
	if strings.Contains(key, "/secrets/") || strings.Contains(key, "/serviceaccounts/") {
		*secrets = append(*secrets, key)

		// Extract namespace
		nsRegex := regexp.MustCompile(`/registry/secrets/([^/]+)/`)
		if matches := nsRegex.FindStringSubmatch(key); len(matches) > 1 {
			namespaces[matches[1]] = true
		}
	}

	// Check for sensitive key names
	sensitivePatterns := []string{"password", "token", "key", "secret", "credential", "auth", "cert", "private"}
	keyLower := strings.ToLower(key)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(keyLower, pattern) {
			*sensitive = append(*sensitive, key)
			break
		}
	}

	// Check if value contains base64-encoded data (potential secrets)
	if node.Value != "" {
		if _, err := base64.StdEncoding.DecodeString(node.Value); err == nil {
			if len(node.Value) > 20 && len(node.Value) < 10000 {
				// Likely a base64-encoded secret
				*sensitive = append(*sensitive, key)
			}
		}
	}

	// Recurse into child nodes
	for _, child := range node.Nodes {
		e.walkNodes(child, secrets, namespaces, sensitive)
	}
}

func main() {
	// Get target from environment or args
	host := os.Getenv("CERT_X_GEN_TARGET_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
	port := 2379
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// Command line args override
	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		if p, err := strconv.Atoi(os.Args[2]); err == nil {
			port = p
		}
	}

	result := Result{Findings: []Finding{}}
	client := NewEtcdClient(host, port)

	// Step 1: Check if etcd is accessible
	accessible, err := client.CheckVersion()
	if err != nil || !accessible {
		outputJSON(result)
		return
	}

	// Step 2: Find secrets and sensitive keys
	secretPaths, namespaces, sensitiveKeys := client.FindSecrets()

	// Convert namespaces map to slice
	var namespaceList []string
	for ns := range namespaces {
		namespaceList = append(namespaceList, ns)
	}

	// Limit output sizes
	if len(secretPaths) > 20 {
		secretPaths = secretPaths[:20]
	}
	if len(namespaceList) > 10 {
		namespaceList = namespaceList[:10]
	}
	if len(sensitiveKeys) > 10 {
		sensitiveKeys = sensitiveKeys[:10]
	}

	evidence := map[string]interface{}{
		"etcd_version":    client.version,
		"secrets_count":   len(secretPaths),
		"namespaces":      namespaceList,
		"sample_paths":    secretPaths,
		"sensitive_keys":  sensitiveKeys,
	}

	// Build description
	severity := "critical"
	if len(secretPaths) == 0 {
		severity = "high"
	}

	desc := fmt.Sprintf("Kubernetes etcd database is exposed without authentication on %s:%d. ", host, port)
	desc += fmt.Sprintf("etcd version: %s. ", client.version)

	if len(secretPaths) > 0 {
		desc += fmt.Sprintf("Found %d secret paths. ", len(secretPaths))
		desc += fmt.Sprintf("Namespaces exposed: %s. ", strings.Join(namespaceList, ", "))
		desc += "Attackers can extract all cluster secrets including service account tokens, TLS certificates, and application credentials."
	} else {
		desc += "etcd is accessible but no Kubernetes secrets paths were found. "
		desc += "May be a standalone etcd or custom configuration."
	}

	finding := Finding{
		ID:          "k8s-etcd-exposed",
		Name:        "Kubernetes etcd Secrets Exposure",
		Severity:    severity,
		Confidence:  95,
		Description: desc,
		Evidence:    evidence,
		Remediation: "Enable etcd authentication and TLS. Restrict etcd access to kube-apiserver only. Use network policies to isolate etcd. Consider using encrypted etcd at rest.",
		CWE:         []string{"CWE-200", "CWE-306"},
		CVSSScore:   9.8,
	}

	result.Findings = append(result.Findings, finding)
	outputJSON(result)
}

func outputJSON(result Result) {
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}

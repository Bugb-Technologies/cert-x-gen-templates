// CERT-X-GEN Go Template - Kubernetes Service Account Token Abuse
//
// @id: service-account-token-abuse
// @name: Kubernetes Service Account Token Abuse
// @author: BugB Technologies
// @severity: critical
// @description: Detects Kubernetes misconfigurations that expose service account tokens to unauthenticated or minimally-privileged attackers. Checks for: unauthenticated Secrets API access, Kubelet /pods endpoint token path exposure, token-based API pivoting to kube-system secrets, and default service account over-permission. Token extraction and lateral movement (pivoting) are simulated in read-only detection mode.
// @tags: kubernetes, service-account, token-abuse, secrets, kubelet, privilege-escalation, lateral-movement, k8s, cloud-native
// @cwe: CWE-522
// @confidence: 95
// @references: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/, https://attack.mitre.org/techniques/T1528/, https://www.cncf.io/blog/2021/08/20/kubernetes-rbac-least-privilege/, https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K01-insecure-workload-configurations

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Finding represents a CERT-X-GEN security finding
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

// K8s API response types
type SecretList struct {
	Kind  string `json:"kind"`
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Type string `json:"type"`
		Data map[string]string `json:"data"`
	} `json:"items"`
}

type PodList struct {
	Kind  string `json:"kind"`
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
			Volumes            []struct {
				Name      string `json:"name"`
				Projected *struct {
					Sources []struct {
						ServiceAccountToken *struct {
							Path              string `json:"path"`
							ExpirationSeconds int    `json:"expirationSeconds"`
						} `json:"serviceAccountToken"`
					} `json:"sources"`
				} `json:"projected"`
			} `json:"volumes"`
			Containers []struct {
				Name            string `json:"name"`
				VolumeMounts    []struct {
					Name      string `json:"name"`
					MountPath string `json:"mountPath"`
				} `json:"volumeMounts"`
			} `json:"containers"`
		} `json:"spec"`
	} `json:"items"`
}

type ServiceAccountList struct {
	Kind  string `json:"kind"`
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Secrets []struct {
			Name string `json:"name"`
		} `json:"secrets"`
		AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
	} `json:"items"`
}

// insecureHTTPSClient returns an http.Client that skips TLS verification.
// Used only where the target may present a self-signed cert (e.g., K8s API server in dev clusters).
func insecureHTTPSClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// secureHTTPSClient returns an http.Client that enforces TLS.
func secureHTTPSClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}
}

func get(ctx context.Context, client *http.Client, url, token string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 131072)) // 128 KB cap
	return resp, body, err
}

func main() {
	target := os.Getenv("CERT_X_GEN_TARGET_HOST")
	if target == "" && len(os.Args) > 1 {
		target = os.Args[1]
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: No target specified. Set CERT_X_GEN_TARGET_HOST or pass as argument.")
		fmt.Println("[]")
		os.Exit(1)
	}

	target = normalizeTarget(target)
	findings := []Finding{}

	// ── Check 1: Unauthenticated Secrets API access on port 6443 ──────────────
	fmt.Fprintf(os.Stderr, "[*] Check 1/4 - Testing unauthenticated Secrets API on port 6443...\n")
	secretFindings := testSecretsAPIAnonymous(target, 6443)
	findings = append(findings, secretFindings...)

	// ── Check 2: Kubelet /pods endpoint token path exposure on port 10250 ─────
	fmt.Fprintf(os.Stderr, "[*] Check 2/4 - Testing Kubelet /pods API on port 10250 for token paths...\n")
	if f := testKubeletPodTokenPaths(target, 10250); f != nil {
		findings = append(findings, *f)
	}

	// ── Check 3: Service Account over-permission (automountServiceAccountToken) ─
	fmt.Fprintf(os.Stderr, "[*] Check 3/4 - Testing for over-privileged default service account (port 6443)...\n")
	if f := testDefaultSAOverPermission(target, 6443); f != nil {
		findings = append(findings, *f)
	}

	// ── Check 4: Token pivoting — use any extracted token to reach kube-system ──
	fmt.Fprintf(os.Stderr, "[*] Check 4/4 - Testing token pivoting to kube-system secrets (port 6443)...\n")
	if f := testTokenPivoting(target, 6443, findings); f != nil {
		findings = append(findings, *f)
	}

	out, err := json.Marshal(findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		fmt.Println("[]")
		os.Exit(1)
	}
	fmt.Println(string(out))
}

// ── Check 1: Unauthenticated Secrets API ──────────────────────────────────────
// testSecretsAPIAnonymous probes the K8s API server for unauthenticated access
// to the /api/v1/secrets and /api/v1/namespaces/{ns}/secrets endpoints.
// This is the primary token extraction vector: service account tokens are
// stored as Opaque/kubernetes.io/service-account-token secrets.
func testSecretsAPIAnonymous(host string, port int) []Finding {
	findings := []Finding{}
	baseURL := fmt.Sprintf("https://%s:%d", host, port)
	client := insecureHTTPSClient(12 * time.Second)

	// Probe cluster-scoped secrets listing first
	namespacesToProbe := []string{"", "default", "kube-system", "kube-public"}

	for _, ns := range namespacesToProbe {
		var endpoint string
		if ns == "" {
			endpoint = baseURL + "/api/v1/secrets"
		} else {
			endpoint = fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", baseURL, ns)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, body, err := get(ctx, client, endpoint, "")
		cancel()

		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Secrets API (%s): connection failed: %v\n", endpoint, err)
			continue
		}

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			fmt.Fprintf(os.Stderr, "[+] Secrets API (%s): authentication required (HTTP %d) — properly secured\n", endpoint, resp.StatusCode)
			continue
		}

		if resp.StatusCode != 200 {
			fmt.Fprintf(os.Stderr, "[-] Secrets API (%s): unexpected HTTP %d — skipping\n", endpoint, resp.StatusCode)
			continue
		}

		// Parse response for service account tokens
		var secretList SecretList
		if jsonErr := json.Unmarshal(body, &secretList); jsonErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Secrets API (%s): failed to parse JSON: %v\n", endpoint, jsonErr)
			continue
		}

		if secretList.Kind != "SecretList" {
			fmt.Fprintf(os.Stderr, "[-] Secrets API (%s): response kind=%s — not a SecretList\n", endpoint, secretList.Kind)
			continue
		}

		// Filter for service account token secrets
		saTokenSecrets := []map[string]string{}
		extractedTokens := []string{}
		for _, item := range secretList.Items {
			if item.Type == "kubernetes.io/service-account-token" || item.Type == "Opaque" {
				entry := map[string]string{
					"name":      item.Metadata.Name,
					"namespace": item.Metadata.Namespace,
					"type":      item.Type,
				}
				saTokenSecrets = append(saTokenSecrets, entry)

				// Attempt to decode base64 token data
				if tokenB64, ok := item.Data["token"]; ok {
					if decoded, decErr := base64.StdEncoding.DecodeString(tokenB64); decErr == nil {
						tokenStr := string(decoded)
						if strings.HasPrefix(tokenStr, "eyJ") { // JWT prefix
							extractedTokens = append(extractedTokens, tokenStr[:min(len(tokenStr), 64)]+"...[truncated]")
						}
					}
				}
			}
		}

		scope := "cluster-wide"
		if ns != "" {
			scope = "namespace/" + ns
		}

		fmt.Fprintf(os.Stderr, "[!] Secrets API (%s, %s): EXPOSED — found %d secrets, %d SA tokens\n",
			endpoint, scope, len(secretList.Items), len(saTokenSecrets))

		severity := "CRITICAL"
		cvss := 9.8
		titleScope := "Cluster-Wide"
		if ns != "" {
			severity = "CRITICAL"
			cvss = 9.1
			titleScope = fmt.Sprintf("Namespace '%s'", ns)
		}

		findings = append(findings, Finding{
			TemplateID:   "service-account-token-abuse",
			TemplateName: "Kubernetes Service Account Token Abuse",
			Host:         host,
			Severity:     severity,
			Confidence:   98,
			Title: fmt.Sprintf("Unauthenticated K8s Secrets API Exposes Service Account Tokens — %s on %s:%d",
				titleScope, host, port),
			Description: fmt.Sprintf(
				"The Kubernetes API server at %s allows unauthenticated access to the Secrets API (%s). "+
					"%d total secrets were listed, %d of which are service account tokens. "+
					"An attacker can extract long-lived bearer tokens and use them to authenticate "+
					"to the Kubernetes API as privileged service accounts, enabling lateral movement "+
					"and full cluster compromise.",
				endpoint, scope, len(secretList.Items), len(saTokenSecrets),
			),
			Evidence: map[string]interface{}{
				"endpoint":             endpoint,
				"scope":                scope,
				"http_status":          resp.StatusCode,
				"total_secrets":        len(secretList.Items),
				"sa_token_count":       len(saTokenSecrets),
				"sa_token_secrets":     saTokenSecrets,
				"extracted_jwt_tokens": extractedTokens,
				"authentication":       "not_required",
			},
			CWE:       "CWE-522",
			CVSSScore: cvss,
			Remediation: "1. Enable RBAC: --authorization-mode=Node,RBAC on kube-apiserver.\n" +
				"2. Disable anonymous access: --anonymous-auth=false.\n" +
				"3. Restrict secret access to only namespaces and service accounts that require it.\n" +
				"4. Rotate all exposed service account tokens immediately.\n" +
				"5. Enable secret encryption at rest: --encryption-provider-config.\n" +
				"6. Audit secret access: kubectl get events --field-selector reason=Unauthorized.",
			References: []string{
				"https://kubernetes.io/docs/concepts/configuration/secret/",
				"https://attack.mitre.org/techniques/T1528/",
				"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
				"https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
			},
			MatchedAt: time.Now().UTC().Format(time.RFC3339),
		})

		// Only report once per unique exposure level (cluster vs ns)
		if ns == "" {
			break // Cluster-wide access found; namespace probes are redundant
		}
	}

	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Secrets API: no unauthenticated access detected\n")
	}
	return findings
}

// ── Check 2: Kubelet /pods token path exposure ────────────────────────────────
// testKubeletPodTokenPaths probes the Kubelet API (port 10250) for the /pods
// endpoint. If accessible, it enumerates pod specs looking for automounted
// service account token volume mounts — revealing which pods have tokens
// accessible at /var/run/secrets/kubernetes.io/serviceaccount/token inside them.
func testKubeletPodTokenPaths(host string, port int) *Finding {
	baseURL := fmt.Sprintf("https://%s:%d", host, port)
	client := insecureHTTPSClient(12 * time.Second)

	// Some clusters expose /runningpods/ or /pods
	endpoints := []string{"/pods", "/runningpods/"}
	for _, path := range endpoints {
		url := baseURL + path
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, body, err := get(ctx, client, url, "")
		cancel()

		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Kubelet %s: connection failed: %v\n", path, err)
			continue
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			fmt.Fprintf(os.Stderr, "[+] Kubelet %s: requires authentication (HTTP %d) — secure\n", path, resp.StatusCode)
			continue
		}
		if resp.StatusCode != 200 {
			fmt.Fprintf(os.Stderr, "[-] Kubelet %s: HTTP %d — skipping\n", path, resp.StatusCode)
			continue
		}

		var podList PodList
		if err := json.Unmarshal(body, &podList); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Kubelet %s: JSON parse failed: %v\n", path, err)
			continue
		}
		if podList.Kind != "PodList" {
			continue
		}

		// Find pods with automounted SA tokens
		tokenMountDetails := []map[string]interface{}{}
		for _, pod := range podList.Items {
			hasSAToken := false
			mountPaths := []string{}

			for _, container := range pod.Spec.Containers {
				for _, vm := range container.VolumeMounts {
					if strings.Contains(vm.MountPath, "serviceaccount") ||
						strings.Contains(vm.MountPath, "secrets/kubernetes.io") ||
						vm.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
						hasSAToken = true
						mountPaths = append(mountPaths, fmt.Sprintf("%s:%s", container.Name, vm.MountPath))
					}
				}
			}

			if hasSAToken {
				tokenMountDetails = append(tokenMountDetails, map[string]interface{}{
					"pod":              pod.Metadata.Name,
					"namespace":        pod.Metadata.Namespace,
					"service_account":  pod.Spec.ServiceAccountName,
					"token_mountpaths": mountPaths,
				})
			}
		}

		fmt.Fprintf(os.Stderr, "[!] Kubelet %s: EXPOSED — %d total pods, %d with SA token mounts\n",
			path, len(podList.Items), len(tokenMountDetails))

		return &Finding{
			TemplateID:   "service-account-token-abuse",
			TemplateName: "Kubernetes Service Account Token Abuse",
			Host:         host,
			Severity:     "CRITICAL",
			Confidence:   95,
			Title: fmt.Sprintf("Kubelet API Exposes Pod Service Account Token Mount Paths on %s:%d",
				host, port),
			Description: fmt.Sprintf(
				"The Kubelet API on port %d responds without authentication to %s. "+
					"%d pods are enumerated, %d of which have service account tokens automounted at predictable paths. "+
					"If the Kubelet exec API is also exposed, an attacker can exec into any pod and "+
					"read the service account token at /var/run/secrets/kubernetes.io/serviceaccount/token, "+
					"enabling full API server authentication as that pod's service account.",
				port, path, len(podList.Items), len(tokenMountDetails),
			),
			Evidence: map[string]interface{}{
				"kubelet_endpoint":    url,
				"http_status":         resp.StatusCode,
				"total_pods":          len(podList.Items),
				"pods_with_sa_tokens": len(tokenMountDetails),
				"token_mount_details": tokenMountDetails,
				"token_path_pattern":  "/var/run/secrets/kubernetes.io/serviceaccount/token",
			},
			CWE:       "CWE-522",
			CVSSScore: 9.6,
			Remediation: "1. Disable anonymous Kubelet access: --anonymous-auth=false in kubelet config.\n" +
				"2. Require Webhook authentication: --authentication-token-webhook=true.\n" +
				"3. Disable automounting where unnecessary: automountServiceAccountToken: false in pod specs.\n" +
				"4. Apply NetworkPolicies to restrict pod-to-Kubelet communication.\n" +
				"5. Rotate service account tokens for affected pods immediately.",
			References: []string{
				"https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/",
				"https://attack.mitre.org/techniques/T1528/",
				"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting",
			},
			MatchedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	fmt.Fprintf(os.Stderr, "[-] Kubelet: /pods not accessible without authentication\n")
	return nil
}

// ── Check 3: Default Service Account Over-Permission ─────────────────────────
// testDefaultSAOverPermission probes the K8s API server to check if the default
// service account in the default namespace has been granted excessive permissions
// (a common misconfiguration in older Helm charts and tutorials).
func testDefaultSAOverPermission(host string, port int) *Finding {
	baseURL := fmt.Sprintf("https://%s:%d", host, port)
	client := insecureHTTPSClient(12 * time.Second)

	// First try to list service accounts anonymously
	url := fmt.Sprintf("%s/api/v1/namespaces/default/serviceaccounts", baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	resp, body, err := get(ctx, client, url, "")
	cancel()

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] SA check: connection failed: %v\n", err)
		return nil
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		fmt.Fprintf(os.Stderr, "[+] SA check: authentication required (HTTP %d) — properly secured\n", resp.StatusCode)
		return nil
	}

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "[-] SA check: HTTP %d — skipping\n", resp.StatusCode)
		return nil
	}

	var saList ServiceAccountList
	if err := json.Unmarshal(body, &saList); err != nil {
		fmt.Fprintf(os.Stderr, "[!] SA check: JSON parse failed: %v\n", err)
		return nil
	}

	// Look for the default SA and check automount setting
	overPermissionedSAs := []map[string]interface{}{}
	for _, sa := range saList.Items {
		automount := true // K8s default is true if not set
		if sa.AutomountServiceAccountToken != nil {
			automount = *sa.AutomountServiceAccountToken
		}
		secretCount := len(sa.Secrets)

		// default SA with automount=true and associated secrets is a risk indicator
		isHighRisk := (sa.Metadata.Name == "default" && automount) ||
			(automount && secretCount > 0)

		if isHighRisk {
			overPermissionedSAs = append(overPermissionedSAs, map[string]interface{}{
				"name":                          sa.Metadata.Name,
				"namespace":                     sa.Metadata.Namespace,
				"automount_service_account_token": automount,
				"associated_secrets":            secretCount,
				"risk":                          "token_automounted_in_all_pods",
			})
		}
	}

	if len(overPermissionedSAs) == 0 {
		fmt.Fprintf(os.Stderr, "[-] SA check: no over-permissioned service accounts detected\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "[!] SA check: found %d over-permissioned SA(s) with automount enabled\n",
		len(overPermissionedSAs))

	return &Finding{
		TemplateID:   "service-account-token-abuse",
		TemplateName: "Kubernetes Service Account Token Abuse",
		Host:         host,
		Severity:     "HIGH",
		Confidence:   85,
		Title: fmt.Sprintf("Over-Permissioned Service Account with Automount Enabled on %s:%d",
			host, port),
		Description: fmt.Sprintf(
			"Unauthenticated access to the ServiceAccounts API revealed %d service account(s) "+
				"with automountServiceAccountToken=true (or unset, which defaults to true). "+
				"The 'default' service account token is automatically mounted into every pod in the namespace. "+
				"If any workload is compromised, the attacker immediately obtains a Kubernetes API bearer token "+
				"that may have cluster-level permissions if RBAC is not properly scoped.",
			len(overPermissionedSAs),
		),
		Evidence: map[string]interface{}{
			"endpoint":              url,
			"http_status":           resp.StatusCode,
			"total_service_accounts": len(saList.Items),
			"over_permissioned":     overPermissionedSAs,
		},
		CWE:       "CWE-522",
		CVSSScore: 8.1,
		Remediation: "1. Set automountServiceAccountToken: false on the default service account.\n" +
			"2. Create dedicated service accounts per workload with least-privilege RBAC roles.\n" +
			"3. Avoid granting permissions to the default service account.\n" +
			"4. Use projected service account tokens with short expiry (expirationSeconds: 3600).\n" +
			"5. Review all ClusterRoleBindings and RoleBindings for default service accounts.\n" +
			"kubectl patch serviceaccount default -p '{\"automountServiceAccountToken\":false}'",
		References: []string{
			"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting",
			"https://attack.mitre.org/techniques/T1528/",
			"https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K01-insecure-workload-configurations",
		},
		MatchedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// ── Check 4: Token Pivoting ───────────────────────────────────────────────────
// testTokenPivoting takes any JWT tokens extracted in previous checks and
// attempts to use them to access privileged API paths, measuring the blast
// radius of a successful token extraction attack.
// This is DETECTION ONLY — reads no sensitive data beyond what is needed
// to establish access level (HTTP status codes + resource counts).
func testTokenPivoting(host string, port int, existingFindings []Finding) *Finding {
	baseURL := fmt.Sprintf("https://%s:%d", host, port)
	client := insecureHTTPSClient(12 * time.Second)

	// Extract any tokens found during Check 1
	candidateTokens := extractTokensFromFindings(existingFindings)

	// Also test with an empty token (anonymous) as baseline pivot attempt
	candidateTokens = append([]string{""}, candidateTokens...)

	// Privileged pivot targets — ordered by sensitivity
	pivotEndpoints := []struct {
		path        string
		description string
		cvss        float64
	}{
		{"/api/v1/namespaces/kube-system/secrets", "kube-system secrets (contains cluster CA, etcd certs)", 10.0},
		{"/api/v1/namespaces/kube-system/configmaps", "kube-system configmaps (cluster configuration)", 8.5},
		{"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "cluster role bindings (privilege map)", 8.0},
		{"/api/v1/nodes", "cluster node inventory", 7.5},
		{"/api/v1/namespaces", "all namespaces", 7.0},
	}

	// Attempt pivot with each token candidate
	for _, token := range candidateTokens {
		tokenLabel := "anonymous"
		if token != "" {
			tokenLabel = "extracted_sa_token"
		}

		pivotResults := []map[string]interface{}{}
		successCount := 0

		for _, ep := range pivotEndpoints {
			url := baseURL + ep.path
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			resp, body, err := get(ctx, client, url, token)
			cancel()

			result := map[string]interface{}{
				"endpoint":    ep.path,
				"description": ep.description,
				"token_used":  tokenLabel,
			}

			if err != nil {
				result["status"] = "connection_failed"
				result["error"] = err.Error()
				pivotResults = append(pivotResults, result)
				continue
			}

			result["http_status"] = resp.StatusCode

			if resp.StatusCode == 200 {
				successCount++
				result["accessible"] = true
				result["cvss_impact"] = ep.cvss

				// Count items exposed (no content reading — just metadata)
				itemCount := strings.Count(string(body), "\"name\":")
				result["items_exposed_approx"] = itemCount
				fmt.Fprintf(os.Stderr, "[!] PIVOT SUCCESS: %s — %s (token=%s, items~%d)\n",
					ep.path, ep.description, tokenLabel, itemCount)
			} else {
				result["accessible"] = false
				fmt.Fprintf(os.Stderr, "[-] Pivot blocked: %s HTTP %d (token=%s)\n",
					ep.path, resp.StatusCode, tokenLabel)
			}
			pivotResults = append(pivotResults, result)
		}

		if successCount == 0 {
			continue
		}

		// Calculate composite CVSS based on highest accessible endpoint
		highestCVSS := 0.0
		for _, r := range pivotResults {
			if accessible, ok := r["accessible"].(bool); ok && accessible {
				if cvss, ok := r["cvss_impact"].(float64); ok && cvss > highestCVSS {
					highestCVSS = cvss
				}
			}
		}

		tokenTypeLabel := "Anonymous"
		if token != "" {
			tokenTypeLabel = "Extracted Service Account Token"
		}

		return &Finding{
			TemplateID:   "service-account-token-abuse",
			TemplateName: "Kubernetes Service Account Token Abuse",
			Host:         host,
			Severity:     "CRITICAL",
			Confidence:   97,
			Title: fmt.Sprintf("Service Account Token Pivoting Successful — %d/%d Privileged Endpoints Accessible on %s:%d",
				successCount, len(pivotEndpoints), host, port),
			Description: fmt.Sprintf(
				"Token pivoting simulation using %s successfully accessed %d out of %d privileged Kubernetes API endpoints. "+
					"This confirms that an attacker who extracts a service account token (or exploits anonymous access) "+
					"can immediately pivot to read cluster-level secrets, enumerate all namespaces and nodes, "+
					"and map the full RBAC privilege structure — achieving lateral movement to full cluster control.",
				tokenTypeLabel, successCount, len(pivotEndpoints),
			),
			Evidence: map[string]interface{}{
				"token_type":            tokenLabel,
				"pivot_endpoints_total": len(pivotEndpoints),
				"pivot_success_count":   successCount,
				"pivot_results":         pivotResults,
				"highest_cvss_reached":  highestCVSS,
			},
			CWE:       "CWE-522",
			CVSSScore: highestCVSS,
			Remediation: "1. Rotate all service account tokens immediately.\n" +
				"2. Apply RBAC least-privilege: revoke wildcard get/list/watch on secrets.\n" +
				"3. Disable anonymous auth: --anonymous-auth=false.\n" +
				"4. Encrypt etcd at rest to protect stored tokens.\n" +
				"5. Implement audit logging to detect token extraction and pivoting.\n" +
				"6. Use short-lived projected tokens (TokenRequest API) instead of long-lived static secrets.",
			References: []string{
				"https://attack.mitre.org/techniques/T1528/",
				"https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/",
				"https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
				"https://www.cncf.io/blog/2021/08/20/kubernetes-rbac-least-privilege/",
			},
			MatchedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	fmt.Fprintf(os.Stderr, "[-] Token pivoting: no privileged endpoints accessible\n")
	return nil
}

// ── Utility helpers ───────────────────────────────────────────────────────────

// extractTokensFromFindings pulls any JWT tokens stored in finding evidence
// from previous checks so they can be used in the pivot test.
func extractTokensFromFindings(findings []Finding) []string {
	tokens := []string{}
	for _, f := range findings {
		if rawTokens, ok := f.Evidence["extracted_jwt_tokens"]; ok {
			if tokenSlice, ok := rawTokens.([]string); ok {
				for _, t := range tokenSlice {
					// Strip the "[truncated]" suffix we added for display
					clean := strings.TrimSuffix(t, "...[truncated]")
					if strings.HasPrefix(clean, "eyJ") && len(clean) > 20 {
						tokens = append(tokens, clean)
					}
				}
			}
		}
	}
	return tokens
}

func normalizeTarget(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	// Remove trailing path
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	// Remove port suffix (we add ports ourselves per-check)
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		// Only strip if not an IPv6 address
		if !strings.Contains(target[:idx], "]") {
			target = target[:idx]
		}
	}
	return strings.TrimSpace(target)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

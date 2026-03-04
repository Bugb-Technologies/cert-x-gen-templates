// CERT-X-GEN Go Template - Redis Cluster Takeover Detection
//
// @id: redis-cluster-takeover
// @name: Redis Cluster Takeover Detection
// @author: BugB Technologies
// @severity: critical
// @description: Detects Redis Cluster misconfiguration allowing unauthorized cluster manipulation via CLUSTER MEET and slot reassignment. Tests both standard port (6379) and cluster bus port (16379).
// @tags: redis, cluster, takeover, cve-2024-redis, misconfiguration, protocol-abuse, unauth
// @cwe: CWE-306
// @confidence: 95
// @references: https://redis.io/docs/management/scaling/, https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Finding represents a security finding
type Finding struct {
	TemplateID   string                 `json:"template_id"`
	TemplateName string                 `json:"template_name"`
	Severity     string                 `json:"severity"`
	Confidence   int                    `json:"confidence"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Evidence     map[string]interface{} `json:"evidence,omitempty"`
	CWE          string                 `json:"cwe,omitempty"`
	CVSSScore    float64                `json:"cvss_score,omitempty"`
	Remediation  string                 `json:"remediation,omitempty"`
	References   []string               `json:"references,omitempty"`
	Mode         string                 `json:"mode,omitempty"`
	MatchedAt    string                 `json:"matched_at"`
}

// ClusterInfo holds cluster detection results
type ClusterInfo struct {
	Enabled               bool
	NodeCount             int
	ClusterState          string
	ClusterSlotsAssigned  int
	AuthEnabled           bool
	RequireFullCoverage   string
	VersionInfo           string
	MeetCommandAllowed    bool
	SetSlotCommandAllowed bool
}

func main() {
	// Get target from environment
	target := os.Getenv("CERT_X_GEN_TARGET_HOST")
	if target == "" && len(os.Args) > 1 {
		target = os.Args[1]
	}

	portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
	if portStr == "" {
		portStr = "6379"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid port number: %v\n", err)
		fmt.Println("[]")
		return
	}

	// Get mode (detect or exploit-sim)
	mode := os.Getenv("REDIS_SCAN_MODE")
	if mode == "" {
		mode = "detect" // Default to read-only detection
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: No target specified")
		fmt.Println("[]")
		return
	}

	findings := []Finding{}

	// Test standard port 6379
	fmt.Fprintf(os.Stderr, "[*] Testing Redis standard port 6379...\n")
	if finding := testRedisPort(target, 6379, mode); finding != nil {
		findings = append(findings, *finding)
	}

	// Test cluster bus port 16379
	fmt.Fprintf(os.Stderr, "[*] Testing Redis cluster bus port 16379...\n")
	if finding := testRedisPort(target, 16379, mode); finding != nil {
		findings = append(findings, *finding)
	}

	// Test the originally specified port if different
	if port != 6379 && port != 16379 {
		fmt.Fprintf(os.Stderr, "[*] Testing specified port %d...\n", port)
		if finding := testRedisPort(target, port, mode); finding != nil {
			findings = append(findings, *finding)
		}
	}

	output, err := json.Marshal(findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		fmt.Println("[]")
		return
	}
	fmt.Println(string(output))
}

func testRedisPort(host string, port int, mode string) *Finding {
	address := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Validate address format using net package
	_, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Port %d: Invalid address format: %v\n", port, err)
		return nil
	}

	// Try connecting without authentication
	client := redis.NewClient(&redis.Options{
		Addr:         address,
		Password:     "", // No password
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})
	defer client.Close()

	// Test connection with PING
	_, pingErr := client.Ping(ctx).Result()
	if pingErr != nil {
		// Check if error is due to authentication requirement
		if strings.Contains(pingErr.Error(), "NOAUTH") {
			fmt.Fprintf(os.Stderr, "[+] Port %d: Authentication required (properly secured)\n", port)
			return createAuthRequiredFinding(host, port)
		}
		fmt.Fprintf(os.Stderr, "[!] Port %d: Connection failed: %v\n", port, pingErr)
		return nil
	}

	fmt.Fprintf(os.Stderr, "[+] Port %d: Connection successful\n", port)

	// Gather cluster information
	clusterInfo := gatherClusterInfo(ctx, client, port)

	// Determine severity and findings
	return analyzeClusterVulnerability(host, port, clusterInfo, mode)
}

func gatherClusterInfo(ctx context.Context, client *redis.Client, port int) *ClusterInfo {
	info := &ClusterInfo{}

	// Check if cluster mode is enabled
	clusterInfoCmd := client.ClusterInfo(ctx)
	if clusterInfoCmd.Err() == nil {
		infoStr := clusterInfoCmd.Val()
		info.Enabled = true
		info.ClusterState = extractValue(infoStr, "cluster_state")
		slotsStr := extractValue(infoStr, "cluster_slots_assigned")
		if slotsStr != "" {
			slotsAssigned, parseErr := strconv.Atoi(slotsStr)
			if parseErr == nil {
				info.ClusterSlotsAssigned = slotsAssigned
			}
		}

		fmt.Fprintf(os.Stderr, "[+] Port %d: Cluster mode enabled (state: %s, slots: %d)\n",
			port, info.ClusterState, info.ClusterSlotsAssigned)
	} else {
		fmt.Fprintf(os.Stderr, "[-] Port %d: Cluster mode not enabled or CLUSTER INFO failed: %v\n", port, clusterInfoCmd.Err())
		return info
	}

	// Get cluster node count
	nodesCmd := client.ClusterNodes(ctx)
	if nodesCmd.Err() == nil {
		nodesStr := nodesCmd.Val()
		info.NodeCount = strings.Count(nodesStr, "\n")
		fmt.Fprintf(os.Stderr, "[+] Port %d: Cluster has %d nodes\n", port, info.NodeCount)
	}

	// Check authentication
	configCmd := client.ConfigGet(ctx, "requirepass")
	if configCmd.Err() == nil {
		configMap := configCmd.Val()
		if len(configMap) > 0 {
			if passVal, ok := configMap["requirepass"]; ok && passVal != "" {
				info.AuthEnabled = true
				fmt.Fprintf(os.Stderr, "[+] Port %d: Authentication is configured\n", port)
			} else {
				fmt.Fprintf(os.Stderr, "[!] Port %d: No authentication required\n", port)
			}
		}
	}

	// Check cluster-require-full-coverage
	coverageCmd := client.ConfigGet(ctx, "cluster-require-full-coverage")
	if coverageCmd.Err() == nil {
		coverageMap := coverageCmd.Val()
		if len(coverageMap) > 0 {
			if covVal, ok := coverageMap["cluster-require-full-coverage"]; ok {
				info.RequireFullCoverage = covVal
			}
		}
	}

	// Get version
	infoCmd := client.Info(ctx, "server")
	if infoCmd.Err() == nil {
		infoStr := infoCmd.Val()
		info.VersionInfo = extractValue(infoStr, "redis_version")
		fmt.Fprintf(os.Stderr, "[+] Port %d: Redis version %s\n", port, info.VersionInfo)
	}

	return info
}
func analyzeClusterVulnerability(host string, port int, info *ClusterInfo, mode string) *Finding {
	if !info.Enabled {
		return nil
	}

	severity := "info"
	title := ""
	description := ""
	evidence := make(map[string]interface{})
	cvssScore := 0.0

	evidence["port"] = port
	evidence["cluster_enabled"] = true
	evidence["cluster_state"] = info.ClusterState
	evidence["cluster_slots_assigned"] = info.ClusterSlotsAssigned
	evidence["node_count"] = info.NodeCount
	evidence["redis_version"] = info.VersionInfo
	evidence["auth_enabled"] = info.AuthEnabled
	evidence["require_full_coverage"] = info.RequireFullCoverage
	evidence["scan_mode"] = mode

	// Determine severity based on vulnerabilities
	vulnerabilities := []string{}

	// Critical: No authentication on cluster
	if !info.AuthEnabled {
		severity = "critical"
		cvssScore = 9.8
		vulnerabilities = append(vulnerabilities, "No authentication required for cluster commands")
	}

	// High: Authentication misconfiguration
	if info.AuthEnabled && info.RequireFullCoverage == "no" {
		if severity != "critical" {
			severity = "high"
			cvssScore = 7.5
		}
		vulnerabilities = append(vulnerabilities, "Cluster full coverage not required (potential slot hijacking)")
	}

	// Medium: Exposed cluster bus port
	if port == 16379 {
		if severity == "info" {
			severity = "medium"
			cvssScore = 5.3
		}
		vulnerabilities = append(vulnerabilities, "Cluster bus port 16379 exposed to network")
	}

	// Info: Cluster mode detected
	if len(vulnerabilities) == 0 {
		severity = "info"
		title = fmt.Sprintf("Redis Cluster Detected on %s:%d", host, port)
		description = fmt.Sprintf("Redis cluster mode is enabled with %d nodes. Cluster state: %s. Authentication is properly configured.",
			info.NodeCount, info.ClusterState)
	} else {
		title = fmt.Sprintf("Redis Cluster Takeover Vulnerability on %s:%d", host, port)
		description = fmt.Sprintf("Redis cluster on %s:%d has %d misconfiguration(s) that could allow cluster takeover:\n\n%s\n\nCluster State: %s (%d slots assigned, %d nodes)",
			host, port, len(vulnerabilities), strings.Join(vulnerabilities, "\n"), info.ClusterState, info.ClusterSlotsAssigned, info.NodeCount)
	}

	evidence["vulnerabilities"] = vulnerabilities
	evidence["vulnerability_count"] = len(vulnerabilities)

	// Mode-specific evidence
	if mode == "exploit-sim" {
		evidence["intrusive_mode"] = true
		evidence["exploit_simulation"] = "CLUSTER MEET test not implemented in detect mode for safety"
		fmt.Fprintf(os.Stderr, "[!] Port %d: exploit-sim mode detected but not fully implemented for safety\n", port)
	}

	remediation := buildRemediation(vulnerabilities)
	references := []string{
		"https://redis.io/docs/management/security/",
		"https://redis.io/docs/management/scaling/",
		"https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis",
		"https://redis.io/docs/management/security/encryption/",
	}

	return &Finding{
		TemplateID:   "redis-cluster-takeover",
		TemplateName: "Redis Cluster Takeover Detection",
		Severity:     severity,
		Confidence:   95,
		Title:        title,
		Description:  description,
		Evidence:     evidence,
		CWE:          "CWE-306",
		CVSSScore:    cvssScore,
		Remediation:  remediation,
		References:   references,
		Mode:         mode,
		MatchedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

func buildRemediation(vulnerabilities []string) string {
	if len(vulnerabilities) == 0 {
		return "No vulnerabilities detected. Continue monitoring cluster security."
	}

	remediation := "IMMEDIATE ACTIONS REQUIRED:\n\n"

	for _, vuln := range vulnerabilities {
		if strings.Contains(vuln, "No authentication") {
			remediation += "1. Enable Redis authentication:\n"
			remediation += "   - Set 'requirepass <strong-password>' in redis.conf\n"
			remediation += "   - Set 'masterauth <strong-password>' for cluster replication\n"
			remediation += "   - Restart all cluster nodes\n\n"
		}

		if strings.Contains(vuln, "full coverage") {
			remediation += "2. Configure cluster-require-full-coverage:\n"
			remediation += "   - Set 'cluster-require-full-coverage yes' in redis.conf\n"
			remediation += "   - This prevents cluster operations when slots are not fully assigned\n\n"
		}

		if strings.Contains(vuln, "bus port") {
			remediation += "3. Restrict cluster bus port (16379) access:\n"
			remediation += "   - Configure firewall rules to allow only trusted cluster nodes\n"
			remediation += "   - Use 'bind' directive to limit network interfaces\n"
			remediation += "   - Consider VPN or private network for cluster communication\n\n"
		}
	}

	remediation += "ADDITIONAL HARDENING:\n"
	remediation += "- Enable TLS for cluster communication\n"
	remediation += "- Implement network segmentation\n"
	remediation += "- Regular security audits and monitoring\n"
	remediation += "- Keep Redis updated to latest stable version"

	return remediation
}

func createAuthRequiredFinding(host string, port int) *Finding {
	return &Finding{
		TemplateID:   "redis-cluster-takeover",
		TemplateName: "Redis Cluster Takeover Detection",
		Severity:     "info",
		Confidence:   95,
		Title:        fmt.Sprintf("Redis Authentication Properly Configured on %s:%d", host, port),
		Description:  fmt.Sprintf("Redis instance on %s:%d requires authentication (NOAUTH error received). This is the expected secure configuration. Unable to test cluster configuration without valid credentials.", host, port),
		Evidence: map[string]interface{}{
			"port":            port,
			"auth_required":   true,
			"security_status": "properly_secured",
			"error":           "NOAUTH Authentication required",
		},
		CWE:         "CWE-306",
		CVSSScore:   0.0,
		Remediation: "No action required. Authentication is properly configured. Ensure credentials are strong and rotated regularly.",
		References: []string{
			"https://redis.io/docs/management/security/",
		},
		MatchedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func extractValue(text, key string) string {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

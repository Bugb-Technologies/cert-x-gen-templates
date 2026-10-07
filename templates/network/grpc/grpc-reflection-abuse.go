package main

// @id: grpc-reflection-abuse
// @name: gRPC Reflection API Exposure Detection
// @author: CERT-X-GEN Security Team
// @severity: high
// @description: Detects gRPC servers with reflection API enabled, exposing service definitions and methods
// @tags: grpc, reflection, information-disclosure, service-enumeration
// @cwe: CWE-200, CWE-538
// @cvss: 5.3
// @references: https://github.com/grpc/grpc/blob/master/doc/server-reflection.md, https://grpc.io/docs/guides/reflection/
// @confidence: 95
// @version: 1.1.0

/*
gRPC Reflection API Exposure Detection Template

This template detects gRPC servers with the Server Reflection API enabled,
which allows clients to discover service definitions, methods, and message
types at runtime without requiring .proto files.

VULNERABILITY BACKGROUND:
The gRPC Server Reflection protocol is designed for development and debugging,
allowing tools like grpcurl and grpcui to dynamically discover and interact
with gRPC services. When left enabled in production:

1. Attackers can enumerate all available services
2. Method signatures and message schemas are exposed
3. Attack surface is fully mapped without authentication
4. Internal service names and structures are revealed
5. Facilitates targeted attacks on specific endpoints

DETECTION STRATEGY:
1. Establish gRPC connection to target (ports: 9090, 50051, or custom)
2. Query grpc.reflection.v1alpha.ServerReflection service
3. List all registered services
4. Extract method definitions
5. Assess severity based on exposed service types

VERDICTS (template contract):
- Reflection answers a ListServices query (v1alpha or v1) -> one finding.
- Reflection is Unimplemented on both v1alpha and v1     -> empty findings
  array, which cxg records as REFUTED (the server is not vulnerable).
- The probe could not complete (connection refused, timeout, any other RPC
  error) -> a JSON {"error": ...} object on stdout and exit status 1, which
  cxg records as ERRORED. An unreachable target is never reported as either
  vulnerable or safe.

INDICATORS OF VULNERABILITY:
- Reflection service responds successfully
- Multiple services enumerated
- Sensitive internal service names exposed
- No authentication required for reflection queries

WHY GO:
- Native gRPC support via google.golang.org/grpc
- Protocol buffer handling
- Efficient connection management
- Low-level control over RPC calls

SAFETY NOTE:
This template performs SAFE ENUMERATION only. It queries the reflection API
but does not invoke any business logic methods or attempt exploitation.

ATTACK IMPACT:
- CVSS: 5.3 (Medium)
- Full service enumeration and API discovery
- Information disclosure about internal architecture
- Facilitates reconnaissance for further attacks
- May expose sensitive internal service names
*/

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
)

// Metadata structure for template information
var Metadata = map[string]interface{}{
	"id":   "grpc-reflection-abuse",
	"name": "gRPC Reflection API Exposure Detection",
	"author": map[string]string{
		"name":  "CERT-X-GEN Security Team",
		"email": "security@cert-x-gen.io",
	},
	"severity":    "high",
	"description": "Detects gRPC servers with reflection API enabled exposing service definitions",
	"tags":        []string{"grpc", "reflection", "information-disclosure", "service-enumeration"},
	"language":    "go",
	"confidence":  95,
	"cwe":         []string{"CWE-200", "CWE-538"},
	"cvss":        5.3,
	"references": []string{
		"https://github.com/grpc/grpc/blob/master/doc/server-reflection.md",
		"https://grpc.io/docs/guides/reflection/",
		"https://github.com/fullstorydev/grpcurl",
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

// GRPCReflectionResult holds enumeration data
type GRPCReflectionResult struct {
	ReflectionEnabled bool
	Services          []string
	ServiceCount      int
	Methods           map[string][]string
	HasSensitiveNames bool
	SensitiveServices []string
}

// isSensitiveServiceName checks if service name indicates internal/sensitive functionality
func isSensitiveServiceName(serviceName string) bool {
	sensitiveKeywords := []string{
		"admin", "internal", "private", "debug", "test",
		"management", "auth", "user", "account", "payment",
		"billing", "credential", "secret", "token", "key",
	}

	lowerName := strings.ToLower(serviceName)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerName, keyword) {
			return true
		}
	}
	return false
}

// errReflectionUnavailable means the server answered, but does not implement
// the reflection service: the secure configuration, not a probe failure.
var errReflectionUnavailable = errors.New("reflection service not implemented")

// isUnimplemented reports whether err is the gRPC status a server returns for
// a service it does not register.
func isUnimplemented(err error) bool {
	return status.Code(err) == codes.Unimplemented
}

// listServicesV1Alpha asks the v1alpha reflection service for every service name.
func listServicesV1Alpha(ctx context.Context, conn *grpc.ClientConn) ([]string, error) {
	stream, err := grpc_reflection_v1alpha.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{ListServices: "*"},
	}); err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	list := resp.GetListServicesResponse()
	if list == nil {
		return nil, fmt.Errorf("no list services response")
	}
	names := []string{}
	for _, svc := range list.Service {
		names = append(names, svc.Name)
	}
	return names, nil
}

// listServicesV1 asks the v1 reflection service for every service name.
func listServicesV1(ctx context.Context, conn *grpc.ClientConn) ([]string, error) {
	stream, err := grpc_reflection_v1.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&grpc_reflection_v1.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_ListServices{ListServices: "*"},
	}); err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	list := resp.GetListServicesResponse()
	if list == nil {
		return nil, fmt.Errorf("no list services response")
	}
	names := []string{}
	for _, svc := range list.Service {
		names = append(names, svc.Name)
	}
	return names, nil
}

// queryReflectionAPI queries the gRPC reflection service.
//
// It returns errReflectionUnavailable when the server is reachable but
// implements neither reflection version, and any other error when the probe
// itself could not complete.
func queryReflectionAPI(host string, port int, timeout time.Duration) (*GRPCReflectionResult, error) {
	result := &GRPCReflectionResult{
		Services:          []string{},
		Methods:           make(map[string][]string),
		SensitiveServices: []string{},
	}

	// Connect to gRPC server
	target := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return result, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// v1alpha is what most servers register; v1 is the stable name newer
	// servers may register instead. Only when BOTH are Unimplemented is
	// reflection off.
	names, err := listServicesV1Alpha(ctx, conn)
	if err != nil && isUnimplemented(err) {
		names, err = listServicesV1(ctx, conn)
		if err != nil && isUnimplemented(err) {
			return result, errReflectionUnavailable
		}
	}
	if err != nil {
		return result, fmt.Errorf("reflection request failed: %w", err)
	}

	result.ReflectionEnabled = true

	for _, serviceName := range names {
		// Skip the reflection service itself
		if strings.Contains(serviceName, "grpc.reflection") {
			continue
		}

		result.Services = append(result.Services, serviceName)

		// Check for sensitive service names
		if isSensitiveServiceName(serviceName) {
			result.HasSensitiveNames = true
			result.SensitiveServices = append(result.SensitiveServices, serviceName)
		}
	}

	result.ServiceCount = len(result.Services)

	return result, nil
}

// testVulnerability is the main detection function.
//
// An empty slice with a nil error means "not vulnerable": the server answered
// and reflection is not implemented. A non-nil error means the probe could not
// reach a verdict, and the caller must report it as an error, not as a finding.
func testVulnerability(host string, port int, timeout int) ([]Finding, error) {
	findings := []Finding{}
	target := fmt.Sprintf("%s:%d", host, port)

	// Query reflection API
	testResult, err := queryReflectionAPI(host, port, time.Duration(timeout)*time.Second)
	if errors.Is(err, errReflectionUnavailable) {
		// Reflection disabled: the secure configuration. No finding.
		return findings, nil
	}
	if err != nil {
		return nil, err
	}

	// Analyze results and determine severity
	severity := "info"
	confidence := 95
	title := "gRPC Reflection Enabled"
	description := "gRPC server has reflection API enabled."

	if testResult.ServiceCount == 0 {
		// Reflection enabled but no services (unusual)
		severity = "low"
		title = "gRPC Reflection Enabled (No Services)"
		description = "Reflection API is enabled but no services are exposed."
	} else if testResult.ServiceCount <= 2 && !testResult.HasSensitiveNames {
		// Few services, no sensitive names
		severity = "medium"
		confidence = 80
		title = "gRPC Reflection Enabled (Limited Exposure)"
		description = fmt.Sprintf("Reflection API exposes %d service(s). Limited information disclosure.",
			testResult.ServiceCount)
	} else if testResult.HasSensitiveNames {
		// Sensitive service names exposed
		severity = "high"
		confidence = 95
		title = "gRPC Reflection Exposes Sensitive Services"
		description = fmt.Sprintf("Reflection API enabled and exposes %d service(s), including %d with sensitive names. "+
			"This allows attackers to enumerate internal services and understand system architecture.",
			testResult.ServiceCount, len(testResult.SensitiveServices))
	} else {
		// Multiple services exposed
		severity = "high"
		confidence = 90
		title = "gRPC Reflection Exposes Multiple Services"
		description = fmt.Sprintf("Reflection API enabled and exposes %d service(s). "+
			"Attackers can enumerate all available methods and message types.",
			testResult.ServiceCount)
	}

	// Build evidence
	evidence := map[string]interface{}{
		"reflection_enabled":  testResult.ReflectionEnabled,
		"service_count":       testResult.ServiceCount,
		"services":            testResult.Services,
		"has_sensitive_names": testResult.HasSensitiveNames,
	}

	if testResult.HasSensitiveNames {
		evidence["sensitive_services"] = testResult.SensitiveServices
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
		finding.Remediation = "Disable gRPC reflection in production environments. " +
			"Only enable reflection for development/testing. " +
			"If reflection is required, implement authentication and restrict access to authorized clients. " +
			"Consider using allowlisting for reflection queries."
		finding.CWEIDs = Metadata["cwe"].([]string)
		finding.CVSSScore = Metadata["cvss"].(float64)
	}

	findings = append(findings, finding)
	return findings, nil
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
			port = 9090 // Default gRPC port
		} else {
			fmt.Sscanf(portStr, "%d", &port)
		}
	} else {
		// CLI mode (direct execution)
		if len(os.Args) < 2 {
			result := map[string]interface{}{
				"error": "Usage: grpc-reflection-abuse <host> [port]",
			}
			jsonOutput, _ := json.Marshal(result)
			fmt.Println(string(jsonOutput))
			os.Exit(1)
		}
		host = os.Args[1]
		if len(os.Args) > 2 {
			fmt.Sscanf(os.Args[2], "%d", &port)
		} else {
			port = 9090 // Default gRPC port
		}
	}

	// Run detection with 10s timeout
	findings, err := testVulnerability(host, port, 10)
	if err != nil {
		// No verdict: report an error (exit 1) so cxg records the run as
		// errored rather than as confirmed or refuted.
		errorResult := map[string]interface{}{
			"error":    fmt.Sprintf("gRPC reflection probe failed against %s:%d: %v", host, port, err),
			"findings": []Finding{},
		}
		errorJSON, _ := json.Marshal(errorResult)
		fmt.Println(string(errorJSON))
		// cxg reports stderr (not stdout) as the reason a run errored.
		fmt.Fprintln(os.Stderr, errorResult["error"])
		os.Exit(1)
	}

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

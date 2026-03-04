
---

## 10. Extending the Template

### Testing Multiple Ports

```go
func scanMultiplePorts(host string) []Finding {
    ports := []int{9090, 50051, 8080, 443}
    allFindings := []Finding{}
    
    for _, port := range ports {
        findings := testVulnerability(host, port, 10)
        allFindings = append(allFindings, findings...)
    }
    
    return allFindings
}
```

### Adding Method Enumeration

```go
// Extend to enumerate methods for each service
for _, serviceName := range services {
    err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
        MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileContainingSymbol{
            FileContainingSymbol: serviceName,
        },
    })
    
    resp, _ := stream.Recv()
    fileDescriptor := resp.GetFileDescriptorResponse()
    // Parse and extract method names
}
```

### Custom Sensitive Keywords

```go
// Add organization-specific keywords
func loadSensitiveKeywords() []string {
    keywords := []string{
        "admin", "internal", "private",
        // Add your company-specific terms
        "mycompany", "confidential", "restricted",
    }
    
    // Load from config file
    if data, err := os.ReadFile("keywords.txt"); err == nil {
        lines := strings.Split(string(data), "\n")
        keywords = append(keywords, lines...)
    }
    
    return keywords
}
```

### Integration with Alerting

```go
func sendAlert(finding Finding, webhookURL string) {
    if finding.Severity == "high" {
        payload := map[string]interface{}{
            "text": fmt.Sprintf("⚠️ gRPC Reflection Exposed: %s", finding.Target),
            "details": finding.Evidence,
        }
        
        jsonData, _ := json.Marshal(payload)
        http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
    }
}
```

---

## 11. References

### Primary Documentation

**gRPC Reflection Protocol**:
- [gRPC Server Reflection Protocol](https://github.com/grpc/grpc/blob/master/doc/server-reflection.md)
- [gRPC Reflection Tutorial](https://grpc.io/docs/guides/reflection/)
- [Server Reflection Guide](https://github.com/grpc/grpc-go/tree/master/reflection)

**Tools**:
- [grpcurl](https://github.com/fullstorydev/grpcurl) - Command-line gRPC client with reflection support
- [grpcui](https://github.com/fullstorydev/grpcui) - Web UI for gRPC with reflection
- [BloomRPC](https://github.com/uw-labs/bloomrpc) - GUI client using reflection

### Security Research

**Vulnerabilities & Incidents**:
- [gRPC Reflection Information Disclosure (2019)](https://blog.netspi.com/attacking-grpc-services/)
- [gRPC Service Discovery in Pentests](https://www.vicarius.io/vsociety/posts/grpc-penetration-testing)
- [Cloud-Native Security: gRPC Misconfiguration](https://www.paloaltonetworks.com/blog/prisma-cloud/grpc-security/)

**CVE References**:
- CWE-200: Exposure of Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- CWE-287: Improper Authentication (when reflection bypasses auth)

### Implementation Guides

**Language-Specific**:
- [grpc-go Reflection](https://github.com/grpc/grpc-go/tree/master/reflection)
- [grpcio Python Reflection](https://grpc.github.io/grpc/python/grpc_reflection.html)
- [grpc-java Reflection](https://github.com/grpc/grpc-java/tree/master/services#reflection)
- [grpc-node Reflection](https://github.com/grpc/grpc-node/tree/master/packages/grpc-reflection)

**Security Best Practices**:
- [gRPC Security Guide](https://grpc.io/docs/guides/security/)
- [gRPC Authentication](https://grpc.io/docs/guides/auth/)
- [Production Checklist](https://grpc.io/docs/guides/production-checklist/)

### Standards & Compliance

**OWASP**:
- [API Security Top 10](https://owasp.org/www-project-api-security/)
- [Excessive Data Exposure](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa3-excessive-data-exposure.md)

**NIST Guidelines**:
- NIST SP 800-53: SC-7 (Boundary Protection)
- NIST SP 800-95: Guide to Secure Web Services

### Community Resources

**Blogs & Tutorials**:
- [Securing gRPC Services](https://medium.com/google-cloud/securing-grpc-services-with-cloud-armor-b47d3d5b4f3a)
- [gRPC Production Best Practices](https://www.cncf.io/blog/2021/07/19/grpc-at-scale/)
- [Kubernetes gRPC Security](https://kubernetes.io/blog/2018/11/07/grpc-load-balancing-on-kubernetes/)

**Books**:
- "gRPC: Up and Running" (O'Reilly) - Chapter on Security
- "Cloud Native Go" - gRPC Security Section
- "Microservices Security in Action" - Service Mesh & gRPC

---

## Appendix: Quick Reference

### Detection Checklist

- [ ] gRPC service responds on target port
- [ ] Reflection service registered
- [ ] `ListServices` query succeeds
- [ ] Services enumerated without authentication
- [ ] Sensitive service names exposed (admin, internal, etc.)
- [ ] Method signatures discoverable

**Risk Score**:
- 0-1 indicators: Low/Info
- 2-3 indicators: Medium
- 4+ indicators: High

### Quick Test Commands

```bash
# Using grpcurl
grpcurl -plaintext target.com:50051 list

# Using CERT-X-GEN
go run grpc-reflection-abuse.go target.com 50051

# Check specific service
grpcurl -plaintext target.com:50051 describe myapp.Service
```

### Emergency Remediation

```go
// Quick fix: Comment out reflection registration
// reflection.Register(grpcServer)

// Better fix: Environment-based
if os.Getenv("ENABLE_REFLECTION") == "true" {
    reflection.Register(grpcServer)
}
```

### Verification Command

```bash
# Should return error if properly secured
grpcurl -plaintext your-server.com:50051 list 2>&1 | grep -i "unimplemented\|unknown service"
```

---

**End of gRPC Reflection API Exposure Detection Playbook**

*For questions or contributions: security@cert-x-gen.io*


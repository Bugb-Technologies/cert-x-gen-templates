#!/bin/bash
#
# CERT-X-GEN Docker Registry Unauthenticated Access Detection Template
#
# Template Metadata:
#   ID: docker-registry-unauthenticated
#   Name: Docker Registry Unauthenticated Access Detection
#   Author: CERT-X-GEN Security Team
#   Severity: high
#   Description: Detects Docker Registry instances accessible without authentication,
#                allowing unauthorized access to container images and potentially sensitive
#                data. Tests for catalog listing, image enumeration, and manifest access.
#   Tags: docker, registry, container, authentication, devops, image-repository
#   Language: shell
#   CWE: CWE-306 (Missing Authentication for Critical Function)
#   References:
#     - https://cwe.mitre.org/data/definitions/306.html
#     - https://docs.docker.com/registry/deploying/
#     - https://docs.docker.com/registry/configuration/#auth
################################################################################

# Template metadata
TEMPLATE_ID="docker-registry-v2-unauthenticated"
TEMPLATE_NAME="Docker Registry v2 Unauthenticated Access"
SEVERITY="critical"
CONFIDENCE=95
TAGS="docker,registry,container,unauthenticated"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Usage
usage() {
    echo "Usage: $0 <target> [port]"
    echo "Example: $0 registry.example.com 5000"
    exit 1
}

# Log finding
log_finding() {
    local severity=$1
    local title=$2
    local description=$3
    
    echo -e "${RED}[${severity}]${NC} ${title}"
    echo "    Description: ${description}"
    echo "    Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
}

# Test Docker Registry v2 API
test_docker_registry() {
    local target=$1
    local port=${2:-5000}
    local base_url="http://${target}:${port}"
    
    echo "Testing Docker Registry v2 at ${base_url}"
    echo "================================================"
    echo ""
    
    # Test 1: Check version endpoint
    echo "[*] Testing version endpoint..."
    local version_response=$(curl -s -m 5 "${base_url}/v2/" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && [[ ! -z "$version_response" ]]; then
        if echo "$version_response" | grep -q "Docker"; then
            log_finding "CRITICAL" \
                "Docker Registry v2 Accessible" \
                "Registry API endpoint accessible without authentication"
            
            # Extract version info
            echo "    Evidence:"
            echo "    - Endpoint: ${base_url}/v2/"
            echo "    - Response: ${version_response}"
            echo ""
        fi
    fi
    
    # Test 2: List catalog (all repositories)
    echo "[*] Testing catalog enumeration..."
    local catalog_response=$(curl -s -m 5 "${base_url}/v2/_catalog" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$catalog_response" | grep -q "repositories"; then
        log_finding "CRITICAL" \
            "Docker Registry Catalog Enumeration" \
            "Successfully enumerated registry repositories without authentication"
        
        # Parse repositories
        local repos=$(echo "$catalog_response" | grep -o '"repositories":\[[^]]*\]' | sed 's/"repositories"://g')
        local repo_count=$(echo "$catalog_response" | grep -o '"[^"]*"' | grep -v "repositories" | wc -l)
        
        echo "    Evidence:"
        echo "    - Repository count: $repo_count"
        echo "    - Repositories: $repos"
        echo ""
        
        # Test 3: Try to list tags for first repository
        local first_repo=$(echo "$catalog_response" | grep -o '"[^"]*"' | grep -v "repositories" | head -1 | tr -d '"')
        
        if [[ ! -z "$first_repo" ]]; then
            echo "[*] Testing tag enumeration for repository: ${first_repo}..."
            local tags_response=$(curl -s -m 5 "${base_url}/v2/${first_repo}/tags/list" 2>/dev/null)
            
            if [[ $? -eq 0 ]] && echo "$tags_response" | grep -q "tags"; then
                log_finding "HIGH" \
                    "Docker Image Tag Enumeration" \
                    "Successfully enumerated image tags for repository ${first_repo}"
                
                echo "    Evidence:"
                echo "    - Repository: ${first_repo}"
                echo "    - Tags: ${tags_response}"
                echo ""
                
                # Test 4: Try to pull manifest
                local first_tag=$(echo "$tags_response" | grep -o '"[^"]*"' | grep -v "name\|tags" | head -1 | tr -d '"')
                
                if [[ ! -z "$first_tag" ]]; then
                    echo "[*] Testing manifest access for ${first_repo}:${first_tag}..."
                    local manifest_response=$(curl -s -m 5 \
                        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
                        "${base_url}/v2/${first_repo}/manifests/${first_tag}" 2>/dev/null)
                    
                    if [[ $? -eq 0 ]] && echo "$manifest_response" | grep -q "schemaVersion"; then
                        log_finding "CRITICAL" \
                            "Docker Image Manifest Access" \
                            "Successfully accessed image manifest for ${first_repo}:${first_tag}"
                        
                        echo "    Evidence:"
                        echo "    - Image: ${first_repo}:${first_tag}"
                        echo "    - Manifest accessible: YES"
                        echo "    - Can pull image: YES"
                        echo ""
                    fi
                fi
            fi
        fi
    fi
    
    # Test 5: Check for common sensitive repositories
    echo "[*] Checking for sensitive repositories..."
    local sensitive_repos=("admin" "internal" "private" "production" "prod" "staging" "dev")
    
    for repo in "${sensitive_repos[@]}"; do
        local check_response=$(curl -s -m 3 "${base_url}/v2/${repo}/tags/list" 2>/dev/null)
        if [[ $? -eq 0 ]] && echo "$check_response" | grep -q "tags"; then
            log_finding "HIGH" \
                "Sensitive Repository Exposed" \
                "Potentially sensitive repository '${repo}' is accessible"
            
            echo "    Evidence:"
            echo "    - Repository: ${repo}"
            echo "    - Response: ${check_response}"
            echo ""
        fi
    done
}

# Print remediation
print_remediation() {
    echo ""
    echo "=========================================="
    echo "REMEDIATION STEPS"
    echo "=========================================="
    cat << 'EOF'

1. Enable authentication in Docker Registry:
   
   auth:
     htpasswd:
       realm: "Registry Realm"
       path: /path/to/htpasswd

2. Create htpasswd file:
   docker run --rm --entrypoint htpasswd httpd:2 -Bbn username password > htpasswd

3. Enable TLS/SSL:
   http:
     tls:
       certificate: /path/to/cert.pem
       key: /path/to/key.pem

4. Bind to localhost only (if using reverse proxy):
   http:
     addr: 127.0.0.1:5000

5. Use Docker Content Trust for image signing

6. Implement network segmentation and firewall rules

7. Enable access logging:
   log:
     accesslog:
       disabled: false

8. Regular security audits and updates

REFERENCES:
- https://docs.docker.com/registry/configuration/
- https://docs.docker.com/registry/deploying/#restricting-access
- CWE-306: https://cwe.mitre.org/data/definitions/306.html

EOF
}

# Generate JSON output
generate_json_output() {
    cat << EOF
{
  "template": {
    "id": "${TEMPLATE_ID}",
    "name": "${TEMPLATE_NAME}",
    "severity": "${SEVERITY}",
    "confidence": ${CONFIDENCE},
    "language": "shell",
    "tags": ["${TAGS//,/\",\"}"]
  },
  "target": "$1",
  "scan_time": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "findings": []
}
EOF
}

# Main execution
main() {
    if [[ $# -lt 1 ]]; then
        usage
    fi
    
    local target=$1
    local port=${2:-5000}
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  Docker Registry v2 Unauthenticated Access Detection      ║"
    echo "║  CERT-X-GEN Security Template                              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Run tests
    test_docker_registry "$target" "$port"
    
    # Print remediation
    print_remediation
    
    echo ""
    echo "Scan completed at $(date)"
}

# Execute
main "$@"

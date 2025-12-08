#!/bin/bash
#
# CERT-X-GEN Shell Template: Unauthenticated etcd Service
#
# Template Metadata:
#   ID: etcd-unauthenticated-access
#   Name: Unauthenticated etcd Service Detection
#   Author: CERT-X-GEN Security Team
#   Severity: critical
#   Description: Detects unauthenticated etcd services exposing sensitive cluster data.
#                etcd is a distributed key-value store used by Kubernetes and other systems.
#                Unauthenticated access can lead to complete cluster compromise.
#   Tags: etcd,kubernetes,unauth,key-value-store,distributed-systems
#   Language: shell
#   CWE: CWE-306 (Missing Authentication for Critical Function)
#   References:
#     - https://cwe.mitre.org/data/definitions/306.html
#     - https://etcd.io/docs/
#     - https://github.com/etcd-io/etcd
#     - https://www.cvedetails.com/vulnerability-list/vendor_id-18594/product_id-49166/Etcd-Io-Etcd.html
################################################################################

# ========================================
# TEMPLATE METADATA
# ========================================
TEMPLATE_ID="etcd-unauthenticated-access"
TEMPLATE_NAME="Unauthenticated etcd Service Detection"
TEMPLATE_AUTHOR="CERT-X-GEN Security Team"
SEVERITY="critical"
CONFIDENCE=95
TAGS="etcd,kubernetes,unauth,endpoint,vulnerability"
CWE="CWE-306"

CONTEXT_JSON="${CERT_X_GEN_CONTEXT:-}"
ADD_PORTS_ENV="${CERT_X_GEN_ADD_PORTS:-}"
OVERRIDE_PORTS_ENV="${CERT_X_GEN_OVERRIDE_PORTS:-}"

# ========================================
# COLORS AND OUTPUT HELPERS
# ========================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# ========================================
# HELPER FUNCTIONS
# ========================================

# Calculate CVSS score from severity
calculate_cvss_score() {
    local severity=$1
    case "$severity" in
        critical) echo "9.8" ;;
        high) echo "7.5" ;;
        medium) echo "5.0" ;;
        low) echo "3.0" ;;
        info) echo "0.0" ;;
        *) echo "5.0" ;;
    esac
}

# Create a finding in JSON format
create_finding() {
    local title=$1
    local description=$2
    local evidence=$3
    local severity=${4:-$SEVERITY}
    local remediation=${5:-"Apply authentication and authorization to etcd service"}
    
    local cvss_score=$(calculate_cvss_score "$severity")
    
    cat << EOF
{
    "template_id": "${TEMPLATE_ID}",
    "severity": "${severity}",
    "confidence": ${CONFIDENCE},
    "title": "${title}",
    "description": "${description}",
    "evidence": ${evidence},
    "cwe": "${CWE}",
    "cvss_score": ${cvss_score},
    "remediation": "${remediation}",
    "references": [
        "https://cwe.mitre.org/data/definitions/306.html",
        "https://etcd.io/docs/v3.5/op-guide/security/",
        "https://www.cvedetails.com/vulnerability-list/vendor_id-18594/product_id-49166/Etcd-Io-Etcd.html"
    ]
}
EOF
}

# Check dependencies
check_dependencies() {
    local deps=("etcdctl" "curl" "nc")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_warning "Missing dependencies: ${missing[*]}"
        log_info "Install etcdctl with: apt-get install etcd-client (Ubuntu) or download from https://github.com/etcd-io/etcd/releases"
        return 1
    fi
    
    return 0
}

# ========================================
# SCANNING FUNCTIONS
# ========================================

# Test if etcd endpoint is accessible
test_etcd_endpoint() {
    local host=$1
    local port=$2
    
    log_info "Testing etcd endpoint at ${host}:${port}"
    
    # First check if port is open
    if ! nc -z -w 3 "$host" "$port" 2>&1 | grep -q "succeeded\|open"; then
        log_warning "Port ${port} is not open"
        return 1
    fi
    
    log_success "Port ${port} is open, testing etcd service"
    return 0
}

# Test unauthenticated etcd access using etcdctl
test_etcd_unauth_access() {
    local host=$1
    local port=$2
    
    local endpoint="http://${host}:${port}"
    
    log_info "Testing etcd unauthenticated access with: etcdctl --endpoints=${endpoint} member list"
    
    # Try to list etcd members without authentication
    local result
    result=$(timeout 10 etcdctl --endpoints="$endpoint" member list 2>&1)
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        # Check if we got valid member list output
        if echo "$result" | grep -q -E "^[0-9a-f]+, started,"; then
            log_success "Unauthenticated etcd access confirmed - member list retrieved"
            echo "$result"
            return 0
        fi
    fi
    
    # Alternative test: try to get version info
    log_info "Trying alternative test: etcdctl --endpoints=${endpoint} version"
    result=$(timeout 10 etcdctl --endpoints="$endpoint" version 2>&1)
    
    if [ $? -eq 0 ] && echo "$result" | grep -q "etcdctl version:"; then
        log_success "Unauthenticated etcd access confirmed - version info retrieved"
        echo "$result"
        return 0
    fi
    
    return 1
}

# Test etcd health endpoint
test_etcd_health() {
    local host=$1
    local port=$2
    
    local health_url="http://${host}:${port}/health"
    
    log_info "Testing etcd health endpoint: ${health_url}"
    
    local response
    response=$(curl -s -w "\n%{http_code}" -m 5 "$health_url" 2>/dev/null)
    local status_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | head -n -1)
    
    if [ "$status_code" = "200" ]; then
        if echo "$body" | grep -q '"health":"true"'; then
            log_success "etcd health endpoint accessible without authentication"
            echo "$body"
            return 0
        fi
    fi
    
    return 1
}

# ========================================
# MAIN SCANNING LOGIC
# ========================================

scan_target() {
    local host=$1
    local port=${2:-2379}
    local findings="[]"
    
    log_info "Scanning for unauthenticated etcd service on ${host}:${port}"
    
    # Check if etcd endpoint is accessible
    if ! test_etcd_endpoint "$host" "$port"; then
        log_info "etcd service not detected on ${host}:${port}"
        echo "$findings"
        return 0
    fi
    
    # Test unauthenticated access using etcdctl
    local etcd_result=$(test_etcd_unauth_access "$host" "$port")
    if [ ! -z "$etcd_result" ]; then
        local evidence='{"endpoint": "'${host}:${port}'", "command": "etcdctl --endpoints=http://'${host}:${port}' member list", "output": "'$(echo "$etcd_result" | base64 -w 0)'", "vulnerable": true}'
        local finding=$(create_finding \
            "Unauthenticated etcd Service" \
            "etcd service running on ${host}:${port} is accessible without authentication. This exposes sensitive cluster data including configuration, secrets, and cluster state. Attackers can read/write arbitrary data, potentially compromising the entire cluster." \
            "$evidence" \
            "critical" \
            "1. Enable etcd authentication with client certificate authentication\n2. Configure etcd with proper TLS/SSL encryption\n3. Use network policies to restrict access to etcd ports\n4. Consider using etcd gateways or proxies with authentication\n5. Regularly monitor etcd access logs for unauthorized access"
        )
        
        findings=$(echo "$findings" | jq ". += [$finding]")
    fi
    
    # Test health endpoint accessibility
    local health_result=$(test_etcd_health "$host" "$port")
    if [ ! -z "$health_result" ]; then
        local evidence='{"endpoint": "'${host}:${port}'", "health_endpoint": "http://'${host}:${port}'/health", "response": "'$(echo "$health_result" | base64 -w 0)'", "vulnerable": true}'
        local finding=$(create_finding \
            "Unauthenticated etcd Health Endpoint" \
            "etcd health endpoint is accessible without authentication on ${host}:${port}. While this endpoint may contain less sensitive information, it still reveals service status and can be used for reconnaissance." \
            "$evidence" \
            "medium" \
            "1. Restrict access to etcd health endpoints\n2. Implement authentication for all etcd endpoints\n3. Use network segmentation to protect etcd services"
        )
        
        findings=$(echo "$findings" | jq ". += [$finding]")
    fi
    
    echo "$findings"
}

# ========================================
# COMMAND LINE PARSING
# ========================================

usage() {
    cat << EOF
Usage: $0 <target> [port] [options]

CERT-X-GEN Shell Template: ${TEMPLATE_NAME}

Arguments:
    target          Target host or IP address
    port            Target port (default: 2379)

Options:
    --json          Output findings as JSON
    --verbose       Enable verbose output
    --help          Show this help message

Environment Variables:
    CERT_X_GEN_MODE         Set to "engine" for integration mode
    CERT_X_GEN_TARGET_HOST  Target host (overrides argument)
    CERT_X_GEN_TARGET_PORT  Target port (overrides argument)
    CERT_X_GEN_CONTEXT      JSON context data

Example:
    $0 example.com 2379
    $0 192.168.1.100 2376 --json

EOF
    exit 0
}

# ========================================
# MAIN EXECUTION
# ========================================

main() {
    local target=""
    local port=2379
    local json_output=false
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --json)
                json_output=true
                shift
                ;;
            --verbose)
                verbose=true
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                if [ -z "$target" ]; then
                    target=$1
                elif [ "$port" = "2379" ]; then
                    port=$1
                fi
                shift
                ;;
        esac
    done
    
    # Get target from environment if not provided
    if [ -z "$target" ]; then
        target=${CERT_X_GEN_TARGET_HOST:-}
    fi
    
    if [ -z "$target" ]; then
        log_error "No target specified"
        usage
    fi
    
    # Get port from environment if available
    if [ ! -z "$CERT_X_GEN_TARGET_PORT" ]; then
        port=$CERT_X_GEN_TARGET_PORT
    fi
    
    # Check if running in engine mode
    if [ "$CERT_X_GEN_MODE" = "engine" ]; then
        json_output=true
        verbose=false
    fi
    
    # Check dependencies
    if ! $json_output; then
        check_dependencies || exit 1
    fi
    
    # Print banner
    if ! $json_output; then
        echo ""
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  ${TEMPLATE_NAME}"
        echo "║  CERT-X-GEN Security Template"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Target: ${target}:${port}"
        echo "Started: $(date)"
        echo ""
    fi
    
    # Run the scan
    local findings=$(scan_target "$target" "$port")
    
    # Output results
    if $json_output || [ "$CERT_X_GEN_MODE" = "engine" ]; then
        # JSON output for CERT-X-GEN engine
        if [ "$CERT_X_GEN_MODE" = "engine" ]; then
            # Special markers for engine parsing
            echo "[CERT-X-GEN-JSON]${findings}[/CERT-X-GEN-JSON]"
        else
            echo "$findings"
        fi
    else
        # Human-readable output
        local finding_count=$(echo "$findings" | jq '. | length')
        
        if [ "$finding_count" -gt 0 ]; then
            log_success "Found ${finding_count} issue(s)"
            echo ""
            
            # Parse and display each finding
            for i in $(seq 0 $((finding_count - 1))); do
                local finding=$(echo "$findings" | jq ".[$i]")
                local severity=$(echo "$finding" | jq -r '.severity')
                local title=$(echo "$finding" | jq -r '.title')
                local description=$(echo "$finding" | jq -r '.description')
                
                echo -e "${RED}[${severity^^}]${NC} ${title}"
                echo "    ${description}"
                
                if $verbose; then
                    local evidence=$(echo "$finding" | jq '.evidence')
                    echo "    Evidence: ${evidence}"
                fi
                echo ""
            done
        else
            log_info "No issues found"
        fi
        
        echo ""
        echo "Completed: $(date)"
    fi
}

# Check for jq dependency (required for JSON handling)
if ! command -v jq &> /dev/null; then
    log_error "jq is required for JSON processing"
    log_info "Install with: apt-get install jq (Ubuntu) or brew install jq (macOS)"
    exit 1
fi

# Run main function
main "$@"
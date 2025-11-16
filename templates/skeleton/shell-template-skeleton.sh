#!/bin/bash
################################################################################
# CERT-X-GEN Shell Template Skeleton
#
# This is a skeleton template for writing security scanning templates in Bash.
# Copy this file and customize it for your specific security check.
#
# Template Metadata:
#   ID: template-skeleton
#   Name: Shell Template Skeleton
#   Author: Your Name
#   Severity: high
#   Tags: skeleton, example
#   Language: shell
################################################################################

# ========================================
# TEMPLATE METADATA
# ========================================
TEMPLATE_ID="template-skeleton"
TEMPLATE_NAME="Shell Template Skeleton"
TEMPLATE_AUTHOR="Your Name"
SEVERITY="high"  # critical, high, medium, low, info
CONFIDENCE=90
TAGS="skeleton,example"
CWE="CWE-XXX"

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
        critical) echo "9.0" ;;
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
    local remediation=${5:-"Apply security best practices"}
    
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
        "https://cwe.mitre.org/",
        "https://nvd.nist.gov/"
    ]
}
EOF
}

# Check dependencies
check_dependencies() {
    local deps=("curl" "nc")  # Add your required tools here
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_warning "Missing dependencies: ${missing[*]}"
        log_info "Install with: apt-get install ${missing[*]} (Ubuntu) or brew install ${missing[*]} (macOS)"
        return 1
    fi
    
    return 0
}

# ========================================
# SCANNING FUNCTIONS
# ========================================

# Example: Test HTTP endpoint
test_http_endpoint() {
    local host=$1
    local port=$2
    local scheme="http"
    
    [ "$port" = "443" ] && scheme="https"
    
    log_info "Testing ${scheme}://${host}:${port}/"
    
    local response=$(curl -s -w "\n%{http_code}" -m 5 -k "${scheme}://${host}:${port}/" 2>/dev/null)
    local status_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | head -n -1)
    
    if [ "$status_code" = "200" ]; then
        log_success "Endpoint accessible"
        
        # Check for vulnerability indicators
        if echo "$body" | grep -q "vulnerable"; then
            echo "true"
            return 0
        fi
    fi
    
    echo "false"
    return 1
}

# Example: Test network service
test_network_service() {
    local host=$1
    local port=$2
    
    log_info "Testing network service on ${host}:${port}"
    
    # Test if port is open
    if nc -z -w 3 "$host" "$port" 2>&1 | grep -q "succeeded\|open"; then
        log_success "Port ${port} is open"
        
        # Send probe and check response
        local response=$(echo "PROBE" | nc -w 3 "$host" "$port" 2>&1)
        
        if [ ! -z "$response" ]; then
            echo "$response"
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
    local port=${2:-80}
    local findings="[]"
    
    log_info "Scanning ${host}:${port}"
    
    # ========================================
    # CUSTOMIZE THIS SECTION
    # ========================================
    
    # Example: Check HTTP vulnerability
    if test_http_endpoint "$host" "$port" | grep -q "true"; then
        local evidence='{"endpoint": "'${host}:${port}'", "vulnerable": true}'
        local finding=$(create_finding \
            "Vulnerability Detected" \
            "Found vulnerability on ${host}:${port}" \
            "$evidence" \
            "high" \
            "1. Apply security patch\n2. Update configuration\n3. Monitor for exploitation"
        )
        
        # Add finding to results
        findings=$(echo "$findings" | jq ". += [$finding]")
    fi
    
    # Example: Check network service
    local service_response=$(test_network_service "$host" "$port")
    if [ ! -z "$service_response" ]; then
        local evidence='{"response": "'$(echo "$service_response" | base64)'"}'
        local finding=$(create_finding \
            "Service Information Disclosure" \
            "Service on ${host}:${port} disclosed information" \
            "$evidence" \
            "medium"
        )
        
        findings=$(echo "$findings" | jq ". += [$finding]")
    fi
    
    # ========================================
    # END CUSTOMIZATION
    # ========================================
    
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
    port            Target port (default: 80)

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
    $0 example.com 443
    $0 192.168.1.100 8080 --json

EOF
    exit 0
}

# ========================================
# MAIN EXECUTION
# ========================================

main() {
    local target=""
    local port=80
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
                elif [ "$port" = "80" ]; then
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

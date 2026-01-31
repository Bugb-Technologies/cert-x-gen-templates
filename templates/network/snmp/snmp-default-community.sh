#!/bin/bash
#
# @id: snmp-default-community
# @name: SNMP Default Community String Detection
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects SNMP services using default community strings (public/private)
# @tags: snmp, network, default-credentials, reconnaissance
# @cwe: CWE-798
# @cvss: 7.5
# @references: https://nvd.nist.gov/vuln/detail/CVE-2002-0013
# @confidence: 95
# @version: 1.0.0
#
# WHY SHELL?
# SNMP scanning benefits from:
# - Native snmpwalk/snmpget tools (widely available)
# - Simple UDP protocol interaction
# - Easy parsing of text output
# - No compilation needed, runs anywhere
#
################################################################################

set -euo pipefail

# Template Configuration
TEMPLATE_ID="snmp-default-community"
TEMPLATE_NAME="SNMP Default Community String Detection"
SEVERITY="high"
CONFIDENCE=95
CWE="CWE-798"

# Default community strings to test
COMMUNITY_STRINGS=("public" "private" "community" "snmp" "admin" "default")

# Logging (stderr only)
log_info() { echo "[INFO] $1" >&2; }
log_error() { echo "[ERROR] $1" >&2; }

# JSON helpers
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}


# Check if snmpwalk/snmpget is available
check_snmp_tools() {
    if command -v snmpwalk &>/dev/null; then
        echo "snmpwalk"
    elif command -v snmpget &>/dev/null; then
        echo "snmpget"
    else
        echo "none"
    fi
}

# Test SNMP with community string using snmpwalk
test_snmp_walk() {
    local host="$1"
    local port="$2"
    local community="$3"
    local timeout=3
    
    # Try to get system description (OID 1.3.6.1.2.1.1.1.0)
    local result
    result=$(snmpwalk -v2c -c "$community" -t "$timeout" -r 1 "$host:$port" \
             1.3.6.1.2.1.1.1.0 2>/dev/null) || true
    
    if [ -n "$result" ] && ! echo "$result" | grep -qi "timeout\|error\|no response"; then
        echo "$result"
        return 0
    fi
    return 1
}

# Test SNMP with community string using snmpget
test_snmp_get() {
    local host="$1"
    local port="$2"
    local community="$3"
    local timeout=3
    
    local result
    result=$(snmpget -v2c -c "$community" -t "$timeout" -r 1 "$host:$port" \
             1.3.6.1.2.1.1.1.0 2>/dev/null) || true
    
    if [ -n "$result" ] && ! echo "$result" | grep -qi "timeout\|error\|no response"; then
        echo "$result"
        return 0
    fi
    return 1
}

# Fallback: Test UDP port 161 with raw SNMP GET packet
test_snmp_raw() {
    local host="$1"
    local port="$2"
    local community="$3"
    
    # Check if nc supports UDP
    if ! command -v nc &>/dev/null; then
        return 1
    fi
    
    # SNMP v1 GET request for sysDescr (simplified)
    # This is a basic probe - full SNMP would need proper ASN.1 encoding
    local probe
    probe=$(printf '\x30\x26\x02\x01\x00\x04\x06%s\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00' "$community")
    
    local response
    response=$(echo -ne "$probe" | nc -u -w 2 "$host" "$port" 2>/dev/null | head -c 500 | xxd -p) || true
    
    # Check if we got any response (indicates SNMP is listening)
    if [ -n "$response" ] && [ ${#response} -gt 10 ]; then
        echo "SNMP response received (raw)"
        return 0
    fi
    return 1
}


# Main scanning function
scan_snmp() {
    local host="$1"
    local port="${2:-161}"
    local findings=()
    local tool
    tool=$(check_snmp_tools)
    
    log_info "Scanning ${host}:${port} for SNMP default community strings"
    log_info "Using tool: $tool"
    
    for community in "${COMMUNITY_STRINGS[@]}"; do
        local response=""
        local found=false
        
        case "$tool" in
            snmpwalk)
                if response=$(test_snmp_walk "$host" "$port" "$community"); then
                    found=true
                fi
                ;;
            snmpget)
                if response=$(test_snmp_get "$host" "$port" "$community"); then
                    found=true
                fi
                ;;
            none)
                log_info "No SNMP tools found, using raw UDP probe"
                if response=$(test_snmp_raw "$host" "$port" "$community"); then
                    found=true
                fi
                ;;
        esac
        
        if $found; then
            log_info "SUCCESS: Community string '$community' accepted!"
            
            # Extract system info from response
            local sys_desc=""
            if [ -n "$response" ]; then
                sys_desc=$(echo "$response" | head -1 | cut -c1-200)
            fi
            
            local finding
            finding=$(cat << EOF
{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","severity":"${SEVERITY}","confidence":${CONFIDENCE},"title":"SNMP Default Community String on ${host}:${port}","description":"SNMP service accepts default community string '${community}'. $(json_escape "$sys_desc") Attackers can enumerate system information, network topology, and potentially modify device configuration.","host":"${host}","port":${port},"matched_at":"${host}:${port}","evidence":{"community_string":"${community}","response":"$(json_escape "$sys_desc")","tool":"${tool}"},"cwe":"${CWE}","cvss_score":7.5,"remediation":"Change default SNMP community strings. Use SNMPv3 with authentication and encryption. Restrict SNMP access to authorized management systems only."}
EOF
)
            findings+=("$finding")
            break  # Found working community, no need to test more
        fi
    done
    
    # Build JSON array
    local findings_json="["
    local first=true
    for f in "${findings[@]}"; do
        if $first; then
            first=false
        else
            findings_json+=","
        fi
        findings_json+="$f"
    done
    findings_json+="]"
    
    echo "$findings_json"
}

# Main function
main() {
    local target=""
    local port="161"
    
    # Get from environment first (engine mode)
    target="${CERT_X_GEN_TARGET_HOST:-}"
    port="${CERT_X_GEN_TARGET_PORT:-161}"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target) target="$2"; shift 2 ;;
            -p|--port) port="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: $0 --target HOST [--port PORT]" >&2
                exit 0
                ;;
            *) shift ;;
        esac
    done
    
    if [ -z "$target" ]; then
        log_error "No target specified"
        echo '{"findings":[],"metadata":{"template_id":"'"${TEMPLATE_ID}"'","error":"No target"}}'
        exit 0
    fi
    
    local findings
    findings=$(scan_snmp "$target" "$port")
    
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    cat << EOF
{"findings":${findings},"metadata":{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","author":"CERT-X-GEN Security Team","severity":"${SEVERITY}","scan_time":"${timestamp}"}}
EOF
}

main "$@"

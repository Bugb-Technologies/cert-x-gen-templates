#!/bin/bash
# @id: system-context-recon
# @name: System Context Reconnaissance
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Gathers system context for scan correlation using native UNIX tools
# @tags: recon, system, context, shell, unix
# @cwe: N/A
# @cvss: N/A
# @references: N/A
# @confidence: 90
# @version: 1.0.0
#
# WHY SHELL?
# System reconnaissance benefits from:
# - Native tool availability (dig, ping, nmap, curl)
# - Pipe chaining for data transformation
# - No compilation or runtime needed
# - UNIX philosophy: do one thing well
# - Perfect for combining existing tools

set -o pipefail

# Get target from environment or default
HOST="${CERT_X_GEN_TARGET_HOST:-localhost}"
PORT="${CERT_X_GEN_TARGET_PORT:-80}"

# Output helpers
json_escape() {
    echo -n "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g' | tr -d '\n'
}

# Detect if target is local
is_local() {
    [[ "$HOST" == "localhost" || "$HOST" == "127.0.0.1" || "$HOST" == "::1" ]]
}

# Check network reachability
check_reachability() {
    if command -v ping &>/dev/null; then
        if [[ "$(uname)" == "Darwin" ]]; then
            ping -c 1 -W 2 "$HOST" &>/dev/null && echo "reachable" || echo "unreachable"
        else
            ping -c 1 -W 2 "$HOST" &>/dev/null && echo "reachable" || echo "unreachable"
        fi
    else
        echo "unknown"
    fi
}

# DNS resolution
resolve_dns() {
    local result=""
    
    if command -v dig &>/dev/null; then
        result=$(dig +short "$HOST" 2>/dev/null | head -1)
    elif command -v host &>/dev/null; then
        result=$(host "$HOST" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
    elif command -v nslookup &>/dev/null; then
        result=$(nslookup "$HOST" 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}')
    fi
    
    echo "${result:-none}"
}

# Reverse DNS
reverse_dns() {
    local result=""
    
    if command -v dig &>/dev/null; then
        result=$(dig +short -x "$HOST" 2>/dev/null | head -1 | sed 's/\.$//')
    elif command -v host &>/dev/null; then
        result=$(host "$HOST" 2>/dev/null | grep "pointer" | awk '{print $NF}' | sed 's/\.$//')
    fi
    
    echo "${result:-none}"
}

# Get IP geolocation (if external)
get_geolocation() {
    local geo=""
    
    if command -v curl &>/dev/null && ! is_local; then
        # Use ip-api.com (free, no key needed)
        geo=$(curl -s --max-time 5 "http://ip-api.com/json/$HOST?fields=country,city,isp,org" 2>/dev/null)
        if [[ -n "$geo" ]] && echo "$geo" | grep -q "country"; then
            echo "$geo"
            return
        fi
    fi
    
    echo '{"country":"unknown","city":"unknown"}'
}

# Detect if port is open (quick check)
check_port() {
    local target_port="${1:-$PORT}"
    
    if command -v nc &>/dev/null; then
        nc -z -w 2 "$HOST" "$target_port" &>/dev/null && echo "open" || echo "closed"
    elif command -v bash &>/dev/null; then
        (echo >/dev/tcp/"$HOST"/"$target_port") 2>/dev/null && echo "open" || echo "closed"
    else
        echo "unknown"
    fi
}

# Get SSL certificate info
check_ssl_cert() {
    local cert_info=""
    
    if command -v openssl &>/dev/null; then
        cert_info=$(echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>/dev/null | \
                    openssl x509 -noout -subject -dates 2>/dev/null | \
                    tr '\n' ' ' | sed 's/subject=/Subject: /; s/notBefore=/Valid From: /; s/notAfter=/ Valid Until: /')
    fi
    
    echo "${cert_info:-none}"
}

# Detect web server
detect_webserver() {
    local server=""
    
    if command -v curl &>/dev/null; then
        server=$(curl -s --max-time 5 -I "http://$HOST:$PORT/" 2>/dev/null | \
                 grep -i "^server:" | cut -d: -f2- | tr -d '\r' | xargs)
    fi
    
    echo "${server:-unknown}"
}

# Get HTTP headers
get_http_headers() {
    if command -v curl &>/dev/null; then
        curl -s --max-time 5 -I "http://$HOST:$PORT/" 2>/dev/null | \
            grep -iE "^(server|x-powered-by|x-aspnet|x-frame-options|content-security-policy):" | \
            head -5 | tr '\n' '; ' | sed 's/; $//'
    fi
}

# WHOIS lookup
get_whois() {
    local whois_info=""
    
    if command -v whois &>/dev/null && ! is_local; then
        whois_info=$(whois "$HOST" 2>/dev/null | \
                     grep -iE "^(orgname|organization|netname|country):" | \
                     head -3 | tr '\n' '; ')
    fi
    
    echo "${whois_info:-none}"
}

# Quick port scan of common ports
quick_port_scan() {
    local open_ports=()
    local common_ports=(21 22 23 25 53 80 110 143 443 445 993 995 3306 3389 5432 5900 6379 8080 8443 27017)
    
    for p in "${common_ports[@]}"; do
        if [[ "$(check_port "$p")" == "open" ]]; then
            open_ports+=("$p")
        fi
    done
    
    echo "${open_ports[*]}"
}

# Main execution
main() {
    # Gather all context
    local IS_LOCAL
    is_local && IS_LOCAL="true" || IS_LOCAL="false"
    
    local PING_STATUS
    PING_STATUS=$(check_reachability)
    
    local DNS_RESULT
    DNS_RESULT=$(resolve_dns)
    
    local REVERSE_DNS
    REVERSE_DNS=$(reverse_dns)
    
    local PORT_STATUS
    PORT_STATUS=$(check_port)
    
    local WEBSERVER
    WEBSERVER=$(detect_webserver)
    
    local HTTP_HEADERS
    HTTP_HEADERS=$(get_http_headers)
    
    local TIMESTAMP
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    local SCAN_HOST
    SCAN_HOST=$(hostname 2>/dev/null || echo "unknown")
    
    local SCAN_USER
    SCAN_USER=$(whoami 2>/dev/null || echo "unknown")
    
    # Quick port scan (only if not localhost to avoid scanning self)
    local OPEN_PORTS=""
    if [[ "$IS_LOCAL" != "true" ]]; then
        OPEN_PORTS=$(quick_port_scan)
    fi
    
    # Output JSON with required fields
    cat << EOF
{"findings":[{"template_id":"system-context-recon","template_name":"System Context Reconnaissance","severity":"info","confidence":90,"title":"System Context Gathered","description":"Gathered system context for target ${HOST}:${PORT}","matched_at":"${HOST}:${PORT}","host":"${HOST}","port":${PORT},"evidence":{"target":{"host":"${HOST}","port":${PORT},"is_local":${IS_LOCAL}},"network":{"ping_status":"${PING_STATUS}","dns_resolution":"${DNS_RESULT}","reverse_dns":"${REVERSE_DNS}","port_status":"${PORT_STATUS}","open_ports":"$(json_escape "$OPEN_PORTS")"},"http":{"webserver":"$(json_escape "$WEBSERVER")","headers":"$(json_escape "$HTTP_HEADERS")"},"scan_info":{"timestamp":"${TIMESTAMP}","scan_host":"${SCAN_HOST}","scan_user":"${SCAN_USER}"}},"remediation":"This is reconnaissance data for correlation with other findings."}],"metadata":{"template_id":"system-context-recon","template_name":"System Context Reconnaissance","author":"CERT-X-GEN Security Team","severity":"info","scan_time":"${TIMESTAMP}"}}
EOF
}

# Run main
main

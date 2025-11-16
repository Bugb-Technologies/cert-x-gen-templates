#!/bin/bash
################################################################################
# Apache Kafka Unauthenticated Access Detection
#
# Tests for Kafka brokers exposed without authentication/authorization.
# Checks:
# - Broker connectivity
# - Topic enumeration
# - Consumer group listing
# - Admin API access
#
# Author: CERT-X-GEN Security Team
# Severity: Critical
# CWE: CWE-306 (Missing Authentication for Critical Function)
################################################################################

TEMPLATE_ID="kafka-unauthenticated-access"
TEMPLATE_NAME="Apache Kafka Unauthenticated Access Detection"
SEVERITY="critical"
CONFIDENCE=90
TAGS="kafka,apache,messaging,unauthenticated"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <kafka_host> [kafka_port]"
    echo "Example: $0 kafka.example.com 9092"
    echo ""
    echo "Requirements:"
    echo "  - kafkacat (or kcat) installed"
    echo "  - nc (netcat) installed"
    exit 1
}

log_finding() {
    local severity=$1
    local title=$2
    local description=$3
    
    echo -e "${RED}[${severity}]${NC} ${title}"
    echo "    ${description}"
    echo "    Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
}

check_dependencies() {
    local missing=0
    
    if ! command -v kafkacat &> /dev/null && ! command -v kcat &> /dev/null; then
        echo -e "${YELLOW}[WARNING]${NC} kafkacat/kcat not found. Install for full testing:"
        echo "  macOS: brew install kcat"
        echo "  Ubuntu: apt-get install kafkacat"
        missing=1
    fi
    
    if ! command -v nc &> /dev/null; then
        echo -e "${YELLOW}[WARNING]${NC} netcat not found. Limited testing available."
        missing=1
    fi
    
    return $missing
}

test_broker_connectivity() {
    local host=$1
    local port=$2
    
    echo "[*] Testing Kafka broker connectivity..."
    
    # Test if port is open
    if nc -zv -w 3 "$host" "$port" 2>&1 | grep -q "succeeded\|open"; then
        log_finding "INFO" \
            "Kafka Broker Port Open" \
            "Kafka broker at ${host}:${port} is accessible"
        return 0
    else
        echo "    [-] Kafka broker not accessible on ${host}:${port}"
        return 1
    fi
}

test_metadata_query() {
    local host=$1
    local port=$2
    local kafkacat_cmd=""
    
    # Determine which command is available
    if command -v kcat &> /dev/null; then
        kafkacat_cmd="kcat"
    elif command -v kafkacat &> /dev/null; then
        kafkacat_cmd="kafkacat"
    else
        echo "    [-] kafkacat/kcat not available, skipping metadata test"
        return 1
    fi
    
    echo "[*] Querying Kafka metadata..."
    
    # Query broker metadata
    local metadata=$(timeout 5 $kafkacat_cmd -L -b "${host}:${port}" 2>&1)
    
    if [[ $? -eq 0 ]] && [[ ! -z "$metadata" ]]; then
        log_finding "CRITICAL" \
            "Kafka Metadata Accessible Without Authentication" \
            "Successfully retrieved cluster metadata from ${host}:${port}"
        
        echo "    Evidence:"
        echo "$metadata" | head -20
        echo ""
        
        # Extract broker count
        local broker_count=$(echo "$metadata" | grep -c "broker")
        echo "    - Broker count: $broker_count"
        
        # Extract topic count
        local topic_count=$(echo "$metadata" | grep -c "topic")
        echo "    - Topic count: $topic_count"
        echo ""
        
        return 0
    else
        echo "    [-] Could not retrieve metadata (may require authentication)"
        return 1
    fi
}

test_topic_listing() {
    local host=$1
    local port=$2
    local kafkacat_cmd=""
    
    if command -v kcat &> /dev/null; then
        kafkacat_cmd="kcat"
    elif command -v kafkacat &> /dev/null; then
        kafkacat_cmd="kafkacat"
    else
        return 1
    fi
    
    echo "[*] Attempting to list Kafka topics..."
    
    # List topics
    local topics=$(timeout 5 $kafkacat_cmd -L -b "${host}:${port}" 2>&1 | grep "topic" | grep -v "^$")
    
    if [[ ! -z "$topics" ]]; then
        log_finding "HIGH" \
            "Kafka Topic Enumeration" \
            "Successfully enumerated Kafka topics without authentication"
        
        echo "    Topics discovered:"
        echo "$topics" | head -10
        echo ""
        
        # Check for sensitive topic names
        if echo "$topics" | grep -iE "(password|secret|credential|key|token|auth|admin|prod|production)"; then
            log_finding "CRITICAL" \
                "Sensitive Kafka Topics Exposed" \
                "Topics with potentially sensitive names are accessible"
        fi
        
        return 0
    fi
    
    return 1
}

test_consume_messages() {
    local host=$1
    local port=$2
    local kafkacat_cmd=""
    
    if command -v kcat &> /dev/null; then
        kafkacat_cmd="kcat"
    elif command -v kafkacat &> /dev/null; then
        kafkacat_cmd="kafkacat"
    else
        return 1
    fi
    
    echo "[*] Testing message consumption..."
    
    # Try to consume from __consumer_offsets (internal topic)
    local messages=$(timeout 3 $kafkacat_cmd -C -b "${host}:${port}" -t __consumer_offsets -c 1 2>&1)
    
    if [[ $? -eq 0 ]] || echo "$messages" | grep -v "error\|Error"; then
        log_finding "CRITICAL" \
            "Kafka Message Consumption Without Authentication" \
            "Successfully consumed messages from Kafka topics"
        
        echo "    Evidence: Message consumption successful"
        echo ""
        return 0
    fi
    
    return 1
}

test_jmx_port() {
    local host=$1
    local jmx_port=9999
    
    echo "[*] Testing for exposed JMX port..."
    
    if nc -zv -w 3 "$host" "$jmx_port" 2>&1 | grep -q "succeeded\|open"; then
        log_finding "HIGH" \
            "Kafka JMX Port Exposed" \
            "JMX port ${jmx_port} is accessible - may allow remote code execution"
        
        echo "    Evidence:"
        echo "    - JMX Port: ${jmx_port}"
        echo "    - Risk: Remote JMX without authentication can lead to RCE"
        echo ""
        return 0
    fi
    
    return 1
}

print_remediation() {
    cat << 'EOF'

╔══════════════════════════════════════════════════════════════╗
║                    REMEDIATION STEPS                         ║
╚══════════════════════════════════════════════════════════════╝

1. Enable SASL Authentication in server.properties:
   
   listeners=SASL_PLAINTEXT://0.0.0.0:9092
   security.inter.broker.protocol=SASL_PLAINTEXT
   sasl.mechanism.inter.broker.protocol=PLAIN
   sasl.enabled.mechanisms=PLAIN

2. Configure JAAS for SASL/PLAIN:
   
   KafkaServer {
     org.apache.kafka.common.security.plain.PlainLoginModule required
     username="admin"
     password="admin-secret"
     user_admin="admin-secret"
     user_producer="producer-secret";
   };

3. Enable SSL/TLS Encryption:
   
   listeners=SSL://0.0.0.0:9093
   ssl.keystore.location=/var/private/ssl/kafka.server.keystore.jks
   ssl.keystore.password=keystore_password
   ssl.key.password=key_password
   ssl.truststore.location=/var/private/ssl/kafka.server.truststore.jks
   ssl.truststore.password=truststore_password

4. Enable Authorization (ACLs):
   
   authorizer.class.name=kafka.security.authorizer.AclAuthorizer
   super.users=User:admin

5. Set ACLs for topics:
   
   kafka-acls.sh --authorizer-properties zookeeper.connect=localhost:2181 \
     --add --allow-principal User:producer \
     --operation Write --topic my-topic

6. Secure JMX:
   
   JMX_PORT=9999
   KAFKA_JMX_OPTS="-Dcom.sun.management.jmxremote.authenticate=true \
     -Dcom.sun.management.jmxremote.ssl=true \
     -Dcom.sun.management.jmxremote.password.file=/path/to/jmxremote.password"

7. Network Segmentation:
   - Use firewall rules to restrict broker access
   - Deploy Kafka in private subnet
   - Use VPN for external access

8. Monitoring & Auditing:
   - Enable audit logs
   - Monitor authentication failures
   - Track topic access patterns

9. Regular Updates:
   - Keep Kafka updated to latest stable version
   - Apply security patches promptly

10. Additional Hardening:
    - Disable auto topic creation
    - Implement rate limiting
    - Use quotas to prevent resource exhaustion

REFERENCES:
- https://kafka.apache.org/documentation/#security
- https://docs.confluent.io/platform/current/security/index.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html

EOF
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
    fi
    
    local host=$1
    local port=${2:-9092}
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║    Apache Kafka Unauthenticated Access Detection            ║"
    echo "║    CERT-X-GEN Security Template                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Target: ${host}:${port}"
    echo "Scan started: $(date)"
    echo ""
    
    check_dependencies
    echo ""
    
    # Run tests
    test_broker_connectivity "$host" "$port" || exit 1
    test_metadata_query "$host" "$port"
    test_topic_listing "$host" "$port"
    test_consume_messages "$host" "$port"
    test_jmx_port "$host"
    
    # Print remediation
    print_remediation
    
    echo ""
    echo "Scan completed: $(date)"
}

main "$@"

#!/bin/bash
# Final comprehensive test for GitLab Version Fingerprint template

set -e

CONTAINER_NAME="gitlab-test"
HTTP_PORT="8080"
RESULTS_DIR="test-results-$(date +%Y%m%d-%H%M%S)"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

print_header() {
    echo ""
    echo "================================================================"
    echo "$1"
    echo "================================================================"
    echo ""
}

mkdir -p "$RESULTS_DIR"

print_header "GitLab Version Fingerprint - Comprehensive Test Suite"

log_info "Test results will be saved to: $RESULTS_DIR"

# Step 1: Check Docker
print_header "Step 1: Prerequisites Check"
if ! docker info > /dev/null 2>&1; then
    log_error "Docker is not running"
    exit 1
fi
log_info "✅ Docker is running"

if [ ! -f "templates/python/gitlab-version-fingerprint.py" ]; then
    log_error "Template not found"
    exit 1
fi
log_info "✅ Template exists"

# Step 2: Setup GitLab
print_header "Step 2: GitLab Container Setup"

if docker ps -a | grep -q $CONTAINER_NAME; then
    log_warn "Container exists"
    if docker ps | grep -q $CONTAINER_NAME; then
        log_info "Using running container"
    else
        docker start $CONTAINER_NAME
        sleep 10
    fi
else
    log_step "Creating GitLab container..."
    docker run -d \
        --name $CONTAINER_NAME \
        --hostname gitlab.local \
        --publish $HTTP_PORT:80 \
        --env GITLAB_OMNIBUS_CONFIG="external_url 'http://gitlab.local:$HTTP_PORT'" \
        --shm-size 256m \
        gitlab/gitlab-ce:latest
    log_info "✅ Container created"
fi

# Step 3: Wait for GitLab
print_header "Step 3: Waiting for GitLab (3-5 minutes)"

COUNTER=0
MAX_ATTEMPTS=120
START_TIME=$(date +%s)

while [ $COUNTER -lt $MAX_ATTEMPTS ]; do
    if curl -s -f http://localhost:$HTTP_PORT/api/v4/version > /dev/null 2>&1; then
        echo ""
        ELAPSED=$(($(date +%s) - START_TIME))
        log_info "✅ GitLab ready! (${ELAPSED}s)"
        break
    fi
    echo -n "."
    sleep 5
    COUNTER=$((COUNTER + 1))
    if [ $((COUNTER % 12)) -eq 0 ]; then
        echo ""
        log_info "Still waiting... ($((COUNTER * 5))s)"
    fi
done

if [ $COUNTER -eq $MAX_ATTEMPTS ]; then
    log_error "Timeout"
    exit 1
fi

sleep 10

# Step 4: Verify GitLab
print_header "Step 4: Verify GitLab"

GITLAB_API_RESPONSE=$(curl -s http://localhost:$HTTP_PORT/api/v4/version)
echo "$GITLAB_API_RESPONSE" | jq . | tee "$RESULTS_DIR/gitlab-api.json"
DETECTED_VERSION=$(echo "$GITLAB_API_RESPONSE" | jq -r '.version')
log_info "GitLab version: $DETECTED_VERSION"

# Step 5: Test Template (Python)
print_header "Step 5: Test Template - Python Direct"

export CERT_X_GEN_TARGET_HOST="localhost"
export CERT_X_GEN_TARGET_PORT="$HTTP_PORT"

python3 templates/python/gitlab-version-fingerprint.py | tee "$RESULTS_DIR/manual-test.json"

FINDINGS_COUNT=$(cat "$RESULTS_DIR/manual-test.json" | jq -r '.findings | length' 2>/dev/null || echo "0")

if [ "$FINDINGS_COUNT" -gt 0 ]; then
    log_info "✅ DETECTION SUCCESSFUL!"
    cat "$RESULTS_DIR/manual-test.json" | jq '.findings[0]'
    TEMPLATE_VERSION=$(cat "$RESULTS_DIR/manual-test.json" | jq -r '.findings[0].version')
    DETECTION_METHOD=$(cat "$RESULTS_DIR/manual-test.json" | jq -r '.findings[0].detection_method')
    log_info "Version: $TEMPLATE_VERSION via $DETECTION_METHOD"
    if [ "$TEMPLATE_VERSION" = "$DETECTED_VERSION" ]; then
        log_info "✅ Perfect match!"
    fi
else
    log_error "❌ No findings"
fi

# Step 6: Test with cxg
print_header "Step 6: Test Template - cxg CLI"

cxg scan \
    --scope localhost:$HTTP_PORT \
    --templates gitlab-version-fingerprint.py \
    --format json \
    -o "$RESULTS_DIR/cxg-scan.json"

log_info "✅ cxg scan completed"
cat "$RESULTS_DIR/cxg-scan.json" | jq .

# Step 7: FOFA targets
print_header "Step 7: FOFA Targets"

for TARGET in "kura.mirailabs.app:80" "dev-gitlab.hunizm.com:80"; do
    log_step "Testing: $TARGET"
    SAFE=$(echo "$TARGET" | tr ':.' '__')
    cxg scan --scope "$TARGET" --templates gitlab-version-fingerprint.py --format json -o "$RESULTS_DIR/fofa-$SAFE.json" || true
    if [ -f "$RESULTS_DIR/fofa-$SAFE.json" ]; then
        F=$(cat "$RESULTS_DIR/fofa-$SAFE.json" | jq -r '.findings | length' 2>/dev/null || echo "0")
        [ "$F" -gt 0 ] && log_info "✅ Found" || log_warn "⚠️  None"
    fi
done

# Summary
print_header "✅ Tests Complete!"

echo "Results: $RESULTS_DIR"
echo ""
if [ "$FINDINGS_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✅ Template: SUCCESS${NC}"
    echo "   Version: $TEMPLATE_VERSION"
    echo "   Method: $DETECTION_METHOD"
else
    echo -e "${RED}❌ Template: FAILED${NC}"
fi

echo ""
echo "To stop: docker stop $CONTAINER_NAME"
echo "To remove: docker rm $CONTAINER_NAME"


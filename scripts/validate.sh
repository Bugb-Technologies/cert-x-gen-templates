#!/bin/bash
# Template validation script

set -e

# Get script directory and repository root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
TEMPLATES_DIR="$REPO_ROOT/templates"

echo "🔍 Validating CERT-X-GEN Templates"
echo "   Repository: $REPO_ROOT"
echo "   Templates: $TEMPLATES_DIR"
echo ""

ERRORS=0

# Function to validate YAML
validate_yaml() {
    local file=$1
    echo "  Checking: $file"
    
    # Basic YAML syntax
    if ! python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
        echo "    ❌ Invalid YAML syntax"
        ((ERRORS++))
        return
    fi
    
    # Check required fields
    if ! grep -q "^id:" "$file"; then
        echo "    ❌ Missing 'id' field"
        ((ERRORS++))
    fi
    
    if ! grep -q "^info:" "$file"; then
        echo "    ❌ Missing 'info' section"
        ((ERRORS++))
    fi
    
    # Check for secrets
    if grep -qi "password\|api.key\|secret" "$file"; then
        echo "    ⚠️  Warning: Possible hardcoded secret"
    fi
}

# Function to validate Python
validate_python() {
    local file=$1
    echo "  Checking: $file"
    
    # Syntax check
    if ! python3 -m py_compile "$file" 2>/dev/null; then
        echo "    ❌ Invalid Python syntax"
        ((ERRORS++))
        return
    fi
    
    # Check for required elements
    if ! grep -q "if __name__" "$file"; then
        echo "    ⚠️  Warning: Missing main guard"
    fi
}

# Validate YAML templates
echo "📄 Validating YAML templates..."
while IFS= read -r -d '' file; do
    validate_yaml "$file"
done < <(find "$TEMPLATES_DIR/yaml" -name "*.yaml" -o -name "*.yml" -print0 2>/dev/null || true)

echo ""
echo "🐍 Validating Python templates..."
while IFS= read -r -d '' file; do
    validate_python "$file"
done < <(find "$TEMPLATES_DIR/python" -name "*.py" -print0 2>/dev/null || true)

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ All templates valid!"
    exit 0
else
    echo "❌ Found $ERRORS errors"
    exit 1
fi
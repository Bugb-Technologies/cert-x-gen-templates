#!/usr/bin/env python3
"""
Validate YAML template files
"""

import yaml
import sys
from pathlib import Path

REQUIRED_FIELDS = ["id", "info"]
REQUIRED_INFO_FIELDS = ["name", "author", "severity"]
VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"]

def validate_template(path):
    """Validate a single YAML template"""
    
    errors = []
    warnings = []
    
    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        if not isinstance(data, dict):
            errors.append("Template must be a YAML dictionary")
            return errors, warnings
        
        # Check required fields
        for field in REQUIRED_FIELDS:
            if field not in data:
                errors.append(f"Missing required field: {field}")
        
        # Check info section
        if "info" in data:
            info = data["info"]
            for field in REQUIRED_INFO_FIELDS:
                if field not in info:
                    errors.append(f"Missing required info field: {field}")
            
            # Validate severity
            if "severity" in info:
                if info["severity"] not in VALID_SEVERITIES:
                    errors.append(f"Invalid severity: {info['severity']}")
        
        # Check for common issues
        if "password" in str(data).lower() or "api_key" in str(data).lower():
            warnings.append("Possible hardcoded secret detected")
        
        # Check ID format
        if "id" in data:
            template_id = data["id"]
            if not template_id.replace("-", "").replace("_", "").isalnum():
                warnings.append(f"Template ID should use lowercase alphanumeric with hyphens: {template_id}")
        
    except yaml.YAMLError as e:
        errors.append(f"YAML syntax error: {e}")
    except Exception as e:
        errors.append(f"Validation error: {e}")
    
    return errors, warnings

def main():
    """Validate all YAML templates"""
    
    print("🔍 Validating YAML templates...\n")
    
    yaml_dir = Path("yaml")
    if not yaml_dir.exists():
        print("❌ yaml/ directory not found")
        sys.exit(1)
    
    templates = list(yaml_dir.rglob("*.yaml")) + list(yaml_dir.rglob("*.yml"))
    
    total_errors = 0
    total_warnings = 0
    
    for template in templates:
        errors, warnings = validate_template(template)
        
        if errors or warnings:
            print(f"📄 {template}")
            
            for error in errors:
                print(f"  ❌ {error}")
                total_errors += 1
            
            for warning in warnings:
                print(f"  ⚠️  {warning}")
                total_warnings += 1
            
            print()
    
    print(f"Summary: {len(templates)} templates checked")
    print(f"  Errors: {total_errors}")
    print(f"  Warnings: {total_warnings}")
    
    if total_errors > 0:
        sys.exit(1)
    else:
        print("\n✅ All YAML templates valid!")
        sys.exit(0)

if __name__ == "__main__":
    main()
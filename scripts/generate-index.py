#!/usr/bin/env python3
"""
Generate TEMPLATE_REGISTRY.json from template files
"""

import json
import os
import yaml
from pathlib import Path
from datetime import datetime

def scan_templates():
    """Scan all template directories and count templates"""
    
    registry = {
        "version": "1.0.0",
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "total_templates": 0,
        "languages": {},
        "categories": {},
        "templates": []
    }
    
    # Get script directory and repository root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    templates_dir = repo_root / "templates"
    
    # Language directories
    languages = ["yaml", "python", "javascript", "c", "cpp", "go", 
                 "java", "rust", "ruby", "perl", "php", "shell"]
    
    for lang in languages:
        lang_path = templates_dir / lang
        if not lang_path.exists():
            continue
            
        # Count templates by extension
        if lang == "yaml":
            templates = list(lang_path.rglob("*.yaml")) + list(lang_path.rglob("*.yml"))
        elif lang in ["python"]:
            templates = list(lang_path.rglob("*.py"))
        elif lang in ["javascript"]:
            templates = list(lang_path.rglob("*.js"))
        elif lang in ["c"]:
            templates = list(lang_path.rglob("*.c"))
        elif lang in ["cpp"]:
            templates = list(lang_path.rglob("*.cpp"))
        elif lang in ["go"]:
            templates = list(lang_path.rglob("*.go"))
        elif lang in ["java"]:
            templates = list(lang_path.rglob("*.java"))
        elif lang in ["rust"]:
            templates = list(lang_path.rglob("*.rs"))
        elif lang in ["shell"]:
            templates = list(lang_path.rglob("*.sh"))
        else:
            templates = []
        
        count = len(templates)
        if count > 0:
            registry["languages"][lang] = count
            registry["total_templates"] += count
            
            # Parse template metadata
            for template_path in templates:
                try:
                    metadata = extract_metadata(template_path, lang)
                    if metadata:
                        registry["templates"].append(metadata)
                        
                        # Count categories
                        category = metadata.get("category", "other")
                        registry["categories"][category] = registry["categories"].get(category, 0) + 1
                except Exception as e:
                    print(f"Warning: Could not parse {template_path}: {e}")
    
    return registry

def extract_metadata(path, lang):
    """Extract metadata from template file"""
    
    if lang == "yaml":
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                return {
                    "id": data.get("id", ""),
                    "name": data.get("info", {}).get("name", ""),
                    "severity": data.get("info", {}).get("severity", "info"),
                    "language": lang,
                    "path": str(path),
                    "category": detect_category(path)
                }
    
    # For other languages, extract from comments
    elif lang == "python":
        with open(path, 'r') as f:
            lines = f.readlines()
            metadata = {"language": lang, "path": str(path)}
            for line in lines[:20]:  # Check first 20 lines
                if "Template:" in line:
                    metadata["id"] = line.split("Template:")[1].strip()
                elif "Name:" in line:
                    metadata["name"] = line.split("Name:")[1].strip()
                elif "Severity:" in line:
                    metadata["severity"] = line.split("Severity:")[1].strip()
            metadata["category"] = detect_category(path)
            return metadata
    
    return None

def detect_category(path):
    """Detect category from file path"""
    path_str = str(path).lower()
    
    if "cve" in path_str:
        return "cve"
    elif "network" in path_str or "service" in path_str:
        return "network"
    elif "web" in path_str or "http" in path_str:
        return "web"
    elif "cloud" in path_str:
        return "cloud"
    elif "misconfiguration" in path_str:
        return "misconfiguration"
    else:
        return "other"

if __name__ == "__main__":
    print("📊 Generating template registry...")
    
    # Get repository root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    registry = scan_templates()
    
    # Write to file in repo root
    output_file = repo_root / "TEMPLATE_REGISTRY.json"
    with open(output_file, "w") as f:
        json.dump(registry, f, indent=2)
    
    print(f"✅ Generated registry with {registry['total_templates']} templates")
    print(f"   Languages: {', '.join(registry['languages'].keys())}")
    print(f"   Categories: {', '.join(registry['categories'].keys())}")
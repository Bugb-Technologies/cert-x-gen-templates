# GitLab Version Fingerprint - Detection Playbook

## Overview

**Template ID:** `gitlab-version-fingerprint`  
**Language:** Python  
**Severity:** Informational  
**Category:** Version Detection / Reconnaissance  
**Tags:** `gitlab`, `version`, `fingerprint`, `recon`, `informational`

### Purpose

This template identifies the version of GitLab Community Edition (CE) or Enterprise Edition (EE) running on a target system. Version information is crucial for:

- **CVE Mapping:** Identifying known vulnerabilities affecting specific versions
- **Patch Management:** Determining if security updates are needed
- **Infrastructure Assessment:** Understanding the technology stack
- **Attack Surface Analysis:** Planning further security testing

### Detection Methodology

The template employs three complementary detection methods, executed sequentially:

1. **API Endpoint Detection** (`/api/v4/version`)
   - Most reliable method when API is accessible
   - Returns structured JSON with version information
   - May require authentication on hardened instances

2. **HTTP Header Analysis**
   - Checks `X-GitLab-Version` header
   - Analyzes `Server` header for GitLab identification
   - Lightweight and fast detection method

3. **HTML Metadata Extraction**
   - Parses login page (`/users/sign_in`) for version strings
   - Searches for `data-page-version` attributes
   - Examines meta tags and JavaScript references

## Technical Details

### Target Information

- **Primary Ports:** 80 (HTTP), 443 (HTTPS)
- **Alternative Ports:** 8080, 8443, 9443 (custom deployments)
- **Protocol Support:** Both HTTP and HTTPS with SSL certificate bypass

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CERT_X_GEN_TARGET_HOST` | Target hostname or IP | Required |
| `CERT_X_GEN_TARGET_PORT` | Target port | `80` |

### Output Format
```json
{
  "findings": [
    {
      "id": "gitlab-version-fingerprint",
      "severity": "info",
      "name": "GitLab Version Detected",
      "host": "gitlab.example.com",
      "port": 443,
      "protocol": "https",
      "version": "15.11.3",
      "detection_method": "api",
      "description": "GitLab version 15.11.3 detected via api",
      "recommendation": "Ensure GitLab is updated to the latest version to avoid known vulnerabilities"
    }
  ]
}
```

## Usage Examples

### Basic Scan
```bash
# Scan a single GitLab instance
cxg scan --scope gitlab.example.com --templates gitlab-version-fingerprint.py

# Scan with specific port
cxg scan --scope gitlab.example.com:8443 --templates gitlab-version-fingerprint.py

# Scan multiple targets from file
cxg scan --scope gitlab-targets.txt --templates gitlab-version-fingerprint.py
```

### Advanced Usage
```bash
# Scan with JSON output
cxg scan --scope gitlab.example.com \
  --templates gitlab-version-fingerprint.py \
  --format json \
  -o gitlab-versions.json

# Scan subnet for GitLab instances
cxg scan --scope 192.168.1.0/24 \
  --ports 80,443,8080,8443 \
  --templates gitlab-version-fingerprint.py
```

## Real-World Testing

The template was tested against multiple live GitLab instances discovered via FOFA. Testing demonstrates graceful handling of both successful detections and hardened instances.

**Key Observations:**
- All targets completed successfully (no crashes or errors)
- Graceful handling of connection failures and timeouts
- SSL/TLS certificate verification bypass working correctly
- Template returns empty findings array when version cannot be determined

## Security Implications

### Critical Vulnerabilities in GitLab History

| CVE | Version Affected | Severity | Impact |
|-----|------------------|----------|--------|
| CVE-2021-22205 | < 13.10.3 | Critical (10.0) | Remote Code Execution via ExifTool |
| CVE-2023-2825 | 16.0.0 - 16.0.7 | High | Path traversal |
| CVE-2023-5356 | < 16.5.1 | High | Account takeover |
| CVE-2024-6678 | < 17.1.2 | Critical | Authentication bypass |

## FOFA Search Queries

Find GitLab instances for testing:
```
app="GitLab"
app="GitLab" && port="80"
title="GitLab"
```

## References

- **GitLab Version API:** https://docs.gitlab.com/ee/api/version.html
- **GitLab Security:** https://about.gitlab.com/releases/categories/releases/
- **CERT-X-GEN:** https://github.com/Bugb-Technologies/cert-x-gen

---

**Author:** BugB Technologies  
**Created:** January 2026  
**Version:** 1.0.0  
**License:** Apache 2.0

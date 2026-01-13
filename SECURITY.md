# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

Send an email to **security@bugb.io** with:

- Type of vulnerability
- Template file affected
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **24 hours:** Acknowledgment of your report
- **7 days:** Initial assessment
- **30 days:** Resolution or status update

### Scope

**In Scope:**
- Vulnerabilities in template logic
- Bypass of security checks
- False negatives (missed vulnerabilities)
- Privilege escalation in templates
- Information disclosure

**Out of Scope:**
- False positives (reported via regular issues)
- Feature requests
- Issues with CERT-X-GEN CLI (report to main repo)

## Security Best Practices

### For Template Authors

1. **Never hardcode credentials**
2. **Validate all inputs**
3. **Handle errors gracefully**
4. **Avoid destructive operations**
5. **Test in isolated environments**

### For Template Users

1. **Review templates before use**
2. **Run in controlled environments**
3. **Respect target permissions**
4. **Monitor template execution**
5. **Report suspicious behavior**

## Template Security Review

All templates undergo security review before merge:

- ✅ No hardcoded secrets
- ✅ No destructive operations
- ✅ Proper error handling
- ✅ Safe default configuration
- ✅ Clear documentation

## Disclosure Policy

After a vulnerability is patched:

1. Credit reporter (if desired)
2. Publish CVE (if applicable)
3. Update CHANGELOG.md
4. Release security advisory

## Contact

- **Security Team:** security@bugb.io
- **PGP Key:** [Available on request]
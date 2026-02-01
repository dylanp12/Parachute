# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Parachute, please report it responsibly.

### How to Report

**DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email us at: **security@parachute.dev**

Include the following in your report:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** assessment
4. **Suggested fix** (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### Recognition

We appreciate responsible disclosure and will:

- Credit you in the security advisory (unless you prefer anonymity)
- Add you to our security contributors list
- Provide a letter of acknowledgment upon request

## Security Best Practices

When deploying Parachute:

1. **Use strong passwords** - Set `PARACHUTE_PASSWORD` to a secure value
2. **Enable IP whitelisting** - Restrict access in production
3. **Use the hardened Docker profile** - `docker-compose.hardened.yml`
4. **Keep updated** - Enable Dependabot and update regularly
5. **Review egress rules** - Only allow necessary domains
6. **Monitor audit logs** - Check for suspicious activity

## Known Security Features

- Basic Auth / Bearer Token authentication
- IP whitelisting
- Rate limiting
- Command blocking and approval workflows
- PII detection and blocking
- Egress domain whitelisting
- Audit logging with correlation IDs

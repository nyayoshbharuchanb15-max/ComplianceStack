# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within ComplianceStack, please send an email to the repository maintainer. All security vulnerabilities will be promptly addressed.

**Please do NOT report security vulnerabilities through public GitHub issues.**

## Disclosure Policy

When the maintainer receives a security bug report, they will assign it to a primary handler. This person will coordinate the fix and release process, including the following actions:

1. Confirm the problem and determine the affected versions.
2. Audit code to find any potential similar problems.
3. Prepare fixes for all releases still under maintenance.
4. Cut a new security release.

## Security Considerations

ComplianceStack is designed with security-first principles:

- **Zero Data Egress**: All audit operations run in-process. No data leaves your infrastructure.
- **On-Premise Only**: No telemetry, no external API calls, no cloud dependencies.
- **OAuth 2.1 + RBAC**: Role-based access control with scoped endpoints.
- **Ed25519 Cryptographic Signing**: Keys never leave the container.
- **PII Redaction**: Middleware intercepts and redacts PII from all API responses.
- **Merkle Audit Trail**: Tamper-evident evidence chain for compliance.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.1.x   | :white_check_mark: |
| 3.0.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Best Practices

When deploying ComplianceStack:

1. **Always change default passwords** before production deployment
2. **Generate strong secrets** for AUTH_PRIVATE_KEY and SIGNING_KEY
3. **Use HTTPS** in production environments
4. **Enable RBAC** (set DEMO_MODE=false)
5. **Monitor logs** for unauthorized access attempts
6. **Regular updates** to keep dependencies secure

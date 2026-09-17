# SENTINEL — Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability within SENTINEL, please send an email to the maintainers. All security vulnerabilities will be promptly addressed.

**Please do not report security vulnerabilities through public GitHub issues.**

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response SLA

- **Acknowledgement**: within 48 hours
- **Triage**: within 5 business days
- **Fix or mitigation**: within 30 days for critical/high, 90 days for medium/low

## Security Measures

- API keys are SHA-256 hashed, never stored in plaintext
- Rate limiting on all endpoints
- Input validation via Pydantic at every boundary
- RBAC/ABAC with deny-by-default
- Audit logging on all sensitive actions
- Offline-first: no network imports in `src/sentinel/`
- PCAP parsing should be sandboxed in production (resource limits)
- Release artifacts are checksummed (SHA-256)

## Dependency Scanning

- `pip-audit` in CI
- `ruff` for static analysis
- Manual review of new dependencies

## Secret Management

- No secrets in code or env files in production
- Use a secret manager (Vault/cloud KMS) in production
- Rotate keys periodically

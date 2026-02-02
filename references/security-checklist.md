# Security Checklist

Apply every category to the plan. Mark: YES (addressed), NO (must fix before proceeding), N/A (not applicable to this task).

## 1. Authentication

- [ ] Every privileged operation requires verified identity
- [ ] No default or hardcoded credentials exist anywhere
- [ ] Password storage uses bcrypt/scrypt/argon2 with per-user salts
- [ ] Multi-factor authentication is supported where applicable
- [ ] Session tokens are cryptographically random, sufficient length (>=128 bits)
- [ ] Session expiration and revocation are implemented
- [ ] Authentication failures use constant-time comparison (no timing oracle)
- [ ] Lockout or rate-limiting after repeated failures

## 2. Authorization & Access Control

- [ ] Default-deny: access is blocked unless explicitly granted
- [ ] Authorization checked server-side on every request (not just UI hiding)
- [ ] Role/permission model uses least privilege
- [ ] No IDOR: object access validated against current user's permissions
- [ ] Admin functions separated and protected with additional controls
- [ ] API keys and service accounts scoped to minimum required permissions
- [ ] No privilege escalation paths via parameter tampering or forced browsing

## 3. Input Validation

- [ ] All external input validated at the trust boundary
- [ ] Allowlist validation preferred over denylist
- [ ] Type, length, range, and format enforced on every field
- [ ] File uploads validated: type, size, content (magic bytes, not just extension)
- [ ] File uploads stored outside webroot with randomized names
- [ ] No raw user input in SQL, shell commands, OS calls, LDAP, XML, or log entries
- [ ] Parameterized queries or ORM for all database access
- [ ] No eval(), exec(), or dynamic code execution with user-controlled input

## 4. Output Encoding

- [ ] HTML output: context-aware encoding (element, attribute, JS, CSS, URL contexts)
- [ ] SQL output: parameterized queries only
- [ ] Shell output: no string interpolation; use subprocess with array args
- [ ] Log output: structured logging, no raw user input in log messages
- [ ] API responses: Content-Type headers set correctly, no reflection of raw input

## 5. Cryptography

- [ ] TLS 1.2+ for all network communication
- [ ] Sensitive data encrypted at rest using AES-256-GCM or equivalent
- [ ] Cryptographic keys managed via secret store, never in source code
- [ ] No custom crypto implementations — use vetted libraries only
- [ ] Random values use CSPRNG (e.g., secrets module, /dev/urandom)
- [ ] Certificate validation enabled, no disabling of TLS verification
- [ ] JWT: algorithm pinned (no "alg:none"), short expiry, signed server-side

## 6. Secrets Management

- [ ] No secrets in source code, config files committed to VCS, or logs
- [ ] Secrets loaded from environment variables or dedicated secret stores
- [ ] Secrets never appear in URLs, query strings, or error messages
- [ ] Secrets rotatable without code changes
- [ ] .gitignore / .dockerignore exclude all secret-containing files
- [ ] CI/CD secrets masked in logs

## 7. Error Handling & Logging

- [ ] Errors fail closed (deny access on failure, not grant)
- [ ] User-facing errors are generic, no stack traces or internal details
- [ ] Detailed errors logged server-side only
- [ ] Security events logged: auth success/failure, authz denials, input validation failures, admin actions
- [ ] Logs never contain: passwords, tokens, PII, credit card numbers, session IDs
- [ ] Log integrity protected (append-only, shipped to central store)
- [ ] Alerting configured for anomalous patterns

## 8. Data Protection & Privacy

- [ ] Collect minimum necessary data only
- [ ] PII identified and classified
- [ ] Data retention policy defined and enforced
- [ ] User data deletable on request (right to erasure)
- [ ] Sensitive data masked in logs, analytics, and non-production environments
- [ ] Data at rest encrypted, backups encrypted
- [ ] Cross-border data transfer requirements considered

## 9. Network & Infrastructure

- [ ] Services not exposed publicly unless required
- [ ] Network segmentation between trust zones
- [ ] Firewall rules default-deny, minimum ports open
- [ ] Database not directly reachable from the internet
- [ ] Internal service-to-service communication authenticated (mTLS, service tokens)
- [ ] DNS, TLS certificates, and cloud IAM reviewed

## 10. Dependency & Supply Chain

- [ ] Dependencies pinned to specific versions (lockfile present)
- [ ] No known critical/high CVEs in dependency tree
- [ ] Minimal dependency count; each justified
- [ ] Dependencies sourced from official registries
- [ ] Lock files committed to version control
- [ ] Automated vulnerability scanning in CI/CD pipeline

## 11. Deployment & Configuration

- [ ] Debug mode disabled in production
- [ ] Default accounts and sample data removed
- [ ] Security headers set: CSP, HSTS, X-Content-Type-Options, X-Frame-Options
- [ ] CORS policy restrictive, not wildcard
- [ ] Container images minimal (distroless/alpine), no root user
- [ ] Infrastructure as code reviewed for misconfigurations
- [ ] Rollback procedure documented and tested

## 12. Availability & Resilience

- [ ] Rate limiting on all public endpoints
- [ ] Request size limits enforced
- [ ] Timeouts set on all external calls
- [ ] Circuit breakers for downstream dependencies
- [ ] Graceful degradation under load
- [ ] Resource exhaustion vectors identified and mitigated (CPU, memory, disk, file descriptors, connections)

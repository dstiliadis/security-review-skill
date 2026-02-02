# Anti-Patterns: Recurring Security Disasters

These patterns appear repeatedly in breach postmortems. If you recognize any in the current plan or code, stop and fix immediately.

## Authentication Anti-Patterns

**AP-AUTH-01: Plaintext or reversibly-encrypted passwords**
Seen in: Adobe 2013 (153M accounts), RockYou 2009. Store passwords with bcrypt/scrypt/argon2 + per-user salt. Never MD5, SHA1, or SHA256 without a KDF.

**AP-AUTH-02: Credential stuffing with no rate limit**
Seen in: Repeated breaches across streaming, retail, financial services. Enforce rate limits, account lockout, and CAPTCHA on auth endpoints.

**AP-AUTH-03: JWT "alg:none" or symmetric key confusion**
Seen in: Countless API breaches. Pin the algorithm server-side. Validate every token. Never trust the header's "alg" claim.

**AP-AUTH-04: Session fixation / no rotation on privilege change**
Regenerate session ID after login, privilege escalation, or password change.

**AP-AUTH-05: Magic links / tokens with no expiry or single-use enforcement**
Tokens must expire (short TTL) and be invalidated after first use.

## Authorization Anti-Patterns

**AP-AUTHZ-01: Client-side-only access control**
Seen in: Parler data scrape 2021, countless SPAs. Server must enforce every permission check. UI hiding is cosmetic, not security.

**AP-AUTHZ-02: Insecure Direct Object Reference (IDOR)**
Seen in: USPS 2018 (60M records), First American Financial 2019 (885M records). Validate that the requesting user owns or is permitted to access the referenced object on every request.

**AP-AUTHZ-03: Mass assignment / over-posting**
Seen in: GitHub 2012 (Rails mass assignment). Allowlist accepted fields. Never bind raw request bodies to models.

**AP-AUTHZ-04: Broken function-level authorization**
Admin endpoints discoverable and callable by regular users. Enforce role checks on every handler, not just the route table.

**AP-AUTHZ-05: Privilege escalation via parameter tampering**
Changing `role=user` to `role=admin` in a request. Never trust client-supplied role or permission values.

## Injection Anti-Patterns

**AP-INJ-01: SQL injection**
Seen in: Heartland 2008 (130M cards), TalkTalk 2015. Use parameterized queries exclusively. No string concatenation for SQL.

**AP-INJ-02: Command injection via shell interpolation**
Seen in: Shellshock (Bash CVE-2014-6271). Use subprocess with argument arrays, never shell=True with user input.

**AP-INJ-03: Server-Side Template Injection (SSTI)**
User input in template engines (Jinja2, Twig, etc.) can execute arbitrary code. Never pass raw input to template render functions.

**AP-INJ-04: LDAP / XPath / NoSQL injection**
Same root cause as SQLi but different targets. Parameterize or sanitize for the specific interpreter.

**AP-INJ-05: Log injection / CRLF injection**
Attacker injects newlines or control characters to forge log entries, poison caches, or split HTTP responses. Sanitize or encode all user input before logging or including in HTTP headers.

## Data Exposure Anti-Patterns

**AP-DATA-01: Secrets in source code or version control**
Seen in: Uber 2016 (57M records, AWS keys in GitHub repo). Use secret stores. Scan repos with tools like trufflehog or gitleaks.

**AP-DATA-02: Verbose error messages in production**
Stack traces, SQL queries, file paths in error responses. Use generic user-facing errors; log details server-side only.

**AP-DATA-03: Unencrypted data at rest**
Seen in: Equifax 2017 (internal systems), numerous S3 bucket exposures. Encrypt all sensitive data at rest.

**AP-DATA-04: PII in logs, analytics, or URLs**
Seen in: Facebook 2019 (passwords logged plaintext). Structured logging with sensitive field redaction. Never log tokens, passwords, SSNs, or credit card numbers.

**AP-DATA-05: Exposed cloud storage (S3 buckets, GCS, Azure Blobs)**
Seen in: Capital One 2019, countless others. Default-deny public access. Audit bucket policies.

## Cryptography Anti-Patterns

**AP-CRYPTO-01: Rolling your own crypto**
Never implement custom encryption, hashing, or key exchange. Use NaCl/libsodium, OpenSSL, or platform-provided libraries.

**AP-CRYPTO-02: Using deprecated algorithms**
MD5, SHA1, RC4, DES, 3DES, ECB mode. Use AES-256-GCM, SHA-256+, ChaCha20-Poly1305.

**AP-CRYPTO-03: Hardcoded encryption keys or IVs**
Keys must be generated randomly, stored in secret managers, and rotatable.

**AP-CRYPTO-04: Disabled TLS verification**
`verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify: true`. Never disable in production. Fix the certificate instead.

**AP-CRYPTO-05: Predictable random values for security purposes**
Using `Math.random()`, `random.random()`, or `rand()` for tokens, nonces, or keys. Use CSPRNG: `secrets` (Python), `crypto.randomBytes` (Node), `SecureRandom` (Java/Ruby).

## Infrastructure Anti-Patterns

**AP-INFRA-01: Database directly exposed to internet**
Seen in: Meow attack 2020 (thousands of unsecured DBs wiped). Databases behind private subnets, accessed only through application layer or bastion.

**AP-INFRA-02: Running as root / excessive container privileges**
Seen in: Container escape exploits. Run as non-root, drop capabilities, use read-only filesystems where possible.

**AP-INFRA-03: No network segmentation**
Seen in: Target 2013 (HVAC vendor pivoted to POS network). Segment by trust level. Firewall between zones.

**AP-INFRA-04: Debug endpoints in production**
`/debug`, `/actuator`, `/phpinfo`, `DJANGO_DEBUG=True`. Remove or gate behind VPN + auth.

**AP-INFRA-05: Wildcard CORS**
`Access-Control-Allow-Origin: *` with credentials. Enumerate allowed origins explicitly.

## Supply Chain Anti-Patterns

**AP-SUPPLY-01: Unpinned dependencies**
Version ranges allow malicious updates. Pin exact versions in lockfiles.

**AP-SUPPLY-02: Typosquatting / dependency confusion**
Seen in: ua-parser-js 2021, event-stream 2018. Verify package names. Use scoped registries for internal packages.

**AP-SUPPLY-03: Outdated dependencies with known CVEs**
Seen in: Equifax 2017 (Apache Struts CVE-2017-5638). Automated scanning in CI. Patch critical CVEs immediately.

## Logic & Design Anti-Patterns

**AP-LOGIC-01: TOCTOU race conditions**
Time-of-check vs time-of-use. Use atomic operations, database transactions, or file locking.

**AP-LOGIC-02: Unlimited resource consumption**
No pagination, no request size limits, no timeouts. ReDoS from unbounded regex. Always bound loops, queries, and allocations.

**AP-LOGIC-03: Insecure deserialization**
Seen in: Apache Commons (Java), pickle (Python), YAML.load (Ruby/Python). Never deserialize untrusted data with full object instantiation. Use safe loaders and allowlisted types.

**AP-LOGIC-04: Open redirects**
`?redirect=https://evil.com` used for phishing. Validate redirect targets against an allowlist of internal paths.

**AP-LOGIC-05: Missing idempotency on state-changing operations**
Replayed requests cause duplicate charges, double-writes. Use idempotency keys for critical mutations.

**AP-LOGIC-06: Trusting client-side validation alone**
All client-side checks are bypassable. Server must independently validate everything.

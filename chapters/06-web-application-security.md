# 6. Web Application Security (OWASP Top 10)

## OWASP Top 10 2021

### 1. Broken Access Control
- **Definition**: Users can access/do unauthorized actions.
- **Examples**:
  - User 1 changes URL from `/profile/1` to `/profile/2` → sees another user's data.
  - Non-admin user accesses `/admin` panel.
  - User modifies request to escalate privileges.
- **Causes**:
  - Missing authorization checks.
  - Insecure direct object references (IDOR).
  - Horizontal/vertical privilege escalation.
- **Mitigation**: Enforce authorization on all requests; principle of least privilege; use RBAC.
- **SOC Detection**: Monitor for 403 (Forbidden) errors followed by successful 200 (OK) responses; unusual access patterns.

### 2. Cryptographic Failures
- **Definition**: Data in transit/at rest not properly encrypted or hashed.
- **Examples**:
  - Passwords stored as plaintext.
  - Sensitive data sent over HTTP (not HTTPS).
  - Weak encryption (DES, RC4).
  - Hardcoded encryption keys in code.
- **Mitigation**:
  - Use HTTPS/TLS for all data in transit.
  - Hash passwords with bcrypt/Argon2.
  - Encrypt sensitive data at rest (AES-256).
  - Rotate encryption keys regularly.
- **SOC Detection**: Monitor for HTTP (unencrypted) traffic carrying credentials; weak ciphers in TLS handshakes.

### 3. Injection (SQLi, OS Command Injection, LDAP Injection)
- **Definition**: Attacker inserts malicious code into application input.

#### SQL Injection (SQLi)
**Vulnerable Code**:
```python
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
db.execute(query)
```

**Attack**:

- Input: `username = admin' --`
- Query becomes: `SELECT * FROM users WHERE username='admin' --' AND password='...'`
- `--` comments out rest; query returns admin user without password check.

**Real-World Impact**:

- Dump entire database.
- Modify/delete data.
- Read files from server.
- Execute OS commands (depending on DB).

**Defense**:

- Parameterized queries (prepared statements):

```python
query = "SELECT * FROM users WHERE username=? AND password=?"
db.execute(query, (username, password))
```

- Input validation (whitelist, length, type).
- ORM frameworks (Django ORM, SQLAlchemy).


#### Command Injection

**Vulnerable Code**:

```bash
cmd = "ping " + hostname
os.system(cmd)
```

**Attack**:

- Input: `hostname = 8.8.8.8; cat /etc/passwd`
- Command: `ping 8.8.8.8; cat /etc/passwd`
- Attacker reads sensitive files.

**Defense**:

- Avoid shell commands; use libraries.
- Input validation.
- Use subprocess with array, not shell=True.


### 4. Insecure Design

- **Definition**: Missing security controls in design phase.
- **Examples**:
    - No rate limiting on login → brute force.
    - No CSRF protection → account hijacking.
    - Weak password policy → easy guessing.
- **Mitigation**: Threat modeling, security requirements, secure design patterns.


### 5. Security Misconfiguration

- **Definition**: Insecure default settings, incomplete setups, unnecessary features.
- **Examples**:
    - Default credentials (admin/admin).
    - Unnecessary ports/services enabled.
    - Debug mode on in production.
    - Overly permissive CORS.
    - Exposed sensitive files (.git, .env, backup files).
- **Mitigation**:
    - Minimal installation (only needed software).
    - Change defaults.
    - Security scanning tools (Nessus, Qualys).
    - Infrastructure as Code with security checks.
- **SOC Detection**: Monitor for requests to common sensitive paths (/.git, /.env, /admin, /backup).


### 6. Vulnerable and Outdated Components

- **Definition**: Using libraries, frameworks, plugins with known CVEs.
- **Examples**:
    - Old version of jQuery with XSS vulnerability.
    - Outdated OpenSSL with heartbleed.
    - Unmaintained Node.js packages.
- **Mitigation**:
    - Dependency scanning (npm audit, OWASP Dependency Check).
    - Keep up-to-date; monitor CVE feeds.
    - Remove unnecessary dependencies.
- **SOC Detection**: Monitor library/software versions; cross-reference with CVE databases.


### 7. Identification and Authentication Failures

- **Definition**: Weak authentication; session management flaws.
- **Examples**:
    - Plaintext session tokens.
    - Brute-forcible login.
    - Session fixation (attacker sets user's session ID).
    - No MFA.
- **Mitigation**:
    - MFA/2FA.
    - Strong password policy + rate limiting on login.
    - Secure session management (HttpOnly, Secure, SameSite cookies).
    - Password reset via email, not security questions.
- **SOC Detection**: Monitor failed login attempts; unusual session activity; MFA bypass attempts.


### 8. Software and Data Integrity Failures

- **Definition**: Insecure CI/CD, auto-update without verification, tampering with serialized data.
- **Examples**:
    - Pulling code from untrusted sources.
    - Not verifying signatures of updates.
    - Deserialization of untrusted data (object injection).
- **Mitigation**:
    - Code signing and verification.
    - Secure CI/CD pipeline.
    - Avoid serialization of sensitive objects.
- **SOC Detection**: Monitor for code/application modifications; integrity checks.


### 9. Security Logging and Monitoring Failures

- **Definition**: Insufficient logging; no alerts; no forensics capability.
- **Examples**:
    - No login attempt logging.
    - No audit trail for sensitive operations.
    - Logs stored without integrity protection.
    - No alerting on anomalies.
- **Mitigation**:
    - Log authentication, access, data changes.
    - Centralized logging (SIEM).
    - Real-time alerting.
    - Immutable logs.
- **SOC Focus**: This is your domain! Implement logging for all vulnerabilities above; correlate logs to detect attacks.


### 10. Server-Side Request Forgery (SSRF)

- **Definition**: Attacker tricks server into making unintended requests.
- **Example**:

```
User enters URL to fetch: http://192.168.1.1/admin
Server (trusted on internal network) fetches URL.
Server returns internal admin page to attacker.
```

- **Impact**:
    - Access internal services (Redis, databases, cloud metadata).
    - Port scanning.
    - Credential harvesting.
- **Mitigation**:
    - URL validation (whitelist, blocklist internal IPs).
    - Disable HTTP redirects or limit redirects.
    - Network segmentation.

---

## XSS (Cross-Site Scripting) – Deep-Dive

### Types

#### Stored XSS (Persistent)

- **How**: Attacker injects script into database (comment, profile, post).
- **When**: Others view the page, script executes in their browser.
- **Impact**: Affects many users; long-lived.

**Example**:

- Attacker posts comment: `<script>alert('XSS')</script>`
- Comment saved in DB without sanitization.
- Every user viewing the page gets XSS'd.


#### Reflected XSS (Non-Persistent)

- **How**: Script in URL parameter; server reflects it in response.
- **When**: User clicks malicious link.
- **Impact**: Single user, requires click.

**Example**:

- Attacker crafts link: `example.com/search?q=<script>alert('XSS')</script>`
- Server returns page with script in it.
- User's browser executes script.


#### DOM-Based XSS

- **How**: Client-side JavaScript processes untrusted input unsafely.
- **When**: JavaScript modifies DOM without sanitization.

**Example**:

```javascript
// Vulnerable code
var searchTerm = location.hash.substring(1); // Get URL fragment
document.getElementById('result').innerHTML = searchTerm; // Unsafe!

// URL: example.com#<img src=x onerror="alert('XSS')">
// Script executes on page.
```


### Payload Examples

```html
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<body onload="alert('XSS')">
<iframe src="javascript:alert('XSS')">
<input onfocus="alert('XSS')" autofocus>
```


### Defense

- **Output Encoding**: Encode special characters before sending to browser.
    - `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`
- **Input Validation**: Whitelist allowed characters.
- **CSP (Content Security Policy)**: Header limiting where scripts can come from.

```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

- **Use Frameworks**: Most modern frameworks (React, Vue, Angular) auto-encode by default.

---

## CSRF (Cross-Site Request Forgery)

### How It Works

```
1. User logs into bank.com, gets session cookie.
2. User visits attacker.com without logging out of bank.
3. attacker.com has hidden form:
   <form action="bank.com/transfer" method="POST">
     <input name="amount" value="1000000">
     <input name="to" value="attacker_account">
     <input type="submit" value="Click here">
   </form>
4. User clicks link (or auto-submits form).
5. Browser sends bank.com request WITH session cookie.
6. Bank processes transfer (user authenticated).
7. Attacker's account receives money.
```


### Why It Works

- Browser automatically includes cookies for bank.com when requesting bank.com.
- Bank sees valid session → assumes request is legitimate.
- No way to distinguish user-initiated request from attacker's site.


### Defense

- **CSRF Tokens**: Server generates unique token; form includes it.
    - Attacker can't predict token (not in cookie).
    - Server verifies token before processing.
- **SameSite Cookie**: Browser doesn't send cookie for cross-site requests.

```
Set-Cookie: sessionid=...; SameSite=Strict
```

- **Referer Check**: Verify request came from your domain.

---

## Open Redirects

### What & How

- **Vulnerability**: App redirects to user-supplied URL without validation.
- **Example**:

```
https://bank.com/logout?redirect_to=https://evil.com
Server: redirect user to redirect_to parameter.
Result: User redirected to evil.com after logout.
```


### Attack Scenario

1. Attacker crafts: `bank.com/logout?redirect_to=phishing.evil.com`
2. Attacker sends link in phishing email: "Click to log out securely."
3. User clicks, logs out from legitimate bank.com.
4. User redirected to phishing.evil.com (looks like bank.com).
5. User re-enters credentials into phishing site.

### Defense

- **Whitelist**: Only allow redirects to known URLs.

```
allowed_redirects = ['/', '/home', '/dashboard']
if redirect_to not in allowed_redirects:
    return error
```

- **URL Validation**: Ensure URL is same-origin.

```python
from urllib.parse import urlparse
parsed = urlparse(redirect_to)
if parsed.netloc != request.host:
    return error
```

- **Relative URLs Only**: Allow `/path` but not `//` or `http://`.

---

---

[Index](../README.md) | [Previous: Cryptography & PKI](05-cryptography-pki.md) | [Next: Malware & Threat Analysis](07-malware-threat-analysis.md)

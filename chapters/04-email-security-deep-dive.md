# 4. Email Security Deep-Dive (SPF/DKIM/DMARC)

## Email Flow (Simplified)

```

Sender (Alice@acme.com)
↓
Sender's SMTP Server (mail.acme.com)
↓
Internet (SMTP)
↓
Recipient's SMTP Server (mail.recipient.com)
↓
Recipient's Mailbox

```

---

## SPF (Sender Policy Framework)

### What & How
- **Definition**: TXT record listing servers authorized to send mail for a domain.
- **Implementation**: Domain publishes SPF record at DNS.
- **Check**: Receiver compares email's source IP against SPF record.

### SPF Record Example
```

acme.com TXT "v=spf1 ip4:192.0.2.0 include:_spf.google.com ~all"

```

**Breakdown**:
- `v=spf1`: Version 1 of SPF.
- `ip4:192.0.2.0`: This IP can send mail for acme.com.
- `include:_spf.google.com`: Also allow Google's mail servers (if using Google Workspace).
- `~all`: Soft fail for all others (accept but mark as suspicious).
- Alternative: `-all` (hard fail; reject all others).

### SPF Validation Results
- **Pass**: Email from authorized IP.
- **Fail**: Email from unauthorized IP.
- **SoftFail (~)**: Probably not authorized; recipient can accept or flag.
- **Neutral**: No policy defined.
- **None**: No SPF record.

### SPF Limitations
1. **Only checks envelope-from (5321.From)**, not display From header (5322.From).
   - Attacker can spoof display name while using authorized IP.
2. **Broken by forwarding**: Forward breaks chain (email re-sent from forwarder's IP).
   - Solution: Sender Rewriting Scheme (SRS).
3. **No integrity**: Doesn't prevent message tampering.

### SOC Phishing Check
```

Email received from: "support@acme.com"
Step 1: Extract envelope-from via header inspection.
Step 2: Check SPF record for acme.com (DNS lookup).
Step 3: Verify sender IP matches SPF record.
Step 4: If SPF fails + domain is known to organization → likely phishing.

```

---

## DKIM (DomainKeys Identified Mail)

### What & How
- **Definition**: Uses public-key cryptography to verify email authenticity and integrity.
- **How**:
  1. Mail server signs email with private key (DKIM-Signature header added).
  2. Domain publishes public key in DNS as TXT record.
  3. Receiver verifies signature using public key.
  4. If signature valid → email truly from domain + not tampered.

### DKIM Record Example (DNS)
```

default._domainkey.acme.com TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA..."

```

**Breakdown**:
- `default._domainkey`: DKIM selector (domain can have multiple selectors for key rotation).
- `v=DKIM1`: DKIM version.
- `k=rsa`: Key type (RSA).
- `p=...`: Public key (RSA public key).

### DKIM Signature (in email header)
```

DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=acme.com; s=default; h=from:to:subject:date; bh=...; b=...

```

**Breakdown**:
- `a=rsa-sha256`: Algorithm (RSA with SHA-256).
- `d=acme.com`: Domain signing.
- `s=default`: Selector.
- `h=from:to:subject:date`: Headers signed.
- `bh=...`: Body hash.
- `b=...`: Signature (encrypted hash).

### DKIM Validation Results
- **Pass**: Signature valid; message unchanged.
- **Fail**: Signature invalid or doesn't match domain.
- **Neutral**: No DKIM signature present.

### DKIM Advantages Over SPF
- Survives forwarding (signature stays valid).
- Protects message integrity (hash detects tampering).
- Works with multiple domains/services.

---

## DMARC (Domain-based Message Authentication, Reporting and Conformance)

### What & How
- **Definition**: Policy framework on top of SPF + DKIM.
- **Purpose**: Define handling rules for authentication failures + request reports.

### DMARC Record Example
```

_dmarc.acme.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@acme.com; ruf=mailto:forensics@acme.com; fo=1; rf=afrf; aspf=r"

```

**Breakdown**:
- `v=DMARC1`: DMARC version.
- `p=quarantine`: Policy if auth fails:
  - `none`: No action (monitoring only).
  - `quarantine`: Move to spam folder.
  - `reject`: Reject email entirely.
- `rua=mailto:dmarc@acme.com`: Send aggregate reports (daily summary).
- `ruf=mailto:forensics@acme.com`: Send forensic reports (detailed failure data).
- `fo=1`: Forensic report options (1 = report if SPF or DKIM fails).
- `rf=afrf`: Forensic report format (AFRF = Authentication Failure Reporting Format).
- `aspf=r`: DKIM/SPF alignment policy (strict or relaxed).

### DMARC Alignment
- **SPF Alignment**: Domain in envelope-from must match domain in From header (strict) or organizational domain (relaxed).
- **DKIM Alignment**: Domain in DKIM signature must match From header (strict) or organizational domain (relaxed).

### DMARC Validation Results
- **Pass**: SPF and/or DKIM aligned + auth passes.
- **Fail**: SPF/DKIM failed + not aligned.

### DMARC Reports
- **Aggregate Report** (RUA): XML daily summary of auth results.
  - Example: "1000 emails passed DKIM, 50 failed SPF, 20 failed alignment."
- **Forensic Report** (RUF): Detailed per-email failure info.
  - Example: Exact headers, timestamps, auth results for each failed email.

---

## SPF/DKIM/DMARC in Phishing Analysis

### Email Header Inspection Checklist
```

From: noreply@acme.com
Sender: sender@acme.com
Return-Path: bounce@acme.com
Authentication-Results: acme.com
spf=pass smtp.mailfrom=acme.com
dkim=pass header.d=acme.com header.s=default
dmarc=pass

```

**Red Flags**:
- SPF/DKIM/DMARC all `fail` → email spoofed.
- `From` domain differs from `Return-Path` / `Sender` → suspicious.
- Lack of authentication headers → no auth configured (risky).

### Case Study: Phishing Email Detection

**Scenario**:
- User reports email from "support@acme.com" asking to verify password.
- Email body: "Click here to re-verify your account."
- Link goes to: `acme-verify.xyz` (attacker domain).

**SOC Analysis**:

1. **Header Inspection**:
```

From: support@acme.com
Return-Path: bounce@attacker.com  ← MISMATCH!
Authentication-Results:
spf=fail (1.2.3.4 not in acme.com SPF record)
dkim=fail (signature domain: attacker.com)
dmarc=fail (spf/dkim not aligned)

```

2. **SPF Check**: Domain is acme.com; email source IP 1.2.3.4 not in SPF → **FAIL**.

3. **DKIM Check**: DKIM signature domain is attacker.com, not acme.com → **FAIL**.

4. **DMARC Check**: SPF/DKIM failed + no alignment → **FAIL**.

5. **Link Analysis**: Hover over link → `acme-verify.xyz` (not acme.com) → credential phishing confirmed.

6. **Action**: Block sender, quarantine email, alert user.

---

---

[Index](../README.md) | [Previous: DNS & Domain Security](03-dns-domain-security.md) | [Next: Cryptography & PKI](05-cryptography-pki.md)

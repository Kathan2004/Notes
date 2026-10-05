# 14. 100+ Scenario-Based Q&A

## Core Fundamentals Q&A

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

## Networking & Ports Q&A

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

## DNS & Email Security Q&A

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

## Cryptography & PKI Q&A

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

## Web Application Security Q&A

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

## Malware & Threat Analysis Q&A

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

## Attack Frameworks Q&A

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


### Q25: Map the same phishing attack to MITRE ATT&CK.

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

## Incident Response Q&A

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

## Active Directory Q&A

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

## Phishing & Social Engineering Q&A

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

## Additional Scenario-Based Q&A

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

### Q36: Lateral Movement via Pass-the-Hash – Detect & Respond.

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

### Q38: Detect Data Exfiltration – Red Flags & Response.

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
11. **MITRE ATT&CK**: Tactics (goals) → Techniques (how) → Sub-Techniques (variations). Map alerts to tactics.
12. **Pyramid of Pain**: Hash (easy to change) → IPs → Domains → Patterns → Tools → TTPs (hard to change). Invest in TTP detection.
13. **IR**: Detection → Containment → Eradication → Recovery → Post-Incident.
14. **AD**: Users, Groups, Computers, OUs, GPOs. Kerberos (tickets, time-limited) vs NTLM (hash-based, weak). Monitor for privilege escalation, pass-the-hash, credential theft.
15. **SOC L1 Focus**: Alert triage, SIEM queries, escalation, threat intel. Not deep forensics/rule writing (those are L2/L3).

---

[Index](../README.md) | [Previous: Red Flags & Detection Patterns](13-red-flags-detection-patterns.md)

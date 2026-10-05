# 1. Core Fundamentals (CIA, AAA, Networking Basics)

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
- **Mitigations**: Hashing (SHA-256 or SHA-3; MD5 and SHA-1 are collision-broken and unfit for integrity), digital signatures, code signing, checksums, HMAC, file integrity monitoring (FIM).
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

---

[Index](../README.md) | [Next: Networking Fundamentals (IP, TCP/UDP, Ports)](02-networking-fundamentals.md)

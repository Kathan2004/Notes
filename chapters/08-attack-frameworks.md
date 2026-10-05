# 8. Attack Frameworks (Kill Chain, MITRE, Pyramid of Pain)

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


#### 6. Command & Control (C2)

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

## MITRE ATT&CK Framework

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
| **Command & Control** | Remote access | Beaconing, DNS tunneling, encrypted channels |
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


#### 2. IPs & Ports

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

---

[Index](../README.md) | [Previous: Malware & Threat Analysis](07-malware-threat-analysis.md) | [Next: Incident Response & SOC Operations](09-incident-response-soc-operations.md)

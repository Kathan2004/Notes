# 11. Active Directory Deep-Dive

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
- Alert: Unusual access to AD management tools (Active Directory Users & Computers).
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

---

[Index](../README.md) | [Previous: Authentication & Access Control (MFA, Kerberos, OAuth)](10-authentication-access-control.md) | [Next: Tools & Commands Reference](12-tools-commands-reference.md)

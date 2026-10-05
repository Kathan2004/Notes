# 13. Red Flags & Detection Patterns

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

---

[Index](../README.md) | [Previous: Tools & Commands Reference](12-tools-commands-reference.md) | [Next: 100+ Scenario-Based Q&A](14-scenario-based-qa.md)

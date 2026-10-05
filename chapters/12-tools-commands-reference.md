# 12. Tools & Commands Reference

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

```

**SOC Use**: Reconnaissance detection; baseline port changes


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

```

**SOC Use**: Phishing investigation; domain enumeration; DNSSEC validation


### netstat / ss (Network Connections)

```bash
# Show listening ports
netstat -an | grep LISTEN

# Show established connections
netstat -an | grep ESTABLISHED

# Show process associated with connection
netstat -antp (Linux) / netstat -anob (Windows)

```

**SOC Use**: Identify unexpected listening ports; C2 beaconing connections


---

## SIEM Query Examples (KQL for Microsoft Sentinel, SPL for Splunk)

### Detect Brute Force (KQL / SPL)

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

---

[Index](../README.md) | [Previous: Active Directory Deep-Dive](11-active-directory-deep-dive.md) | [Next: Red Flags & Detection Patterns](13-red-flags-detection-patterns.md)

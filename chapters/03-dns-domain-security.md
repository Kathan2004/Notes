# 3. DNS & Domain Security

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

---

[Index](../README.md) | [Previous: Networking Fundamentals (IP, TCP/UDP, Ports)](02-networking-fundamentals.md) | [Next: Email Security Deep-Dive (SPF/DKIM/DMARC)](04-email-security-deep-dive.md)

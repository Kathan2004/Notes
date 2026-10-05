# 2. Networking Fundamentals (IP, TCP/UDP, Ports)

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
| 53 | TCP/UDP | DNS | Domain Name System. UDP for most queries; TCP for zone transfers, responses over 512 bytes (common with DNSSEC) and DNS over TLS on 853. |
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

---

[Index](../README.md) | [Previous: Core Fundamentals (CIA, AAA, Networking Basics)](01-core-fundamentals.md) | [Next: DNS & Domain Security](03-dns-domain-security.md)

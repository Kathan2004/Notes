# SOC Analyst Field Notes

Working notes for Security Operations Center analysts: fundamentals, attack techniques, detection logic and incident response. Written for interview prep and day-to-day triage, and organised so each chapter stands on its own.

```
fundamentals ─► network & DNS ─► email ─► crypto ─► web ─► malware ─► frameworks ─► IR ─► identity ─► AD ─► tooling ─► detections ─► scenarios
```

## Chapters

| # | Chapter | Covers |
|---|---|---|
| 1 | [Core Fundamentals (CIA, AAA, Networking Basics)](chapters/01-core-fundamentals.md) | CIA triad, AAA, threat vs vulnerability vs risk |
| 2 | [Networking Fundamentals (IP, TCP/UDP, Ports)](chapters/02-networking-fundamentals.md) | OSI, IPv4/IPv6, TCP vs UDP, handshake, ports, Telnet vs SSH |
| 3 | [DNS & Domain Security](chapters/03-dns-domain-security.md) | resolution, record types, poisoning, amplification, tunnelling, DGAs |
| 4 | [Email Security Deep-Dive (SPF/DKIM/DMARC)](chapters/04-email-security-deep-dive.md) | SPF, DKIM, DMARC, header analysis, phishing triage |
| 5 | [Cryptography & PKI](chapters/05-cryptography-pki.md) | symmetric vs asymmetric, hashing, TLS, certificates, PKI |
| 6 | [Web Application Security (OWASP Top 10)](chapters/06-web-application-security.md) | OWASP Top 10: how each class works, how to detect it, how to fix it |
| 7 | [Malware & Threat Analysis](chapters/07-malware-threat-analysis.md) | classification, static and dynamic analysis, strings, IOCs, living-off-the-land |
| 8 | [Attack Frameworks (Kill Chain, MITRE, Pyramid of Pain)](chapters/08-attack-frameworks.md) | Cyber Kill Chain, MITRE ATT&CK, Pyramid of Pain |
| 9 | [Incident Response & SOC Operations](chapters/09-incident-response-soc-operations.md) | IR lifecycle, alert triage, escalation, SIEM workflow |
| 10 | [Authentication & Access Control (MFA, Kerberos, OAuth)](chapters/10-authentication-access-control.md) | MFA factors and attacks, Kerberos flow and attacks, OAuth 2.0 |
| 11 | [Active Directory Deep-Dive](chapters/11-active-directory-deep-dive.md) | AD objects, NTLM vs Kerberos, pass-the-hash, privilege escalation, recon, audit events |
| 12 | [Tools & Commands Reference](chapters/12-tools-commands-reference.md) | nmap, Wireshark, dig, netstat/ss, KQL and SPL detections, Windows and Linux CLI |
| 13 | [Red Flags & Detection Patterns](chapters/13-red-flags-detection-patterns.md) | high-signal indicators to alert on |
| 14 | [100+ Scenario-Based Q&A](chapters/14-scenario-based-qa.md) | 100+ interview and on-shift scenarios with worked answers |

## How to use

- **Interview prep.** Read chapters 1-11 in order, then work through [chapter 14](chapters/14-scenario-based-qa.md) without looking at the answers.
- **On shift.** Jump to [Tools & Commands](chapters/12-tools-commands-reference.md) and [Red Flags](chapters/13-red-flags-detection-patterns.md).
- **Navigation.** Every chapter links back to this index and to its neighbours.

## Contributing

Corrections are welcome. Open an issue or a pull request with a source for the change.

## License

See [LICENSE](LICENSE).

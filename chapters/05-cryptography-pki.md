# 5. Cryptography & PKI

## Hashing vs Encryption

### Hashing
- **Definition**: One-way function; input → fixed-length hash. Cannot reverse.
- **Purpose**: Integrity verification, password storage, fingerprinting.
- **Properties**:
- Deterministic: Same input = same hash.
- Avalanche effect: Tiny input change = completely different hash.
- Collision-resistant: Hard to find two inputs with same hash.
- **Common Algorithms**:
- **MD5** (128-bit): ❌ Broken (collisions found); deprecated.
- **SHA-1** (160-bit): ⚠️ Weak (collisions possible); avoid for security.
- **SHA-256** (256-bit): ✅ Secure; standard.
- **SHA-512** (512-bit): ✅ Very secure; paranoid.
- **bcrypt**: ✅ Slow, designed for passwords.
- **PBKDF2**: ✅ Key derivation, password storage.
- **Argon2**: ✅ Modern, GPU-resistant password hashing.

**Example**:
```

Input: "password123"
MD5: 482c811da5d5b4bc6d497ffa98491e38
SHA-256: ef92b778bafe771e89245d171bafae2c0ce58494fe20e9ad0b2c69d37b06c4a6

```

### Encryption
- **Definition**: Two-way function; plaintext + key → ciphertext; reverse with key.
- **Purpose**: Confidentiality (protecting data).
- **Types**:
  - **Symmetric**: Same key for encrypt/decrypt. Fast.
  - **Asymmetric**: Public key (encrypt) + private key (decrypt). Slower.

### Use Cases
| Scenario | Hash | Encryption |
|----------|------|------------|
| Store passwords safely | ✓ | ✗ (shouldn't be reversible) |
| Detect file tampering | ✓ | ✗ (need irreversibility) |
| Hide data in transit | ✗ | ✓ |
| Digital signatures | ✓ (sign hash) | ✓ (public key crypto) |
| Password recovery | ✗ | ✗ (hash can't be reversed; use password reset) |

---

## Symmetric Encryption

### How It Works
```

Alice                          Bob
plaintext                      plaintext
↓ (encrypt w/ shared key)        ↑ (decrypt w/ shared key)
ciphertext ←→ insecure channel ←→ ciphertext

```

### Common Algorithms
- **AES (Advanced Encryption Standard)** ✅
  - 128, 192, or 256-bit key.
  - Industry standard; used in TLS, VPN, full-disk encryption.
  - Modes: ECB (bad), CBC, CTR, GCM.
- **3DES (Triple DES)**: ⚠️ Deprecated (slow, small block size).
- **Blowfish/Twofish**: Older; still used in some systems.
- **ChaCha20**: Modern, fast; used in TLS 1.3.

### Key Management Problem
- **Challenge**: How do Alice and Bob agree on secret key over insecure channel?
- **Solution**: Asymmetric encryption (Diffie-Hellman key exchange, TLS handshake).

---

## Asymmetric Encryption (Public-Key Cryptography)

### How It Works
```

Alice publishes: Public Key A (can encrypt)
Alice keeps secret: Private Key A (can decrypt)

Anyone (Bob) can:

1. Get Alice's public key (from keyserver, certificate).
2. Encrypt message with public key A.
3. Send to Alice.

Only Alice can:
4. Decrypt with private key A.

```

### Common Algorithms
- **RSA** (Rivest-Shamir-Adleman):
  - Key size: 2048, 4096 bits (larger = slower but more secure).
  - Standard for email (PGP), VPN, code signing.
- **ECC** (Elliptic Curve Cryptography):
  - Smaller key sizes, same security as RSA.
  - Faster; used in modern TLS (ECDHE).
- **Ed25519**: Modern ECC variant; used in SSH keys, TLS.

### Use Cases
1. **Encryption**: Bob encrypts message with Alice's public key; Alice decrypts with private key.
2. **Digital Signatures**: Alice signs with private key; others verify with public key (proves Alice authored message).
3. **Key Exchange**: DH/ECDHE to establish shared symmetric key over insecure channel.

---

## PKI (Public Key Infrastructure)

### What It Is
- System for managing public keys, certificates, trust.
- Components: CAs (Certificate Authorities), certificates, key pairs, revocation mechanisms.

### X.509 Certificates
- **What**: Document binding public key to identity.
- **Contents**:
  - Subject (who the cert is for): CN=example.com, O=Example Inc.
  - Issuer (who signed it): C=US, O=Verisign.
  - Public Key.
  - Validity period (Not Before, Not After).
  - Serial number, signature algorithm, signature.

**Example (decoded)**:
```

Certificate:
Data:
Version: 3
Serial Number: 01:23:45:67
Signature Algorithm: sha256WithRSAEncryption
Issuer: CN=Verisign, O=Verisign
Subject: CN=example.com, O=Example Inc
Not Before: Jan 1, 2024
Not After: Dec 31, 2025
Public Key:
Algorithm: rsaEncryption
Public-Key: (2048 bit)
[RSA key data]
Extensions:
Subject Alt Name: example.com, www.example.com
Authority Key Id: [CA's key ID]
Subject Key Id: [This cert's key ID]
Signature Algorithm: sha256WithRSAEncryption
Signature Value: [Digital signature]

```

### Trust Chain
```

Root CA (self-signed)
↓ (signs)
Intermediate CA
↓ (signs)
End-Entity Certificate (for example.com)

```

- **Root CA**: Self-signed; installed in browser/OS trust store.
- **Intermediate CA**: Signs end-entity certs; issued by Root.
- **End-Entity Cert**: Your website/server's cert; issued by Intermediate.

**Why Chain?** If Root key compromised, only revoke Intermediate → other Intermediate CAs still trusted.

### Certificate Validation (Browser)
1. Server sends certificate to client.
2. Client extracts public key and validates signature using Issuer's public key.
3. Client validates certificate chain to Root.
4. Client checks certificate hasn't expired or been revoked (CRL/OCSP).
5. Client verifies cert Subject matches domain in URL.
6. If all valid → "🔒 Secure" padlock appears.

### Certificate Revocation
- **CRL (Certificate Revocation List)**: Signed list of revoked serial numbers; checked infrequently (stale data).
- **OCSP (Online Certificate Status Protocol)**: Real-time query to CA; slower but current.
- **OCSP Stapling**: Server caches OCSP response, provides to client (faster).

### Common Certificate Issues (SOC Detection)
- **Self-signed cert**: Subject = Issuer (browser warning). Common on internal services or attacker servers.
- **Expired cert**: Not After date passed. Common on compromised servers or legacy systems.
- **Cert mismatch**: Subject doesn't match requested domain. Browser warning; indicates MITM or misconfiguration.
- **Untrusted CA**: Issuer not in trust store. Attacker-controlled CA or corporate proxy.

---

---

[Index](../README.md) | [Previous: Email Security Deep-Dive (SPF/DKIM/DMARC)](04-email-security-deep-dive.md) | [Next: Web Application Security (OWASP Top 10)](06-web-application-security.md)

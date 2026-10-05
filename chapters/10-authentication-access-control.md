# 10. Authentication & Access Control (MFA, Kerberos, OAuth)

## MFA (Multi-Factor Authentication)

### Factors of Authentication

1. **Knowledge** (something you know): Password, PIN, security question.
2. **Possession** (something you have): Hardware token, phone, smart card.
3. **Inherence** (something you are): Fingerprint, face, iris.
4. **Location/Context** (where/when): IP range, time window, device.

### MFA Methods

- **Password + SMS OTP**: User knows password; SMS sends one-time code.
- **Password + Hardware Token**: User knows password; token generates code (TOTP/HOTP).
- **Password + Push Notification**: User knows password; phone app confirms login.
- **Biometric + Possession**: Fingerprint + smart card.
- **Context-based**: Risk score triggers additional factor.


### Security Benefits

- **Defense Against Phishing**: Attacker steals password; still needs phone/token.
- **Defense Against Brute Force**: Attacker can't guess OTP (time-limited).
- **Defense Against Credential Stuffing**: Even if password leaked in breach, MFA blocks access.


### Challenges & Attacks

- **SIM Swap**: Attacker convinces carrier to transfer phone number; receives SMS codes.
    - Defense: Don't use SMS for sensitive accounts; use app-based OTP or hardware tokens.
- **Phishing MFA Codes**: Attacker's site accepts login; prompts for MFA code; passes code to real site.
    - Defense: Educate users; use U2F/WebAuthn (hardware key) instead of code-based.
- **MFA Fatigue**: Users constantly approve notifications; attacker sends many; user approves one accidentally.
    - Defense: Limit approval notifications; use passwordless auth.

---

## Kerberos (Network Authentication Protocol)

### Background

- **Use**: Microsoft Active Directory (Windows domains); Linux with krb5.
- **Alternative**: NTLM (older, weaker; Kerberos preferred).
- **Trust Model**: Central authority (KDC) vouches for user identity.


### Key Concepts

#### KDC (Key Distribution Center)

- Trusted server holding user/computer password hashes.
- **AS** (Authentication Server): Issues TGT (proof of login).
- **TGS** (Ticket Granting Server): Issues service tickets (access to resource).


#### TGT (Ticket-Granting Ticket)

- Proof user authenticated to domain.
- Obtained after password entry; cached locally.
- Expires (default 10 hours).


#### Service Ticket

- Proof user authorized for specific service (file share, email, etc.).
- Obtained from TGS; sent to service.
- Service validates ticket; grants access.


### Kerberos Flow (Simplified)

```
USER (john@ACME.COM)
    ↓ [Step 1: Send username/password hash]
KDC/AS (Authentication Server)
    ↓ [Step 2: Verify hash; send TGT (encrypted with KDC secret)]
    ↓
USER (caches TGT)
    ↓ [Step 3: User wants to access file server; sends TGT to TGS]
KDC/TGS (Ticket Granting Server)
    ↓ [Step 4: Verify TGT; send service ticket (encrypted with file server secret)]
    ↓
FILE SERVER
    ↓ [Step 5: User presents service ticket; server decrypts; grants access]
    ↓
USER accesses files.
```


### Kerberos Attacks (SOC L1 Awareness)

#### Pass-the-Ticket (PTT)

- **Attack**: Attacker steals TGT from one user's machine; uses it to impersonate that user.
- **How**: Tools like Mimikatz extract TGT; apply to attacker's process.
- **Detection**: Unusual ticket usage (different source IP).


#### Golden Ticket

- **Attack**: Attacker obtains KDC secret; forges TGT for any user.
- **Impact**: Permanent domain access (even after password reset).
- **Detection**: Very hard; requires log analysis of ticket inconsistencies.


#### Kerberoasting

- **Attack**: Attacker requests service ticket for service account; cracks password offline.
- **How**: Service account passwords often weak (set once, forgotten).
- **Detection**: Monitor for requests for unusual service tickets.


### Defense

- **Enforce Strong Passwords**: Service accounts too.
- **Regular Audits**: Find orphaned/unused accounts.
- **Monitor Ticket Usage**: Alert on pass-the-ticket patterns.
- **Privilege Access Management (PAM)**: Restrict who can access sensitive accounts.

---

## OAuth 2.0 (Authorization, not Authentication)

### Purpose

- **Use**: Allow 3rd-party apps to access user data (without sharing password).
- **Example**: Login with Google; Google authorizes app to access your calendar.


### Flow

```
USER
  ↓ [Clicks "Login with Google"]
APP (3rd-party)
  ↓ [Redirects user to Google]
GOOGLE (Authorization Server)
  ↓ [User enters Google password]
  ↓ [User authorizes app to access calendar]
  ↓ [Google sends authorization code back to app]
GOOGLE → APP (authorization code)
  ↓
APP [Server-side: exchanges code for access token]
GOOGLE → APP (access token)
  ↓
APP [Uses token to access user's calendar on behalf of user]
GOOGLE (grants calendar access to app)
  ↓
USER (logged in; calendar shared with app)
```


### Security Notes

- **Not Authentication**: OAuth doesn't verify user identity (doesn't replace password).
- **Phishing Risk**: Attacker redirects user to fake Google login; steals OAuth code.
- **Token Leakage**: If app's access token stolen, attacker accesses user's Google data.

---

---

[Index](../README.md) | [Previous: Incident Response & SOC Operations](09-incident-response-soc-operations.md) | [Next: Active Directory Deep-Dive](11-active-directory-deep-dive.md)

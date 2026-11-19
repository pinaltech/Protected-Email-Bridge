# Local Encrypted-Mail Gateway — Functional Specification

```
Document:   Functional Specification (Informational)
Status:     Draft
Category:   Protocol / Product Requirements
```

## Abstract

This document specifies the externally observable behaviour of a **Local
Encrypted-Mail Gateway** (hereafter "the Gateway"). The Gateway runs on an end
user's machine and lets standard mail clients reach an end-to-end encrypted
mail service. Toward the mail client it acts as an IMAP4rev1 server and an
SMTP submission server, both bound to the loopback interface. Toward the remote
service it acts as an authenticated HTTPS/JSON API client. All OpenPGP
encryption, decryption, signing and key handling happen locally.

The document covers:

* the remote API transport, its endpoints and payloads,
* the SRP-based authentication protocol and its second factors,
* key derivation, key unlocking, and the OpenPGP message lifecycle,
* the IMAP server: capabilities, mailbox model, flag semantics, and how each
  command maps onto API operations,
* initial synchronisation and incremental event processing,
* the SMTP server: extensions, the submission pipeline, recipient
  encryption-preference resolution, and error reporting,
* the mobile push-notification client profile: device-key generation and
  storage, device registration, the end-to-end encrypted push envelope and
  its decryption, notification payload types, notification quick actions,
  and notification-originated synchronisation (§14).

## Table of Contents

1.  Introduction
2.  Conventions and Terminology
3.  Deployment Constants and Local Artifacts
4.  Remote API Transport
5.  Authentication and Session Management
6.  Keys, Passphrases and Key Unlocking
7.  Remote Data Model
8.  Remote API Endpoint Reference
9.  OpenPGP Lifecycle
10. Local Credentials, Accounts and Address Modes
11. IMAP Server
12. Synchronisation and Event Processing
13. SMTP Submission Server
14. Mobile Push-Notification Client Profile
15. Security Considerations
16. Appendix A — Message Fingerprint Algorithm
17. Appendix B — Default Values and Limits
18. Appendix C — Status and Error Code Tables

---

## 1. Introduction

### 1.1 Purpose

The remote mail service stores all message bodies and attachments encrypted
with OpenPGP keys that only the user can unlock. Standard mail clients cannot
use such a service directly. The Gateway closes this gap. It:

1. authenticates to the service on the user's behalf and unlocks the user's
   private keys locally,
2. downloads, decrypts and rebuilds every message as a standard RFC 5322 /
   MIME literal,
3. serves those literals over IMAP and maps IMAP mutations (flags, copies,
   moves, deletions, appends, mailbox management) onto service API calls,
4. accepts outgoing mail over SMTP, decides per recipient how the message must
   be encrypted and/or signed, and submits it through the service API.

### 1.2 Scope

In scope: every behaviour a compatible re-implementation needs, whether a
client or the remote service can observe it.

Out of scope: user-interface flows, update mechanisms, crash reporting,
telemetry semantics, OS keychain integration, and the internal layout of local
storage. These appear only where they affect protocol behaviour.

### 1.3 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as
described in RFC 2119 and RFC 8174.

---

## 2. Conventions and Terminology

| Term | Meaning |
|---|---|
| **Gateway** | The local software specified here. |
| **Service** | The remote encrypted-mail provider, reached through its HTTPS API. |
| **Client** | Any IMAP or SMTP mail user agent that connects to the Gateway. |
| **Account** | One authenticated Service user. The Gateway MAY serve several Accounts at once. |
| **Address** | One email address owned by an Account. An Account has one or more Addresses, each with its own key ring. |
| **Label** | A Service-side tag. Labels have one of four types (§7.3). Folders, user labels and system mailboxes are all Labels. |
| **Mailbox** | An IMAP mailbox the Gateway exposes. Most Mailboxes correspond to exactly one Label. |
| **Literal** | A complete RFC 5322 message octet stream as served over IMAP. |
| **User key ring** | The Account-level OpenPGP private keys. |
| **Address key ring** | The OpenPGP private keys of one Address. |
| **Salted key passphrase** | The secret derived from the user's mailbox password that unlocks the User key ring (§6.2). |
| **Gateway password** | A random secret the Gateway generates. Clients use it, instead of the Service password, to authenticate over IMAP and SMTP (§10.1). |
| **Event** | One entry in the Service's change log, used for incremental sync (§12.2). |
| **Notification Client** | A mobile mail application that receives end-to-end encrypted push notifications from the Service (§14). |
| **Push Provider** | The operating-system vendor's push relay (for example, a mobile cloud-messaging service). It carries notifications from the Service to the device but MUST NOT be able to read them. |
| **Device token** | The opaque address the Push Provider issues to one application installation. |
| **Device key** | A device-local OpenPGP key pair. Its public half is registered with the Service and used to encrypt push notifications to the device (§14.2). |
| **LE(x)** | The fixed-length little-endian byte encoding of integer *x*. |
| **B64** | Standard Base64 (RFC 4648 §4) with padding, unless stated otherwise. |
| **B64URL-NP** | URL-safe Base64 (RFC 4648 §5) without padding. |

All JSON property names in this document are case-sensitive and appear exactly
as they go on the wire. Unless stated otherwise, JSON booleans are encoded as
the integers `0` (false) and `1` (true). This document calls that encoding
**IntBool**.

---

## 3. Deployment Constants and Local Artifacts

### 3.1 Deployment Constants

Several values are fixed by the Service operator and MUST be configured for
interoperability. This specification refers to them by symbolic name and does
not reproduce their values.

| Symbol | Description |
|---|---|
| `API_BASE_URL` | Absolute HTTPS base URL of the Service API. All endpoint paths in §8 are relative to it. |
| `MODULUS_SIGNING_KEY` | An armored OpenPGP public key (Ed25519 primary key with a Curve25519 encryption subkey). The Service uses it to clear-sign SRP moduli (§5.1.2). The Gateway MUST pin it. |
| `SRP_SALT_SUFFIX` | A fixed 6-octet ASCII string appended to the decoded SRP salt in password-hash versions 3 and 4 (§5.1.3). |
| `REFRESH_REDIRECT_URI` | A fixed absolute URI sent in the token-refresh request (§5.5.1). |
| `APP_PRODUCT_TOKEN` | Product identifier embedded in the application-version header (§4.2). |
| `API_TLS_PINS` | OPTIONAL set of SubjectPublicKeyInfo SHA-256 pins for the API endpoints and their proxies (§4.10). |

### 3.2 Local Artifacts

The following identifiers are visible only between the Gateway and its Clients.
The Service never interprets them. An implementation MAY choose any values,
but MUST use them consistently. Recommended neutral names are shown.

| Symbol | Recommended value | Purpose |
|---|---|---|
| `HDR_INTERNAL_ID` | `X-Gw-Internal-Id` | Carries the Service message ID in served literals (§11.8.2). |
| `HDR_EXTERNAL_ID` | `X-Gw-External-Id` | Carries the original RFC 5322 Message-ID (§11.8.2). |
| `HDR_SERVER_DATE` | `X-Gw-Date` | Carries the Service's receive time (§11.8.2). |
| `HDR_LOCAL_ID` | `X-Gw-Local-Id` | Carries the IMAP server's local message identity (§11.10). |
| `INTERNAL_ID_DOMAIN` | `internal.invalid` | Pseudo-domain used to synthesise Message-IDs and References from Service message IDs (§11.8.2, §13.6). |
| `RECOVERY_MAILBOX` | `Recovered Messages` | Mailbox that holds APPENDed messages the Service rejected (§11.11). |

---

## 4. Remote API Transport

### 4.1 General

1. Every request MUST use HTTPS to `API_BASE_URL` + *path*.
2. Request and response bodies are JSON (`application/json`), except where
   §8 specifies `multipart/form-data` or raw binary.
3. A successful JSON response carries `"Code": 1000` (single-item success) or
   `"Code": 1001` (multi-status: per-item results appear in a `Responses`
   array). HTTP status 200 accompanies success.
4. Any HTTP status ≥ 400 is an error. The body SHOULD be decoded as an
   **API Error object** (§4.4).

### 4.2 Request Headers

| Header | When | Value |
|---|---|---|
| `x-pm-appversion` | Every request | `<platform>-<APP_PRODUCT_TOKEN>@<semver>`. `<platform>` is one of `linux`, `macos`, `windows`: the platform the Client runs on, unless the embedding application names another. The Service rejects missing or unsupported values with error code 5001 or 5003. |
| `User-Agent` | Every request | `<client>/<version> (<os>)`. `<client>/<version>` is the name and version of the most recent mail client seen (from the IMAP `ID` command, §11.4.3), or `NoClient/0.0.1` if none has been seen. Spaces in the client version are folded as `A (B)` → `A-B`. When an SMTP session authenticates while the agent is still the default, `UnknownClient/0.0.1` is substituted. Identification strings from note-taking agents MUST be ignored. |
| `x-pm-uid` | Every authenticated request | The session UID (§5.1.6). |
| `Authorization` | Every authenticated request | `Bearer <AccessToken>`. |
| `x-pm-human-verification-token` | When retrying after a human-verification challenge (§5.3) | The verification token. |
| `x-pm-human-verification-token-type` | Same as above | Comma-separated list of verification methods. |
| `X-HTTP-Method-Override` | Message listing (§8.6) | `GET`. Sent on a `POST` whose body carries the filter. |
| `Priority` | Metrics submission (§8.12) | `u=6`. |

### 4.3 Clock Synchronisation

On every response, the Gateway SHOULD parse the HTTP `Date` header (RFC 1123
format) and use it as the reference "now" for OpenPGP operations: signature
creation time, and key and signature validity checks. This tolerates local
clock skew.

### 4.4 API Error Object

```json
{
  "Code":    <integer>,
  "Error":   "<human readable message>",
  "Details": <any JSON value, optional>
}
```

The HTTP status code is carried alongside. If the body cannot be decoded, the
Gateway MUST synthesise an error with `Code = 0` and the HTTP status text as
the message.

Error codes with defined Gateway behaviour:

| Code | Meaning | Gateway behaviour |
|---|---|---|
| 1000 | Success | — |
| 1001 | Multi-status | Inspect each `Responses[i].Response.Code`. |
| 2001 | Invalid value / validation failed | During draft creation (HTTP 422): report "malformed message" (§13.15). |
| 2002 | Invalid list of recipients | During draft creation (HTTP 422): report it. |
| 2024 | Message too large | During draft creation (HTTP 422): report it. |
| 5001 | App version missing | Fatal configuration error. |
| 5003 | App version bad | Notify the user that an upgrade is mandatory. |
| 6003 | Username invalid | Login failure. |
| 8002 | Wrong password | Login failure. |
| 9001 | Human verification required | §5.3. |
| 10004 | Paid plan required | Login failure. |
| 10013 | Refresh token invalid | Clear the stored session. The Account becomes signed out. |
| 12087 | Invalid human-verification token | Login failure. |
| 33102 | Address does not exist | Recipient key lookup (HTTP 422): report the unknown recipient (§13.15). |

### 4.5 Transport-Level Retry

1. On HTTP 429 or 503, the request MUST be retried after `Retry-After`
   seconds. If the header is absent or not an integer, wait 10 s. Add a uniform
   random 0–9 s in both cases.
2. On a connection failure (no HTTP response) or a mid-stream network error,
   the request SHOULD be retried.
3. Retry at most **3** times. No single wait may exceed **60 s**.

### 4.6 Application-Level Back-off

Long-running loops (event polling §12.2, sync metadata/download §12.1, the
initial latest-event fetch) MUST wrap Service calls in an additional back-off.
On any error whose HTTP status is 429 or ≥ 500, wait the next value in the
sequence **20, 40, 80, 160, 300, 600 s** (staying at 600 s thereafter), plus a
uniform random 0–9 s, then retry indefinitely. The sequence resets at the start
of each logical operation.

### 4.7 Access-Token Refresh

1. If an authenticated request returns HTTP **401**, the Gateway MUST perform a
   token refresh (§5.5.1), then retry the original request exactly once.
2. If the refresh returns HTTP **400** or **422**, the session is dead. The
   Gateway MUST fire a "deauthenticated" condition **once per session**: it
   stops the Account's services and marks the Account signed out.
3. If the refresh returns HTTP 409, 429, 500 or 503, the failure is transient.
   The original operation fails, and the session is kept.
4. After a successful refresh, the Gateway MUST persist the new
   `RefreshToken`, and the new `AccessToken` if it stores one.

### 4.8 Connectivity State

The Gateway keeps a binary connectivity state (*up*/*down*). Any HTTP response
sets it to *up*. A transport failure that is not a caller cancellation sets it
to *down*. While it is *down*, event polling (§12.2) MUST pause; it resumes on
the transition back to *up*. `GET /tests/ping` MAY be used as a probe: any HTTP
response, including an error status, counts as reachable.

### 4.9 Paging Conventions

* The maximum page size for list endpoints is **150**.
* Bulk message actions (§8.7) MUST be split into chunks of at most 150 IDs.
* The message-ID enumeration endpoint returns at most **1000** IDs per call.

### 4.10 Certificate Pinning (OPTIONAL)

The Gateway SHOULD validate that the API server's certificate chain contains a
public key matching one of `API_TLS_PINS`. On a mismatch it MAY report the
failure to the Service and SHOULD refuse the connection.

---

## 5. Authentication and Session Management

### 5.1 SRP Login

The Service authenticates the password with a variant of SRP-6a. Every
big-integer value is 2048 bits (L = 256 octets), serialised **little-endian**,
zero-padded to L octets.

#### 5.1.1 Step 1 — Info Request

`POST /auth/v4/info`

```json
{ "Username": "<username or email>" }
```

Response:

```json
{
  "Code": 1000,
  "Version": 4,
  "Modulus": "<clear-signed armored text>",
  "ServerEphemeral": "<B64>",
  "Salt": "<B64>",
  "SRPSession": "<opaque>",
  "2FA": { "Enabled": 0, "FIDO2": { "AuthenticationOptions": null, "RegisteredKeys": [] } }
}
```

#### 5.1.2 Modulus Verification

1. `Modulus` is an OpenPGP cleartext-signed message (RFC 4880 §7).
2. The Gateway MUST check that no data follows the signature block. If any
   does, it MUST abort.
3. The Gateway MUST verify the detached signature over the cleartext with
   `MODULUS_SIGNING_KEY`. If verification fails, it MUST abort.
4. The cleartext is B64. Decoding it yields the modulus octets **N̂**
   (256 octets). Interpreted little-endian, they give the integer **N**.

#### 5.1.3 Password Hashing

Let *P* be the password octets, *U* the username, *s* the B64-decoded `Salt`,
and **N̂** the modulus octets.

Define the **expand hash**:

```
H(x) = SHA-512(x ‖ 0x00) ‖ SHA-512(x ‖ 0x01) ‖ SHA-512(x ‖ 0x02) ‖ SHA-512(x ‖ 0x03)      (256 octets)
```

Define **bcrypt(P, S)** as the full 60-character modular-crypt output
`$2y$10$<22-char salt><31-char hash>`, with cost 10. *S* is a radix-64 salt
string in the bcrypt alphabet `./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`,
unpadded.

| Version | Hashed password *x̂* (256 octets) |
|---|---|
| 3, 4 | `H( bcrypt(P, R64(s ‖ SRP_SALT_SUFFIX)) ‖ N̂ )`, where R64 is unpadded radix-64 encoding in the bcrypt alphabet. *s* is 10 octets, so the input is 16 octets and the salt 22 characters. |
| 2 | Same as version 1, with *U* first stripped of every `-`, `.`, `_` and lower-cased. |
| 1 | `H( bcrypt(P, hex(MD5(lower(U)))) ‖ N̂ )`. The salt string is the 32-character lowercase hex digest; bcrypt consumes its leading 22 characters. |
| 0 | Let *P′* = B64(SHA-512(lower(U) ‖ P)) (88 characters). Apply version 1 with password *P′* and username *U*. |

Versions other than 0–4 MUST be rejected. The salt is only decoded for
versions ≥ 3.

#### 5.1.4 Parameter Validation

Before computing proofs, the Gateway MUST verify all of the following, and
abort if any check fails:

* the generator *g* = 2;
* `bitlen(N)` = 2048;
* *N* ≡ 3 (mod 8): bits 0 and 1 set, bit 2 clear;
* (N−1)/2 is probably prime (≥ 10 Miller–Rabin rounds);
* g^((N−1)/2) mod N = N−1;
* 1 < B < N−1, where B is the little-endian integer of the decoded
  `ServerEphemeral`.

#### 5.1.5 Proof Computation

```
k  = int_le( H( LE(g) ‖ LE(N) ) ) mod N          ; MUST satisfy 1 < k < N−1
x  = int_le( x̂ )

repeat:
    a  ← uniform random in [0, N−1), accepted only if 4096 < a < N−1
    A  = g^a mod N                                ; Â = LE(A) (256 octets)
    u  = int_le( H( Â ‖ B̂ ) )                     ; B̂ = decoded ServerEphemeral octets
until u ≠ 0

base     = (B − k · g^x) mod N
exponent = (u · x + a) mod (N − 1)
S        = base^exponent mod N                    ; Ŝ = LE(S)

M1 = H( Â ‖ B̂ ‖ Ŝ )                              ; client proof
M2 = H( Â ‖ M1 ‖ Ŝ )                             ; expected server proof
```

Constant-time big-integer arithmetic is RECOMMENDED for every operation that
involves *a*, *x* or *S*.

#### 5.1.6 Step 2 — Auth Request

`POST /auth/v4`. If a human-verification token is available (§5.3), its
headers are added.

```json
{
  "Username": "<same as step 1>",
  "ClientEphemeral": "<B64(Â)>",
  "ClientProof": "<B64(M1)>",
  "SRPSession": "<from step 1>",
  "FIDO2": { "AuthenticationOptions": null, "ClientData": "", "AuthenticatorData": "", "Signature": "", "CredentialID": null }
}
```

(The `FIDO2` object MAY be sent empty, as above. `TwoFactorCode` is omitted.)

Response:

```json
{
  "Code": 1000,
  "UserID": "<id>",
  "UID": "<session uid>",
  "AccessToken": "<token>",
  "RefreshToken": "<token>",
  "ServerProof": "<B64>",
  "Scope": "<space separated scopes>",
  "2FA": { "Enabled": <0|1|2|3>, "FIDO2": { "AuthenticationOptions": {...}, "RegisteredKeys": [...] } },
  "PasswordMode": <1|2>
}
```

The Gateway MUST compare B64-decoded `ServerProof` with M2. On a mismatch it
MUST abort and treat the server as unauthenticated.

* `2FA.Enabled` is a bitmask: 1 = TOTP, 2 = FIDO2, 3 = both.
* `PasswordMode`: 1 = single password (the login password is also the key
  password); 2 = two passwords (a separate mailbox password unlocks the keys).

#### 5.1.7 Duplicate Login

If the authenticated `UserID` already belongs to a connected Account in this
Gateway, the Gateway MUST revoke the new session (§5.5.2) and report "already
logged in".

### 5.2 Second Factor

`POST /auth/v4/2fa` (authenticated with the new session).

#### 5.2.1 TOTP

```json
{ "TwoFactorCode": "123456", "FIDO2": { ...empty... } }
```

#### 5.2.2 FIDO2 / WebAuthn Assertion

1. Read `2FA.FIDO2.AuthenticationOptions.publicKey` from the auth response:
   * `rpId` — string;
   * `challenge` — JSON array of integers 0–255;
   * `allowCredentials` — array of objects whose `id` is an integer array.
     The array MUST NOT be empty.
2. Build the client data JSON object
   `{"challenge": B64URL-NP(challenge), "origin": "https://" + rpId, "type": "webauthn.get"}`.
   Serialise it to UTF-8 JSON.
3. Ask the authenticator for an assertion with:
   relying party = `rpId`; client-data hash = SHA-256(client data JSON);
   allowed credentials = the decoded `id` byte strings;
   user presence required; PIN if the device supports one.
   With multiple devices attached, the Gateway SHOULD refuse and ask the user
   to keep one.
4. Decode the CBOR byte string returned as authenticator data to get the raw
   authenticator data.
5. Submit:

```json
{
  "FIDO2": {
    "AuthenticationOptions": <echo of the object received>,
    "ClientData":        "<B64(client data JSON)>",
    "AuthenticatorData": "<B64(raw authenticator data)>",
    "Signature":         "<B64(assertion signature)>",
    "CredentialID":      [<integers of the credential id used>]
  }
}
```

### 5.3 Human Verification

If a login-phase request (`/auth/v4`, `/core/v4/users`) fails with code
**9001**, `Details` contains:

```json
{ "HumanVerificationMethods": ["captcha", ...], "HumanVerificationToken": "<token>" }
```

The Gateway MUST surface the challenge to the user. Once it is solved, the
Gateway repeats the full login (from §5.1.1). On the auth request and the
first user fetch, it adds `x-pm-human-verification-token: <token>` and
`x-pm-human-verification-token-type: <methods joined by ",">`.

### 5.4 Completing Login

1. Determine the key password: the login password if `PasswordMode` = 1;
   otherwise prompt for the mailbox password.
2. `GET /core/v4/users` → User (§7.1).
3. `GET /core/v4/keys/salts` → salts (§6.1).
4. Derive the salted key passphrase for the **primary** user key (§6.2).
5. Unlock the User key ring (§6.3). If no key unlocks, report "failed to
   unlock" and keep the session open so the user can re-enter the mailbox
   password.
6. On any other failure after step 2, revoke the session (§5.5.2).
7. On success, persist: UserID, username, primary email, session UID,
   RefreshToken, salted key passphrase, and a Gateway password (§10.1).

### 5.5 Session Lifecycle

#### 5.5.1 Refresh

`POST /auth/v4/refresh` (unauthenticated):

```json
{
  "UID": "<session uid>",
  "RefreshToken": "<token>",
  "ResponseType": "token",
  "GrantType": "refresh_token",
  "RedirectURI": "<REFRESH_REDIRECT_URI>",
  "State": "<random opaque string, 32 random octets>",
  "AccessToken": "<current access token, omitted if unknown>"
}
```

The response has the same shape as §5.1.6.

At start-up, a stored Account MUST be resumed with a refresh. If that fails
with code 10013, the stored UID and RefreshToken MUST be cleared.

#### 5.5.2 Logout / Revocation

`DELETE /auth/v4` (authenticated) revokes the current session. The Gateway
MUST call it on explicit logout, and on login failures after step 2 of §5.4.

#### 5.5.3 Other Session Endpoints (OPTIONAL)

* `GET /auth/v4/sessions` → `{"Sessions":[{"UID","CreateTime","ClientID","MemberID","Revocable","LocalizedClientName"}]}`
* `DELETE /auth/v4/sessions/{uid}` revokes one session.
* `DELETE /auth/v4/sessions` revokes all sessions.
* `GET /auth/v4/modulus` → `{"Modulus","ModulusID"}`.

---

## 6. Keys, Passphrases and Key Unlocking

### 6.1 Key Salts

`GET /core/v4/keys/salts`:

```json
{ "KeySalts": [ { "ID": "<key id>", "KeySalt": "<B64, 16 octets>" } ] }
```

### 6.2 Salted Key Passphrase

For a key with ID *id*:

1. Find the salt entry with matching `ID`. If there is none, fail.
2. Compute `bcrypt(keyPassword, R64(B64decode(KeySalt)))` (cost 10, `$2y$`).
3. The salted key passphrase is the **last 31 octets** of the 60-character
   result (the hash component).

The Gateway derives it for the user's **primary** key (the key with
`Primary = 1`). It MUST store the result, never the plaintext password.

### 6.3 Unlocking Key Rings

A Key object (§7.1) carries an armored, passphrase-protected private key.

**User key ring.** Iterate keys with `Active = 1`. Unlock each with the
salted key passphrase. Then verify that each private key matches its public
key; discard keys that fail. At least one key MUST unlock.

**Address key ring.** Iterate keys with `Active = 1`. For each:

* If both `Token` and `Signature` are non-empty:
  decrypt `Token` (an armored OpenPGP message) with the User key ring;
  verify `Signature` (an armored detached signature) over the decrypted token
  octets with the User key ring;
  the passphrase is the decrypted token octets.
* Otherwise: the passphrase is the salted key passphrase.

Unlock and integrity-check as for user keys. An address with no unlockable key
is unusable: it is skipped for receiving, and sending from it fails.

**First key.** Where this document says "the address's first key", it means
the first unlocked key in the Address key ring, in Service order. That key is
used for every encryption-to-self and every signature the Gateway produces.

Private key material SHOULD be wiped from memory as soon as each operation
completes.

### 6.4 Public Key Lookup

`GET /core/v4/keys?Email=<address>`:

```json
{
  "Code": 1000,
  "Keys": [ { "Flags": <bitmask>, "PublicKey": "<armored>" } ],
  "RecipientType": <1|2>
}
```

* `RecipientType`: 1 = internal (hosted by the Service), 2 = external.
* `Flags` bits: 1 = trusted (not compromised; signatures may be trusted);
  2 = active (may be encrypted to).
* For external recipients, `Keys` may hold keys the Service discovered through
  Web Key Directory. Keys that cannot be parsed MUST be ignored.
* HTTP 422 with code 33102 means the address does not exist.

---

## 7. Remote Data Model

Field lists name the JSON properties. Types: `S` string, `I` integer,
`B` IntBool, `[]T` array of T.

### 7.1 User and Key

**User** (`{"User": {...}}`):
`ID S`, `Name S`, `DisplayName S`, `Email S`, `Keys []Key`, `UsedSpace I`,
`MaxSpace I`, `MaxUpload I`, `Credit I`, `Currency S`,
`ProductUsedSpace {Calendar,Contact,Drive,Mail,Pass: I}`.

**Key**:
`ID S`, `PrivateKey S` (armored), `Token S`, `Signature S`, `Primary B`,
`Active B`, `Flags I` (bits as in §6.4).

### 7.2 Address

`GET /core/v4/addresses` → `{"Addresses":[Address]}`.

**Address**:
`ID S`, `Email S`, `Send B`, `Receive B`, `Status I`, `Type I`, `Order I`,
`DisplayName S`, `Keys []Key`.

| `Status` | Meaning |
|---|---|
| 0 | Disabled |
| 1 | Enabled |
| 2 | Deleting |

| `Type` | Meaning |
|---|---|
| 1 | Original |
| 2 | Alias |
| 3 | Custom domain |
| 4 | Premium |
| 5 | External |

Addresses MUST be sorted by ascending `Order`. The **primary address** is the
first one after sorting. An external address with `Send = 1` is a
"bring-your-own-email" address that can send. An external address with
`Send = 0` can neither send nor be an import target.

**Email comparison.** Comparisons are case-insensitive. Before comparing an
email with an owned address, a `+tag` sub-address suffix in the local part
MUST be stripped: `user+tag@d` ≡ `user@d`.

### 7.3 Label

`GET /core/v4/labels?Type=<n>` → `{"Labels":[Label]}`. The Gateway queries
types 4, 3 and 1.

**Label**:
`ID S`, `ParentID S`, `Name S`, `Path S`, `Color S`, `Type I`.
`Path` is the full slash-separated path, e.g. `"Work/2024"`.

| `Type` | Meaning |
|---|---|
| 1 | Label (tag; flat; non-exclusive) |
| 2 | Contact group (ignored by the Gateway) |
| 3 | Folder (hierarchical; exclusive location) |
| 4 | System |

**Reserved system label IDs:**

| ID | Name | Exposed over IMAP |
|---|---|---|
| `0` | Inbox | yes |
| `1` | All Drafts | no |
| `2` | All Sent | no |
| `3` | Trash | yes |
| `4` | Spam | yes |
| `5` | All Mail | yes (visibility configurable) |
| `6` | Archive | yes |
| `7` | Sent | yes |
| `8` | Drafts | yes |
| `9` | Outbox | no |
| `10` | Starred | yes |
| `12` | All Scheduled | yes (as `Scheduled`, hidden when empty) |

A Label is **wanted** if it has type 1 or 3, or if it has type 4 and its ID is
in the "yes" rows above. Only wanted labels become Mailboxes, and only wanted
label IDs count when computing a message's Mailbox membership.

### 7.4 Message

**MessageMetadata**:

| Field | Type | Notes |
|---|---|---|
| `ID` | S | |
| `AddressID` | S | The owning Address; its keys decrypt the message. |
| `LabelIDs` | []S | |
| `ExternalID` | S | RFC 5322 Message-ID without angle brackets. |
| `Subject` | S | |
| `Sender` | Addr | |
| `ToList`, `CCList`, `BCCList`, `ReplyTos` | []Addr | |
| `Flags` | I | Bitmask, see below. |
| `Time` | I | Unix seconds. |
| `Size` | I | Octets. |
| `Unread` | B | |
| `IsReplied`, `IsRepliedAll`, `IsForwarded` | B | |
| `NumAttachments` | I | |

**Addr** is `{"Name": S, "Address": S}`.

**Message** (full) = MessageMetadata plus:

* `Header S` — raw header block;
* `ParsedHeaders` — object: field name → string, or array of strings, with
  key order significant;
* `Body S` — armored OpenPGP message;
* `MIMEType S` — one of `text/plain`, `text/html`, `multipart/mixed`;
* `Attachments []Attachment`.

**Attachment**:
`ID S`, `Name S`, `Size I`, `MIMEType S`, `Disposition S` (`inline` |
`attachment`), `Headers` (same encoding as `ParsedHeaders`), `KeyPackets S`
(B64 of binary PKESK packets), `Signature S`.

**ParsedHeaders encoding.** The JSON key order is the original header order.
A string value is one field instance; an array value is several instances of
that field, in order. Any other value type is an error.

**Message flag bits:**

| Bit | Name | | Bit | Name |
|---|---|---|---|---|
| 0 | Received | | 14 | Receipt |
| 1 | Sent | | 16 | Receipt request |
| 2 | Internal | | 17 | Public key attached |
| 3 | End-to-end | | 18 | Signed |
| 4 | Auto | | 19 | Unsubscribed |
| 5 | Replied | | 20 | Scheduled send |
| 6 | Replied-all | | 21 | Alias |
| 7 | Forwarded | | 23 | DMARC pass |
| 8 | Auto-replied | | 24 | SPF fail |
| 9 | Imported | | 25 | DKIM fail |
| 10 | Opened | | 26 | DMARC fail |
| 11 | Receipt sent | | 27 | Ham (manual) |
| 12 | Notified | | 28 | Spam (auto) |
| 13 | Touched | | 29 | Spam (manual) |
| | | | 30 | Phishing (auto) |
| | | | 31 | Phishing (manual) |

Derived predicates:

* **Draft** ⇔ neither Received (bit 0) nor Sent (bit 1) is set.
* **Seen** ⇔ `Unread = 0`.
* **Starred** ⇔ `LabelIDs` contains `"10"`.

### 7.5 Mail Settings

`GET /mail/v4/settings` → `{"MailSettings": {...}}`:
`DisplayName S`, `Signature S`, `DraftMIMEType S`, `AttachPublicKey B`,
`Sign I` (0 = don't sign external mail by default, 1 = sign),
`PGPScheme I` (an encryption scheme value, §13.12).

### 7.6 Contacts

**ContactEmail**: `ID`, `Name`, `Email`, `Type []S`, `ContactID`, `LabelIDs`.

**Contact**: `ID`, `Name`, `UID`, `Size`, `CreateTime`, `ModifyTime`,
`ContactEmails []ContactEmail`, `LabelIDs`, `Cards []Card`.

**Card**: `Type I`, `Data S`, `Signature S`.

`Type` is a bitmask: 0 = clear, bit 0 (1) = encrypted, bit 1 (2) = signed.
For an encrypted card, `Data` is an armored OpenPGP message; decrypt it with
the User key ring. For a signed card, `Signature` is an armored detached
signature over the vCard text; verify it with the User key ring.

**Per-recipient encryption preferences** are stored in vCard 4.0 (RFC 6350)
**groups**. A group is identified by the group prefix of the `EMAIL` property
whose value equals the recipient address. Recognised properties in that group:

| Property | Values | Meaning |
|---|---|---|
| `X-PM-SCHEME` | `pgp-mime` \| `pgp-inline` | Preferred PGP scheme. |
| `X-PM-MIMETYPE` | `text/plain` \| `text/html` \| … | Preferred body format. |
| `X-PM-SIGN` | `true` \| `false` | Sign messages to this contact. |
| `X-PM-ENCRYPT` | `true` \| `false` | Encrypt messages to this contact. |
| `X-PM-ENCRYPT-UNTRUSTED` | `true` \| `false` | Encrypt with server-discovered (WKD) keys. Default **true** when absent. |
| `KEY` | `data:…;base64,<B64>` | A pinned public key. Everything after the first comma is B64 of a binary (unarmored) key. May repeat. |

The Gateway reads preferences **only from the signed card** (type 2). If the
card is missing, its signature fails to verify, or no group matches, the
contact has no preferences.

### 7.7 Events

**Event**:

| Field | Type | Notes |
|---|---|---|
| `EventID` | S | |
| `Refresh` | I | Bitmask: bit 0 (1) = mail refresh required; 255 = refresh everything. |
| `User` | User | Optional. |
| `UserSettings` | object | Optional. `{Telemetry: I, CrashReports: I}`. |
| `MailSettings` | MailSettings | Optional. |
| `Messages` | []`{ID, Action, Message: MessageMetadata}` | |
| `Labels` | []`{ID, Action, Label}` | |
| `Addresses` | []`{ID, Action, Address}` | |
| `Notifications` | []`{ID, UID, UserID, Type, Time, Payload: {Title, Subtitle, Body}}` | `Type` is text (e.g. `modal`) |
| `UsedSpace` | I | Optional. |
| `More` | B | 1 if further events are immediately available. |

`Action` values: 0 = delete, 1 = create, 2 = update, 3 = update flags.

### 7.8 Undo Token

`{"Token": S, "ValidUntil": I (unix seconds)}`.

---

## 8. Remote API Endpoint Reference

All endpoints except those in §5.1/§5.5.1 and the explicitly unauthenticated
ones require the authenticated headers of §4.2.

### 8.1 Summary

| Method | Path | Purpose | § |
|---|---|---|---|
| POST | `/auth/v4/info` | SRP parameters | 5.1.1 |
| POST | `/auth/v4` | SRP proof / login | 5.1.6 |
| POST | `/auth/v4/2fa` | Second factor | 5.2 |
| POST | `/auth/v4/refresh` | Refresh tokens | 5.5.1 |
| DELETE | `/auth/v4` | Logout | 5.5.2 |
| GET | `/core/v4/users` | Current user | 7.1 |
| GET | `/core/v4/keys/salts` | Key salts | 6.1 |
| GET | `/core/v4/keys?Email=` | Recipient public keys | 6.4 |
| GET | `/core/v4/addresses` | Addresses | 7.2 |
| GET | `/core/v4/addresses/{id}` | One address | 7.2 |
| GET | `/core/v4/labels?Type=` | Labels by type | 7.3 |
| POST | `/core/v4/labels` | Create label | 8.4 |
| PUT | `/core/v4/labels/{id}` | Update label | 8.4 |
| DELETE | `/core/v4/labels/{id}` | Delete label | 8.4 |
| GET | `/core/v4/events/latest` | Latest event ID | 8.5 |
| GET | `/core/v4/events/{id}` | Events after ID | 8.5 |
| POST (GET override) | `/mail/v4/messages` | Count / list metadata | 8.6 |
| GET | `/mail/v4/messages/{id}` | Full message | 8.6 |
| GET | `/mail/v4/messages/ids` | Enumerate IDs | 8.6 |
| GET | `/mail/v4/messages/count` | Per-label counts | 8.6 |
| PUT | `/mail/v4/messages/read` | Mark read | 8.7 |
| PUT | `/mail/v4/messages/unread` | Mark unread | 8.7 |
| PUT | `/mail/v4/messages/forward` | Mark forwarded | 8.7 |
| PUT | `/mail/v4/messages/unforward` | Unmark forwarded | 8.7 |
| PUT | `/mail/v4/messages/label` | Add label | 8.7 |
| PUT | `/mail/v4/messages/unlabel` | Remove label | 8.7 |
| PUT | `/mail/v4/messages/delete` | Permanently delete | 8.7 |
| POST | `/mail/v4/undoactions` | Undo label action | 8.7 |
| POST | `/mail/v4/messages` | Create draft | 8.8 |
| PUT | `/mail/v4/messages/{id}` | Update draft | 8.8 |
| POST | `/mail/v4/messages/{id}` | Send draft | 8.9 |
| POST | `/mail/v4/attachments` | Upload attachment | 8.10 |
| GET | `/mail/v4/attachments/{id}` | Download attachment data | 8.10 |
| POST | `/mail/v4/messages/import` | Import messages | 8.11 |
| GET | `/mail/v4/settings` | Mail settings | 7.5 |
| GET | `/contacts/v4/emails?Email=&Page=&PageSize=` | Contact emails | 8.12 |
| GET | `/contacts/v4/{id}` | Contact with cards | 8.12 |
| GET | `/core/v4/settings` | User settings | 8.12 |
| GET | `/tests/ping` | Reachability (unauthenticated) | 4.8 |
| POST | `/core/v4/devices` | Register device for push notifications | 14.3 |
| GET | `/mail/v4/conversations/{id}` | Conversation with message metadata | 14.7.2 |

### 8.2 Users and Addresses

* `GET /core/v4/users` → `{"User": User}`
* `GET /core/v4/addresses` → `{"Addresses": [Address]}`
* `GET /core/v4/addresses/{id}` → `{"Address": Address}`

### 8.3 Keys

See §6.1 and §6.4.

### 8.4 Labels

Create: `POST /core/v4/labels`

```json
{ "Name": "x", "Color": "#f66", "Type": 3, "ParentID": "<id, omitted if none>" }
```

Response: `{"Label": Label}`.

Update: `PUT /core/v4/labels/{id}`

```json
{ "Name": "y", "Color": "<unchanged color>", "ParentID": "<omitted if none>" }
```

Response: `{"Label": Label}`.

Delete: `DELETE /core/v4/labels/{id}`.

To read a single label, the Gateway lists the relevant types and selects by
ID. If the ID is absent, the label is treated as "no such label".

### 8.5 Events

* `GET /core/v4/events/latest` → `{"EventID": S, ...}`
* `GET /core/v4/events/{eventID}` → `Event` (§7.7), describing the changes
  *after* `eventID`.

**Chained fetch.** While `More = 1`, the client SHOULD fetch again with the
returned `EventID`, up to **50** events per poll cycle. If the last returned
`EventID` equals the requested one, nothing has changed.

### 8.6 Message Retrieval

**Listing / counting.** `POST /mail/v4/messages` with header
`X-HTTP-Method-Override: GET`. Body = filter plus paging:

```json
{
  "ID": ["<id>", ...],          // omitted when empty
  "Subject": "...",             // omitted when empty
  "AddressID": "...",           // omitted when empty
  "ExternalID": "...",          // omitted when empty
  "LabelID": "...",             // omitted when empty
  "EndID": "...",               // omitted when empty
  "Desc": 0,
  "Page": 0,
  "PageSize": 150,
  "Sort": "ID"
}
```

* **Count only:** send the filter with `"Limit": "0"` (a *string*) and no
  paging fields. Response: `{"Total": I}`.
* **Page:** response `{"Messages": [MessageMetadata], "Stale": B}`. If
  `Stale = 1`, repeat the identical request until `Stale = 0`.
* `EndID` + `Desc = 1` returns messages ordered by ID descending, starting at
  `EndID` inclusive. This drives the cursor-based sync of §12.1.

**Full message.** `GET /mail/v4/messages/{id}` → `{"Message": Message}`.
HTTP 422 means the message no longer exists.

**ID enumeration.** `GET /mail/v4/messages/ids?Limit=<≤1000>[&AfterID=<id>]`
→ `{"IDs": [S]}`. Repeat with `AfterID` = last ID until the result is empty.

**Counts.** `GET /mail/v4/messages/count` →
`{"Counts": [{"LabelID": S, "Total": I, "Unread": I}]}`. The total for label
`"5"` (All Mail) is the Account's message count.

### 8.7 Message Actions

Body for read / unread / delete / forward / unforward:

```json
{ "IDs": ["<id>", ...] }      // ≤ 150 per request
```

* `read`, `unread`, `delete`: success is the HTTP status.
* `forward`, `unforward`: response `{"Code":1001,"Responses":[{"ID":S,"Response":{"Code":I,"Error":S}}]}`.
  Any per-item `Code ≠ 1000` is a failure.

Label / unlabel:

```json
{ "LabelID": "<label id>", "IDs": ["<id>", ...] }    // ≤ 150 per request
```

Response: `{"Responses":[{"ID","Response":{...}}], "UndoToken": UndoToken}`.

If any item in a chunk fails, the Gateway MUST undo every previously
*successful* chunk of the same logical operation. For each collected token
whose `ValidUntil` is still in the future, it sends `POST /mail/v4/undoactions`
with the token object as body. It then reports failure. Response to undo:
`{"Messages":[Message]}`.

### 8.8 Drafts

Create: `POST /mail/v4/messages`

```json
{
  "Message": {
    "Subject": "...",
    "Sender":  {"Name": "...", "Address": "..."},
    "ToList":  [Addr], "CCList": [Addr], "BCCList": [Addr],
    "Body":    "<armored OpenPGP message, §9.4>",
    "MIMEType": "text/html" | "text/plain",
    "Unread":  0,
    "ExternalID": "<Message-ID without <>; omitted if empty>"
  },
  "AttachmentKeyPackets": null,
  "ParentID": "<id; omitted if none>",
  "Action": <0..4>
}
```

`Action`: 0 = reply, 1 = reply-all, 2 = forward, 3 = auto-response,
4 = read-receipt.

Response: `{"Message": Message}`.

Update: `PUT /mail/v4/messages/{id}`, with `{"Message": {...}, "AttachmentKeyPackets": ...}`.
`Body` is re-encrypted only if non-empty.

### 8.9 Send

`POST /mail/v4/messages/{draftID}`

```json
{
  "Packages": [
    {
      "Addresses": {
        "<recipient email>": {
          "Type": <scheme>,
          "Signature": <0|1|2>,
          "BodyKeyPacket": "<B64; omitted if none>",
          "AttachmentKeyPackets": { "<attachmentID>": "<B64>" }   // omitted if empty
        }
      },
      "MIMEType": "text/plain" | "text/html" | "multipart/mixed",
      "Type": <bitwise OR of recipient schemes>,
      "Body": "<B64 of the encrypted data packet>",
      "BodyKey": { "Key": "<B64 session key>", "Algorithm": "aes256" },        // only for clear schemes
      "AttachmentKeys": { "<attachmentID>": { "Key": "...", "Algorithm": "..." } } // omitted if empty
    }
  ]
}
```

Response: `{"Sent": Message}`. Package construction is specified in §13.13.

### 8.10 Attachments

**Upload:** `POST /mail/v4/attachments`, `multipart/form-data`:

| Part | Kind | Content |
|---|---|---|
| `MessageID` | field | Draft ID. |
| `Filename` | field | Attachment filename. |
| `MIMEType` | field | Media type including parameters, excluding `name`/`filename`. |
| `Disposition` | field | `inline` or `attachment`. |
| `ContentID` | field | Content-ID without angle brackets; may be empty. |
| `KeyPackets` | file (`blob`, `application/octet-stream`) | Binary PKESK packet(s). |
| `DataPacket` | file (`blob`, `application/octet-stream`) | Binary SEIPD packet. |
| `Signature` | file (`blob`, `application/octet-stream`) | Binary detached signature over the plaintext. |

Response: `{"Attachment": Attachment}`.

**Download:** `GET /mail/v4/attachments/{id}`. The response body is the raw
binary **data packet**; the key packets come from the Attachment's
`KeyPackets` field. A non-200 status is decoded as an API Error object.

### 8.11 Import

`POST /mail/v4/messages/import`, `multipart/form-data`:

* For each message *i* (0-based, as a decimal string): a file part named
  `"<i>"`, filename `"<i>.eml"`, content type `message/rfc822`. Its content is
  the encrypted literal (§9.6) followed by CRLF.
* One part named `Metadata`, content type `application/json`, holding an
  object keyed by the same names:

```json
{
  "0": { "AddressID": "...", "LabelIDs": ["0", "10"], "Unread": 1, "Flags": 1 }
}
```

Constraints: at most **10** messages per request; the combined encrypted size
per request MUST NOT exceed **70 MiB**; any single encrypted message larger
than 70 MiB MUST be refused before upload.

Response:

```json
{ "Responses": [ { "Name": "0", "Response": { "Code": 1000, "MessageID": "<id>" } } ] }
```

Results MUST be matched to inputs by `Name`. Any per-item `Code ≠ 1000` is a
failure.

### 8.12 Contacts, Settings and Ancillary Endpoints

* `GET /contacts/v4/emails?Email=<e>&Page=<n>&PageSize=<≤150>` →
  `{"ContactEmails":[ContactEmail], "Total": I}`. Page from 0 until
  `Total` is covered.
* `GET /contacts/v4/{id}` → `{"Contact": Contact}`.
* `GET /core/v4/settings` → `{"UserSettings": {"Telemetry": I, "CrashReports": I}}`.
* OPTIONAL ancillary endpoints, with no effect on mail semantics:
  * `GET /feature/v2/frontend?<stickyKey>=<uuid>` → `{"Code", "toggles":[{"name","enabled"}]}` (remote feature switches);
  * `POST /data/v1/metrics` with `{"Metrics":[{"Name","Version","Timestamp","Data"}]}`;
  * `POST /core/v4/reports/bug` (multipart);
  * `GET /core/v4/organizations`.

---

## 9. OpenPGP Lifecycle

### 9.1 Profile

* OpenPGP per RFC 4880, with the extensions of the crypto library used.
  Ed25519/X25519 keys MUST be supported.
* Symmetric cipher for every new encryption: **AES-256**. The session-key
  algorithm identifier on the wire is `"aes256"`.
* Message encryption is performed **without compression**.
* Default signature hash: **SHA-256**.
* The armor headers of produced messages MAY carry a `Version:` header and,
  for undecryptable-content placeholders, a `Comment:` header (§9.9).
* "Now" for every operation is the Service-synchronised time (§4.3).

### 9.2 Incoming Message Decryption

1. Select the Address key ring for the message's `AddressID`.
2. Dearmor `Body` and decrypt it with that key ring. Signatures are **not**
   verified on this path; the plaintext is accepted regardless of signature
   state.
3. For each attachment *j*: B64-decode `KeyPackets`, concatenate the
   downloaded data packet, and decrypt the resulting OpenPGP message with the
   same key ring.
4. A failure on the body or on any attachment is recorded per item and does
   not abort the build (§11.8.4).

For `MIMEType = multipart/mixed` messages (received as PGP/MIME), the
decrypted body is a complete MIME entity. If the encrypted message contained
one-pass signature packets, the first signature is extracted
(serialised packet plus hash algorithm name) so that it can be presented as
`multipart/signed` (§11.8.3).

### 9.3 Message Hashing for Deduplication

See Appendix A.

### 9.4 Draft Body Encryption

The draft body is UTF-8 text (HTML or plain). It is encrypted to the
address's **first key** only, unsigned, and armored. Encryption happens before
create/update (§8.8).

### 9.5 Attachment Encryption (Upload)

Using the address's first key:

1. Detached signature: sign the plaintext attachment octets → binary
   signature.
2. Encrypt the plaintext as a binary literal whose literal-data filename is
   the attachment filename. Split the result into the PKESK packet(s)
   (`KeyPackets`) and the SEIPD packet (`DataPacket`).
3. Upload per §8.10.
4. From the response, B64-decode `KeyPackets` and decrypt them with the
   address key ring. This recovers the attachment **session key**, which
   §13.13 needs.

### 9.6 Import Encryption

Before import, a literal is encrypted to the target Address's first key.

**Per-part mode (preferred).** Walk the MIME tree. If any part:
has an unparsable header or Content-Disposition; has a subtype of `encrypted`
or `signed`; or is a second `text/*` part — fall back to full mode.
Otherwise rebuild the tree, keeping the original multipart boundaries and
header blocks:

* Multipart: write the original header, then each child recursively,
  delimited by the original boundary.
* `text/*` or `message/*` leaf:
  decode the Content-Transfer-Encoding;
  if a `charset` parameter is present, transcode the body to UTF-8 and
  rewrite `Content-Type` with `charset=utf-8`;
  remove `Content-Transfer-Encoding`;
  the body becomes an **armored** OpenPGP message (encrypted, not signed) of
  the decoded text.
* Any other leaf:
  decode the CTE;
  set `Content-Transfer-Encoding: base64`;
  the body becomes the B64 encoding of the **binary** OpenPGP message
  (encrypted, not signed) of the decoded content.

Charset resolution order: an injected charset decoder if available; the IANA
MIME registry name; the same name with the prefix `cs`; the WHATWG encoding
label; otherwise the part fails.

**Full mode (fallback).** Encrypt **and sign** the whole literal with the
address key ring, armor it, and wrap it as RFC 3156 PGP/MIME:

```
Message-Id / From / To / Subject / Date / Received / Cc   (copied from original if present)
Mime-version: 1.0
Content-Type: multipart/encrypted; boundary=<32 hex>; protocol="application/pgp-encrypted"

--<b>
Content-Description: PGP/MIME version identification
Content-Type: application/pgp-encrypted

Version: 1
--<b>
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename=encrypted.asc
Content-Type: application/octet-stream; name="encrypted.asc"

<armored message>
--<b>--
```

### 9.7 Outgoing Body Encryption (Send)

For each package (§13.13):

1. Encrypt the package body to the address's **first key**, **signed** with
   the same key ring (an embedded signature).
2. Split the result. The data packet (SEIPD) is B64-encoded into the package
   `Body`.
3. Decrypt the key packet with the address key ring to recover the body
   session key.
4. Per recipient:
   * encrypting schemes: encrypt the body session key to the recipient's
     selected public key → `BodyKeyPacket` (B64 of a PKESK); for text
     packages, encrypt each attachment session key the same way →
     `AttachmentKeyPackets[attID]`;
   * clear schemes: put the plaintext session key (B64) and algorithm into the
     package-level `BodyKey`, and, for text packages, `AttachmentKeys[attID]`.
     The Service then performs the clear delivery.

### 9.8 Contact Card Processing

See §7.6. Encrypted cards are decrypted with the User key ring. Signed cards
are verified with the User key ring. A verification failure means "no
preferences".

### 9.9 Undecryptable Content

If decryption fails, the Gateway MUST NOT drop the message. It produces a
placeholder (§11.8.4) that contains the original armored ciphertext. The armor
carries a `Comment:` header that reads
`This message could not be decrypted: <reason>` or
`This attachment could not be decrypted: <reason>`.

---

## 10. Local Credentials, Accounts and Address Modes

### 10.1 Gateway Password

1. When an Account is first added, the Gateway generates **16 random octets**
   from a CSPRNG. This is the Gateway password secret.
2. It is presented to the user as **B64URL-NP** (22 characters). The user
   enters this string in the mail client as the password for both IMAP and
   SMTP.
3. To authenticate, the Gateway B64URL-NP-decodes the supplied password and
   compares it with the stored secret **in constant time**.
4. The Gateway SHOULD keep an archive mapping SHA-256(primary email) to the
   secret, and reuse the secret when the same primary email logs in again.
   This way, client configuration survives a logout/login cycle.

### 10.2 Client Authentication Rule

A client credential pair (*username*, *password*) authenticates as Account
*A*, Address *X* if and only if:

* the password matches *A*'s Gateway password (§10.1); and
* *username* case-insensitively equals the email of an Address *X* of *A*
  whose `Status` = 1 (enabled). No `+tag` stripping is applied here.

### 10.3 Address Modes

Each Account is in one of two modes. The default is **combined**.

| Mode | IMAP | SMTP |
|---|---|---|
| **Combined** | One IMAP mailbox set, bound to the primary address, holds the messages of **all** addresses. Login with **any** enabled address succeeds into this set. | Any enabled address can authenticate. Parent lookup (§13.9) spans all addresses. |
| **Split** | One independent IMAP mailbox set **per address**. Login succeeds only into the set of the address used as username. Messages appear only in their owning address's set. | Any enabled address can authenticate. Parent lookup is restricted to the authenticated address. |

Changing the mode MUST discard all local IMAP state for the Account, rebuild
the mailbox set(s), and run a full resynchronisation (§12.1). In combined
mode, if the primary address changes (because of an `Order` change), the
existing mailbox set is re-bound to the new primary address without a resync.

### 10.4 Persisted Per-Account State

The Gateway MUST persist, encrypted at rest:

* UserID, username, primary email;
* session UID and RefreshToken;
* salted key passphrase;
* Gateway password secret;
* address mode;
* last processed EventID;
* sync progress: labels done, messages done, last synced message ID,
  failed message IDs, and the event ID at which sync started;
* a random key for the local message cache.

The persisted-state key SHOULD be held in the OS credential store.

---

## 11. IMAP Server

### 11.1 Listener

* Bind address: **127.0.0.1**.
* Port: configurable. The default is the first free port at or above **1143**.
* Security: configurable per listener.
  * **Implicit TLS** (TLS from the first octet), or
  * **Plain with STARTTLS** (the default).
  STARTTLS is offered in both cases.
* Certificate: a self-signed RSA-2048 X.509 certificate.
  Subject CN = `127.0.0.1`; SAN IP = `127.0.0.1`; CA = true;
  KeyUsage = keyEncipherment | digitalSignature | certSign;
  ExtKeyUsage = serverAuth, clientAuth; validity 20 years.
  It MUST be regenerated if it expires within 31 days.
* TLS parameters: minimum protocol version **TLS 1.2**. The server does not
  request client certificates. The same TLS configuration applies to the
  IMAP and SMTP listeners, for both implicit TLS and STARTTLS.

### 11.2 Greeting and Capabilities

Greeting:

```
* OK [CAPABILITY <caps…>] <product name> <version> - session ID <n>
```

The full capability set is
`IMAP4rev1 UNSELECT UIDPLUS MOVE ID IDLE AUTH=PLAIN STARTTLS`.

| Capability | Before auth | After auth | Notes |
|---|---|---|---|
| `IMAP4rev1` | ✓ | ✓ | RFC 3501 |
| `STARTTLS` | ✓ | ✓ | RFC 3501 §6.2.1 |
| `IDLE` | ✓ | ✓ | RFC 2177. MAY be disabled by operator switch. |
| `ID` | ✓ | ✓ | RFC 2971 |
| `AUTH=PLAIN` | ✓ | ✓ | RFC 4616. MAY be disabled by configuration. |
| `UNSELECT` | | ✓ | RFC 3691 |
| `UIDPLUS` | | ✓ | RFC 4315 |
| `MOVE` | | ✓ | RFC 6851 |

`CAPABILITY` returns the pre-auth subset until login succeeds. The tagged OK
of `LOGIN`/`AUTHENTICATE` carries the full list as a `[CAPABILITY …]` response
code. `LOGINDISABLED` is never advertised; plaintext LOGIN is allowed on
loopback.

### 11.3 Command Set and States

| State | Commands |
|---|---|
| Any | `CAPABILITY`, `NOOP`, `ID`, `LOGOUT`, `STARTTLS` |
| Not authenticated | `LOGIN`, `AUTHENTICATE PLAIN` |
| Authenticated | `SELECT`, `EXAMINE`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE`, `LIST`, `LSUB`, `STATUS`, `APPEND`, `IDLE` |
| Selected | `CHECK`, `CLOSE`, `EXPUNGE`, `UID EXPUNGE`, `UNSELECT`, `SEARCH`, `FETCH`, `STORE`, `COPY`, `MOVE`, and the `UID` forms of `FETCH`/`SEARCH`/`STORE`/`COPY`/`MOVE` |

* Unknown commands → `BAD`.
* After **20 consecutive** parse/syntax errors in one session, the server
  closes the connection.
* If the selected mailbox becomes invalid (for example, deleted by another
  session), the next command gets
  `* BYE` with an inconsistent-state reason, and the connection closes.
* `LOGIN`/`AUTHENTICATE` while already authenticated → `BAD`.

**FETCH attributes:** `ALL`, `FAST`, `FULL`, `ENVELOPE`, `FLAGS`,
`INTERNALDATE`, `RFC822`, `RFC822.HEADER`, `RFC822.SIZE`, `RFC822.TEXT`,
`BODY`, `BODYSTRUCTURE`, `BODY[<section>]<<partial>>`,
`BODY.PEEK[<section>]<<partial>>`, `UID`.
Section specifiers: `HEADER`, `HEADER.FIELDS (…)`, `HEADER.FIELDS.NOT (…)`,
`TEXT`, `MIME`, and numeric part paths.

**SEARCH keys:** all RFC 3501 keys: `ALL ANSWERED BCC BEFORE BODY CC DELETED
DRAFT FLAGGED FROM HEADER KEYWORD LARGER NEW NOT OLD ON OR RECENT SEEN
SENTBEFORE SENTON SENTSINCE SINCE SMALLER SUBJECT TEXT TO UID UNANSWERED
UNDELETED UNDRAFT UNFLAGGED UNKEYWORD UNSEEN`, sequence sets, and
parenthesised lists. `CHARSET` is accepted. Search is evaluated **locally**
against the cached literals.

**STATUS items:** `MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN`.

Mailbox names on the wire are modified UTF-7 (RFC 3501 §5.1.3). An
`INBOX<delim>` prefix is matched case-insensitively.

### 11.4 Authentication

#### 11.4.1 LOGIN / AUTHENTICATE PLAIN

1. Credentials are checked against every Account by the rule of §10.2. In
   split mode, the IMAP mailbox set chosen is the one bound to the matching
   address.
2. Failure → `NO`. After **3 consecutive** failed attempts (across all
   users), the third failure is reported as "login blocked", and the counter
   resets after a configurable jail interval (default 0 s). A successful
   login resets the counter.
3. Success → `OK [CAPABILITY …] Logged in`.

#### 11.4.2 Disabling AUTHENTICATE

If AUTHENTICATE is disabled by configuration, `AUTH=PLAIN` is not advertised
and only `LOGIN` is accepted.

#### 11.4.3 ID

`ID (<k> <v> …)` stores the client identity for the session and replies with
the server's `name`, `version`, `vendor` and `support-url`. `ID NIL` returns
the server identity only. The client `name` and `version` feed the API
User-Agent (§4.2) and the per-client connection limits (§11.12).

### 11.5 Mailbox Model

#### 11.5.1 Hierarchy and Naming

* Hierarchy delimiter: **`/`**.
* **System mailboxes** sit at the top level and are named by the Service label
  `Name`. Exceptions:
  * a name equal to "inbox" (case-insensitively) is normalised to `INBOX`;
  * label `12` is named **`Scheduled`**.
* **Folders** (type 3) appear under the top-level placeholder **`Folders`**:
  `Folders/<path segments of Label.Path>`.
* **Labels** (type 1) appear under the top-level placeholder **`Labels`**:
  `Labels/<Label.Path>`, a single level.
* `Folders` and `Labels` themselves are **`\Noselect`** placeholders and are
  always present.
* `RECOVERY_MAILBOX` (§11.11) is a local top-level mailbox with
  `\Noinferiors`.

#### 11.5.2 Mailbox Attributes

| Mailbox | Attributes |
|---|---|
| Every system mailbox | `\Noinferiors` plus the entry below |
| Trash (`3`) | `\Trash` |
| Spam (`4`) | `\Junk` |
| All Mail (`5`) | `\All` |
| Archive (`6`) | `\Archive` |
| Sent (`7`) | `\Sent` |
| Drafts (`8`) | `\Drafts` |
| Starred (`10`) | `\Flagged` |
| `Folders`, `Labels` placeholders | `\Noselect` |
| User folders and labels | (none) |

Special-use attributes follow RFC 6154 and are returned in `LIST` responses.

#### 11.5.3 Visibility

* All Mail: visible when the Gateway's "show All Mail" setting is on (the
  default); hidden otherwise.
* Scheduled: hidden while empty.
* Every other mailbox: always visible.

#### 11.5.4 Mailbox FLAGS and PERMANENTFLAGS

* All mailboxes except All Mail:
  `FLAGS` = `PERMANENTFLAGS` = `(\Seen \Flagged \Deleted $Forwarded Forwarded)`.
* All Mail: `(\Seen \Flagged)`.

#### 11.5.5 Subscriptions

`SUBSCRIBE`, `UNSUBSCRIBE` and `LSUB` are handled **locally**. Nothing is sent
to the Service.

### 11.6 Message Membership

A message is a member of Mailbox *M* if and only if its `LabelIDs` contains
*M*'s label ID **and** that label is wanted (§7.3). One Service message can
therefore appear in several Mailboxes (for example, Inbox, Starred,
`Labels/x` and All Mail), each time with its own UID.

### 11.7 UIDs and UIDVALIDITY

* UIDs are assigned per Mailbox, strictly increasing, starting at 1.
* UIDVALIDITY = the number of whole seconds since **2023-02-01T00:00:00Z**.
  If two values would collide within the same second, the later one is
  incremented, so every value generated is strictly greater than the last.
* UIDVALIDITY changes only when a Mailbox is recreated (for example, after a
  full resync).
* Upper bounds: 2³²−1 for mailbox count, messages per mailbox, UID and
  UIDVALIDITY. Exceeding a bound is an error.

### 11.8 Literal Synthesis

The Gateway builds the IMAP literal for each message from the full Message
and its decrypted parts. The literal is built once, cached, and served
byte-identically on every FETCH.

#### 11.8.1 Structure Selection

1. If the message has **attachments**: build **multipart/mixed** (§11.8.3,
   case A).
2. Otherwise, if `MIMEType` is **multipart/mixed**: PGP/MIME
   reconstruction (case B).
3. Otherwise: **single-part** (case C).

Before building, if the decrypted body starts with a header section that
contains `From:`, `To:` and `Date:` fields, every line inside that section
that begins with `From ` or `>From ` (an mbox delimiter) is removed.

#### 11.8.2 Top-Level Header Synthesis

1. Start with `ParsedHeaders`: every field instance, in the given order,
   copied verbatim.
2. Apply each of the following **only if the field is absent or its value
   differs**. This keeps unchanged fields in their original position.

| Field | Rule |
|---|---|
| `Subject` | `Subject`, RFC 2047 Q-encoded UTF-8 if non-ASCII. Only if `Subject` is non-empty. |
| `From` | `Sender` formatted as an RFC 5322 mailbox (display name encoded per RFC 2047 when needed). Only if `Sender` is non-empty. |
| `Reply-To` | Comma-joined `ReplyTos`. Only if the message is **not** a draft and `ReplyTos` is not a single empty entry. |
| `To` / `Cc` / `Bcc` | Comma-joined lists, when non-empty. |
| `Message-Id` | If absent: `<ExternalID>` when `ExternalID` is non-empty; otherwise `<ID@INTERNAL_ID_DOMAIN>`. |
| `Date` | If the existing value is missing, unparsable, or earlier than 1970-01-01: set it to `Time` (RFC 1123Z, UTC). If `Time` ≤ 0, use **1982-08-13 00:00:00 +0000** instead. If `X-Original-Date` is absent, add it with the (possibly zero) parsed original date, formatted the same way. |
| `HDR_INTERNAL_ID` | The Service message `ID`. |
| `HDR_EXTERNAL_ID` | `<ExternalID>`, when non-empty. |
| `HDR_SERVER_DATE` | `Time` (RFC 1123Z, UTC). |
| `References` | If no existing References value contains `ID`: append `<ID@INTERNAL_ID_DOMAIN>` to the existing references, space-separated. |

#### 11.8.3 Body Construction

Boundaries are 64 lowercase hex characters (32 octets from a CSPRNG). If the
CSPRNG is unavailable, the build MUST fail.

**Text part header:**

```
Content-Type: <MIMEType>[; charset=utf-8]          (charset only if body is valid UTF-8)
Content-Transfer-Encoding: quoted-printable
```

**Attachment part header:**

1. The attachment `Headers`, in order.
2. `Content-Type`: the attachment `MIMEType` with its parameters, plus
   `name` and `filename` set to the Q-encoded UTF-8 attachment name. If
   `MIMEType` cannot be parsed, it is copied verbatim.
3. `Content-Disposition: <Disposition>; filename=<Q-encoded name>`.
4. `Content-Transfer-Encoding: base64`. For `message/rfc822` attachments the
   CTE field is removed instead.

**Case A — multipart/mixed:**

```
<top header>
Content-Type: multipart/mixed; boundary=<b1>

--<b1>
[ if any inline attachments:
    Content-Type: multipart/related; boundary=<b2>
    --<b2> <text part>
    --<b2> <inline attachment 1> …
    --<b2>--
  else:
    <text part> ]
--<b1> <regular attachment 1>
…
--<b1>--
```

Inline attachments are those with `Disposition = inline`. Order within each
group follows the Service order.

**Case B — PGP/MIME:**

* If a signature was extracted (§9.2):
  ```
  <top header>
  Content-Type: multipart/signed; micalg=<hash name>; protocol="application/pgp-signature"; boundary=<b>

  --<b>
  <decrypted entity: header + body, as decrypted>
  --<b>
  Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
  Content-Disposition: attachment; filename="OpenPGP_signature"
  Content-Description: OpenPGP digital signature

  <armored detached signature>
  --<b>--
  ```
  `micalg` carries the hash algorithm name exactly as the OpenPGP library
  reports it (for example `SHA-256`).
* Otherwise:
  1. Remove `Content-Type` from the top header.
  2. Add each header field of the decrypted entity that is not already
     present in the top header.
  3. The body is the decrypted entity's body.

  The decrypted entity is split into header and body at the first empty line.
  If the header section is not a valid header, the whole content is treated
  as body.

**Case C — single-part:** the top header plus the text-part header fields,
followed by the decrypted body.

#### 11.8.4 Decryption-Failure Placeholders

* Body failure, cases A and C: build case A. The text part is replaced by a
  part with `Content-Type: <MIMEType>` whose content is the original armored
  message re-armored with the comment of §9.9.
* Body failure, case B:
  ```
  Content-Type: multipart/encrypted; boundary=<b>; protocol="application/pgp-encrypted"
  --<b>
  Content-Type: application/pgp-encrypted
  Content-Description: PGP/MIME version identification

  Version: 1
  --<b>
  Content-Type: application/octet-stream; name="encrypted.asc"
  Content-Disposition: inline; filename="encrypted.asc"
  Content-Description: OpenPGP encrypted message

  <original armored Body>
  --<b>--
  ```
* Attachment failure: the part becomes
  `Content-Type: application/octet-stream; name="<name>.pgp"` with
  `Content-Disposition: <disposition>; filename="<name>.pgp"`. Its content is
  the armored concatenation of `KeyPackets` and the data packet, with the
  comment of §9.9.

#### 11.8.5 Build Failure Placeholder

If building or parsing fails entirely, the message is still exposed in its
Mailboxes, as the following literal:

```
Date: <Time as RFC 1123Z>
Subject: Message failed to build
Content-Type: text/plain
Content-Transfer-Encoding: base64

<base64, wrapped at 76 columns, of:>
Failed to build message: 
Subject:   <Subject>
Error:     <error text>
MessageID: <ID>
```

The message ID MUST be recorded as **failed**. A later successful build (for
example, from an update event) MUST clear that record.

### 11.9 Flag Semantics

#### 11.9.1 Deriving Flags from the Service

| IMAP flag | Set when |
|---|---|
| `\Seen` | `Unread = 0` |
| `\Flagged` | `LabelIDs` contains `10` |
| `\Draft` | Draft predicate (§7.4) |
| `\Answered` | `IsReplied = 1` or `IsRepliedAll = 1` |
| `$Forwarded` **and** `Forwarded` | `IsForwarded = 1` |

#### 11.9.2 STORE → Service

Only *effective* changes are propagated. For example, adding `\Seen` to an
already-seen message sends nothing.

| Flag change | Service call |
|---|---|
| +`\Seen` / −`\Seen` | `PUT /mail/v4/messages/read` / `unread` |
| +`\Flagged` / −`\Flagged` | label / unlabel with label `10` |
| +/− `$Forwarded` or `Forwarded` (case-insensitive) | `forward` / `unforward`. Setting either variant sets both locally. |
| `\Deleted` | **Local only.** Scoped to the selected mailbox. |
| `\Answered`, `\Draft`, keywords | **Local only.** Not propagated. |
| `\Recent` | Read-only. Any attempt to set it is an error. |

`STORE FLAGS` (replace) is computed as the equivalent add/remove set.
Messages in `RECOVERY_MAILBOX` never trigger Service calls.

### 11.10 Command-to-API Mapping

#### 11.10.1 COPY

* The target MUST NOT be All Mail (`5`), Scheduled (`12`) or
  `RECOVERY_MAILBOX`; otherwise the result is `NO`.
* Action: label the messages with the target label (§8.7).
* Copying out of `RECOVERY_MAILBOX` re-imports each message into the target
  (APPEND semantics, §11.10.4).
* The response carries `[COPYUID <uidvalidity> <src-uids> <dst-uids>]`.

#### 11.10.2 MOVE

* Refused (`NO`) if:
  source is Inbox and target is Sent; source is Sent and target is Inbox;
  either side is All Mail or Scheduled; or the target is `RECOVERY_MAILBOX`.
* Action:
  1. Label the messages with the target label.
  2. Let *expunge-source* = (the source is a user label, type 1) **or** (the
     target is a folder or system label, types 3 or 4).
  3. If *expunge-source* is true: unlabel the messages from the source label,
     and expunge them from the source Mailbox in IMAP.
  4. Otherwise the messages stay in the source Mailbox. This happens when
     moving from a folder to a user label: IMAP MOVE then behaves like COPY.
* Moving out of `RECOVERY_MAILBOX` re-imports the messages and removes them
  from the recovery mailbox.
* The response carries `[COPYUID …]` and untagged `EXPUNGE` for the removed
  source messages.

#### 11.10.3 EXPUNGE / CLOSE / UID EXPUNGE

The messages flagged `\Deleted` in the selected Mailbox (restricted to the
given UID set for `UID EXPUNGE`) are removed from that Mailbox:

1. Refused for All Mail and Scheduled.
2. Unlabel the messages from the Mailbox's label.
3. If the Mailbox is **Trash** (`3`) or **Drafts** (`8`):
   1. Fetch the metadata of the affected messages in chunks of ≤ 150
      (`ID` filter, §8.6).
   2. For each message, collect its remaining label IDs, excluding:
      unwanted labels; labels `1`, `2`, `5` and `12`; and the mailbox's own
      label.
      A label unknown locally is resolved by listing types 3 and 4. If it
      still cannot be found, it is ignored.
   3. If nothing remains, the message is permanently deleted
      (`PUT /mail/v4/messages/delete`).
4. Expunging from `RECOVERY_MAILBOX` only removes local copies.

`CLOSE` performs an implicit expunge without untagged responses. `UNSELECT`
does not expunge.

#### 11.10.4 APPEND

1. Mailbox resolution: if the mailbox does not exist → `NO [TRYCREATE]`.
   All Mail → `NO` (not allowed).
2. Header validation, for any mailbox other than Drafts:
   * a non-empty `Date` is REQUIRED;
   * a non-empty, parsable `From` is REQUIRED;
   * if `From` lists more than one mailbox, a parsable `Sender` is REQUIRED;
   * if `Sender` is present, it MUST be non-empty and parsable.

   A violation → `BAD`.
3. **Re-APPEND detection** (not for Drafts). If the literal carries
   `HDR_LOCAL_ID` naming a message this IMAP server already knows, and that
   message is not marked deleted: add that existing message to the target
   Mailbox (COPY semantics) and return its new UID. No import happens. This
   supports clients that implement move as APPEND + delete.
   For APPEND to Drafts, any `HDR_LOCAL_ID` header is first stripped.
4. **Send deduplication.** Compute the message fingerprint (Appendix A) and
   collect the `To`/`Cc`/`Bcc` address set of the literal. If an SMTP
   submission with the same fingerprint and the same recipient set is in
   flight or recently completed (§13.6): wait up to **90 s** for it to finish.
   If it succeeded, do not import. Instead, fetch the already-sent Service
   message, build its literal, and bind the APPEND to that message.
5. **Import target address:**
   1. Start with the IMAP set's bound address (combined mode: primary;
      split mode: that address). If it is external and cannot send, use the
      primary address instead.
   2. In combined mode only, parse the first address of `From` (or of
      `Sender` if `From` is empty). Find an owned address that matches it
      (case-insensitive, `+tag` stripped). If one matches and it differs from
      the bound address, use it, **unless** it is external and cannot send,
      or the target is Drafts and the matched address is disabled or cannot
      send. In those cases keep the bound address.
6. **Drafts target:**
   * Parse the literal leniently (invalid address lists tolerated).
   * Create a draft (§8.8):
     body = the rich (HTML) body if non-empty, else the plain body;
     `MIMEType` per §13.8; `Sender` = the import address's DisplayName and
     Email; To/Cc/Bcc and `ExternalID` from the headers; no ParentID;
     `Action` = 0.
   * Upload each attachment (§8.10). Disposition is `inline` only if the
     part's disposition is `inline` **and** it has a Content-ID; otherwise
     `attachment`.
7. **Other targets: import** (§8.11) with:
   * `LabelIDs` = [target] + [`10`] if `\Flagged`;
   * `Unread` = not `\Seen` (for Drafts imports this is always false);
   * `Flags`:
     * Received if the target is Inbox;
     * Sent if the target is Sent;
     * else Received if the literal has a `Received:` header;
     * else Sent;
     * plus Replied if `\Answered` was given.
   * If the literal has no top-level text part (§13.8 rule 8), add an empty
     `text/plain; charset=utf8` part first.
8. After a successful create/import, fetch the resulting Service message,
   build its literal (§11.8), and store **that** literal as the appended
   message. The response is `OK [APPENDUID <uidvalidity> <uid>]`.
9. **Failure handling:**
   * If the encrypted size exceeds the import limit → `NO`. Nothing is
     stored.
   * For any other failure, the literal is stored in `RECOVERY_MAILBOX`
     (§11.11) and the command returns `NO`. If an identical literal is
     already there, the error text indicates a likely duplicate.

#### 11.10.5 CREATE

* The name MUST have at least two components. The first MUST be `Folders`
  or `Labels`. Anything else → `NO` (not allowed).
* `Labels/<name>`: exactly one component after the prefix. Create a type-1
  label with color `#f66`.
* `Folders/<p1>/…/<pn>`: if n > 1, the parent path `<p1>/…/<pn−1>` MUST
  already exist as a folder; otherwise → `NO`. Create a type-3 folder named
  `<pn>` with color `#f66` and the parent's ID.

#### 11.10.6 RENAME

* The same prefix and shape rules as CREATE apply to the new name.
* Label: fetch the current label, then update its name and keep its color.
* Folder: resolve the new parent from the new path (it MUST exist), then
  update the name and parent and keep the color.
* Renaming between the `Folders` and `Labels` hierarchies is not supported.

#### 11.10.7 DELETE

`DELETE /core/v4/labels/{id}` for the Mailbox's label.

#### 11.10.8 FETCH

Served from the local literal cache. If a cached literal is missing, the
Gateway fetches the full message and attachments from the Service and
rebuilds the literal (§11.8). `INTERNALDATE` = Service `Time`, or the current
time if `Time` ≤ 0. `RFC822.SIZE` = the size of the built literal.

### 11.11 Recovery Mailbox

* `RECOVERY_MAILBOX` exists for every IMAP set. It has attributes
  `\Noinferiors`, and FLAGS/PERMANENTFLAGS `(\Seen \Flagged \Deleted)`.
* It holds literals whose APPEND the Service rejected, so that user content
  is never silently lost.
* COPY/MOVE **into** it → `NO`. COPY/MOVE **out of** it re-imports.
* Its content is never synchronised to the Service.

### 11.12 Connection Admission Control

* **Rolling rate:** new connections are counted in 6 buckets of 10 s each
  (a 60 s window). When more than **400** connections were opened within the
  window, new connections are closed immediately.
* **Per-client concurrency:** sessions are keyed by the client's `ID name`.
  * `outlook` (substring) → Outlook;
  * `thunderbird` → Thunderbird;
  * contains both `mac` and `mail` → Apple Mail;
  * contains both `mac` and `notes`, or anything else → unknown.

  Apple Mail is limited to **60** concurrent sessions (fallback profile:
  **25**). The other clients are unlimited.

  A session that exceeds its client's limit receives
  `* BYE Too many connections for this IMAP client` and is closed.

### 11.13 Unsolicited Responses and IDLE

* Changes that arrive from the Service (§12) or from other sessions are
  delivered as standard untagged `EXISTS`, `EXPUNGE`, `FETCH (FLAGS …)` and
  `RECENT` responses. They are sent at command boundaries, and continuously
  during IDLE.
* During IDLE, pending responses are flushed in batches every **500 ms**.
* `DONE` ends IDLE with `OK IDLE`.

### 11.14 Mailbox Name Conflict Resolution

When the Gateway creates or renames a Mailbox for a Service label (during
sync or a label event), the target name may already be in use locally by a
**different** label ID. The Gateway resolves the conflict as follows:

1. Look up the label currently holding that name.
   * If it no longer exists on the Service: delete its Mailbox, then create
     or rename the new one.
   * If it exists and its current Service name differs from the local name:
     resolve that label's own new name recursively (this procedure), then
     create or rename the new one.
   * If it exists and its name is unchanged: report an inconsistency error.
2. If a cycle is found (as in a name swap), temporarily rename the label in
   the cycle by prefixing `tmp_` to the last path component. The final rename
   later in the chain overwrites the temporary name.
3. Before creating the `Folders` and `Labels` placeholders: if either name is
   held by a non-placeholder ID that is not a Service label, delete that
   Mailbox silently. If it is held by a Service label, this is an error.

---

## 12. Synchronisation and Event Processing

### 12.1 Initial Synchronisation

Sync runs for each Account whenever its sync state is incomplete: after
first login, after a refresh event, after an address-mode change, or after a
user-requested repair.

1. **Record the start event.** If no start-event ID is stored, store the
   current last-processed EventID as the *start-sync event ID*.
2. **Labels.** Fetch labels of types 4, 3 and 1. In every IMAP set, create
   the `Folders` and `Labels` placeholders and every wanted label's Mailbox,
   applying §11.14. Persist "labels done".
3. **Count.** `GET /mail/v4/messages/count`. The total for label `5` is the
   progress denominator. Progress is reported in 4 stages per message.
4. **Metadata pass.** Iterate in descending ID order:
   * First page: filter `{Desc:1}`, page 0, size **128**.
   * Next pages: filter `{EndID:<last ID>, Desc:1}`, page 0, size 128. If the
     first result's ID equals `EndID`, drop it.
   * Stop when a page is empty.
   * Persist the last ID seen, so that sync can resume.
5. **Batching.** Accumulate message IDs into a download batch. Close the batch
   when it reaches **64** messages, or when adding the next message's `Size`
   would reach the download-memory budget. A single oversized message forms a
   batch on its own.
6. **Download.** For each batch:
   1. Fetch the full messages concurrently. HTTP 422 means the message was
      deleted; skip it.
   2. Fetch every attachment's data packet concurrently.
   3. Concurrency starts at the maximum (default 2 × 32 = 64). Before each
      chunk, if the previous chunk hit any 429/5xx, concurrency resets to 2;
      otherwise it doubles, capped at the maximum.
   4. Each request uses the back-off of §4.6.
7. **Build.** Decrypt and build each literal (§11.8). Build failures produce
   placeholders (§11.8.5) and are recorded as failed.
8. **Apply.**
   * Combined mode: all messages go to the single IMAP set.
   * Split mode: each message goes to the set of its `AddressID`.
   * Membership = wanted labels; flags per §11.9.1. Label IDs that are
     unknown at this point are tolerated.
   * After each batch, persist the last synced message ID.
9. **Finish.** Persist "messages done". Then **rewind** the event loop to the
   start-sync event ID, and clear that ID. Changes that happened during sync
   are thereby replayed.
10. **Failure.** On any error, wait **20 s** and restart from step 1 using
    the persisted progress.

While sync is running, the event loop (§12.2) keeps processing events in
"sync mode": unknown labels are tolerated, and every update to a draft or
sent message triggers a full re-fetch.

**Memory budget.** The configured maximum sync memory defaults to 2 GiB. It
is clamped to between 800 MiB and half of system RAM.

| Budget | Download memory | Build memory |
|---|---|---|
| < 2 GiB | 40 MiB | 64 MiB |
| = 2 GiB | 128 MiB | 128 MiB |
| > 2 GiB | 128 MiB + (budget − 2 GiB) / 8 | 128 MiB + (budget − 2 GiB) / 8 |

### 12.2 Event Loop

1. **Start.** Load the last processed EventID. If there is none, fetch
   `/core/v4/events/latest` (with back-off) and store it.
2. **Poll.** Every **20 s + uniform random [0, 20 s)**: fetch events after
   the last EventID (with back-off and chained fetch, §8.5). Skip the cycle
   while paused (disconnected, §4.8).
3. **Dispatch.** Deliver each event, in order, to every Account subsystem
   (identity, IMAP, SMTP, user settings). Within an event, each subsystem
   processes the parts in this order:
   Refresh → User → Addresses → Labels → Messages → UsedSpace.
   Subsystems MAY process an event concurrently or one after another. In
   either case, an event completes only after every subsystem has finished
   it, and a failure in any subsystem fails the event (step 5).
4. **Commit.** After the whole batch succeeds, store the last EventID.
5. **Errors** while handling an event:
   * Retry on the next cycle without advancing (transient): caller
     cancellation; network errors; unexpected EOF; JSON type errors; HTTP 429;
     HTTP ≥ 500.
   * Any other error is a **bad event**: pause polling and notify the user,
     who chooses either **resync** (rebuild local IMAP state, §12.1) or
     **logout**.
6. **Rewind.** The loop MUST support being reset to an earlier EventID, as
   required by §12.1 step 9.

### 12.3 Event Semantics

#### 12.3.1 Refresh

If `Refresh & 1` is set:

1. Reload the User and the Addresses.
2. Cancel any running sync.
3. Remove all local IMAP data for the Account.
4. Rebuild the IMAP set(s).
5. Clear the sync state, and start a full sync (§12.1) whose start event is
   the refresh event.

#### 12.3.2 User

Replace the cached User. Its keys, used space and similar fields take effect
for subsequent operations.

#### 12.3.3 Addresses

All subsystems update their address view. Then:

* **Combined mode:** if the primary address changed, re-bind the IMAP set to
  the new primary.
* **Split mode:**

| Event | Condition | Effect |
|---|---|---|
| Create | Address is enabled | Add a new IMAP set for it and populate its Mailboxes from the label cache. |
| Update | Became enabled | Add an IMAP set. |
| Update | Became disabled | Remove the IMAP set and delete its local data. |
| Update | Other changes | Update metadata only. |
| Delete | Address was enabled | Remove the IMAP set. |

#### 12.3.4 Labels

Unwanted labels are ignored for create and update.

| Action | Effect |
|---|---|
| Create | Cache the label; resolve name conflicts (§11.14); create the Mailbox in every IMAP set. |
| Update | Re-fetch the label (the event may lack the updated path). If the label no longer exists (422), skip it. Update the cache, resolve conflicts, and rename the Mailbox. Then repeat for every cached descendant (labels whose `ParentID` chain leads to it), because their paths changed too. |
| Delete | Delete the Mailbox in every IMAP set and remove the label from the cache. |

#### 12.3.5 Messages

| Action | Condition | Effect |
|---|---|---|
| Create (1) | — | Fetch the full message; on 422, ignore. Build the literal. Add it to the IMAP set for `AddressID`. If that set is gone: in combined mode use the primary set; in split mode drop the update. Unknown label IDs are an error outside sync mode. |
| Update (2) | The message is a draft, or has the Sent flag | Full re-fetch and rebuild. **Replace** the literal in IMAP; the message gets new UIDs in its Mailboxes. Create the message if it is missing. |
| Update (2) or Update-flags (3) | Otherwise | Set Mailbox membership = wanted labels, and set the flags per §11.9.1. If the message is unknown locally, treat the event as Create. |
| Delete (0) | — | Remove the message from all Mailboxes in every IMAP set. |

In sync mode, the "draft or Sent" full-replace rule also applies to
Update-flags (3).

---

## 13. SMTP Submission Server

### 13.1 Listener

* Bind address: **127.0.0.1**. Default port: the first free port at or above
  **1025** that is not the IMAP port.
* Security: implicit TLS, or plain with STARTTLS (the default). It uses the
  same certificate as IMAP (§11.1).
* Greeting: `220 127.0.0.1 ESMTP Service Ready`.
* Maximum command line length: **65 536** octets. No recipient limit. No
  message size limit is advertised.

### 13.2 EHLO Response

```
250-Hello <domain>
250-PIPELINING
250-8BITMIME
250-ENHANCEDSTATUSCODES
250-CHUNKING
250-STARTTLS                 (only on a non-TLS connection)
250-AUTH PLAIN LOGIN         (mechanism order unspecified)
250 SIZE
```

`HELO` returns `250 2.0.0 Hello <domain>`. Responses carry RFC 3463 enhanced
status codes.

### 13.3 Commands

| Command | Behaviour |
|---|---|
| `EHLO` / `HELO` | Required before MAIL/AUTH. Creates the session. A missing argument → `501 5.5.2`. |
| `STARTTLS` | `220 2.0.0 Ready to start TLS`. If already in TLS → `502 5.5.1`. A failed handshake → `550 5.0.0`. |
| `AUTH PLAIN` | RFC 4616. An initial response is allowed. An authorization identity, if present, MUST equal the authentication identity; otherwise `454 4.7.0 Identities not supported`. |
| `AUTH LOGIN` | Legacy LOGIN mechanism: username and password exchanged as B64 334 challenges. |
| `MAIL FROM:<a>` | Records the reverse path. Accepted parameters: `SIZE=`, `BODY=7BIT|8BITMIME`, `AUTH=<…>`. `SMTPUTF8`, `REQUIRETLS`, `BODY=BINARYMIME` → `504 5.5.4` (not implemented). Reply: `250 2.0.0 Roger, accepting mail from <a>`. |
| `RCPT TO:<a>` | Appends a recipient; an empty address is ignored. Reply: `250 2.0.0 I'll make sure <a> gets this`. |
| `DATA` | `354 2.0.0 Go ahead. End your data with <CR><LF>.<CR><LF>`. Then runs submission (§13.5). |
| `BDAT <n> [LAST]` | RFC 3030 chunking. Intermediate chunks → `250 2.0.0 Continue`. `LAST` triggers submission. |
| `RSET` | `250 2.0.0 Session reset`. Clears the reverse path and recipients. |
| `NOOP` | `250 2.0.0 I have sucessfully done nothing` |
| `VRFY` | `252 2.5.0 Cannot VRFY user, but will accept message` |
| `QUIT` | `221 2.0.0 Bye` |
| `SEND SOML SAML EXPN HELP TURN` | `502 5.5.1 <cmd> command not implemented` |

* AUTH is allowed over plaintext on loopback. A second AUTH →
  `503 5.5.1 Already authenticated`. An unknown mechanism → `504 5.7.4`. A
  client cancel (`*`) → `501 5.0.0 Negotiation cancelled`. Bad B64 →
  `454 4.7.0 Invalid base64 data`.
* More than 3 protocol syntax errors →
  `500 5.5.1 Too many errors. Quiting now`, and the connection closes.
* `MAIL` and `RCPT` do not require prior AUTH at the protocol level. An
  unauthenticated transaction fails at DATA with the "account not available"
  error (§13.15).
* After DATA/BDAT completes, successfully or not, the transaction state
  resets.

### 13.4 Authentication

AUTH succeeds by the rule of §10.2. The session then records the Account and
the authenticated **address ID**. Failure reasons map to the reply text
`invalid username or password` (unknown credentials) or `unknown error`, with
code `454 4.7.0`.

### 13.5 Submission Pipeline

On end-of-data, with reverse path *F*, recipients *R* (from RCPT TO) and raw
octets *D*:

1. If *R* is empty → error *InvalidRecipient*.
2. If the session's Account is unknown → error *NoSuchUser*.
3. **Throttle check** (§13.16).
4. *F* MUST match an owned address (case-insensitive, `+tag` stripped);
   otherwise → *InvalidReturnPath*.
5. Read *D* fully. If *D* ends with `CRLF.CRLF`, strip that terminator.
6. **Deduplication** (§13.6). If an identical submission already succeeded
   within the window, return success **without sending**.
7. Parse *D* as MIME (§13.8). If the first address of the top-level `From`
   header parses, it **replaces** *F*. It MUST again match an owned address;
   otherwise → *InvalidReturnPath*.
8. The sender address MUST have `Send = 1` and `Status = 1`. Otherwise →
   *CannotSendFromAddress(address)*.
9. Fetch the mail settings (§7.5).
10. Unlock the User key ring and the sender's Address key ring. Use the
    address's **first key** for every operation below.
11. If the message has no text part, attach an empty text part (§13.8,
    rule 8).
12. If `AttachPublicKey = 1`: attach the armored public key of the first key,
    as described in §13.8 rule 9.
13. Extract the message model (§13.8).
14. Resolve the parent and the drafts to delete (§13.9).
15. Create the draft (§13.10).
16. Upload the attachments and collect their session keys (§13.11).
17. Resolve the per-recipient send preferences (§13.12).
18. Build the packages (§13.13) and send (§8.9).
19. On success: delete the drafts collected in step 14 (failures are only
    logged), and mark the dedup entry as sent with the resulting message ID.
20. On any failure after step 6: remove the dedup entry, and return the
    mapped error (§13.15).

### 13.6 Duplicate Suppression

* Key: (message fingerprint per Appendix A, **set** of recipients compared
  order-independently).
* Entries expire **30 minutes** after insertion.
* SMTP: if an entry with the same key exists, wait up to **90 s** for it to
  resolve.
  * If it was sent, report success without re-sending.
  * If it failed (its entry was removed), insert a new entry and proceed.
* IMAP APPEND (§11.10.4 step 4) only *queries* entries. The recipient set is
  taken from the literal's To/Cc/Bcc headers.

### 13.7 Sender Address Canonicalisation

In the draft, the sender address is replaced by the owned address's
canonical form. If the header address was `local+tag@domain`, the `+tag` is
preserved: `<canonical-local>+tag@<canonical-domain>`.

### 13.8 MIME Parsing and Normalisation

The parser applies these rules in order:

1. **End-of-data trimming.** A trailing `\r\n.\r\n` is removed.
2. **Encoded CTE.** An RFC 2047 encoded-word inside
   `Content-Transfer-Encoding` is decoded.
3. **Charset normalisation.**
   * Every `text/html` part is converted to UTF-8, and every
     `<meta charset>` or `<meta content="…; charset=…">` in it is rewritten
     to `UTF-8`. The HTML is re-serialised only if a meta tag changed.
   * Every non-attachment `text/*` part is converted to UTF-8.
   * In both cases the `charset` parameter is set to `UTF-8`.
   * The decoder comes from the declared charset. If the charset is unknown:
     use no conversion if the body is already valid UTF-8; otherwise detect
     the encoding heuristically from the content.
4. **Inline-image patch** (top-level children only, at least two children).
   For each `image/*` child whose disposition is `inline` (explicit, or
   implied by a Content-ID when no disposition header exists) **and** that
   has no Content-ID:
   * Generate a UUID content ID and set it on the image.
   * If the previous sibling is `text/plain`: convert it to `text/html`
     (`<html><body><p>…</p><img src="cid:<id>"/></body></html>`, with
     newlines turned into `<br/>`).
   * Otherwise: insert a new `text/html; charset=UTF-8` part
     `<html><body><img src="cid:<id>"/></body></html>` before the image.

   Once any patch applies, every other top-level `text/plain` child is also
   converted to HTML in the same way.
5. **Header extraction** (top level):
   * `Subject`: RFC 2047 decoded, with a fallback charset-tolerant decoder.
   * `From`: first mailbox.
   * `To`, `Cc`, `Bcc`, `Reply-To`: address lists.
   * `Message-ID` → ExternalID, with angle brackets stripped.
   * `In-Reply-To` → reply-to ID, with angle brackets stripped.
   * `X-Forwarded-Message-Id` → forward ID, with angle brackets stripped.
   * `References`: split on whitespace and commas, angle brackets stripped.

   SMTP submission rejects unparsable address lists. IMAP draft APPEND
   tolerates them.
6. **Attachment collection** (tree walk; the first matching rule wins):
   1. disposition `attachment` → attachment;
   2. `text/calendar` → attachment;
   3. other `text/*` → body candidate, not an attachment;
   4. any other leaf → attachment.

   For each attachment:

   | Property | Derivation |
   |---|---|
   | MIME type | From `Content-Type`. An empty value means `text/plain`. Duplicate parameters are tolerated. |
   | Name | `filename` from Content-Disposition, else `name` from Content-Type, else `message.eml` for `message/rfc822`, else `attachment<ext>` from the MIME type, else `attachment.bin`. |
   | Content-ID | Set if the disposition is `inline`, or if there is no disposition header and a `Content-Id` is present. Angle brackets and spaces are trimmed. |
   | Data | The decoded body. |

7. **Bodies.**
   * *Rich body*: concatenate all non-attachment `text/html` parts. Within
     `multipart/alternative`, choose the last alternative made entirely of
     `text/html`; otherwise choose the last alternative.
   * *Plain body*: the same walk, preferring `text/plain`. Any selected
     `text/html` part is converted to plain text.
   * *MIME type*: `text/html` if any non-attachment `text/html` part exists
     anywhere; otherwise `text/plain`.
   * *MIME body*: the entire (normalised) message re-serialised. Any part
     whose content has octets ≥ 0x80 is re-encoded as base64.
8. **Empty text part rule.** A message has no text part if (a) the root is
   `multipart/mixed` and none of its direct children without a
   Content-Disposition is `text/*`, or (b) the root is not multipart/mixed and
   is not `text/*`. In that case append a child:
   `Content-Type: text/plain;charset=utf8`,
   `Content-Transfer-Encoding: quoted-printable`, with an empty body.
9. **Adding a child to a non-multipart/mixed root.** Move the root's content
   headers (`Content-Type`, `Content-Disposition`,
   `Content-Transfer-Encoding`) and body into a new first child. The root
   becomes `multipart/mixed`. Public-key attachments use:
   `Content-Type: application/pgp-keys; name="<n>.asc"; filename="<n>.asc"`,
   `Content-Disposition: attachment; name=…; filename=…`,
   `Content-Transfer-Encoding: base64`.
   Here `<n>` = `publickey - <first identity name> - 0x<first 8 hex digits of fingerprint, uppercase>`,
   Q-encoded if needed.

### 13.9 Parent Resolution

Let *refs* = References + [In-Reply-To] (if present).

1. Partition *refs*:
   * **internal**: the reference contains `INTERNAL_ID_DOMAIN`; the Service ID
     is the part before `@INTERNAL_ID_DOMAIN`;
   * **external**: everything else.
2. For each internal ID: list its metadata (`ID` filter; plus `AddressID` =
   the authenticated address in split mode).
   * A non-draft result becomes the parent (a later one overrides an earlier
     one).
   * A draft result is added to *drafts-to-delete*.
3. If there is no parent and *external* is non-empty: list metadata with
   `ExternalID` = the **last** external reference (plus `AddressID` in split
   mode).
   * Exactly one result: it becomes the parent, but only if it has the Sent
     or the Received flag.
   * More than one result: the first with the Sent flag becomes the parent.
   * None: no parent.
4. A lookup failure is logged. The send proceeds without a parent.

### 13.10 Draft Creation

* `Sender`: the parsed From. If it is missing, use *F*; if the address is
  empty, fill in *F*. The address MUST match an owned address (`+tag`
  stripped, case-insensitive); otherwise → *SenderAddressNotOwned*. The
  address is then canonicalised (§13.7).
* `ToList`: the header To entries **whose address is in *R***; other To
  entries are dropped.
* `CCList`: the header Cc, unchanged.
* `BCCList`: the header Bcc, plus every address in *R* that is not already in
  To, Cc or Bcc. The `Name` of the added entries is empty.
* `Subject`, `ExternalID`: from the headers.
* `MIMEType`: from §13.8. `Body` = the rich body if `text/html`, the plain
  body if `text/plain`. Any other type → *UnsupportedOutgoingMIME*.
* `ParentID`: from §13.9.
* `Action`:
  * if In-Reply-To is present and equals `X-Forwarded-Message-Id` → 2
    (forward);
  * else if In-Reply-To is present → 0 (reply);
  * else → 2.
* Create per §8.8. On HTTP 422, map codes 2001, 2024 and 2002 per §13.15.

### 13.11 Attachment Upload

The attachments are uploaded concurrently. For each one:

* Disposition normalisation:
  * `inline` with no Content-ID → `attachment`;
  * `attachment` → unchanged;
  * anything else (including empty) → `inline` if it has a Content-ID,
    otherwise `attachment`.
* The `MIMEType` field is the media type with its original parameters,
  except `name` and `filename`.
* Encrypt, sign and upload per §9.5. Recover the session key keyed by the
  returned attachment `ID`.

### 13.12 Send Preference Resolution

For each recipient address in the **created draft's** To, Cc and Bcc lists
(all looked up concurrently):

1. **Key lookup** (§6.4). On HTTP 422 with code 33102 →
   *RecipientAddressDoesNotExist(address)*. Any other error fails the send.
2. **Contact settings** (§7.6). List the contact emails for the address and
   pick an entry whose `Email` equals the recipient exactly. Fetch the
   contact and read the signed card's group. Missing data means empty
   settings, with `EncryptUntrusted` defaulting to true.
3. **Compute** the preferences (encrypt *e*, sign *s*, scheme *σ*, MIME type
   *m*, public key *k*). Each starts **unset**.

**Encryption scheme values:**

| Value | Name | Meaning |
|---|---|---|
| 1 | Internal | The Service's internal end-to-end scheme. |
| 2 | Encrypted-to-outside | Password-protected external mail. Never chosen by the Gateway. |
| 4 | Clear | Cleartext; optionally signed inline for `text/plain`. |
| 8 | PGP/Inline | Inline PGP, `text/plain` only. |
| 16 | PGP/MIME | RFC 3156 encrypted and signed. |
| 32 | Clear-MIME | RFC 3156 signed, not encrypted. |

**Signature type values:** 0 = none, 1 = detached, 2 = attached.

**Phase A — PGP settings.**

* **Internal recipient** (`RecipientType` = 1):
  * Keys MUST be non-empty.
  * *e* = true, *s* = true, *σ* = "internal".
  * If the contact sets `X-PM-MIMETYPE`, *m* = that value.
  * *k* = the selected key (see below).
* **External with usable WKD keys** (`RecipientType` = 2 and at least one
  parseable key):
  * *e* = `EncryptUntrusted`.
  * If `EncryptUntrusted`, *s* = true; else if the contact sets `X-PM-SIGN`,
    *s* = that value.
  * If the contact sets a scheme, *σ* = that scheme.
  * If *σ* = pgp-mime, unset *m*. If *σ* = pgp-inline, *m* = `text/plain`.
  * *k* = the selected key.
* **External without keys:**
  * *e* = `X-PM-ENCRYPT` (false if absent).
  * If the contact sets `X-PM-SIGN`, *s* = that value. If *e* is true,
    *s* = true.
  * If the contact sets a scheme, *σ* = that scheme.
  * If the contact's sign is true: pgp-mime → unset *m*; pgp-inline →
    *m* = `text/plain`.
  * Otherwise, if the contact sets `X-PM-MIMETYPE`, *m* = that value.
  * If the contact pins keys: *k* = the first pinned key.

**Key selection** (internal and WKD cases):

1. Compare the fingerprints of the contact's pinned keys with the Service
   keys.
2. If any match: the first matching Service key.
3. Else: the first Service key. (If pinned keys exist but none match, an
   interactive client SHOULD ask the user to confirm trust. The Gateway
   proceeds.)

**Phase B — defaults from the mail settings.**

* If *e* is unset, *e* = false.
* If mail settings `Sign` > 0 and *s* is unset, *s* = true.
* If *e* is true, *s* = true.
* If *σ* is unset: `PGPScheme` = 8 → pgp-inline; `PGPScheme` = 16 →
  pgp-mime. Any other value leaves it unset.
* If *s* is true and *σ* = pgp-inline: *m* = `text/plain`. Otherwise, if *m*
  is unset, *m* = mail settings `DraftMIMEType`.

**Phase C — composer MIME type** (the draft's MIME type *c*):

* If the recipient is not internal and *s* is true: *m* = `text/plain` for
  pgp-inline, `multipart/mixed` for anything else.
* Else if *c* = `text/plain`: *m* = `text/plain`.

**Phase D — final mapping.**

| Condition | EncryptionScheme |
|---|---|
| Internal recipient | 1 (Internal) |
| *s* ∧ *e* | 8 if *σ* = pgp-inline, else 16 |
| *s* ∧ ¬*e* | 4 if *σ* = pgp-inline, else 32 |
| otherwise | 4 (Clear) |

`SignatureType` = 1 if *s*, else 0. The result also carries `Encrypt` = *e*,
`MIMEType` = *m* and `PubKey` = *k*.

### 13.13 Package Construction

Partition the recipients by the result of §13.12:

**MIME package.** Built if any recipient has scheme 16 or 32.

* `MIMEType` = `multipart/mixed`.
* Body = the MIME body (§13.8 rule 7), encrypted per §9.7.
* Every member MUST have MIME type `multipart/mixed` and signature type 1.
  A violation is an error.
* Scheme 16: `BodyKeyPacket` = the session key encrypted to *k*. *k* is
  required.
* Scheme 32: the package-level `BodyKey` = the plaintext session key.
* No attachment keys: attachments are already inside the MIME body.

**Text packages.** Built for recipients with scheme 1, 4 or 8, grouped by
*m*:

* *m* = `text/html`: package body = the rich body.
* *m* = `text/plain`: package body = the plain body.
* *m* = `multipart/mixed`: error.

Validation per recipient:

* scheme 1 requires *e*;
* scheme 8 requires *m* = `text/plain`;
* *s* ∧ ¬*e*: scheme 8 is invalid, and scheme 4 requires a `text/plain`
  package.

Per recipient:

* Scheme 4: the package-level `BodyKey` and `AttachmentKeys[id]` = the
  plaintext session keys.
* If *e*: *k* is required, and the signature type MUST be 1.
  `BodyKeyPacket` = the body session key encrypted to *k*.
  `AttachmentKeyPackets[id]` = each attachment session key encrypted to *k*.

In every package, `Addresses[email]` = `{Type: scheme, Signature: type, …}`,
and the package `Type` |= scheme. PGP/Inline (8) is deprecated and SHOULD
trigger a warning in logs.

### 13.14 Response to the Client

On success, the reply is `250 2.0.0 OK: queued`. The sent message reaches
the Sent mailbox through the normal event flow (§12.3.5).

### 13.15 Error Mapping

All submission errors are returned to the client as
**`554 5.0.0 Error: <text>`**. The text is chosen by the first matching rule:

| Condition | Text |
|---|---|
| Recipient key lookup failed with "address does not exist" for address *a* | `No email was sent. The address <a> does not exist. Correct the recipient and resend the message` |
| Same chain, address unknown | `No email was sent. One or more addresses do not exist. Correct the recipients and resend the message` |
| Draft creation returned 422 / 2001 | `This message couldn't be sent because the email client sent a malformed message` |
| *CannotSendFromAddress(a)* | `You cannot send from this address: <a>. Check your email client and gateway settings` |
| Throttled (§13.16) | `Too many failed send attempts. Try again later` |
| *SenderAddressNotOwned* | `The sender address is not valid for this account. Check your email client and account settings, or choose a different sender address` |
| *UnsupportedOutgoingMIME* | `This message uses an unsupported message format. Try plain text or HTML` |
| Authentication check failed | `User Authentication failed. Please check the outgoing server configuration in your mail client and try again` |
| *NoSuchUser* | `The account is not available in the gateway. Verify the outgoing server settings in your mail client and try again` |
| *InvalidRecipient* or *InvalidReturnPath* | `The sender or recipient address is not valid. Review the addresses and resend the message` |
| Anything else | The underlying error text. |

Draft-creation 422 codes 2024 (too large) and 2002 (invalid recipients) are
reported as "message too large" and "invalid list of recipients"
respectively.

### 13.16 Failure Throttling

Per Account:

* Each submission records its request time *t*.
* If the submission fails **and** *t* − *t*_prev ≤ 1 s, increment the
  failure counter. Otherwise (success, or a gap > 1 s), reset it to 0.
  Then *t*_prev ← *t*.
* If the counter is ≥ **3** when a new submission arrives:
  * if *t* − *t*_prev ≥ **20 s**, reset the counter and proceed;
  * otherwise reject with the *Throttled* error, without contacting the
    Service.

---

## 14. Mobile Push-Notification Client Profile

This section specifies how a **Notification Client** (a mobile mail
application, with the Android profile as the reference) receives,
decrypts, presents and acts on push notifications from the Service. It is
independent of the IMAP/SMTP Gateway in §10–§13. It reuses the transport
(§4), authentication (§5) and data model (§7) of this document.

### 14.1 Overview and Design Goals

1. **Confidentiality from the Push Provider.** Every notification travels
   through a third-party Push Provider. The Service MUST encrypt the whole
   notification (topic, sender, subject and recipient metadata) with a public
   key that only the receiving device holds. The Push Provider sees nothing
   but an opaque session identifier and an OpenPGP message.
2. **Account-independent key.** One device key serves every Account signed in
   on the installation. Decrypting a notification needs neither the user's
   password nor an unlocked User or Address key ring. This lets notifications
   be processed while the application is not running and the mailbox keys are
   locked.
3. **Business-unit agnostic envelope.** The decryption step makes no
   assumption about the notification's content beyond "UTF-8 JSON". Product
   semantics are applied in a second, separate parsing step (§14.5).
4. **Bounded background work.** Actions taken from a notification run inside
   the operating system's limited background-execution window (§14.6).

The lifecycle has five phases:

```
 ┌────────────┐   ┌──────────────┐   ┌─────────────┐   ┌───────────┐   ┌───────────────┐
 │ Device key │──▶│ Registration │──▶│  Delivery   │──▶│ Decryption│──▶│ Presentation  │
 │ (§14.2)    │   │ (§14.3)      │   │ (§14.4)     │   │ (§14.4.3) │   │ & action      │
 └────────────┘   └──────────────┘   └─────────────┘   └───────────┘   │ (§14.5–14.7)  │
                                                                       └───────────────┘
```

### 14.2 Device Key

#### 14.2.1 Generation

1. The Notification Client MUST generate the device key locally. It MUST NOT
   synchronise the key's private half with the Service or with other devices.
2. Algorithm: an elliptic-curve OpenPGP key (RFC 4880 / RFC 9580). That is,
   an EdDSA (Ed25519) primary signing key with an ECDH (Curve25519)
   encryption subkey.
3. User ID: a fixed, non-routable placeholder with identical name and email
   components. The RECOMMENDED value is
   `not_for_email_use@domain.tld <not_for_email_use@domain.tld>`. The key
   MUST NOT be usable as, or published as, a mail key.
4. The private key is generated **without** a passphrase.
5. Exactly **one** device key exists per application installation. It is
   shared by all Accounts and sessions on that installation.

#### 14.2.2 Storage

1. The private key is serialised as an **unlocked binary** (unarmored)
   OpenPGP transferable secret key, then encoded as B64 for storage.
2. The B64 string MUST be stored only in the platform's secure credential
   store (for example, a hardware-backed key store or keychain). It MUST NOT
   be written to the general application database, logs or backups.
3. The serialised bytes are secret. In-memory copies SHOULD be zeroed when
   no longer needed.
4. On load, the client decodes the B64, imports the unlocked binary secret
   key, and derives the public key from it. The public key is never stored
   separately as a secret.

#### 14.2.3 Reuse and Regeneration

* If a device key is already in the secure store, the client MUST reuse it
  for every registration.
* If none exists (first run, or the secure store was cleared), the client
  MUST generate a new key, store it (§14.2.2), and use its public half for
  the registration in progress.
* A regenerated key makes notifications encrypted to the previous key
  undecryptable. Because registrations are repeated for every session on
  every process start (§14.3.3), the Service learns the new key at the next
  registration pass.

#### 14.2.4 Public-Key Export

For registration, the public key is exported as an **ASCII-armored** OpenPGP
public key block (`-----BEGIN PGP PUBLIC KEY BLOCK-----` …).

### 14.3 Device Registration

#### 14.3.1 Inputs from the Platform

The host platform supplies a **device registration record**:

| Element | Type | Description |
|---|---|---|
| Device token | string | The Push Provider address of this installation. |
| Environment | enumeration | The Push Provider and build channel (§14.3.4). |
| Ping notification status | integer, OPTIONAL | Opaque platform-reported status of background "ping" delivery. Passed through unchanged. |
| Push notification status | integer, OPTIONAL | Opaque platform-reported status of user-visible notification permission. Passed through unchanged. |

The platform MAY update this record at any time, for example when the Push
Provider rotates the token or the user changes notification permissions.

#### 14.3.2 Request

`POST /core/v4/devices` (authenticated with the session being registered,
§4.2):

```json
{
  "DeviceToken": "<push provider token>",
  "Environment": <integer, §14.3.4>,
  "PublicKey": "<ASCII-armored device public key>",
  "PingNotificationStatus": <integer | null>,
  "PushNotificationStatus": <integer | null>
}
```

* Absent OPTIONAL statuses are sent as JSON `null`.
* `PublicKey` is always present in this profile. A null `PublicKey` would ask
  for unencrypted delivery, which this profile forbids.
* Success: HTTP 200 with `"Code": 1000`. The response body carries nothing
  else of significance.

A registration binds **(session UID, device token, device public key)** on
the Service. Every Account signed in on the device is registered separately,
under its own session.

#### 14.3.3 Registration Procedure

The client runs a long-lived background registration process. Its only state
is the **current registration record** and the **set of session UIDs already
registered** in this process lifetime. Both are held in memory only.

1. **Triggers.** The procedure runs one step whenever either of these
   happens:
   a. the platform supplies a new or changed registration record. The client
      then clears the registered-session set, because every session must be
      re-registered under the new token;
   b. the set of stored sessions changes (a session is added, rotated or
      replaced). Only sessions not yet in the registered set are processed.
2. **Candidate selection.** Candidates are stored sessions whose UID is not
   in the registered set **and** whose Account is fully signed in. A session
   that is still mid-login, still waiting for a second factor, or still
   waiting for key unlock MUST be skipped silently. It is picked up on a
   later trigger.
3. If there are no candidates, or no registration record has been supplied
   yet, the step ends.
4. For each candidate:
   a. obtain the device public key (§14.2.3);
   b. send the request in §14.3.2 with the candidate's session;
   c. on success, add the UID to the registered set.
5. **Error handling** (per step):

| Condition | Behaviour |
|---|---|
| Network failure (no HTTP response, or a transport error classed as network) | Wait until the OS reports connectivity, then wait a further **500 ms**, then retry the whole step. The delay prevents a tight loop when the connectivity probe succeeds but the endpoint keeps failing. |
| HTTP 403 with API error code **9100** (missing scopes) | The session is authenticated but not yet fully scoped, typically because a second factor is pending. Abandon the step **without** error. The scope upgrade later changes the stored session, which re-triggers registration. |
| Another in-memory user context already owns the Account (the session was rotated while the old context is alive) | Skip that session, log a warning, and continue with the others. |
| Device-key generation, storage or export fails | Fatal for the step. Report the error. |
| Any other API error | Fatal for the step. Report the error. |

6. Because the registered set lives only in memory, every process start
   re-registers every signed-in session as soon as the platform supplies the
   registration record. This is REQUIRED behaviour. It keeps the Service's
   view of the token and key current.

#### 14.3.4 Environment Codes

| Value | Push Provider / channel |
|---|---|
| 4 | Android cloud messaging (the reference profile) |
| 6 | Apple push, production |
| 7 | Apple push, beta / pre-release |
| 14 | Apple push, production, alternate app target |
| 15 | Apple push, development, alternate app target |
| 16 | Apple push, development |

Other values MUST NOT be sent. On a local store, values outside this table
MUST be rejected as out of range.

#### 14.3.5 Unregistration

This profile defines no explicit unregistration request. A registration is
scoped to the session that created it, so revoking the session (§5.5.2) ends
delivery for that Account. On sign-out, a client SHOULD revoke the session.

### 14.4 Delivery and Decryption

#### 14.4.1 Push Envelope

The Push Provider delivers a data message carrying two string fields:

| Field | Description |
|---|---|
| `UID` | The session UID (§5.1.6) of the recipient Account's registered session. This is **not** the UserID. |
| `encryptedMessage` | An ASCII-armored OpenPGP message (`-----BEGIN PGP MESSAGE-----` …), encrypted to the device public key. |

The field names are case-sensitive, and their casing differs on purpose.
The envelope carries nothing else in the clear.

#### 14.4.2 Service-Side Encryption (informative)

The Service:

1. builds the notification object (§14.5) and serialises it as UTF-8 JSON;
2. encrypts the octets to the device public key registered for the target
   session, as a raw (literal-data) OpenPGP message, ASCII-armored;
3. adds **no** signature;
4. places the result, and the session UID, into the envelope.

#### 14.4.3 Client-Side Decryption

On receipt, the client MUST:

1. Load the device private key from the secure store (§14.2.2). If it is
   missing, fail with a cryptographic error. The notification cannot be
   shown, and the client MUST NOT ask the Service for its content.
2. Decrypt `encryptedMessage` (armored) with the device private key.
3. **Not** verify a signature. The notification is encrypted to a public key
   and carries no signer, so authenticity comes only from the channel and
   from the follow-up authenticated API calls (§14.7). Content from a
   notification MUST therefore be treated as **advisory display data**. It
   MUST NOT be stored as authoritative mailbox state.
4. Parse the plaintext as UTF-8 JSON. If parsing fails, report a
   deserialisation error.
5. Map `UID` to a locally stored session. That identifies which Account the
   notification belongs to. If no local session matches the UID, the client
   SHOULD discard the notification.
6. Run product-level parsing (§14.5).

Decryption needs no network access and no unlocked mailbox keys.

Failures in steps 1–4 MUST be logged without the plaintext, and the
notification MUST be dropped.

### 14.5 Notification Payloads

#### 14.5.1 Discriminated Union

The decrypted JSON is an adjacently tagged object:

```json
{ "type": "<kind>", "data": { ... } }
```

| `type` | Meaning |
|---|---|
| `email` | A new or changed mail message (§14.5.2). |
| `open_url` | An informational notice that opens a web page when tapped. For example, the Service sends one when the Account signs in on a new device (§14.5.3). |

A client MUST reject an unknown `type` with a deserialisation error. It MUST
NOT display unknown types.

Within `data`, property names are **camelCase**, except inside the sender
object (§14.5.4), which uses **PascalCase**. Boolean-like presentation hints
use **IntBool** (§2).

#### 14.5.2 `email` Payload

| Field | Type | Req. | Description |
|---|---|---|---|
| `title` | S | yes | Notification title, as the Service rendered it. |
| `subtitle` | S | yes | Notification subtitle, as the Service rendered it. |
| `body` | S | yes | The message **subject**. |
| `messageId` | S | yes | The Service message ID (§7.4). |
| `sender` | Sender | yes | §14.5.4. |
| `badge` | I | yes | Value for the application-icon badge (unread count). |
| `largeIcon` | S | yes | Constant `"large_icon"`. Clients ignore it. |
| `smallIcon` | S | yes | Constant `"small_icon"`. Clients ignore it. |
| `sound` | IntBool | no | Play a sound. Default 0. |
| `vibrate` | IntBool | no | Vibrate. Default 0. |
| `action` | S | no | **Android profile only.** See below. |

**`action` values:**

| Value | Client behaviour |
|---|---|
| `message_created` | A new message arrived. Show a full notification. |
| `message_touched` | Another device has already seen or handled the message (it corresponds to the *Touched* message flag, §7.4). The client SHOULD dismiss any notification it is showing for `messageId`, and SHOULD NOT show a new one. |
| *absent* | Treat as `message_created`. Non-Android profiles never send `action`. |
| *any other string* | Forward-compatible. The client MUST accept the payload, keep the raw value, and SHOULD NOT show a notification for it. |

A message that has a `message_created` notification on display can be
cleared later by a `message_touched` notification with the same `messageId`.
Clients SHOULD therefore key displayed notifications by
(Account, `messageId`), and SHOULD group them per Account.

#### 14.5.3 `open_url` Payload

| Field | Type | Req. | Description |
|---|---|---|---|
| `title` | S | yes | Title. |
| `subtitle` | S | yes | Subtitle. |
| `body` | S | yes | Notification text. |
| `url` | S | yes | Absolute URL to open when the user taps the notification. |
| `sender` | Sender | yes | §14.5.4. |
| `badge` | I | yes | Badge value. |
| `largeIcon`, `smallIcon` | S | yes | Constants. Ignored. |
| `messageId` | S | yes | Correlation identifier. May be empty. Not a mail message reference. |
| `sound`, `vibrate` | IntBool | no | As in §14.5.2. Default 0. |

When the user taps the notification, the client SHOULD open `url` in an
in-application web view. The client SHOULD refuse to open URLs whose scheme is not `https`.

#### 14.5.4 Sender Object

```json
{ "Name": "<display name>", "Address": "<email>", "Group": "<contact group name or empty>" }
```

All three properties are REQUIRED strings and MAY be empty. They are
personal data. Clients MUST redact them in logs.

#### 14.5.5 Presentation Model

After parsing, a client needs only:

* **email:** subject (`body`), sender (Name, Address, Group), `messageId`,
  `action`, and the owning Account (from `UID`);
* **open_url:** content (`body`), sender, `url`, and the owning Account.

`title`, `subtitle`, `badge`, `sound`, `vibrate` and the icon fields are
hints. A client MAY render its own title, for example from the sender name
and the Account address, and MAY apply the user's local sound and vibration
preferences instead.

### 14.6 Notification Quick Actions

#### 14.6.1 Action Set

An `email` notification MAY offer these actions. Each targets the Service
message ID from the payload. When the action fires, the client may not know
any local identifier for the message.

| Action | Remote effect | Endpoint |
|---|---|---|
| Mark as read | Clear *Unread* | `PUT /mail/v4/messages/read` with `{"IDs": ["<messageId>"]}` |
| Move to Archive | Move to system label `6` | `PUT /mail/v4/messages/label` with `{"Action": 1, "IDs": ["<messageId>"], "LabelID": "6", "SpamAction": null}` |
| Move to Trash | Move to system label `3` | `PUT /mail/v4/messages/label` with `{"Action": 1, "IDs": ["<messageId>"], "LabelID": "3", "SpamAction": null}` |

Responses follow §8.7: `{"Code": 1001, "Responses": [{"ID", "Response": {"Code", "Error"}}], "UndoToken": …}`
for label, and `{"Responses": [...]}` for read. Quick actions never use undo
tokens.

#### 14.6.2 Execution Procedure

Inputs: the Account (resolved from `UID`), the action, and OPTIONALLY the
remaining background-execution time *T* that the operating system reports,
in milliseconds.

1. Resolve the Account's session. If the Account has no initialised session
   (for example, signed out), finish successfully without doing anything.
2. **Time budget.** If *T* is known, the request deadline is
   `min(T − 1 s, 30 s)`, floored at zero. The 30 s cap reflects the shortest
   background window that mobile operating systems guarantee for
   notification handlers. If *T* is unknown, the normal request timeout
   applies.
3. **Immediate remote attempt.** Send the request in §14.6.1 once, within
   the deadline, with transport-level retries (§4.5) **disabled**.
4. **Durable enqueue.** Whatever the result of step 3, record the action in
   the Account's persistent outgoing-action queue at the **highest**
   priority. The record holds:
   * the action and its target message ID;
   * a flag that says whether the remote request must still be sent. The
     flag is *true* if step 3 failed and *false* if it succeeded.
5. **Local application.** When the queued action is processed locally:
   * If the message already exists in the local store, apply the matching
     local mutation (mark read, or move to Archive or Trash) and record its
     inverse so that it can be reverted.
   * If the message is not in the local store, which is the usual case
     because the notification arrived before event sync, do nothing locally.
     The next event sync (§12.3) brings the server state, which already
     reflects the action.
6. **Deferred remote application.** When the queue runs its remote phase,
   it re-sends the request in §14.6.1 only if the flag is *true*. It then
   uses the queue's normal retry policy and no deadline.
7. **Revert.** If the queued action fails permanently, any local mutation
   from step 5 MUST be reverted.
8. **Rebase.** When server state for the message arrives later, the queued
   action needs no reconciliation of its own. Server state wins.

Queue records MUST be versioned. A record written by an earlier format that
lacks the remote-pending flag MUST be read with the flag set to *true*.

### 14.7 Opening a Notification

When the user taps an `email` notification, the client MUST show fresh
server state, not cached state. Locally cached data may be stale, or the
message may not have been synced yet.

#### 14.7.1 Message Resolution

1. **Always fetch.** Request the message metadata by ID, even if a local copy
   exists:
   `GET /mail/v4/messages?ID[0]=<messageId>&Page=0`
   (array filters use indexed query parameters).
   Response: `{"Messages": [MessageMetadata], "Total": I, "Stale": B, ...}`.
2. If `Messages` is empty, fail with "message not found on server" and show
   nothing.
3. **Dependencies.** Before storing the message, fetch and store any
   referenced objects that are missing locally: labels and folders in
   `LabelIDs`, the owning Address, and the conversation.
4. **Store.** In one local transaction:
   a. decide whether the server copy may overwrite the local copy. If the
      message is a draft that is open in a local composer, and it has not
      been sent or scheduled in the meantime, the stored copy is kept as is.
      Otherwise the server copy is applied;
   b. upsert the message;
   c. re-apply ("rebase") every pending local action that touches this
      message, so that the stored state equals server state plus pending
      local intent.
5. Re-read the message from the local store and return it. It now carries
   the server update with the rebased local actions applied.

#### 14.7.2 Conversation Opening

When the client opens the conversation that holds the resolved message, and
the open was triggered by a notification:

1. If the OS reports no connectivity, fail with a network error. A
   notification-originated open MUST NOT silently fall back to stale data.
2. Request `GET /mail/v4/conversations/{conversationId}`.
   Response: `{"Conversation": Conversation, "Messages": [MessageMetadata]}`.
3. If the request returns HTTP 422 with API code **20052** (conversation does
   not exist), the conversation has been deleted. Show nothing; this is not
   an error.
4. Fetch missing dependencies, as in §14.7.1 step 3, for the conversation
   and each message.
5. Store the conversation and its messages, and rebase pending local
   actions, in one transaction.
6. Display the conversation in the context of the label the user opened it
   from (normally Inbox). If the conversation no longer carries that label,
   report an error to the user interface; do not show an empty view.
7. Choose the focused message with the label's normal rule: the oldest
   message in the most recent run of consecutive unread messages, or else
   the latest message.
8. If the conversation was resurfaced by a snooze reminder, mark it as read
   in that label.

Message bodies are fetched and decrypted later, on demand, with the
Address key ring (§9.2). Neither the notification nor the device key ever
gives access to message bodies.

### 14.8 Relationship to Authentication

* **SRP is not used** to receive or decrypt notifications. The device key
  works without the user's password and without any SRP exchange.
* Registration (§14.3) and every follow-up request (§14.6, §14.7) need a
  session established through the normal login (§5.1–§5.4), including any
  second factor (§5.2). On a 401 they refresh the token as in §4.7.
* A session that is still waiting for its second factor has reduced scopes.
  Its registration requests fail with code 9100 and are deferred (§14.3.3).
* Mobile clients send `x-pm-appversion` as `<platform>-<product>@<semver>`.
  The `<platform>` token names the mobile operating system, for example
  `android`. The values listed in §4.2 apply only to desktop clients.

### 14.9 Error Summary

| Phase | Condition | Outcome |
|---|---|---|
| Registration | Network failure | Wait for connectivity, then 500 ms, then retry. |
| Registration | 403 / 9100 | Defer until the session's scopes change. |
| Registration | Duplicate in-memory context | Skip the session. |
| Registration | Key failure / other API error | The step fails and the error is reported. |
| Decryption | Device key missing or unreadable | Cryptographic error. The notification is dropped. |
| Decryption | OpenPGP decryption fails | Cryptographic error. The notification is dropped. |
| Decryption | Plaintext is not valid JSON | Deserialisation error. The notification is dropped. |
| Parsing | Unknown `type` | Deserialisation error. The notification is dropped. |
| Parsing | Unknown `action` | Accepted. Typically not displayed. |
| Quick action | Immediate attempt fails or times out | Queued for a deferred remote retry. |
| Quick action | Account has no session | Success, with no effect. |
| Open | Message not on server | "Not found". Nothing is displayed. |
| Open | Conversation deleted (422 / 20052) | Nothing is displayed. Not an error. |
| Open | Offline | Network error. No stale fallback. |

---

## 15. Security Considerations

1. **Loopback only.** Both listeners MUST bind to 127.0.0.1. They speak
   plaintext by default. Exposing them on other interfaces would leak
   decrypted mail and the Gateway password.
2. **Gateway password.** It is a high-entropy random secret (128 bits) that
   is independent of the Service password, so the Service password never
   reaches a mail client. It MUST be compared in constant time.
3. **Secrets at rest.** The salted key passphrase, the refresh token and the
   Gateway password MUST be stored encrypted. The key SHOULD come from an OS
   credential store. The plaintext Service password and mailbox password
   MUST NOT be stored.
4. **SRP.** The modulus MUST be verified against the pinned signing key, and
   the server proof MUST be verified. Otherwise a malicious endpoint could
   learn a password-equivalent verifier or impersonate the Service.
5. **Key trust.** Service-provided recipient keys are trusted by default.
   Pinned contact keys take precedence when their fingerprints match. Where
   they do not match, an implementation SHOULD offer a trust-confirmation
   step.
6. **Signature verification.** Incoming message signatures are **not**
   verified when literals are built. Clients that need signature validation
   must verify the `multipart/signed` output themselves, when it is present.
7. **Debug logging.** Any IMAP/SMTP protocol trace exposes decrypted message
   content. It MUST be opt-in and SHOULD carry a prominent warning.
8. **Memory hygiene.** Unlocked private keys SHOULD be wiped after each
   operation.
9. **Denial of service.** The admission controls of §11.12, the IMAP login
   throttle and the SMTP failure throttle bound the load that runaway
   clients can impose on the Service.
10. **Push-notification confidentiality.** Notifications are encrypted end to
    end to the device key. The Push Provider sees only the session UID, the
    ciphertext size and the delivery timing. Implementations MUST NOT ask for
    unencrypted delivery, and MUST NOT add plaintext fields to the push
    envelope.
11. **Device-key protection.** The device private key is stored unlocked. Its
    protection depends entirely on the platform's secure credential store.
    It MUST be excluded from backups and device-transfer mechanisms. If it is
    compromised, past and future notifications for every Account on the
    device are exposed, but message bodies and mailbox keys are not.
12. **Unauthenticated notification content.** Notifications are not signed.
    Their content is advisory display data. All state changes come from
    authenticated API calls (§14.6, §14.7). Notification text MUST be
    rendered as plain text, never as markup. `open_url` targets SHOULD be
    restricted to `https`.
13. **Personal data in logs.** Sender names, addresses, subjects and
    decrypted payloads MUST NOT be logged in clear.

---

## 16. Appendix A — Message Fingerprint Algorithm

This fingerprint identifies "the same message" across SMTP submission and a
subsequent IMAP APPEND, even though header ordering, boundaries and
transfer encodings may differ.

```
h = SHA-256 context

for F in [Subject]:
    h.update( value of top-level header F, as is )
for F in [From, To, Cc, Reply-To, In-Reply-To]:
    h.update( concat of the bare addr-spec of each address parsed from F
              — or the raw value if it does not parse )

for each LEAF part, in depth-first document order:
    (type, params) = parse(Content-Type)
    if parse succeeds:
        h.update(type)
        for each param key k in ascending byte order, k ≠ "boundary" (case-insensitive):
            h.update(k); h.update(params[k])
    h.update( raw Content-Disposition value )
    body = raw part body
    if type ∈ {text/plain, text/html}:
        decode body per Content-Transfer-Encoding (quoted-printable | base64 | identity)
    remove every CR (0x0D); trim leading/trailing whitespace
    h.update(body)

fingerprint = B64( h.digest() )
```

---

## 17. Appendix B — Default Values and Limits

| Parameter | Value |
|---|---|
| IMAP port | First free port ≥ 1143 |
| SMTP port | First free port ≥ 1025, excluding the IMAP port |
| Listener security | Plain + STARTTLS |
| Show All Mail | On |
| Address mode | Combined |
| Event poll period | 20 s + U[0, 20 s) |
| Event chain cap | 50 per poll |
| Application back-off | 20, 40, 80, 160, 300, 600 s + U[0, 10 s) |
| Transport retries | 3; Retry-After default 10 s + U[0, 10 s); wait cap 60 s |
| Sync retry cool-down | 20 s |
| Sync metadata page | 128 |
| Sync batch | ≤ 64 messages, or the memory budget |
| Sync max parallel downloads | 64 |
| Sync memory | 2 GiB default; clamped to [800 MiB, RAM/2] |
| List page size cap | 150 |
| Bulk action chunk | 150 IDs |
| ID enumeration page | 1000 |
| Import batch | ≤ 10 messages and ≤ 70 MiB |
| Import message size cap | 70 MiB (encrypted) |
| Send dedup entry lifetime | 30 min |
| Send dedup wait | 90 s |
| SMTP failure throttle | 3 failures within 1 s of each other → 20 s lockout |
| SMTP max line | 65 536 octets |
| IMAP login throttle | 3 consecutive failures; jail default 0 s |
| IMAP session error cap | 20 consecutive bad commands |
| IMAP IDLE batching | 500 ms |
| IMAP new-connection cap | 400 per rolling 60 s |
| Apple Mail session cap | 60 (fallback 25) |
| UIDVALIDITY epoch | 2023-02-01T00:00:00Z |
| New label color | `#f66` |
| TLS certificate | RSA-2048, 20-year, CN/SAN 127.0.0.1; renew when < 31 days remain |
| TLS minimum version | 1.2; no client certificate request |
| Gateway password | 16 random octets, B64URL-NP |
| SRP size | 2048 bits, generator 2 |
| bcrypt | `$2y$`, cost 10 |
| Device key algorithm | ECC (Ed25519 primary, Curve25519 ECDH subkey), no passphrase |
| Device key user ID | `not_for_email_use@domain.tld <not_for_email_use@domain.tld>` |
| Device keys per installation | 1 (shared by all Accounts) |
| Device registration retry delay | Wait for connectivity, then 500 ms |
| Quick-action deadline | min(remaining OS time − 1 s, 30 s); no transport retries |
| Quick-action queue priority | Highest |

---

## 18. Appendix C — Status and Error Code Tables

### C.1 SMTP Replies Used

| Code | Enhanced | Meaning |
|---|---|---|
| 220 | — | Greeting; STARTTLS ready |
| 221 | 2.0.0 | Bye |
| 235 | 2.0.0 | Authentication succeeded |
| 250 | 2.0.0 | OK / queued / continue |
| 252 | 2.5.0 | VRFY not supported |
| 334 | — | AUTH challenge |
| 354 | 2.0.0 | Start mail input |
| 421 | 4.0.0 / 4.4.5 | Internal error / too busy |
| 451 | 4.0.0 | Session or backend error during HELO/MAIL/RCPT |
| 454 | 4.7.0 | Authentication failed / invalid B64 |
| 500 | 5.5.x | Syntax error / too many errors |
| 501 | 5.5.2 / 5.5.4 / 5.0.0 | Argument error / negotiation cancelled |
| 502 | 5.5.1 | Command not implemented or out of sequence |
| 503 | 5.5.1 | Already authenticated |
| 504 | 5.5.4 / 5.7.4 | Parameter or mechanism not implemented |
| 523 | 5.7.10 | TLS required (not used on loopback) |
| 550 | 5.0.0 | TLS handshake error |
| 552 | 5.3.4 | Message size exceeded (only if a limit is configured) |
| 554 | 5.0.0 | Submission failed (§13.15) |

### C.2 IMAP Response Codes Used

`CAPABILITY`, `APPENDUID`, `COPYUID`, `TRYCREATE`, `UIDVALIDITY`, `UIDNEXT`,
`PERMANENTFLAGS`, `UNSEEN`, `READ-ONLY`, `READ-WRITE`.

### C.3 Event Action Codes

0 = delete, 1 = create, 2 = update, 3 = update flags.

### C.4 Create-Draft Action Codes

0 = reply, 1 = reply-all, 2 = forward, 3 = auto-response, 4 = read receipt.

### C.5 Push Device Environment Codes

4 = Android cloud messaging, 6 = Apple production, 7 = Apple beta,
14 = Apple production (alternate target), 15 = Apple development (alternate
target), 16 = Apple development.

### C.6 Push-Notification API Error Codes

| HTTP | Code | Context | Meaning |
|---|---|---|---|
| 403 | 9100 | Device registration | Session scopes are missing (second factor pending). Defer. |
| 422 | 20052 | Conversation fetch | The conversation does not exist. |

### C.7 Push Payload Discriminators

`type`: `email`, `open_url`. `action` (Android only): `message_created`,
`message_touched`; any other value is preserved and ignored.

---

*End of document.*

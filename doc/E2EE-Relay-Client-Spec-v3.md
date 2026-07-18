# E2EE Event Sync Relay — Client Adaptation Specification (v3)

Copyright (c) 2026 Thibault Ducray. Licensed under the MIT License.

**Status:** Draft v3

**Scope:** Client guidance for macOS/iOS and PC:
- local-first vault storage
- event-based sync
- SGK encryption
- multi-recipient fan-out
- iOS-aware polling strategy
- **SGK rotation procedure (detailed)**

---

## 1. Summary requirements

Clients MUST:
- Encrypt events using AEAD with **SGK**.
- Use AAD binding (message context + recipient list hash).
- Apply events idempotently (event_id).
- Maintain anti-replay (seen message_ids).
- ACK messages only after durable apply.
- Support **SGK rotation** and key epochs.

---

## 2. Local-first storage (no vendor lock)

### 2.1 Vault DB
- SQLite on local filesystem.
- WAL mode.
- Single-writer.

### 2.2 Secure storage
- iOS/macOS: Keychain (tokens, SGK, pairing secrets).
- Windows: Credential Manager / DPAPI.
- Linux: Secret Service / KWallet.

---

## 3. Identity & routing

### 3.1 Initial bootstrap
1. `GET /relay/v3/registration/challenge` → obtain `{nonce, version, server_date, expires_at}`.
2. Compute `challenge_response` (see §3.3).
3. `POST /relay/v3/devices` with `challenge_nonce` + `challenge_response` → obtain `device_id`, `inbox_id`, `send_token`, `recv_token`.
4. Store all credentials in secure storage (Keychain / Credential Manager / Secret Service).

On `401 challenge_failed`: fetch a new nonce and retry. Do not reuse nonces.
On `401 token_expired`: repeat the full bootstrap; share the new `inbox_id` with sync peers.

### 3.2 Device directory (group membership)
Maintain locally:
- device_id
- inbox_id
- display name
- status (active/revoked)
- last_seen

This directory is shared to new devices during pairing.

### 3.3 Registration challenge-response

Device registration is gated by a challenge-response that proves the client holds the **master key** without ever transmitting it.

#### Master key

The master key is a shared secret distributed to authorised clients out-of-band (embedded in the app, injected via a secure config system, or stored in a hardware keystore).

| Property | Requirement |
|---|---|
| Length | Minimum 16 bytes; **recommended 32 bytes** |
| Entropy | Cryptographically random |
| Storage | Never log, transmit, or store in plaintext; use platform keystore |
| Format on server | `MASTER_KEY_B64URL` (base64url, no padding) or `MASTER_KEY` (raw text ≥ 16 chars) |

#### Key hierarchy

```
master_key   (never transmitted)
    │
    └─ daily_key = HMAC-SHA256(master_key,  version + ":" + server_date)
            │
            └─ response  = HMAC-SHA256(daily_key,   nonce + ":" + version + ":" + platform + ":" + client_version)
```

The daily key rotates every UTC day, bounding the exposure window for any key material derived from the master key.

#### Computation rules

- All string inputs are **UTF-8 encoded** before use as HMAC input.
- `nonce` is used as-is — the base64url string returned by the server, **not** decoded to bytes.
- `platform` and `client_version` must match **exactly** the strings sent in the registration body.
- `response` is base64url-encoded (no padding) and placed in `challenge_response`.

#### Reference pseudocode

```python
def compute_challenge_response(
    master_key: bytes, version: str, server_date: str,
    nonce: str, platform: str, client_version: str,
) -> bytes:
    daily_key = HMAC_SHA256(key=master_key,   msg=f"{version}:{server_date}")
    return    HMAC_SHA256(key=daily_key,     msg=f"{nonce}:{version}:{platform}:{client_version}")

challenge_response_field = base64url_nopad(compute_challenge_response(...))
```

#### Nonce lifecycle

- Each nonce is **single-use** and valid for **2 minutes**.
- A nonce is atomically consumed on successful registration.
- On any error (network failure, wrong HMAC), fetch a **new nonce** — do not reuse.
- Do not cache nonces between app launches.

---

## 4. Sync cryptography (SGK)

### 4.1 SGK and epochs
For each `stream_id` (vault), maintain:
- `sgk_epoch` (integer, starts at 1)
- `SGK[epoch]` (current + optionally previous during overlap)

Events include `sgk_epoch` in the encrypted plaintext and SHOULD include it in AAD.

### 4.2 Encryption
- AEAD: AES-GCM or ChaCha20-Poly1305.
- Random nonce per message.

### 4.3 AAD (canonical)
AAD MUST include:
- message_id
- stream_id
- sender_device_id
- hash(sorted(recipient_inbox_ids))
- cipher_version
- sender_counter
- sgk_epoch

---

## 5. Event model

### 5.1 Standard event
Plaintext (before encryption):

```json
{
  "type": "vault_event",
  "stream_id": "opaque_stream_id",
  "event_id": "uuid-v4",
  "sgk_epoch": 3,
  "sender_device_id": "uuid-v4",
  "sender_counter": 123,
  "logical_clock": {"device": "uuid-v4", "counter": 123},
  "op": "upsert|delete",
  "record_id": "uuid-v4",
  "payload": {
    "record_revision": 77,
    "encrypted_fields": {"password_enc": "..."},
    "metadata": {"title": "..."}
  }
}
```

### 5.2 Idempotence
- Apply only if `event_id` not already in `applied_event_ids`.
- Persist applied markers before ACK.

---

## 6. Pairing (QR-based)

Pairing bootstraps:
- SGK + sgk_epoch for one or more streams
- device directory

(Flow unchanged from v2; keep ECDH + HKDF + AEAD; confirmation + expiry.)

---

## 7. Sync engine

### 7.1 Fan-out (multi-recipient)
When sending an event:
- Build `recipient_inbox_ids = all active device inboxes excluding self`.
- Encrypt once with SGK.
- Send a single relay message with the recipients array.

### 7.2 Polling policy

#### iOS
- On entering foreground: poll immediately.
- While foreground: poll every 2 minutes OR keep long-poll open.
- Background: no continuous polling; best-effort using BGAppRefreshTask.

#### macOS + PC
- On startup: poll immediately.
- While running:
  - prefer long-poll to reduce request rate
  - or poll every 1–2 minutes

### 7.3 Processing loop
For each relay message:
1. If message_id already seen: ACK and skip.
2. Decrypt:
   - try current SGK epoch
   - if fails, try previous epoch within overlap window
3. Validate AAD.
4. Parse event.
5. If event_id already applied: ACK and skip.
6. Apply event in DB transaction.
7. Persist applied marker + counters.
8. ACK.

---

## 8. SGK rotation (detailed)

### 8.1 When to rotate
Rotate SGK when:
- a device is revoked (security requirement)
- user explicitly requests “rekey”
- periodic hygiene (optional)

### 8.2 Rotation event type
Define a special event:

```json
{
  "type": "key_rotation",
  "stream_id": "opaque_stream_id",
  "event_id": "uuid-v4",
  "sender_device_id": "uuid-v4",
  "sender_counter": 456,
  "from_epoch": 3,
  "to_epoch": 4,
  "new_sgk": "base64(32 bytes)",
  "effective_at_counter": 500,
  "overlap_policy": {
    "accept_from_epoch": 3,
    "accept_to_epoch": 4,
    "overlap_max_age_seconds": 604800
  }
}
```

**Encryption rule:**
- The `key_rotation` event is encrypted with **SGK[from_epoch]**.
- It is sent only to **active** devices (revoked device inboxes excluded).

### 8.3 Distribution (fan-out)
- Build `recipient_inbox_ids = all active devices excluding sender`.
- Use a **longer TTL** for rotation messages (recommend 30 days) to tolerate offline devices.

### 8.4 Applying rotation on receiver
When a device receives a `key_rotation` event:
1. Verify it decrypts under current epoch (`from_epoch`).
2. Verify `to_epoch == from_epoch + 1`.
3. Store `SGK[to_epoch]` securely.
4. Set current epoch to `to_epoch`.
5. Start encrypting outgoing events with `SGK[to_epoch]`.

### 8.5 Overlap window (compatibility)
To handle in-flight messages and temporary desync:
- Devices SHOULD accept decryptions with:
  - the current epoch, and
  - the immediate previous epoch,
for up to `overlap_max_age_seconds` (e.g., 7 days).

After overlap expires, drop the previous SGK from secure storage.

### 8.6 Handling devices that missed the rotation
Because rotation messages have long TTL:
- Offline devices will receive the rotation event upon next poll.
- Until then, they may continue sending events encrypted under the old SGK.

Receiver behavior:
- During overlap window, accept old-epoch events.
- After overlap window, reject old-epoch events (tamper / outdated key).

### 8.7 Rotation on device revocation
Revocation procedure (client-side):
1. Remove revoked device from device directory.
2. Trigger SGK rotation.
3. Send `key_rotation` event to remaining devices.
4. Optionally send a `device_directory_update` event to propagate the updated directory.

### 8.8 Security notes
- In this model, a revoked device *still knows* the old SGK, but it will not receive the rotation message because:
  - it is excluded from `recipient_inbox_ids`, and
  - it cannot submit forged messages without a valid send_token.
- Therefore, it cannot learn the new SGK via the relay.

---

## 9. macOS & PC client implementation guidance

### 9.1 macOS (Swift)
- Keep sync engine running while app is open.
- Prefer long-poll with a background Task.
- Persist outbox and applied_event_ids in SQLite.
- Store tokens + SGK epochs in Keychain.

### 9.2 Windows
- Suggested model: tray app that starts at login.
- Networking: background thread with long-poll.
- Storage:
  - SQLite for vault + sync metadata
  - Credential Manager for tokens + SGK

### 9.3 Linux
- Suggested model: user-level daemon (systemd --user) or tray app.
- Secret storage: Secret Service.

### 9.4 Cross-platform serialization
- Use canonical JSON or CBOR.
- Define stable field ordering for AAD hashing inputs.


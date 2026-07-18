# E2EE Event Sync Relay — Client API Specification (v3)

Copyright (c) 2026 Thibault Ducray. Licensed under the MIT License.

**Status:** Stable v3
**Base URL:** `https://<host>/relay/v3`

---

## 1. Overview

The relay is a **store-and-forward queue** for end-to-end encrypted events. The server is intentionally dumb:

- It stores ciphertext blobs and routes them to recipient inboxes.
- It never decrypts, interprets, or modifies ciphertext.
- It does not expose delivery receipts to senders.

**Design principles**

| Property | Detail |
|---|---|
| Confidentiality | Server cannot read payloads (AEAD encryption is the client's responsibility) |
| Integrity | Server cannot modify payloads without detection |
| Delivery semantics | At-least-once; clients must apply messages idempotently |
| Fan-out | A single message can target multiple recipient inboxes |
| Retention | Messages are deleted per-recipient after ACK, and globally after TTL |

---

## 2. Identifiers and tokens

### 2.1 Identifiers

| Name | Format | Description |
|---|---|---|
| `device_id` | UUIDv4 string | Assigned at registration. Identifies one app install. |
| `inbox_id` | 32 random bytes, base64url-encoded (43 chars, no padding) | Routing key for receiving messages. One per device. |
| `stream_id` | Opaque string chosen by the client | Logical stream or vault identifier. Treated as opaque by the server. |
| `message_id` | UUIDv4 string | Client-chosen. Used for idempotency. |

### 2.2 Capability tokens

Each device receives two tokens at registration. Both are **32 cryptographically random bytes encoded as base64url** (43 chars, no padding). They are returned **once** and never stored in plaintext on the server.

| Token | Scope | Used for |
|---|---|---|
| `send_token` | `send` | Enqueuing messages (`POST /messages`) |
| `recv_token` | `recv` | Polling and ACKing messages for the device's own inbox |

The server stores only the **SHA-256 hash** of each token. The raw token is irrecoverable; if lost the device must re-register.

### 2.3 Token lifecycle

A token is valid until the **first** of these conditions becomes true:

| Condition | Policy | Config env var | Default |
|---|---|---|---|
| Hard expiry | Token was created more than `TOKEN_TTL_SEC` seconds ago | `TOKEN_TTL_SEC` | 31 536 000 s (1 year) |
| Idle expiry | Token has not been used on a send, poll, or ACK request for `TOKEN_IDLE_DAYS` days | `TOKEN_IDLE_DAYS` | 182 days (6 months) |
| Explicit revocation | Client called `POST /tokens/revoke` with this token | — | — |
| Device deletion | Client called `DELETE /devices` (cascades to all device tokens) | — | — |

The server updates `last_used_at` on every successful authenticated request that sends or receives a message. Idle expiry is measured from `last_used_at`, or from `created_at` if the token has never been used.

On expiry the server returns `401 token_expired`. The device must re-register to obtain new tokens.

### 2.4 Authentication

All authenticated endpoints require:

```http
Authorization: Bearer <token>
```

The server hashes the supplied token with SHA-256 and looks it up. On mismatch, revocation, or wrong scope it returns `401` or `403`.

**Scope enforcement:**

- `send` token: the `sender_device_id` in the request body must equal the token's `device_id`.
- `recv` token: the `inbox_id` in the request must equal the token's `inbox_id`.

---

## 3. Encoding conventions

### 3.1 Binary fields in JSON

All binary fields (`ciphertext`, `encrypted_identifier`, `inbox_id` in identifiers) are encoded as **base64url without padding** (RFC 4648 §5, no `=` characters):

```
base64url(bytes)  →  standard URL-safe alphabet, trailing = stripped
```

The server accepts both padded and unpadded base64url when decoding requests.

### 3.2 Timestamps

All timestamps in JSON responses are **RFC 3339 UTC** strings:

```
"2026-03-31T12:00:00.123456Z"
```

### 3.3 Registration challenge HMAC

The challenge-response uses a two-level key hierarchy so that the secret is never transmitted and rotates daily:

```
master_key   — shared secret; server reads from env var; client has it out-of-band
    │
    └─ daily_key = HMAC-SHA256(master_key,  version + ":" + server_date)
            │
            └─ response  = HMAC-SHA256(daily_key,   nonce + ":" + version + ":" + platform + ":" + client_version)
```

All string inputs are UTF-8 encoded before hashing. The `nonce` value is the base64url string exactly as returned by `GET /registration/challenge` (not re-decoded to bytes).

`response` is sent as `challenge_response` in the registration body, encoded as **base64url without padding** (32 raw bytes → 43 characters).

**Example (pseudocode)**

```
server_date   = "2026-03-31"
version       = "V1"
nonce         = "3q2-7wEVTk1L4qhgXw"        # base64url from challenge endpoint
platform      = "iOS"
client_version= "3.0.0"

daily_key = HMAC-SHA256(master_key,   "V1:2026-03-31")
response  = HMAC-SHA256(daily_key,    "3q2-7wEVTk1L4qhgXw:V1:iOS:3.0.0")
challenge_response = base64url(response)      # no padding
```

---

## 4. Endpoints

### 4.1 `GET /relay/v3/registration/challenge` — Fetch registration challenge

No authentication required. Rate-limited per IP (same bucket as device registration).

Returns a single-use nonce that the client must use to prove knowledge of the shared master key before it can register a device.

**Response `200 OK`**

```json
{
  "nonce":       "3q2-7w==base64urlnonce",
  "version":     "V1",
  "server_date": "2026-03-31",
  "expires_at":  "2026-03-31T12:02:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `nonce` | base64url string (22 chars, no padding) | 16 cryptographically random bytes. Single-use — consumed atomically on a successful registration. |
| `version` | string | Algorithm version tag (current: `"V1"`). Included in the HMAC message so the algorithm can be upgraded without rotating the master key. |
| `server_date` | string (`YYYY-MM-DD`, UTC) | The date used for daily key derivation. |
| `expires_at` | RFC 3339 timestamp | The nonce is invalid after this time (2 minutes from issue). |

---

### 4.2 `POST /relay/v3/devices` — Register device

No authentication required. Rate-limited per IP (~6 registrations/minute, burst 5).

**Registration challenge protocol**

Before calling this endpoint the client must:

1. Call `GET /registration/challenge` to obtain a nonce.
2. Derive the daily key and compute the HMAC response (see §3.3 below).
3. Include `challenge_nonce` and `challenge_response` in the request body.

The server verifies the HMAC. If it does not match, or if the nonce is expired or already used, the server returns `401 challenge_failed`.

**Request**

```json
{
  "device_name":        "iPhone 15",
  "platform":           "iOS",
  "client_version":     "3.0.0",
  "challenge_nonce":    "3q2-7w==base64urlnonce",
  "challenge_response": "base64url-of-HMAC-SHA256"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `device_name` | string | no | Stored for diagnostics only. |
| `platform` | string | no | Stored for diagnostics only. Used verbatim in the HMAC message. |
| `client_version` | string | no | Stored for diagnostics only. Used verbatim in the HMAC message. |
| `challenge_nonce` | string | yes | The nonce from `GET /registration/challenge`. |
| `challenge_response` | base64url string | yes | `HMAC-SHA256(daily_key, nonce + ":" + version + ":" + platform + ":" + client_version)` — see §3.3. |

**Response `201 Created`**

```json
{
  "device_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "inbox_id": "DOKCaYyuMgOatYLvIVKaBHO5fvJeDd38dr3tRQdacwY",
  "send_token": "Hyzf-DINHbpFs4hCLn5jVYbNLwmMXzISfuBvnWeV8yQ",
  "recv_token": "6sl1OI-e-oO2XpMn2DNeQCAVnplgIDrv-Mzw2V3ZuWw",
  "server_time": "2026-03-31T12:00:00Z",
  "limits": {
    "max_message_bytes": 262144,
    "max_messages_per_day": 20000,
    "default_ttl_seconds": 1296000,
    "max_ttl_seconds": 2592000,
    "max_recipients_per_message": 50
  }
}
```

**Client responsibilities**

- Store `device_id`, `inbox_id`, `send_token`, and `recv_token` securely. They cannot be recovered from the server.
- The `limits` object reflects the server's current configuration. Clients should read it rather than hardcode limits.

---

### 4.3 `DELETE /relay/v3/devices` — Deregister device

**Auth:** `send_token`

Permanently deletes the device and all associated data: its inbox, both capability tokens, and any undelivered messages still held for its inbox. Messages **sent** by this device that are queued in other inboxes are not affected.

This action is **irreversible**. After a successful response the `send_token` and `recv_token` are invalidated and all further requests with them will return `401`.

**Request body:** none.

**Response `204 No Content`** — device deleted successfully.

**Response `404 Not Found`** — device was already deleted (the token was valid but the device row is gone).

```json
{ "error": { "code": "not_found", "message": "device not found" } }
```

**Notes**

- The `send_token` is used for authentication; the server derives `device_id` from it. No request body is required.
- On deregistration clients should locally discard `device_id`, `inbox_id`, `send_token`, and `recv_token`.
- Re-registering after deregistration requires a new call to `POST /devices`, which assigns a new `device_id` and new tokens.
- **`acked_at` limitation:** as part of deregistration, the server marks `acked_at` on this
  device's own still-pending recipient rows (messages addressed to it that it never polled).
  This is a storage-hygiene step, not a real acknowledgement — the device never actually
  received or decrypted those messages. It exists only so that
  `DeleteFullyAckedMessages` isn't blocked indefinitely by a device that can no longer poll.
  A recipient row's `acked_at` being set therefore does **not** always mean that
  recipient's device successfully processed the message; it may instead mean the device
  deregistered before polling it. This does not affect other, still-active recipients of
  the same message — their own `acked_at` continues to reflect a genuine ACK from a poll.

---

### 4.4 `POST /relay/v3/tokens/revoke` — Revoke token

**Auth:** `send_token` or `recv_token` (either type accepted)

Immediately and permanently invalidates the token used to authenticate the request. Subsequent requests with the same token return `401 unauthorized`.

This is a targeted revocation: only the presented token is revoked. The other token belonging to the same device remains active. To invalidate all tokens at once, call `DELETE /devices` instead.

**Request body:** none.

**Response `200 OK`**

```json
{ "revoked": true }
```

**Notes**

- Revocation is irreversible. There is no un-revoke.
- If the token was already revoked (e.g. a duplicate call), the response is still `200` — the operation is idempotent.
- After revoking both tokens, or after revoking the send token, the device cannot communicate until it re-registers.

---

### 4.5 `POST /relay/v3/messages` — Enqueue message

**Auth:** `send_token`

**Request**

```json
{
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "stream_id": "vault-abc123",
  "sender_device_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "recipient_inbox_ids": [
    "DOKCaYyuMgOatYLvIVKaBHO5fvJeDd38dr3tRQdacwY",
    "tncCqoeXeP3H0bR_p-k5xM7eLqFjGhIo2NsUvWdYzA"
  ],
  "ttl_seconds": 1296000,
  "cipher_version": 1,
  "encrypted_identifier": "c29tZW9wYXF1ZWlk",
  "ciphertext": "aGVsbG93b3JsZA"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `message_id` | UUIDv4 string | yes | Client-generated. Used for idempotency. |
| `stream_id` | string | yes | Opaque stream identifier. |
| `sender_device_id` | UUIDv4 string | yes | Must match the `send_token`'s device. |
| `recipient_inbox_ids` | array of strings | yes | 1–50 inbox IDs. |
| `ttl_seconds` | integer | no | Defaults to 1 296 000 (15 days). Clamped to [1, 2 592 000]. |
| `cipher_version` | integer | yes | Client-defined cipher version. Stored opaque. |
| `encrypted_identifier` | base64url string | no | Optional opaque identifier (e.g. event type encrypted under SGK). |
| `ciphertext` | base64url string | yes | Encrypted payload. Max 262 144 bytes decoded. |

**Idempotency:** if `message_id` already exists the server returns `202` without creating a duplicate.

**Response `202 Accepted`**

```json
{
  "accepted": true,
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "stored_at": "2026-03-31T12:00:01Z",
  "recipients": 2
}
```

**Validation errors → `400`**

- `message_id` is not a valid UUID.
- `recipient_inbox_ids` is empty or has more than 50 entries.
- `ciphertext` is empty or exceeds `max_message_bytes` (decoded size).
- `sender_device_id` does not match the send token's device → `403`.

---

### 4.6 `GET /relay/v3/messages` — Poll inbox

**Auth:** `recv_token`

**Query parameters**

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `inbox_id` | string | yes | — | Must match the `recv_token`'s inbox. |
| `after` | string | no | — | Cursor from a previous response's `next_cursor`. Omit to start from the beginning. |
| `limit` | integer | no | 100 | Max messages to return. Clamped to [1, 100]. |
| `stream_id` | string | no | — | Filter to a specific stream. Omit to receive all streams. |
| `wait_ms` | integer | no | 0 | If the inbox is empty and `wait_ms > 0`, the server holds the connection open for up to `wait_ms` milliseconds, returning as soon as a message arrives or the timeout expires. Clamped to [0, 30 000]. |

**Response `200 OK`**

```json
{
  "inbox_id": "DOKCaYyuMgOatYLvIVKaBHO5fvJeDd38dr3tRQdacwY",
  "next_cursor": "MTc3NDkzMzAzMTU2MzExNTAwMDoyYzA2MmExMi04MzEyLTQ0ZjItYTMxMS1lMzcyZTlkZGFmMTk",
  "messages": [
    {
      "message_id": "550e8400-e29b-41d4-a716-446655440000",
      "stream_id": "vault-abc123",
      "sender_device_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "recipient_inbox_ids": [
        "DOKCaYyuMgOatYLvIVKaBHO5fvJeDd38dr3tRQdacwY",
        "tncCqoeXeP3H0bR_p-k5xM7eLqFjGhIo2NsUvWdYzA"
      ],
      "created_at": "2026-03-31T12:00:01Z",
      "cipher_version": 1,
      "encrypted_identifier": "c29tZW9wYXF1ZWlk",
      "ciphertext": "aGVsbG93b3JsZA"
    }
  ]
}
```

**Cursor pagination**

- `next_cursor` is an opaque base64url string encoding `(created_at_ns, message_id)`.
- Pass it as `after` on the next request to receive only messages newer than the last received one.
- If the response contains no messages, `next_cursor` is an empty string; do **not** advance the cursor.
- The cursor is stable across reconnections and restarts. Clients should persist it.

**Server-side filtering**

The server only returns messages where:
- This inbox is a listed recipient.
- The per-inbox ACK has not been sent yet (`acked_at IS NULL`).
- The message has not expired (`expires_at > now`).

Messages are ordered by `(created_at ASC, message_id ASC)`.

**Long-poll behaviour**

`wait_ms` enables the server to hold the connection open when the inbox is empty:

- The server checks for messages immediately. If found, it returns at once (wait_ms is irrelevant).
- If the inbox is empty, the server blocks until either a new message arrives or `wait_ms` elapses.
- On return the client receives at most one "batch" of newly arrived messages; it should immediately ACK and re-poll.
- The server caps `wait_ms` at 30 000 ms regardless of the value supplied.
- Set the HTTP client timeout to at least `wait_ms / 1000 + 10` seconds.

---

### 4.7 `POST /relay/v3/messages/ack` — Acknowledge messages

**Auth:** `recv_token`

Marks messages as delivered and deleted for this inbox. Once all recipients have ACKed a message, the server permanently deletes it.

**Request**

```json
{
  "inbox_id": "DOKCaYyuMgOatYLvIVKaBHO5fvJeDd38dr3tRQdacwY",
  "message_ids": [
    "550e8400-e29b-41d4-a716-446655440000",
    "661f9511-f3ac-52e5-b827-557766551111"
  ],
  "client_time": "2026-03-31T12:10:00Z"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `inbox_id` | string | yes | Must match the `recv_token`'s inbox. |
| `message_ids` | array of UUIDs | yes | IDs to ACK. Empty array is a no-op. |
| `client_time` | RFC3339 string | no | Client timestamp, stored for diagnostics. |

**Response `200 OK`**

```json
{
  "acked": 2,
  "missing": 0
}
```

| Field | Meaning |
|---|---|
| `acked` | Number of supplied IDs that exist as recipient rows for this inbox (includes already-ACKed). |
| `missing` | Number of supplied IDs not found (already deleted after full ACK, expired, or wrong ID). |

**Idempotency:** ACKing the same message twice is safe. The second call returns `acked: 1, missing: 0` (the row exists, already ACKed).

**Privacy constraint:** ACK is receiver-side only. The sender has no API to query delivery status.

---

### 4.8 `GET /relay/v3/health` — Health check

No authentication required.

**Response `200 OK`**

```json
{
  "status": "ok",
  "server_time": "2026-03-31T12:00:00Z"
}
```

**Response `503 Service Unavailable`** — database unreachable.

```json
{
  "error": {
    "code": "db_unavailable",
    "message": "database ping failed"
  }
}
```

---

### 4.9 `GET /relay/v3/limits` — Server limits

No authentication required. Returns the server's current configuration limits.

**Response `200 OK`**

```json
{
  "max_message_bytes": 262144,
  "max_messages_per_day": 20000,
  "default_ttl_seconds": 1296000,
  "max_ttl_seconds": 2592000,
  "max_recipients_per_message": 50
}
```

Clients should fetch this at startup and use it to validate outgoing messages locally before sending.

---

## 5. Message lifecycle

```
Sender                          Server                          Recipient
  │                               │                               │
  │── POST /messages ────────────▶│ store message + recipients    │
  │◀─ 202 Accepted ───────────────│                               │
  │                               │                               │
  │                               │◀── GET /messages ─────────────│
  │                               │─── 200 {messages:[...]} ─────▶│
  │                               │                               │
  │                               │◀── POST /messages/ack ────────│
  │                               │ mark acked_at for this inbox  │
  │                               │                               │
  │                               │  (when ALL inboxes ACKed)     │
  │                               │  delete message permanently   │
```

**Deletion rules**

1. **Per-recipient deletion**: a message is no longer returned to an inbox once it has been ACKed by that inbox.
2. **Full deletion**: when every listed recipient has ACKed, the message row is deleted.
3. **TTL expiry**: the server runs a background cleanup every ~10 minutes. Messages past their `expires_at` are deleted regardless of ACK status.

---

## 6. Poll strategy

### 6.1 Simple short-poll (recommended for most clients)

```
loop:
    response = GET /messages?inbox_id=...&after=<cursor>&limit=100&wait_ms=0
    if response.messages:
        process(response.messages)
        POST /messages/ack with all message_ids
        cursor = response.next_cursor
    sleep(poll_interval)   # e.g. 5–30 seconds depending on latency requirements
```

- `wait_ms=0` gives an immediate response. The connection is never held open.
- Simple to implement and reason about.
- Message delivery latency equals the poll interval.

### 6.2 Long-poll (lower latency)

```
loop:
    response = GET /messages?inbox_id=...&after=<cursor>&limit=100&wait_ms=30000
    # The server returns immediately if messages exist,
    # or holds the connection up to 30 s if the inbox is empty.
    if response.messages:
        process(response.messages)
        POST /messages/ack with all message_ids
        cursor = response.next_cursor
    # No sleep needed: re-poll immediately after each response.
```

- Delivery latency ≈ network RTT when a message is waiting.
- Requires an HTTP client with a long read timeout (≥ 40 s).
- The server holds at most one connection per inbox.

### 6.3 Cursor management

- On first poll omit `after`; the server returns all unACKed, unexpired messages from the beginning.
- Persist `next_cursor` locally. On reconnect, resume from the persisted cursor.
- If the cursor is lost, omit `after` to receive all outstanding messages again. Because delivery is at-least-once and clients must be idempotent, this is safe.
- Only advance the cursor **after** successfully ACKing the batch.

---

## 7. Abuse limits

### 7.1 Hard limits (per request)

| Constraint | Default | Error |
|---|---|---|
| Max `ciphertext` decoded bytes | 262 144 (256 KiB) | `413 payload_too_large` |
| Max recipients per message | 50 | `400 invalid_request` |
| Max messages per poll response | 100 | — (clamped silently) |
| Max `wait_ms` | 30 000 ms | — (clamped silently) |

### 7.2 Rate limits (token bucket, per token or per IP)

| Endpoint | Limit | Burst |
|---|---|---|
| `GET /registration/challenge` | ~6 req/min per IP (shared with registration) | 5 |
| `POST /devices` | ~6 req/min per IP | 5 |
| `DELETE /devices` | 20 req/s per send_token | 50 |
| `POST /tokens/revoke` | 20 req/s per token | 50 |
| `POST /messages` | 20 req/s per send_token | 50 |
| `GET /messages` | 10 req/s per recv_token | 20 |
| `POST /messages/ack` | 20 req/s per recv_token | 50 |

Rate limit exceeded → `429 Too Many Requests` with `Retry-After` header.

### 7.3 Daily quotas (per send_token, reset at midnight UTC)

| Quota | Default |
|---|---|
| Messages per day | 20 000 |
| Ciphertext bytes per day | 1 073 741 824 (1 GiB) |

Quota exceeded → `429 quota_exceeded`.

> **Note:** daily quotas are tracked in-memory on the server. They reset on server restart and are not shared across multiple server instances.

### 7.4 TTL bounds

| TTL | Value |
|---|---|
| Default (if omitted or 0) | 1 296 000 s (15 days) |
| Minimum | 1 s |
| Maximum | 2 592 000 s (30 days) |

Values outside [1, max] are silently clamped. Use a higher TTL (up to 30 days) for key-rotation messages that must survive devices being offline for extended periods.

---

## 8. Error model

All errors return a JSON body with HTTP status codes in the 4xx–5xx range:

```json
{
  "error": {
    "code": "rate_limited",
    "message": "too many requests",
    "retry_after_seconds": 60
  }
}
```

`retry_after_seconds` is present only when applicable (rate limiting). The `Retry-After` HTTP header is also set.

### Error codes

| HTTP | `code` | Cause |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON, missing required field, invalid UUID, empty ciphertext, too many recipients |
| 401 | `unauthorized` | Missing or malformed `Authorization` header, unknown token, revoked token |
| 401 | `token_expired` | Token has passed its hard expiry (1 year) or idle expiry (6 months without use) |
| 401 | `challenge_required` | `challenge_nonce` or `challenge_response` missing from registration request |
| 401 | `challenge_failed` | Nonce unknown, expired, already used, or HMAC verification failed |
| 403 | `forbidden` | Token type mismatch (send vs recv), or `sender_device_id` / `inbox_id` does not match token |
| 404 | `not_found` | Resource does not exist (e.g. device already deleted) |
| 413 | `payload_too_large` | Decoded ciphertext exceeds `max_message_bytes` |
| 429 | `rate_limited` | Token bucket exhausted for this token or IP |
| 429 | `quota_exceeded` | Daily message or byte quota exceeded for this send_token |
| 500 | `internal_error` | Unexpected server error |
| 503 | `db_unavailable` | Database unreachable (health endpoint only) |

---

## 9. Security requirements

- **TLS required** for all production traffic. The server does not enforce this at the HTTP layer; it is the responsibility of the reverse proxy.
- **Token confidentiality:** treat `send_token` and `recv_token` as secrets equivalent to passwords. Store them in the platform keychain, not in plain files.
- **No ciphertext logging:** the server never logs ciphertext, `encrypted_identifier`, or token values. Clients must apply the same discipline in their own logs.
- **Pseudonymous identifiers:** the server sees `device_id` and `inbox_id` but cannot map them to real-world identities. Do not embed real identity information in `stream_id` or `device_name`.
- **Recommended AEAD AAD** (client-side, not enforced by server): bind ciphertext to its envelope by including the following fields in the AEAD additional data (canonically encoded):
  - `message_id`
  - `stream_id`
  - `sender_device_id`
  - SHA-256 of the sorted `recipient_inbox_ids` list
  - `cipher_version`
  - sender-side monotonic counter

---

## 10. Quick-start checklist

```
1.  GET    /relay/v3/health                    — verify connectivity
2.  GET    /relay/v3/limits                    — read server limits
3a. GET    /relay/v3/registration/challenge    — fetch nonce
3b. POST   /relay/v3/devices                  — register with challenge response; store credentials
4.  Exchange inbox_ids out-of-band with other devices in the sync group
5.  POST   /relay/v3/messages          — enqueue encrypted events
6.  Loop:
      GET  /relay/v3/messages?inbox_id=...&after=<cursor>&wait_ms=0
      if messages: decrypt, apply, POST /relay/v3/messages/ack, advance cursor
      if 401 token_expired: re-register (POST /devices), re-exchange inbox_id with peers
      sleep(<poll_interval>)
7.  POST   /relay/v3/tokens/revoke     — optional: revoke a specific token on suspected compromise
8.  DELETE /relay/v3/devices           — deregister when uninstalling; discard all local credentials
```

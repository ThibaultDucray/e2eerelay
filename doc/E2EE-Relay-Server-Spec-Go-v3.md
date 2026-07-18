# E2EE Event Sync Relay — Server Specification (Go) (v3)

Copyright (c) 2026 Thibault Ducray. Licensed under the MIT License.

**Status:** Draft v3

**Scope:** Go server implementation of API `/v3` with multi-recipient messages and per-recipient ACK tracking. No sender-visible delivery receipts.

---

## 1. Overview

The server is a **dumb relay**:
- Receives encrypted messages from devices.
- Stores them once.
- Delivers them to recipients via polling / long-poll.
- Deletes per recipient after ACK and globally after all recipients ACK or after TTL.

The server MUST NOT decrypt or interpret ciphertext.

---

## 2. Architecture

- Go HTTP service (stateless)
- PostgreSQL DB (recommended)
- Optional Redis for:
  - distributed rate limiting
  - long-poll wake-ups
- Background jobs:
  - TTL purge
  - cleanup of fully-acked messages

---

## 3. Data model (PostgreSQL)

### 3.1 Tables

#### `devices`
- `device_id` uuid PK
- `device_name` text
- `platform` text
- `client_version` text
- `created_at` timestamptz
- `last_seen_at` timestamptz

#### `inboxes`
- `inbox_id` text PK
- `device_id` uuid FK
- `created_at` timestamptz

#### `tokens`
- `token_hash` bytea PK
- `token_type` text (`send`|`recv`)
- `device_id` uuid
- `inbox_id` text NULL (required for recv)
- `created_at` timestamptz
- `revoked_at` timestamptz NULL

#### `messages`
Stores the payload once.
- `message_id` uuid PK
- `stream_id` text
- `sender_device_id` uuid
- `created_at` timestamptz
- `expires_at` timestamptz
- `cipher_version` int
- `encrypted_identifier` bytea NULL
- `ciphertext` bytea
- `size_bytes` int

Indexes:
- `(expires_at)`
- `(created_at, message_id)`

#### `message_recipients`
Tracks delivery per recipient.
- `message_id` uuid FK
- `recipient_inbox_id` text
- `acked_at` timestamptz NULL

PK: `(message_id, recipient_inbox_id)`

Indexes:
- `(recipient_inbox_id, acked_at, message_id)`

---

## 4. Core behaviors

### 4.1 Registration
- Generate device_id, inbox_id, send_token, recv_token.
- Store token hashes.

### 4.2 Authentication
- Bearer token lookup by hash.
- Enforce scope:
  - send: sender_device_id must match token.device_id
  - recv: inbox_id must match token.inbox_id

### 4.3 Enqueue (multi-recipient)
Transaction:
1. Validate size, recipients count, TTL bounds.
2. Insert into `messages` idempotently.
3. Insert into `message_recipients` for each recipient idempotently.

### 4.4 Poll
- Cursor = last `(created_at, message_id)` for this inbox.
- Query join:
  - recipient_inbox_id = $inbox
  - acked_at IS NULL
  - expires_at > now()
  - ordered by `(created_at, message_id)`

Long-poll:
- If `wait_ms` and empty result:
  - block until new message for inbox or timeout.

### 4.5 ACK
- Update `message_recipients.acked_at` for the inbox.
- Idempotent.

**Privacy constraint:**
- Do not expose sender-visible delivery status. ACK exists only for receiver-side deletion and server housekeeping.

### 4.6 Cleanup
- Fully-acked messages: when all recipients are acked, delete message row (or schedule).
- TTL purge: delete expired messages.

---

## 5. Abuse protection

- Rate limit: device registration per IP.
- Rate limit: send/poll/ack per token.
- Daily quotas: messages/day and bytes/day per token.
- Hard limits: max message bytes, max recipients.

---

## 6. Operational

- Config: DB DSN, TLS, limits, rate limits.
- Metrics: endpoint latencies, enqueue bytes, queue depth (approx), purge counts.
- Logs: structured; never log ciphertext.


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
- `message_id` uuid FK, `ON DELETE CASCADE` from `messages`
- `recipient_inbox_id` text — **no FK** to `inboxes`. A message's recipient list is
  immutable metadata about who it was addressed to at send time and must survive that
  inbox/device later being deleted (see §4.6). It's set once by the sender and never
  changed afterward, other than `acked_at` being set by the recipient (or, on
  deregistration, by the server on the recipient's behalf — see below).
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
- Inactive devices: on each cleanup tick, delete any device for which every token is
  revoked, past its hard TTL (`TOKEN_TTL_SEC`), or idle-expired (`TOKEN_IDLE_DAYS`) — i.e.
  no remaining token could pass `AuthMiddleware`. A device with at least one still-usable
  token is left alone. Before deleting such a device, its own still-pending recipient rows
  are acked the same way as explicit deregistration (see below) — it will never poll again
  either way.

**Device deregistration and `acked_at`:** deleting a device (`DELETE /devices`) must not
delete other messages' `message_recipients` rows referencing that device's inbox — see the
schema note in §3. Doing so previously let one recipient's deregistration silently shrink
a still-pending multi-recipient message's recipient list for the remaining recipients,
breaking AAD-bound decryption on the client side (see `BUGFIX-recipient-list-cascade.md`
in the repo root for the full incident writeup).

Instead, deregistration marks `acked_at` (to "now") on the departing device's own
still-pending recipient rows — messages addressed to it that it never polled — before
deleting the device row. This is **not a genuine acknowledgement**; the device never
received or decrypted those messages. It exists purely so `DeleteFullyAckedMessages`
isn't blocked indefinitely by a recipient that can no longer poll. Consequence: a non-NULL
`acked_at` on a recipient row means either "this recipient's device polled and acked it"
or "this recipient's device deregistered before acking it" — the two are indistinguishable
from that column alone. This is a deliberate, documented limitation of what `acked_at`
means, not a bug.

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


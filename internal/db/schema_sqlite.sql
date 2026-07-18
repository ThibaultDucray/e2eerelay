-- Copyright (c) 2026 Thibault Ducray
-- SPDX-License-Identifier: MIT
-- Use of this source code is governed by the MIT license found in the LICENSE file.

CREATE TABLE IF NOT EXISTS relay_devices (
    device_id      TEXT    NOT NULL PRIMARY KEY,
    device_name    TEXT    NOT NULL,
    platform       TEXT    NOT NULL,
    client_version TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_inboxes (
    inbox_id   TEXT    NOT NULL PRIMARY KEY,
    device_id  TEXT    NOT NULL REFERENCES relay_devices(device_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_tokens (
    token_hash   BLOB    NOT NULL PRIMARY KEY,
    token_type   TEXT    NOT NULL CHECK (token_type IN ('send', 'recv')),
    device_id    TEXT    NOT NULL REFERENCES relay_devices(device_id) ON DELETE CASCADE,
    inbox_id     TEXT    NULL REFERENCES relay_inboxes(inbox_id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_used_at INTEGER NULL,
    revoked_at   INTEGER NULL
);

CREATE TABLE IF NOT EXISTS relay_messages (
    message_id            TEXT    NOT NULL PRIMARY KEY,
    stream_id             TEXT    NOT NULL,
    sender_device_id      TEXT    NOT NULL,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    cipher_version        INTEGER NOT NULL,
    encrypted_identifier  BLOB    NULL,
    ciphertext            BLOB    NOT NULL,
    size_bytes            INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_relay_msg_expires ON relay_messages(expires_at);
CREATE INDEX IF NOT EXISTS idx_relay_msg_cursor  ON relay_messages(created_at, message_id);

CREATE TABLE IF NOT EXISTS relay_message_recipients (
    message_id          TEXT    NOT NULL REFERENCES relay_messages(message_id) ON DELETE CASCADE,
    -- No FK to relay_inboxes: a message's recipient list must stay immutable after send,
    -- even if a recipient device later deregisters. See BUGFIX-recipient-list-cascade.md.
    recipient_inbox_id  TEXT    NOT NULL,
    acked_at            INTEGER NULL,
    PRIMARY KEY (message_id, recipient_inbox_id)
);

CREATE INDEX IF NOT EXISTS idx_relay_mr_poll ON relay_message_recipients(recipient_inbox_id, acked_at, message_id);

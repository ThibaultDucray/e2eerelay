// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// B64URL is a []byte that encodes/decodes as base64url (no padding) in JSON.
type B64URL []byte

func (b B64URL) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.RawURLEncoding.EncodeToString([]byte(b)))
}

func (b *B64URL) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Fallback: try standard base64 (some clients may send padded)
		decoded, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("base64url decode: %w", err)
		}
	}
	*b = decoded
	return nil
}

// ----- Request types -----

type ChallengeTokenResponse struct {
	Nonce      string    `json:"nonce"`
	Version    string    `json:"version"`
	ServerDate string    `json:"server_date"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type RegisterDeviceRequest struct {
	DeviceName        string `json:"device_name"`
	Platform          string `json:"platform"`
	ClientVersion     string `json:"client_version"`
	ChallengeNonce    string `json:"challenge_nonce"`
	ChallengeResponse B64URL `json:"challenge_response"`
}

type EnqueueRequest struct {
	MessageID           string   `json:"message_id"`
	StreamID            string   `json:"stream_id"`
	SenderDeviceID      string   `json:"sender_device_id"`
	RecipientInboxIDs   []string `json:"recipient_inbox_ids"`
	TTLSeconds          int      `json:"ttl_seconds"`
	CipherVersion       int      `json:"cipher_version"`
	EncryptedIdentifier *B64URL  `json:"encrypted_identifier,omitempty"`
	Ciphertext          B64URL   `json:"ciphertext"`
}

type AckRequest struct {
	InboxID    string    `json:"inbox_id"`
	MessageIDs []string  `json:"message_ids"`
	ClientTime time.Time `json:"client_time"`
}

// ----- Response types -----

type LimitsInfo struct {
	MaxMessageBytes     int `json:"max_message_bytes"`
	MaxMessagesPerDay   int `json:"max_messages_per_day"`
	DefaultTTLSeconds   int `json:"default_ttl_seconds"`
	MaxTTLSeconds       int `json:"max_ttl_seconds"`
	MaxRecipientsPerMsg int `json:"max_recipients_per_message"`
}

type RegisterDeviceResponse struct {
	DeviceID   string     `json:"device_id"`
	InboxID    string     `json:"inbox_id"`
	SendToken  string     `json:"send_token"`
	RecvToken  string     `json:"recv_token"`
	ServerTime time.Time  `json:"server_time"`
	Limits     LimitsInfo `json:"limits"`
}

type EnqueueResponse struct {
	Accepted   bool      `json:"accepted"`
	MessageID  string    `json:"message_id"`
	StoredAt   time.Time `json:"stored_at"`
	Recipients int       `json:"recipients"`
}

type PollMessage struct {
	MessageID           string    `json:"message_id"`
	StreamID            string    `json:"stream_id"`
	SenderDeviceID      string    `json:"sender_device_id"`
	RecipientInboxIDs   []string  `json:"recipient_inbox_ids"`
	CreatedAt           time.Time `json:"created_at"`
	CipherVersion       int       `json:"cipher_version"`
	EncryptedIdentifier *B64URL   `json:"encrypted_identifier,omitempty"`
	Ciphertext          B64URL    `json:"ciphertext"`
}

type PollResponse struct {
	InboxID    string        `json:"inbox_id"`
	NextCursor string        `json:"next_cursor"`
	Messages   []PollMessage `json:"messages"`
}

type AckResponse struct {
	Acked   int `json:"acked"`
	Missing int `json:"missing"`
}

type HealthResponse struct {
	Status     string    `json:"status"`
	ServerTime time.Time `json:"server_time"`
}

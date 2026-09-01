// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"relay/internal/challenge"
	"relay/internal/db"
)

// ----- Health & Limits -----

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := h.store.Ping(pingCtx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "db_unavailable", "database ping failed", 0)
		return
	}
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:     "ok",
		ServerTime: time.Now().UTC(),
	})
}

func (h *Handlers) Limits(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, LimitsInfo{
		MaxMessageBytes:     h.cfg.MaxMessageBytes,
		MaxMessagesPerDay:   h.cfg.MaxMessagesPerDay,
		DefaultTTLSeconds:   h.cfg.DefaultTTLSeconds,
		MaxTTLSeconds:       h.cfg.MaxTTLSeconds,
		MaxRecipientsPerMsg: h.cfg.MaxRecipientsPerMsg,
	})
}

// ----- Registration challenge -----

func (h *Handlers) GetChallenge(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	nonce, serverDate, expiresAt, err := h.challenges.Issue(now)
	if err != nil {
		h.log.Error("issue challenge nonce", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate challenge", 0)
		return
	}
	writeJSON(w, http.StatusOK, ChallengeTokenResponse{
		Nonce:      nonce,
		Version:    challenge.CurrentVersion,
		ServerDate: serverDate,
		ExpiresAt:  expiresAt,
	})
}

// ----- Register device -----

func (h *Handlers) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	var req RegisterDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body", 0)
		return
	}

	// Validate and consume the challenge nonce.
	if req.ChallengeNonce == "" || len(req.ChallengeResponse) == 0 {
		writeError(w, http.StatusUnauthorized, "challenge_required", "challenge_nonce and challenge_response are required", 0)
		return
	}
	version, serverDate, err := h.challenges.Consume(req.ChallengeNonce, time.Now())
	if err != nil {
		// Don't leak whether the nonce was unknown vs expired.
		writeError(w, http.StatusUnauthorized, "challenge_failed", "invalid or expired challenge", 0)
		return
	}
	if !challenge.VerifyResponse(h.masterKey, version, serverDate, req.ChallengeNonce, req.Platform, req.ClientVersion, req.ChallengeResponse) {
		writeError(w, http.StatusUnauthorized, "challenge_failed", "invalid challenge response", 0)
		return
	}

	deviceID := uuid.New().String()
	inboxID, err := randomBase64URL(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "crypto error", 0)
		return
	}
	sendTokenStr, sendTokenHash, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "crypto error", 0)
		return
	}
	recvTokenStr, recvTokenHash, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "crypto error", 0)
		return
	}

	now := time.Now().UnixNano()
	expiresAt := now + int64(h.cfg.TokenTTLSeconds)*int64(time.Second)
	ctx := r.Context()

	if err := h.store.InsertDevice(ctx, deviceID, req.DeviceName, req.Platform, req.ClientVersion, now); err != nil {
		h.log.Error("insert device", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create device", 0)
		return
	}
	if err := h.store.InsertInbox(ctx, inboxID, deviceID, now); err != nil {
		h.log.Error("insert inbox", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create inbox", 0)
		return
	}
	if err := h.store.InsertToken(ctx, sendTokenHash, "send", deviceID, nil, expiresAt, now); err != nil {
		h.log.Error("insert send token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to store token", 0)
		return
	}
	if err := h.store.InsertToken(ctx, recvTokenHash, "recv", deviceID, &inboxID, expiresAt, now); err != nil {
		h.log.Error("insert recv token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to store token", 0)
		return
	}

	h.log.Info("device registered", deviceID, 0)

	writeJSON(w, http.StatusCreated, RegisterDeviceResponse{
		DeviceID:   deviceID,
		InboxID:    inboxID,
		SendToken:  sendTokenStr,
		RecvToken:  recvTokenStr,
		ServerTime: time.Unix(0, now).UTC(),
		Limits: LimitsInfo{
			MaxMessageBytes:     h.cfg.MaxMessageBytes,
			MaxMessagesPerDay:   h.cfg.MaxMessagesPerDay,
			DefaultTTLSeconds:   h.cfg.DefaultTTLSeconds,
			MaxTTLSeconds:       h.cfg.MaxTTLSeconds,
			MaxRecipientsPerMsg: h.cfg.MaxRecipientsPerMsg,
		},
	})
}

// ----- Revoke token -----

func (h *Handlers) RevokeToken(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	ctx := r.Context()

	if err := h.store.RevokeToken(ctx, token.TokenHash, time.Now().UnixNano()); err != nil {
		h.log.Error("revoke token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to revoke token", 0)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// ----- Deregister device -----

func (h *Handlers) DeregisterDevice(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	ctx := r.Context()

	deleted, err := h.store.DeleteDevice(ctx, token.DeviceID, time.Now().UnixNano())
	if err != nil {
		h.log.Error("delete device", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to deregister device", 0)
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "not_found", "device not found", 0)
		return
	}

	// Eagerly purge messages that have no remaining unACKed recipients after the
	// inbox cascade-delete, rather than waiting for the next cleanup cycle.
	if n, err := h.store.DeleteFullyAckedMessages(ctx); err != nil {
		h.log.Error("post-deregister cleanup", "err", err)
	} else if n > 0 {
		h.log.Info("post-deregister cleanup", "deleted_messages", n)
	}

	h.log.Info("device deregistered", token.DeviceID, 0)

	w.WriteHeader(http.StatusNoContent)
}

// ----- Rename device -----

// maxDeviceNameLen bounds device_name on rename, matching what registration
// implicitly allows given relay_devices.device_name's storage.
const maxDeviceNameLen = 200

func (h *Handlers) RenameDevice(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())

	var req RenameDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body", 0)
		return
	}
	if req.DeviceName == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "device_name is required", 0)
		return
	}
	if len(req.DeviceName) > maxDeviceNameLen {
		writeError(w, http.StatusBadRequest, "invalid_request", "device_name too long", 0)
		return
	}

	ctx := r.Context()
	updated, err := h.store.UpdateDeviceName(ctx, token.DeviceID, req.DeviceName)
	if err != nil {
		h.log.Error("rename device", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to rename device", 0)
		return
	}
	if !updated {
		writeError(w, http.StatusNotFound, "not_found", "device not found", 0)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ----- Enqueue message -----

func (h *Handlers) EnqueueMessage(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())

	var req EnqueueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body", 0)
		return
	}

	// Validate message_id is a valid UUID.
	if _, err := uuid.Parse(req.MessageID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid message_id", 0)
		return
	}

	// Enforce sender_device_id matches the authenticated token's device.
	if req.SenderDeviceID != token.DeviceID {
		writeError(w, http.StatusForbidden, "forbidden", "sender_device_id does not match token", 0)
		return
	}

	// Validate recipients.
	if len(req.RecipientInboxIDs) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "recipient_inbox_ids must not be empty", 0)
		return
	}
	if len(req.RecipientInboxIDs) > h.cfg.MaxRecipientsPerMsg {
		writeError(w, http.StatusBadRequest, "invalid_request", "too many recipients", 0)
		return
	}

	// Validate ciphertext.
	if len(req.Ciphertext) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "ciphertext is required", 0)
		return
	}
	if len(req.Ciphertext) > h.cfg.MaxMessageBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "ciphertext exceeds max size", 0)
		return
	}

	// Clamp TTL.
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = h.cfg.DefaultTTLSeconds
	}
	if ttl > h.cfg.MaxTTLSeconds {
		ttl = h.cfg.MaxTTLSeconds
	}

	// Check daily quota.
	tokenHex := hex.EncodeToString(token.TokenHash)
	if err := h.quota.CheckAndAdd(tokenHex, 1, int64(len(req.Ciphertext))); err != nil {
		writeError(w, http.StatusTooManyRequests, "quota_exceeded", "daily quota exceeded", 0)
		return
	}

	now := time.Now()
	params := db.InsertMessageParams{
		MessageID:      req.MessageID,
		StreamID:       req.StreamID,
		SenderDeviceID: req.SenderDeviceID,
		CreatedAt:      now.UnixNano(),
		ExpiresAt:      now.Add(time.Duration(ttl) * time.Second).UnixNano(),
		CipherVersion:  req.CipherVersion,
		Ciphertext:     []byte(req.Ciphertext),
		SizeBytes:      len(req.Ciphertext),
	}
	if req.EncryptedIdentifier != nil {
		params.EncryptedIdentifier = []byte(*req.EncryptedIdentifier)
	}

	ctx := r.Context()
	if _, err := h.store.InsertMessage(ctx, params); err != nil {
		h.log.Error("insert message", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to store message", 0)
		return
	}
	if err := h.store.InsertMessageRecipients(ctx, req.MessageID, req.RecipientInboxIDs); err != nil {
		h.log.Error("insert recipients", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to store recipients", 0)
		return
	}

	// Wake up long-poll waiters for each recipient.
	for _, inboxID := range req.RecipientInboxIDs {
		h.hub.Notify(inboxID)
	}

	writeJSON(w, http.StatusAccepted, EnqueueResponse{
		Accepted:   true,
		MessageID:  req.MessageID,
		StoredAt:   now.UTC(),
		Recipients: len(req.RecipientInboxIDs),
	})
}

// ----- Poll messages -----

func (h *Handlers) PollMessages(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())

	inboxID := r.URL.Query().Get("inbox_id")
	if inboxID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "inbox_id is required", 0)
		return
	}
	if token.InboxID == nil || *token.InboxID != inboxID {
		writeError(w, http.StatusForbidden, "forbidden", "inbox_id does not match token", 0)
		return
	}

	limit := intQueryParam(r, "limit", h.cfg.MaxPollLimit, 1, h.cfg.MaxPollLimit)
	streamID := r.URL.Query().Get("stream_id")
	waitMs := intQueryParam(r, "wait_ms", 0, 0, h.cfg.MaxWaitMs)

	var afterCreatedAt int64
	var afterMessageID string
	if afterStr := r.URL.Query().Get("after"); afterStr != "" {
		c, err := DecodeCursor(afterStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid cursor", 0)
			return
		}
		afterCreatedAt = c.CreatedAt
		afterMessageID = c.MessageID
	}

	ctx := r.Context()
	pollParams := db.PollParams{
		InboxID:        inboxID,
		AfterCreatedAt: afterCreatedAt,
		AfterMessageID: afterMessageID,
		StreamID:       streamID,
		Limit:          limit,
		NowNs:          time.Now().UnixNano(),
	}

	msgs, err := h.store.PollMessages(ctx, pollParams)
	if err != nil {
		h.log.Error("poll messages", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "poll failed", 0)
		return
	}

	// Long-poll: block if no messages and wait_ms > 0.
	if len(msgs) == 0 && waitMs > 0 {
		ch := h.hub.Subscribe(inboxID)
		defer h.hub.Unsubscribe(inboxID, ch)

		timer := time.NewTimer(time.Duration(waitMs) * time.Millisecond)
		defer timer.Stop()

		select {
		case <-ch:
			// New message arrived; re-query once.
			pollParams.NowNs = time.Now().UnixNano()
			msgs, err = h.store.PollMessages(ctx, pollParams)
			if err != nil {
				h.log.Error("poll messages after notify", "err", err)
				writeError(w, http.StatusInternalServerError, "internal_error", "poll failed", 0)
				return
			}
		case <-timer.C:
			// Timeout — return empty result.
		case <-ctx.Done():
			// Client disconnected.
			return
		}
	}

	resp := buildPollResponse(inboxID, msgs)
	writeJSON(w, http.StatusOK, resp)
}

func buildPollResponse(inboxID string, msgs []db.MessageWithRecipients) PollResponse {
	pollMsgs := make([]PollMessage, 0, len(msgs))
	var nextCursor string

	for _, m := range msgs {
		pm := PollMessage{
			MessageID:         m.MessageID,
			StreamID:          m.StreamID,
			SenderDeviceID:    m.SenderDeviceID,
			RecipientInboxIDs: m.RecipientInboxIDs,
			CreatedAt:         time.Unix(0, m.CreatedAt).UTC(),
			CipherVersion:     m.CipherVersion,
			Ciphertext:        B64URL(m.Ciphertext),
		}
		if len(m.EncryptedIdentifier) > 0 {
			ei := B64URL(m.EncryptedIdentifier)
			pm.EncryptedIdentifier = &ei
		}
		pollMsgs = append(pollMsgs, pm)
		nextCursor = EncodeCursor(Cursor{CreatedAt: m.CreatedAt, MessageID: m.MessageID})
	}

	return PollResponse{
		InboxID:    inboxID,
		NextCursor: nextCursor,
		Messages:   pollMsgs,
	}
}

// ----- ACK -----

func (h *Handlers) AckMessages(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())

	var req AckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body", 0)
		return
	}
	if token.InboxID == nil || *token.InboxID != req.InboxID {
		writeError(w, http.StatusForbidden, "forbidden", "inbox_id does not match token", 0)
		return
	}
	if len(req.MessageIDs) == 0 {
		writeJSON(w, http.StatusOK, AckResponse{Acked: 0, Missing: 0})
		return
	}

	ctx := r.Context()
	acked, missing, err := h.store.AckMessages(ctx, req.InboxID, req.MessageIDs, time.Now().UnixNano())
	if err != nil {
		h.log.Error("ack messages", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "ack failed", 0)
		return
	}

	writeJSON(w, http.StatusOK, AckResponse{Acked: acked, Missing: missing})
}

// ----- Helpers -----

// newToken generates a 32-byte random token. Returns (base64url string, sha256 hash, error).
func newToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", nil, err
	}
	tokenStr := base64.RawURLEncoding.EncodeToString(raw)
	hash := hashToken(tokenStr)
	return tokenStr, hash, nil
}

// randomBase64URL returns n cryptographically random bytes encoded as base64url.
func randomBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// intQueryParam parses an integer query parameter, falling back to def,
// and clamping to [min, max].
func intQueryParam(r *http.Request, key string, def, minVal, maxVal int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	if n < minVal {
		return minVal
	}
	if n > maxVal {
		return maxVal
	}
	return n
}

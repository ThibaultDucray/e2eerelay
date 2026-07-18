// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

// Package challenge implements the registration challenge-response protocol.
//
// Flow:
//  1. Client calls GET /registration/challenge → receives {nonce, version, server_date, expires_at}
//  2. Client computes:
//       daily_key = HMAC-SHA256(master_key, version + ":" + server_date)
//       response  = HMAC-SHA256(daily_key,  nonce + ":" + version + ":" + platform + ":" + client_version)
//  3. Client sends response (base64url) + nonce with POST /devices
//  4. Server calls Consume() to retrieve the stored version/date, then VerifyResponse()
package challenge

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"relay/internal/dailykey"
)

const (
	// CurrentVersion is the algorithm version tag included in the challenge
	// and in the HMAC message. Bump to "V2" when the algorithm changes.
	CurrentVersion = "V1"

	// NonceTTL is how long a challenge nonce is valid.
	NonceTTL = 2 * time.Minute

	nonceSize = 16 // bytes of random entropy
)

type entry struct {
	version    string
	serverDate string // YYYY-MM-DD UTC
	expiresAt  time.Time
}

// Store holds pending registration nonces in memory (single-instance only).
type Store struct {
	mu     sync.Mutex
	nonces map[string]*entry
}

// New returns an empty Store.
func New() *Store {
	return &Store{nonces: make(map[string]*entry)}
}

// Issue generates a fresh nonce for the current UTC date and current version.
// Returns the nonce (base64url, no padding), the server_date string, and expiry time.
func (s *Store) Issue(now time.Time) (nonce, serverDate string, expiresAt time.Time, err error) {
	raw := make([]byte, nonceSize)
	if _, err = rand.Read(raw); err != nil {
		return
	}
	nonce = base64.RawURLEncoding.EncodeToString(raw)
	serverDate = now.UTC().Format("2006-01-02")
	expiresAt = now.Add(NonceTTL)
	s.mu.Lock()
	s.nonces[nonce] = &entry{
		version:    CurrentVersion,
		serverDate: serverDate,
		expiresAt:  expiresAt,
	}
	s.mu.Unlock()
	return
}

// Consume validates the nonce (must exist and not be expired) and removes it
// atomically so it cannot be reused. Returns the stored version and serverDate.
func (s *Store) Consume(nonce string, now time.Time) (version, serverDate string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.nonces[nonce]
	if !ok {
		return "", "", errors.New("unknown nonce")
	}
	if now.After(e.expiresAt) {
		delete(s.nonces, nonce)
		return "", "", errors.New("nonce expired")
	}
	version, serverDate = e.version, e.serverDate
	delete(s.nonces, nonce)
	return version, serverDate, nil
}

// Evict removes all expired nonces. Call periodically to prevent unbounded growth.
func (s *Store) Evict(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.nonces {
		if now.After(e.expiresAt) {
			delete(s.nonces, k)
		}
	}
}

// RunEviction runs a periodic eviction loop until ctx is cancelled.
func RunEviction(ctx context.Context, s *Store) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.Evict(time.Now())
		case <-ctx.Done():
			return
		}
	}
}

// VerifyResponse checks whether the client's HMAC response is correct.
// Crypto is delegated to dailykey.KeyBytes and dailykey.ChallengeHMAC.
// Comparison is constant-time to prevent timing attacks.
func VerifyResponse(masterKey []byte, version, serverDate, nonce, platform, clientVersion string, response []byte) bool {
	t, err := time.ParseInLocation("2006-01-02", serverDate, time.UTC)
	if err != nil {
		return false
	}
	dk, err := dailykey.KeyBytes(masterKey, version, t)
	if err != nil {
		return false
	}
	expected := dailykey.ChallengeHMAC(dk, nonce, version, platform, clientVersion)
	return hmac.Equal(expected, response)
}

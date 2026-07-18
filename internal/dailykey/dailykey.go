// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

// Package dailykey provides daily-key derivation and challenge-response HMAC
// for the registration challenge protocol.
//
// # Key hierarchy
//
//	master_key  (secret, loaded from env, never transmitted)
//	    └─ daily_key = HMAC-SHA256(master_key, version + ":" + YYYY-MM-DD)
//	            └─ challenge_response = HMAC-SHA256(daily_key, nonce + ":" + version + ":" + platform + ":" + client_version)
package dailykey

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// KeyBytes derives the daily key for a given algorithm version and UTC date.
//
//	daily_key = HMAC-SHA256(masterKey, version + ":" + YYYY-MM-DD)
func KeyBytes(masterKey []byte, version string, t time.Time) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("masterKey is empty")
	}
	date := t.UTC().Format("2006-01-02")
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(version + ":" + date))
	return mac.Sum(nil), nil
}

// ChallengeHMAC computes the expected registration challenge response.
//
//	message  = nonce + ":" + version + ":" + platform + ":" + clientVersion
//	response = HMAC-SHA256(dailyKey, message)
//
// nonce is the base64url string exactly as issued by the server.
func ChallengeHMAC(dailyKey []byte, nonce, version, platform, clientVersion string) []byte {
	h := hmac.New(sha256.New, dailyKey)
	h.Write([]byte(fmt.Sprintf("%s:%s:%s:%s", nonce, version, platform, clientVersion)))
	return h.Sum(nil)
}

// DailyKeyUTC is the original helper kept for external callers that need the
// date-only key as a base64url string (e.g. diagnostics or other protocols).
//
//	key = HMAC-SHA256(masterKey, YYYY-MM-DD)   (no version prefix)
func DailyKeyUTC(masterKey []byte, t time.Time) (string, error) {
	if len(masterKey) == 0 {
		return "", errors.New("masterKey is empty")
	}
	date := t.UTC().Format("2006-01-02")
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(date))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// LoadMasterKeyFromEnv loads the master key from environment variables.
// Checks MASTER_KEY_B64URL (base64url, no padding) first, then MASTER_KEY (raw text).
// Returns an error if neither is set or the key is shorter than 16 bytes.
func LoadMasterKeyFromEnv() ([]byte, error) {
	if b64 := strings.TrimSpace(os.Getenv("MASTER_KEY_B64URL")); b64 != "" {
		key, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			return nil, errors.New("invalid MASTER_KEY_B64URL (expected base64url, no padding)")
		}
		if len(key) < 16 {
			return nil, errors.New("MASTER_KEY_B64URL too short (minimum 16 bytes; recommend 32)")
		}
		return key, nil
	}
	if raw := os.Getenv("MASTER_KEY"); raw != "" {
		key := []byte(raw)
		if len(key) < 16 {
			return nil, errors.New("MASTER_KEY too short (minimum 16 bytes; recommend 32)")
		}
		return key, nil
	}
	return nil, errors.New("missing MASTER_KEY_B64URL or MASTER_KEY env var")
}

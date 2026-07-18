// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

package api

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"time"

	"relay/internal/config"
	"relay/internal/db"
)

type contextKey int

const ctxKeyToken contextKey = iota

// AuthMiddleware validates the Bearer token and stores the token row in the
// request context. requiredType must be "send", "recv", or "" (accept either).
func AuthMiddleware(store db.Store, cfg *config.Config, requiredType string) func(http.Handler) http.Handler {
	idleNs := int64(cfg.TokenIdleDays) * 24 * int64(time.Hour)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized", "missing or malformed Authorization header", 0)
				return
			}

			hash := hashToken(raw)
			token, err := store.LookupToken(r.Context(), hash)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "internal_error", "token lookup failed", 0)
				return
			}
			if token == nil || token.RevokedAt != nil {
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or revoked token", 0)
				return
			}

			now := time.Now().UnixNano()

			// Hard expiry: token past its creation TTL.
			if now > token.ExpiresAt {
				writeError(w, http.StatusUnauthorized, "token_expired", "token has expired", 0)
				return
			}

			// Idle expiry: token unused for TokenIdleDays.
			lastActive := token.CreatedAt
			if token.LastUsedAt != nil {
				lastActive = *token.LastUsedAt
			}
			if now-lastActive > idleNs {
				writeError(w, http.StatusUnauthorized, "token_expired", "token expired due to inactivity", 0)
				return
			}

			if requiredType != "" && token.TokenType != requiredType {
				writeError(w, http.StatusForbidden, "forbidden", "token type mismatch", 0)
				return
			}

			// Update last_used_at asynchronously — non-critical, must not block the request.
			go func(h []byte, ts int64) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = store.TouchToken(ctx, h, ts)
			}(hash, now)

			ctx := context.WithValue(r.Context(), ctxKeyToken, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// tokenFromCtx retrieves the authenticated token from the request context.
// Returns nil if not set (should not happen after AuthMiddleware).
func tokenFromCtx(ctx context.Context) *db.TokenRow {
	v, _ := ctx.Value(ctxKeyToken).(*db.TokenRow)
	return v
}

// bearerToken extracts the raw token string from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	tok := strings.TrimPrefix(h, "Bearer ")
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return ""
	}
	return tok
}

// hashToken returns the SHA-256 of the token string (as UTF-8 bytes).
func hashToken(tokenStr string) []byte {
	h := sha256.Sum256([]byte(tokenStr))
	return h[:]
}

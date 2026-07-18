// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

package api

import (
	"context"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"relay/internal/config"
)

type limiterEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// RateLimiter holds per-IP and per-token rate limiters with periodic eviction.
type RateLimiter struct {
	mu      sync.Mutex
	byIP    map[string]*limiterEntry
	byToken map[string]*limiterEntry
	cfg     *config.Config
}

func NewRateLimiter(cfg *config.Config) *RateLimiter {
	return &RateLimiter{
		byIP:    make(map[string]*limiterEntry),
		byToken: make(map[string]*limiterEntry),
		cfg:     cfg,
	}
}

func (rl *RateLimiter) getIP(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e := rl.byIP[ip]
	if e == nil {
		e = &limiterEntry{lim: rate.NewLimiter(rl.cfg.RegIPRate, rl.cfg.RegIPBurst)}
		rl.byIP[ip] = e
	}
	e.lastSeen = time.Now()
	return e.lim
}

func (rl *RateLimiter) getToken(tokenHex string, r rate.Limit, burst int) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e := rl.byToken[tokenHex]
	if e == nil {
		e = &limiterEntry{lim: rate.NewLimiter(r, burst)}
		rl.byToken[tokenHex] = e
	}
	e.lastSeen = time.Now()
	return e.lim
}

// RunEviction periodically removes stale limiter entries to prevent memory growth.
func (rl *RateLimiter) RunEviction(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.evict()
		case <-ctx.Done():
			return
		}
	}
}

func (rl *RateLimiter) evict() {
	cutoff := time.Now().Add(-1 * time.Hour)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, e := range rl.byIP {
		if e.lastSeen.Before(cutoff) {
			delete(rl.byIP, k)
		}
	}
	for k, e := range rl.byToken {
		if e.lastSeen.Before(cutoff) {
			delete(rl.byToken, k)
		}
	}
}

// IPMiddleware rate-limits by client IP. Intended for device registration.
func (rl *RateLimiter) IPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.getIP(r.RemoteAddr).Allow() {
				writeRateLimitError(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TokenMiddleware rate-limits by the authenticated token. action is "send", "poll", or "ack".
func (rl *RateLimiter) TokenMiddleware(action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := tokenFromCtx(r.Context())
			if token == nil {
				next.ServeHTTP(w, r)
				return
			}
			tokenHex := hex.EncodeToString(token.TokenHash)

			var lim *rate.Limiter
			switch action {
			case "send":
				lim = rl.getToken(tokenHex, rl.cfg.SendRate, rl.cfg.SendBurst)
			case "poll":
				lim = rl.getToken(tokenHex, rl.cfg.PollRate, rl.cfg.PollBurst)
			case "ack":
				lim = rl.getToken(tokenHex, rl.cfg.AckRate, rl.cfg.AckBurst)
			default:
				next.ServeHTTP(w, r)
				return
			}
			if !lim.Allow() {
				writeRateLimitError(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

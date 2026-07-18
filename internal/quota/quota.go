// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

// Package quota provides in-memory daily quota tracking per token.
// NOTE: quotas reset on server restart and are not shared across instances.
// For multi-instance deployments, replace with a Redis-backed implementation.
package quota

import (
	"errors"
	"sync"
	"time"

	"relay/internal/config"
)

// ErrQuotaExceeded is returned when a daily quota limit is reached.
var ErrQuotaExceeded = errors.New("daily quota exceeded")

type bucket struct {
	day      int64 // UTC day number (UnixNano / ns-per-day)
	messages int64
	bytes    int64
}

// Store tracks per-token daily message and byte quotas.
type Store struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	cfg     *config.Config
}

func New(cfg *config.Config) *Store {
	return &Store{buckets: make(map[string]*bucket), cfg: cfg}
}

func dayOf(t time.Time) int64 {
	return t.UTC().Unix() / 86400
}

// CheckAndAdd verifies the token has remaining quota and atomically increments
// counters. Returns ErrQuotaExceeded if the add would exceed the limit.
func (s *Store) CheckAndAdd(tokenHex string, msgs int, sz int64) error {
	today := dayOf(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()

	b := s.buckets[tokenHex]
	if b == nil || b.day != today {
		b = &bucket{day: today}
		s.buckets[tokenHex] = b
	}
	if b.messages+int64(msgs) > int64(s.cfg.MaxMessagesPerDay) {
		return ErrQuotaExceeded
	}
	if b.bytes+sz > s.cfg.MaxBytesPerDay {
		return ErrQuotaExceeded
	}
	b.messages += int64(msgs)
	b.bytes += sz
	return nil
}

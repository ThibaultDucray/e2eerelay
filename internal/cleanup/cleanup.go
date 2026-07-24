// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

// Package cleanup runs background jobs to purge expired and fully-acked messages.
package cleanup

import (
	"context"
	"log/slog"
	"time"

	"relay/internal/db"
)

// Run executes cleanup jobs on an interval until ctx is cancelled. idleDays is
// the token idle-expiry window (config.TokenIdleDays) used to find devices
// with no remaining usable token.
func Run(ctx context.Context, store db.Store, intervalSec, idleDays int, log *slog.Logger) {
	interval := time.Duration(intervalSec) * time.Second
	idleNs := int64(idleDays) * 24 * int64(time.Hour)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			runOnce(ctx, store, idleNs, log)
		case <-ctx.Done():
			return
		}
	}
}

func runOnce(ctx context.Context, store db.Store, idleNs int64, log *slog.Logger) {
	now := time.Now().UnixNano()

	expired, err := store.DeleteExpiredMessages(ctx, now)
	if err != nil {
		log.Error("cleanup: delete expired", "err", err)
	} else if expired > 0 {
		log.Info("cleanup: deleted expired messages", "count", expired)
	}

	fullyAcked, err := store.DeleteFullyAckedMessages(ctx)
	if err != nil {
		log.Error("cleanup: delete fully acked", "err", err)
	} else if fullyAcked > 0 {
		log.Info("cleanup: deleted fully acked messages", "count", fullyAcked)
	}

	inactiveDevices, err := store.DeleteInactiveDevices(ctx, now, idleNs)
	if err != nil {
		log.Error("cleanup: delete inactive devices", "err", err)
	} else if inactiveDevices > 0 {
		log.Info("cleanup: deleted inactive devices", "count", inactiveDevices)
	}
}

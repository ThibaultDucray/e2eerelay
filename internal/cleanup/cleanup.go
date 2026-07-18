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

// Run executes cleanup jobs on an interval until ctx is cancelled.
func Run(ctx context.Context, store db.Store, intervalSec int, log *slog.Logger) {
	interval := time.Duration(intervalSec) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			runOnce(ctx, store, log)
		case <-ctx.Done():
			return
		}
	}
}

func runOnce(ctx context.Context, store db.Store, log *slog.Logger) {
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
}

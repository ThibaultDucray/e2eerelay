// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"relay/internal/api"
	"relay/internal/challenge"
	"relay/internal/cleanup"
	"relay/internal/config"
	"relay/internal/dailykey"
	"relay/internal/db"
	"relay/internal/hub"
	"relay/internal/quota"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	log.Info("relay server init")

	masterKey, err := dailykey.LoadMasterKeyFromEnv()
	if err != nil {
		log.Error("registration master key not configured", "err", err,
			"hint", "set MASTER_KEY_B64URL (base64url, 32 bytes) or MASTER_KEY (raw text, ≥16 chars)")
		os.Exit(1)
	}
	log.Info("master key loaded", "bytes", len(masterKey))

	cfg := config.Load()

	store, err := db.Open(cfg)
	if err != nil {
		log.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	if err := store.Migrate(); err != nil {
		log.Error("migration failed", "err", err)
		os.Exit(1)
	}

	h := hub.New()
	q := quota.New(cfg)
	rl := api.NewRateLimiter(cfg)
	cs := challenge.New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleanup.Run(ctx, store, cfg.CleanupIntervalSec, log)
	go rl.RunEviction(ctx)
	go challenge.RunEviction(ctx, cs)

	router := api.NewRouter(cfg, store, h, q, rl, cs, masterKey, log)

	// WriteTimeout must exceed MaxWaitMs to allow long-poll connections to complete.
	maxWaitSec := cfg.MaxWaitMs/1000 + 5
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Duration(maxWaitSec+5) * time.Second,
		WriteTimeout:      time.Duration(maxWaitSec+10) * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Info("relay server starting", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info("shutting down")

	cancel()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Error("shutdown error", "err", err)
	}
}

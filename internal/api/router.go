// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimid "github.com/go-chi/chi/v5/middleware"

	"relay/internal/challenge"
	"relay/internal/config"
	"relay/internal/db"
	"relay/internal/hub"
	"relay/internal/quota"
)

// Handlers holds shared dependencies for all HTTP handlers.
type Handlers struct {
	cfg        *config.Config
	store      db.Store
	hub        *hub.Hub
	quota      *quota.Store
	challenges *challenge.Store
	masterKey  []byte
	log        *slog.Logger
}

// NewRouter builds and returns the HTTP router for the relay server.
// All routes are mounted under /relay/v3.
func NewRouter(cfg *config.Config, store db.Store, h *hub.Hub, q *quota.Store, rl *RateLimiter, cs *challenge.Store, masterKey []byte, log *slog.Logger) http.Handler {
	handlers := &Handlers{cfg: cfg, store: store, hub: h, quota: q, challenges: cs, masterKey: masterKey, log: log}

	r := chi.NewRouter()
	r.Use(chimid.RealIP)
	r.Use(chimid.RequestID)
	r.Use(chimid.Recoverer)
	r.Use(chimid.RequestSize(int64(cfg.MaxMessageBytes + 8192)))

	r.Route("/relay/v3", func(r chi.Router) {
		r.Get("/health", handlers.Health)
		r.Get("/limits", handlers.Limits)

		r.With(rl.IPMiddleware()).Get("/registration/challenge", handlers.GetChallenge)
		r.With(rl.IPMiddleware()).Post("/devices", handlers.RegisterDevice)

		r.With(
			AuthMiddleware(store, cfg, "send"),
			rl.TokenMiddleware("send"),
		).Delete("/devices", handlers.DeregisterDevice)

		r.With(
			AuthMiddleware(store, cfg, "send"),
			rl.TokenMiddleware("send"),
		).Patch("/devices", handlers.RenameDevice)

		r.With(
			AuthMiddleware(store, cfg, ""),
			rl.TokenMiddleware("send"),
		).Post("/tokens/revoke", handlers.RevokeToken)

		r.With(
			AuthMiddleware(store, cfg, "send"),
			rl.TokenMiddleware("send"),
		).Post("/messages", handlers.EnqueueMessage)

		r.With(
			AuthMiddleware(store, cfg, "recv"),
			rl.TokenMiddleware("poll"),
		).Get("/messages", handlers.PollMessages)

		r.With(
			AuthMiddleware(store, cfg, "recv"),
			rl.TokenMiddleware("ack"),
		).Post("/messages/ack", handlers.AckMessages)
	})

	return r
}

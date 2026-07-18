// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

package config

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/time/rate"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	Port       string
	DSN        string
	IsPostgres bool

	MaxMessageBytes     int
	MaxRecipientsPerMsg int
	MaxMessagesPerDay   int
	MaxBytesPerDay      int64
	DefaultTTLSeconds   int
	MaxTTLSeconds       int
	MaxPollLimit        int
	MaxWaitMs           int

	CleanupIntervalSec int

	TokenTTLSeconds int // how long a token is valid after creation
	TokenIdleDays   int // token expires if unused for this many days

	RegIPRate  rate.Limit
	RegIPBurst int

	SendRate  rate.Limit
	SendBurst int
	PollRate  rate.Limit
	PollBurst int
	AckRate   rate.Limit
	AckBurst  int
}

func Load() *Config {
	dsn := getenv("DATABASE_URL", "./data/relay.db")
	isPG := strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
	return &Config{
		Port:                getenv("PORT", "8080"),
		DSN:                 dsn,
		IsPostgres:          isPG,
		MaxMessageBytes:     getint("MAX_MESSAGE_BYTES", 262144),
		MaxRecipientsPerMsg: getint("MAX_RECIPIENTS", 50),
		MaxMessagesPerDay:   getint("MAX_MSG_PER_DAY", 20000),
		MaxBytesPerDay:      int64(getint("MAX_BYTES_PER_DAY", 1<<30)), // 1 GiB default
		DefaultTTLSeconds:   getint("DEFAULT_TTL_SEC", 1296000),        // 15 days
		MaxTTLSeconds:       getint("MAX_TTL_SEC", 2592000),            // 30 days
		MaxPollLimit:        getint("MAX_POLL_LIMIT", 100),
		MaxWaitMs:           getint("MAX_WAIT_MS", 30000), // 30s
		CleanupIntervalSec:  getint("CLEANUP_INTERVAL_SEC", 600),
		TokenTTLSeconds:     getint("TOKEN_TTL_SEC", 31536000), // 1 year
		TokenIdleDays:       getint("TOKEN_IDLE_DAYS", 182),    // 6 months
		RegIPRate:           rate.Limit(getfloat("REG_IP_RATE", 0.1)), // ~6/min
		RegIPBurst:          getint("REG_IP_BURST", 5),
		SendRate:            rate.Limit(getfloat("SEND_RATE", 20)),
		SendBurst:           getint("SEND_BURST", 50),
		PollRate:            rate.Limit(getfloat("POLL_RATE", 10)),
		PollBurst:           getint("POLL_BURST", 20),
		AckRate:             rate.Limit(getfloat("ACK_RATE", 20)),
		AckBurst:            getint("ACK_BURST", 50),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getint(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getfloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

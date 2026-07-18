// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

// Package db provides the database access layer for the relay server.
// Timestamps are stored as int64 Unix nanoseconds for driver-agnostic portability.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"time"

	"relay/internal/config"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

//go:embed schema_pg.sql
var schemaPG string

//go:embed schema_sqlite.sql
var schemaSQLite string

// TokenRow is the DB representation of a relay_tokens row.
type TokenRow struct {
	TokenHash   []byte
	TokenType   string  // "send" | "recv"
	DeviceID    string
	InboxID     *string // nil for send tokens
	CreatedAt   int64
	ExpiresAt   int64
	LastUsedAt  *int64
	RevokedAt   *int64
}

// MessageRow represents a relay_messages row.
type MessageRow struct {
	MessageID           string
	StreamID            string
	SenderDeviceID      string
	CreatedAt           int64
	ExpiresAt           int64
	CipherVersion       int
	EncryptedIdentifier []byte // nil if column was NULL
	Ciphertext          []byte
	SizeBytes           int
}

// MessageWithRecipients is a MessageRow plus the full list of recipient inbox IDs.
type MessageWithRecipients struct {
	MessageRow
	RecipientInboxIDs []string
}

// PollParams holds all parameters for a PollMessages query.
type PollParams struct {
	InboxID        string
	AfterCreatedAt int64  // exclusive lower bound (ns); 0 = no lower bound
	AfterMessageID string // tiebreaker; "" = none
	StreamID       string // "" = all streams
	Limit          int
	NowNs          int64 // for expires_at > now check
}

// InsertMessageParams holds the fields needed to insert a relay_messages row.
type InsertMessageParams struct {
	MessageID           string
	StreamID            string
	SenderDeviceID      string
	CreatedAt           int64
	ExpiresAt           int64
	CipherVersion       int
	EncryptedIdentifier []byte // nil if absent
	Ciphertext          []byte
	SizeBytes           int
}

// Store is the interface for all relay database operations.
type Store interface {
	Migrate() error
	InsertDevice(ctx context.Context, deviceID, deviceName, platform, clientVersion string, nowNs int64) error
	InsertInbox(ctx context.Context, inboxID, deviceID string, nowNs int64) error
	InsertToken(ctx context.Context, tokenHash []byte, tokenType, deviceID string, inboxID *string, expiresAt, nowNs int64) error
	LookupToken(ctx context.Context, hash []byte) (*TokenRow, error)
	// TouchToken updates last_used_at for the given token hash. Non-critical; errors may be ignored.
	TouchToken(ctx context.Context, hash []byte, nowNs int64) error
	// RevokeToken sets revoked_at on the given token hash, immediately invalidating it.
	RevokeToken(ctx context.Context, hash []byte, nowNs int64) error
	InsertMessage(ctx context.Context, p InsertMessageParams) (inserted bool, err error)
	InsertMessageRecipients(ctx context.Context, messageID string, inboxIDs []string) error
	PollMessages(ctx context.Context, p PollParams) ([]MessageWithRecipients, error)
	// AckMessages marks messageIDs as acked for inboxID. Returns the count of existing
	// recipient rows (acked + already-acked) and the count of missing IDs.
	AckMessages(ctx context.Context, inboxID string, messageIDs []string, nowNs int64) (acked, missing int, err error)
	// DeleteDevice acks the device's own still-pending recipient rows (so messages
	// addressed to it can be reaped once their other recipients ack), then removes
	// the device and its inboxes/tokens (via CASCADE). Returns true if the device
	// existed, false if not found.
	DeleteDevice(ctx context.Context, deviceID string, nowNs int64) (bool, error)
	DeleteExpiredMessages(ctx context.Context, nowNs int64) (int64, error)
	DeleteFullyAckedMessages(ctx context.Context) (int64, error)
	Ping(ctx context.Context) error
	Close() error
}

type store struct {
	db   *sql.DB
	isPG bool
}

// Open creates a new Store backed by PostgreSQL or SQLite depending on config.
func Open(cfg *config.Config) (Store, error) {
	var driverName string
	if cfg.IsPostgres {
		driverName = "pgx"
	} else {
		driverName = "sqlite"
	}

	sqlDB, err := sql.Open(driverName, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if cfg.IsPostgres {
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(10)
		sqlDB.SetConnMaxLifetime(5 * time.Minute)
	} else {
		// SQLite: single writer, enable WAL + foreign keys.
		sqlDB.SetMaxOpenConns(1)
		if _, err := sqlDB.Exec("PRAGMA foreign_keys = ON"); err != nil {
			return nil, fmt.Errorf("pragma foreign_keys: %w", err)
		}
		if _, err := sqlDB.Exec("PRAGMA journal_mode = WAL"); err != nil {
			return nil, fmt.Errorf("pragma journal_mode: %w", err)
		}
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return &store{db: sqlDB, isPG: cfg.IsPostgres}, nil
}

// bind rewrites ? placeholders to $N for PostgreSQL; returns query unchanged for SQLite.
func (s *store) bind(query string) string {
	if !s.isPG {
		return query
	}
	n := 0
	var b strings.Builder
	b.Grow(len(query) + 16)
	for _, c := range query {
		if c == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (s *store) Migrate() error {
	schema := schemaSQLite
	if s.isPG {
		schema = schemaPG
	}
	// Split on semicolons and execute each statement individually.
	for _, stmt := range strings.Split(schema, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := s.db.Exec(stmt); err != nil {
			preview := stmt
			if len(preview) > 80 {
				preview = preview[:80]
			}
			return fmt.Errorf("migrate %q: %w", preview, err)
		}
	}
	return nil
}

func (s *store) InsertDevice(ctx context.Context, deviceID, deviceName, platform, clientVersion string, nowNs int64) error {
	q := s.bind(`INSERT INTO relay_devices (device_id, device_name, platform, client_version, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)`)
	_, err := s.db.ExecContext(ctx, q, deviceID, deviceName, platform, clientVersion, nowNs, nowNs)
	return err
}

func (s *store) InsertInbox(ctx context.Context, inboxID, deviceID string, nowNs int64) error {
	q := s.bind(`INSERT INTO relay_inboxes (inbox_id, device_id, created_at) VALUES (?, ?, ?)`)
	_, err := s.db.ExecContext(ctx, q, inboxID, deviceID, nowNs)
	return err
}

func (s *store) InsertToken(ctx context.Context, tokenHash []byte, tokenType, deviceID string, inboxID *string, expiresAt, nowNs int64) error {
	q := s.bind(`INSERT INTO relay_tokens (token_hash, token_type, device_id, inbox_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`)
	_, err := s.db.ExecContext(ctx, q, tokenHash, tokenType, deviceID, inboxID, nowNs, expiresAt)
	return err
}

func (s *store) LookupToken(ctx context.Context, hash []byte) (*TokenRow, error) {
	q := s.bind(`SELECT token_hash, token_type, device_id, inbox_id, created_at, expires_at, last_used_at, revoked_at FROM relay_tokens WHERE token_hash = ?`)
	var t TokenRow
	err := s.db.QueryRowContext(ctx, q, hash).Scan(
		&t.TokenHash, &t.TokenType, &t.DeviceID, &t.InboxID, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *store) TouchToken(ctx context.Context, hash []byte, nowNs int64) error {
	q := s.bind(`UPDATE relay_tokens SET last_used_at = ? WHERE token_hash = ?`)
	_, err := s.db.ExecContext(ctx, q, nowNs, hash)
	return err
}

func (s *store) RevokeToken(ctx context.Context, hash []byte, nowNs int64) error {
	q := s.bind(`UPDATE relay_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`)
	_, err := s.db.ExecContext(ctx, q, nowNs, hash)
	return err
}

func (s *store) InsertMessage(ctx context.Context, p InsertMessageParams) (bool, error) {
	var q string
	if s.isPG {
		q = `INSERT INTO relay_messages (message_id, stream_id, sender_device_id, created_at, expires_at, cipher_version, encrypted_identifier, ciphertext, size_bytes)
		     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING`
	} else {
		q = `INSERT OR IGNORE INTO relay_messages (message_id, stream_id, sender_device_id, created_at, expires_at, cipher_version, encrypted_identifier, ciphertext, size_bytes)
		     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	}
	res, err := s.db.ExecContext(ctx, q,
		p.MessageID, p.StreamID, p.SenderDeviceID,
		p.CreatedAt, p.ExpiresAt, p.CipherVersion,
		nilIfEmpty(p.EncryptedIdentifier), p.Ciphertext, p.SizeBytes,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *store) InsertMessageRecipients(ctx context.Context, messageID string, inboxIDs []string) error {
	if len(inboxIDs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var q string
	if s.isPG {
		q = `INSERT INTO relay_message_recipients (message_id, recipient_inbox_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	} else {
		q = `INSERT OR IGNORE INTO relay_message_recipients (message_id, recipient_inbox_id) VALUES (?, ?)`
	}
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, id := range inboxIDs {
		if _, err := stmt.ExecContext(ctx, messageID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *store) PollMessages(ctx context.Context, p PollParams) ([]MessageWithRecipients, error) {
	args := []interface{}{p.InboxID, p.NowNs}
	q := `SELECT m.message_id, m.stream_id, m.sender_device_id, m.created_at, m.expires_at,
		       m.cipher_version, m.encrypted_identifier, m.ciphertext, m.size_bytes
		  FROM relay_messages m
		  JOIN relay_message_recipients mr ON mr.message_id = m.message_id
		  WHERE mr.recipient_inbox_id = ?
		    AND mr.acked_at IS NULL
		    AND m.expires_at > ?`

	if p.StreamID != "" {
		args = append(args, p.StreamID)
		q += ` AND m.stream_id = ?`
	}
	if p.AfterCreatedAt > 0 || p.AfterMessageID != "" {
		args = append(args, p.AfterCreatedAt, p.AfterCreatedAt, p.AfterMessageID)
		q += ` AND (m.created_at > ? OR (m.created_at = ? AND m.message_id > ?))`
	}
	q += ` ORDER BY m.created_at ASC, m.message_id ASC LIMIT ?`
	args = append(args, p.Limit)

	rows, err := s.db.QueryContext(ctx, s.bind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []MessageWithRecipients
	msgIdx := make(map[string]int) // message_id -> index in msgs

	for rows.Next() {
		var m MessageWithRecipients
		if err := rows.Scan(
			&m.MessageID, &m.StreamID, &m.SenderDeviceID,
			&m.CreatedAt, &m.ExpiresAt, &m.CipherVersion,
			&m.EncryptedIdentifier, &m.Ciphertext, &m.SizeBytes,
		); err != nil {
			return nil, err
		}
		msgIdx[m.MessageID] = len(msgs)
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, nil
	}

	// Fetch all recipient lists for the returned messages in one query.
	msgIDs := make([]interface{}, len(msgs))
	for i, m := range msgs {
		msgIDs[i] = m.MessageID
	}
	rq := `SELECT message_id, recipient_inbox_id FROM relay_message_recipients WHERE message_id IN ` + placeholders(len(msgIDs))
	rrows, err := s.db.QueryContext(ctx, s.bind(rq), msgIDs...)
	if err != nil {
		return nil, err
	}
	defer rrows.Close()

	for rrows.Next() {
		var msgID, inboxID string
		if err := rrows.Scan(&msgID, &inboxID); err != nil {
			return nil, err
		}
		if idx, ok := msgIdx[msgID]; ok {
			msgs[idx].RecipientInboxIDs = append(msgs[idx].RecipientInboxIDs, inboxID)
		}
	}
	if err := rrows.Err(); err != nil {
		return nil, err
	}

	return msgs, nil
}

func (s *store) AckMessages(ctx context.Context, inboxID string, messageIDs []string, nowNs int64) (acked, missing int, err error) {
	if len(messageIDs) == 0 {
		return 0, 0, nil
	}
	ph := placeholders(len(messageIDs))

	// Count existing rows (acked or not) for this inbox + message set.
	cArgs := make([]interface{}, 0, len(messageIDs)+1)
	cArgs = append(cArgs, inboxID)
	for _, id := range messageIDs {
		cArgs = append(cArgs, id)
	}
	cq := `SELECT COUNT(*) FROM relay_message_recipients WHERE recipient_inbox_id = ? AND message_id IN ` + ph
	var existCount int
	if err = s.db.QueryRowContext(ctx, s.bind(cq), cArgs...).Scan(&existCount); err != nil {
		return 0, 0, err
	}

	// Update unacked rows.
	uArgs := make([]interface{}, 0, len(messageIDs)+2)
	uArgs = append(uArgs, nowNs, inboxID)
	for _, id := range messageIDs {
		uArgs = append(uArgs, id)
	}
	uq := `UPDATE relay_message_recipients SET acked_at = ? WHERE recipient_inbox_id = ? AND acked_at IS NULL AND message_id IN ` + ph
	if _, err = s.db.ExecContext(ctx, s.bind(uq), uArgs...); err != nil {
		return 0, 0, err
	}

	return existCount, len(messageIDs) - existCount, nil
}

func (s *store) DeleteDevice(ctx context.Context, deviceID string, nowNs int64) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Ack this device's own still-pending recipient rows before it disappears, so
	// DeleteFullyAckedMessages isn't blocked forever waiting on a device that will
	// never poll again. Not a real ack (the message was never actually delivered/
	// decrypted) but functionally equivalent once the device no longer exists.
	ackQ := s.bind(`
		UPDATE relay_message_recipients SET acked_at = ?
		WHERE acked_at IS NULL AND recipient_inbox_id IN (
			SELECT inbox_id FROM relay_inboxes WHERE device_id = ?
		)`)
	if _, err := tx.ExecContext(ctx, ackQ, nowNs, deviceID); err != nil {
		return false, err
	}

	delQ := s.bind(`DELETE FROM relay_devices WHERE device_id = ?`)
	res, err := tx.ExecContext(ctx, delQ, deviceID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *store) DeleteExpiredMessages(ctx context.Context, nowNs int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM relay_messages WHERE expires_at < ?`), nowNs)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *store) DeleteFullyAckedMessages(ctx context.Context) (int64, error) {
	q := `DELETE FROM relay_messages WHERE message_id IN (
		SELECT m.message_id FROM relay_messages m
		WHERE NOT EXISTS (
			SELECT 1 FROM relay_message_recipients r
			WHERE r.message_id = m.message_id AND r.acked_at IS NULL
		)
	)`
	res, err := s.db.ExecContext(ctx, q)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *store) Close() error {
	return s.db.Close()
}

// placeholders returns "(?, ?, ...)" with n entries.
func placeholders(n int) string {
	if n == 0 {
		return "(NULL)"
	}
	var b strings.Builder
	b.WriteString("(")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("?")
	}
	b.WriteString(")")
	return b.String()
}

// nilIfEmpty returns nil if b is empty, otherwise b. Used to store NULL for
// absent optional byte fields.
func nilIfEmpty(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}

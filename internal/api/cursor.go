// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Cursor encodes the (created_at_ns, message_id) pagination position.
type Cursor struct {
	CreatedAt int64  // Unix nanoseconds
	MessageID string // UUID string
}

// EncodeCursor encodes a Cursor as a base64url-safe opaque string.
func EncodeCursor(c Cursor) string {
	raw := fmt.Sprintf("%d:%s", c.CreatedAt, c.MessageID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor decodes a cursor string previously produced by EncodeCursor.
func DecodeCursor(s string) (Cursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, errors.New("invalid cursor encoding")
	}
	parts := strings.SplitN(string(b), ":", 2)
	if len(parts) != 2 {
		return Cursor{}, errors.New("invalid cursor format")
	}
	ns, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return Cursor{}, errors.New("invalid cursor timestamp")
	}
	return Cursor{CreatedAt: ns, MessageID: parts[1]}, nil
}

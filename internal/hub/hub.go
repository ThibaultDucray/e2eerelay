// Copyright (c) 2026 Thibault Ducray
// SPDX-License-Identifier: MIT
// Use of this source code is governed by the MIT license found in the LICENSE file.

// Package hub provides a pub/sub hub for long-poll notifications.
package hub

import "sync"

// Hub manages waiting channels per inbox for long-poll wakeup.
type Hub struct {
	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

func New() *Hub {
	return &Hub{waiters: make(map[string][]chan struct{})}
}

// Subscribe returns a buffered channel that receives one signal when a message
// arrives for inboxID. Caller must always call Unsubscribe when done.
func (h *Hub) Subscribe(inboxID string) chan struct{} {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.waiters[inboxID] = append(h.waiters[inboxID], ch)
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes the channel from the waiters list.
func (h *Hub) Unsubscribe(inboxID string, ch chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.waiters[inboxID]
	for i, c := range list {
		if c == ch {
			h.waiters[inboxID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(h.waiters[inboxID]) == 0 {
		delete(h.waiters, inboxID)
	}
}

// Notify wakes all waiters for inboxID. Non-blocking; uses buffered channels.
func (h *Hub) Notify(inboxID string) {
	h.mu.Lock()
	list := make([]chan struct{}, len(h.waiters[inboxID]))
	copy(list, h.waiters[inboxID])
	h.mu.Unlock()
	for _, ch := range list {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

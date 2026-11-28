// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

// Package concurrency provides zero-dependency, CGO-free deterministic Go async
// primitives refining the Quint formal models under
// packages/quint-models/engineering/concurrency/.
package concurrency

import (
	"sync"
	"sync/atomic"
)

// Snapshot carries an immutable value paired with its monotonically published
// RCU generation number.
type Snapshot[T any] struct {
	Gen   uint64
	Value T
}

// SnapshotStore refines engineering.concurrency.ui-mainthread-rcu-snapshot:
// readers (e.g. a 120Hz GPU render thread) execute a single wait-free
// atomic.Pointer load without acquiring any mutex, while background writers
// perform slow I/O/parsing off-lock and publish complete immutable snapshots
// via an atomic swap.
type SnapshotStore[T any] struct {
	ptr     atomic.Pointer[Snapshot[T]]
	writeMu sync.Mutex
}

// NewSnapshotStore initializes a SnapshotStore with generation 1.
func NewSnapshotStore[T any](initial T) *SnapshotStore[T] {
	s := &SnapshotStore[T]{}
	s.ptr.Store(&Snapshot[T]{Gen: 1, Value: initial})
	return s
}

// Load returns the latest published immutable snapshot in O(1) without locking.
// Safe to call at 120Hz on the UI main thread.
func (s *SnapshotStore[T]) Load() *Snapshot[T] {
	return s.ptr.Load()
}

// Commit atomically applies a fast, non-blocking pure state transition and
// publishes the next generation. Never perform disk or network I/O inside fn.
func (s *SnapshotStore[T]) Commit(fn func(prev T) T) *Snapshot[T] {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	cur := s.ptr.Load()
	var prev T
	var gen uint64
	if cur != nil {
		prev = cur.Value
		gen = cur.Gen
	}
	next := &Snapshot[T]{Gen: gen + 1, Value: fn(prev)}
	s.ptr.Store(next)
	return next
}

// StageAndPublish runs potentially slow off-lock work (e.g. reading TOML/CSS/
// tokens.json or compiling widgets) completely outside writeMu, then merges the
// staged artifact into the latest published state under writeMu and swaps
// atomically. Readers NEVER observe a torn state or block on stage().
func (s *SnapshotStore[T]) StageAndPublish(
	stage func(base T) (any, error),
	merge func(latest T, staged any) T,
) (*Snapshot[T], error) {
	baseSnap := s.ptr.Load()
	var base T
	if baseSnap != nil {
		base = baseSnap.Value
	}
	staged, err := stage(base)
	if err != nil {
		return baseSnap, err
	}
	return s.Commit(func(latest T) T {
		return merge(latest, staged)
	}), nil
}

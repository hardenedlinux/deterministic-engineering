// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

package concurrency

import (
	"context"
	"errors"
	"sync"
)

// ErrPoolOverloaded indicates that the bounded backpressure admission or queue
// ceiling has been reached.
var ErrPoolOverloaded = errors.New("concurrency: bounded permit pool overloaded")

// PermitState tracks disjoint ownership states matching BackpressureOwners.qnt.
type PermitState uint8

const (
	PermitQueued PermitState = iota
	PermitRunning
	PermitReturned
	PermitCleanup
	PermitDone
)

// PermitPool refines engineering.concurrency.backpressure-memory:
// every admitted job occupies exactly one disjoint state (queued, running,
// returned, or cleanup), admitted <= limit, queued <= queueLimit, and a
// cancelled job retains its permit through non-abortable cleanup until
// FinishCleanup is called.
type PermitPool struct {
	mu                sync.Mutex
	limit             int
	queueLimit        int
	states            map[uint64]PermitState
	queued            int
	nextID            uint64
	drainsSinceRotate int
	rotateThreshold   int
	rotations         uint64
}

// NewPermitPool creates a bounded PermitPool with explicit admission and queue limits.
func NewPermitPool(limit, queueLimit int) *PermitPool {
	if limit <= 0 {
		limit = 1
	}
	if queueLimit <= 0 {
		queueLimit = 1
	}
	rotateThreshold := limit * 4
	if rotateThreshold < 16 {
		rotateThreshold = 16
	}
	return &PermitPool{
		limit:           limit,
		queueLimit:      queueLimit,
		states:          make(map[uint64]PermitState, limit),
		rotateThreshold: rotateThreshold,
	}
}

// Admit acquires a permit in the Queued state if both limit and queueLimit allow.
func (p *PermitPool) Admit() (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.states) >= p.limit || p.queued >= p.queueLimit {
		return 0, ErrPoolOverloaded
	}
	p.nextID++
	id := p.nextID
	p.states[id] = PermitQueued
	p.queued++
	return id, nil
}

// Start transitions a Queued permit to Running.
func (p *PermitPool) Start(id uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.states[id]; !ok || st != PermitQueued {
		return false
	}
	p.states[id] = PermitRunning
	p.queued--
	return true
}

// Complete transitions a Running permit to Returned.
func (p *PermitPool) Complete(id uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.states[id]; !ok || st != PermitRunning {
		return false
	}
	p.states[id] = PermitReturned
	return true
}

// BeginCancelCleanup transitions a Running permit to non-abortable Cleanup
// WITHOUT prematurely releasing its capacity permit.
func (p *PermitPool) BeginCancelCleanup(id uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.states[id]; !ok || st != PermitRunning {
		return false
	}
	p.states[id] = PermitCleanup
	return true
}

// Drain releases a Returned or Cleanup permit cleanly into Done.
// At quiescence (len(states) == 0) after sufficient churn, the backing map is
// rotated to a fresh small allocation so Go map buckets never ratchet forever (SM3).
func (p *PermitPool) Drain(id uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.states[id]
	if !ok || (st != PermitReturned && st != PermitCleanup) {
		return false
	}
	delete(p.states, id)
	p.drainsSinceRotate++
	if len(p.states) == 0 && p.drainsSinceRotate >= p.rotateThreshold {
		p.states = make(map[uint64]PermitState, p.limit)
		p.drainsSinceRotate = 0
		p.rotations++
	}
	return true
}

// Rotations reports how many quiescent map-bucket rotations have been performed.
func (p *PermitPool) Rotations() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rotations
}

// Stats returns active (admitted) and queued counts for invariant verification.
func (p *PermitPool) Stats() (admitted, queued int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.states), p.queued
}

// StructuredScope refines engineering.concurrency.structured-cancellation:
// every background goroutine is lexically bound to a parent scope, new spawns
// are rejected once cancellation begins, and CloseAndDrain blocks until every
// child completes draining (zero orphan effects).
type StructuredScope struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	closing  bool
	wg       sync.WaitGroup
	children int
}

// NewStructuredScope creates a structured concurrency nursery derived from parent.
func NewStructuredScope(parent context.Context) *StructuredScope {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &StructuredScope{ctx: ctx, cancel: cancel}
}

// Go spawns a tracked child goroutine bound to the scope. Returns false if the
// scope has already begun cancelling or closed.
func (s *StructuredScope) Go(fn func(ctx context.Context)) bool {
	if fn == nil {
		return false
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return false
	}
	s.children++
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.children--
			s.mu.Unlock()
			s.wg.Done()
		}()
		fn(s.ctx)
	}()
	return true
}

// ActiveChildren reports the number of currently running or draining children.
func (s *StructuredScope) ActiveChildren() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.children
}

// CloseAndDrain cancels the scope context and blocks until all spawned children
// reach quiescence (0 active children).
func (s *StructuredScope) CloseAndDrain() {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

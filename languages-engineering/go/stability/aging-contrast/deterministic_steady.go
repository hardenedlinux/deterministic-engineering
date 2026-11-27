// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

package agingcontrast

import (
	"context"
	"sync"
)

// DeterministicChannelWorker prevents goroutine leaks (SM2/SM4) by combining
// a buffered result channel, context-aware select inside the worker, and an
// explicit WaitGroup quiescence barrier before returning.
func DeterministicChannelWorker(ctx context.Context, payload []byte) bool {
	resCh := make(chan int, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case resCh <- len(payload):
		case <-ctx.Done():
		}
	}()

	var ok bool
	select {
	case <-resCh:
		ok = true
	case <-ctx.Done():
		ok = false
	}
	// Structured concurrency quiescence barrier: child goroutine is guaranteed exited.
	wg.Wait()
	return ok
}

// DeterministicBufferPool enforces both slotCap and maxRetainCap so spike
// allocations never ratchet quiescent retained memory (SM3).
type DeterministicBufferPool struct {
	mu           sync.Mutex
	slotCap      int
	maxRetainCap int
	pool         [][]byte
}

func NewDeterministicBufferPool(slotCap, maxRetainCap int) *DeterministicBufferPool {
	return &DeterministicBufferPool{
		slotCap:      slotCap,
		maxRetainCap: maxRetainCap,
		pool:         make([][]byte, 0, slotCap),
	}
}

func (p *DeterministicBufferPool) Acquire(size int) []byte {
	if size <= p.maxRetainCap {
		p.mu.Lock()
		if n := len(p.pool); n > 0 {
			buf := p.pool[n-1]
			p.pool = p.pool[:n-1]
			p.mu.Unlock()
			if cap(buf) >= size {
				return buf[:size]
			}
		} else {
			p.mu.Unlock()
		}
	}
	return make([]byte, size)
}

func (p *DeterministicBufferPool) Release(buf []byte) {
	if cap(buf) > p.maxRetainCap {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pool) >= p.slotCap {
		return
	}
	p.pool = append(p.pool, buf[:0])
}

func (p *DeterministicBufferPool) RetainedCapacityBytes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, b := range p.pool {
		total += cap(b)
	}
	return total
}

// DeterministicRetryController enforces congestion-aware load shedding and
// an explicit retry budget (SM5).
type DeterministicRetryController struct {
	QueueCap       int
	RetryBudget    int
	Congested      bool
	QueueDepth     int
	RetriesPending int
	ShedCount      int
}

func (c *DeterministicRetryController) AdmitFresh() bool {
	if c.Congested || c.QueueDepth >= c.QueueCap {
		c.ShedCount++
		return false
	}
	c.QueueDepth++
	return true
}

func (c *DeterministicRetryController) OnTimeoutRetry() bool {
	if !c.Congested || c.QueueDepth == 0 {
		return false
	}
	if c.RetriesPending >= c.RetryBudget || c.QueueDepth >= c.QueueCap {
		c.ShedCount++
		return false
	}
	c.QueueDepth++
	c.RetriesPending++
	return true
}

func (c *DeterministicRetryController) Drain(budget int) {
	for budget > 0 && c.QueueDepth > 0 {
		c.QueueDepth--
		if c.RetriesPending > 0 {
			c.RetriesPending--
		}
		budget--
	}
	if c.QueueDepth == 0 {
		c.Congested = false
	}
}

// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

package agingcontrast

import (
	"context"
	"sync"
)

// BadBlockedChannelWorker demonstrates the canonical Go goroutine leak from
// Tu et al. (ASPLOS 2019): when ctx is cancelled before the worker sends its
// result on an unbuffered channel, the worker goroutine blocks forever and
// retains its stack + captured buffer.
func BadBlockedChannelWorker(ctx context.Context, payload []byte) bool {
	resCh := make(chan int) // unbuffered!
	go func() {
		// Blocks forever if caller already returned on ctx.Done().
		resCh <- len(payload)
	}()
	select {
	case <-resCh:
		return true
	case <-ctx.Done():
		return false
	}
}

// BadBufferPool retains spike-sized byte slices indefinitely without checking
// cap(buf) against a steady-state retain ceiling (SM3 watermark ratchet).
type BadBufferPool struct {
	mu   sync.Mutex
	pool [][]byte
}

func (p *BadBufferPool) Acquire(size int) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.pool); n > 0 {
		buf := p.pool[n-1]
		p.pool = p.pool[:n-1]
		if cap(buf) >= size {
			return buf[:size]
		}
	}
	return make([]byte, size)
}

func (p *BadBufferPool) Release(buf []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// SM3 ARB: retains oversized spike buffers and grows slot count unboundedly.
	p.pool = append(p.pool, buf[:0])
}

func (p *BadBufferPool) RetainedCapacityBytes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, b := range p.pool {
		total += cap(b)
	}
	return total
}

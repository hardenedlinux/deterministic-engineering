// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

package agingcontrast

import (
	"bytes"
	"net"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"
)

// TestGoSubslicePinningAndMapNeverShrink measures REAL Go runtime HeapAlloc via
// runtime.ReadMemStats to contrast two classic Go long-running memory-bloat traps:
//   1. Sub-slicing a large []byte pins the entire backing array across GC vs bytes.Clone.
//   2. Deleting all keys from a Go map retains bucket memory forever vs epoch rotation.
func TestGoSubslicePinningAndMapNeverShrink(t *testing.T) {
	// ── Part A: Sub-slice backing-array pinning vs bytes.Clone ──
	const slabSize = 2 << 20 // 2 MiB per slab
	const slabs = 16         // 32 MiB total if pinned

	runtime.GC()
	var baseStats runtime.MemStats
	runtime.ReadMemStats(&baseStats)

	// Bad pattern: retain 16-byte header sub-slices directly from 2 MiB slabs.
	pinnedHeaders := make([][]byte, 0, slabs)
	for i := 0; i < slabs; i++ {
		big := make([]byte, slabSize)
		big[0] = byte(i + 1)
		pinnedHeaders = append(pinnedHeaders, big[:16])
	}
	runtime.GC()
	var pinnedStats runtime.MemStats
	runtime.ReadMemStats(&pinnedStats)
	// Keep pinnedHeaders alive until after ReadMemStats.
	if len(pinnedHeaders) != slabs || pinnedHeaders[0][0] != 1 {
		t.Fatalf("unexpected pinnedHeaders state")
	}

	// Deterministic pattern: detach small header via bytes.Clone so 2 MiB slabs collect.
	clonedHeaders := make([][]byte, 0, slabs)
	for i := 0; i < slabs; i++ {
		big := make([]byte, slabSize)
		big[0] = byte(i + 1)
		clonedHeaders = append(clonedHeaders, bytes.Clone(big[:16]))
	}
	// Release pinnedHeaders before measuring cloned retention.
	pinnedHeaders = nil
	runtime.GC()
	var clonedStats runtime.MemStats
	runtime.ReadMemStats(&clonedStats)
	if len(clonedHeaders) != slabs || clonedHeaders[0][0] != 1 {
		t.Fatalf("unexpected clonedHeaders state")
	}

	if pinnedStats.HeapAlloc <= baseStats.HeapAlloc+(16<<20) {
		t.Fatalf("expected pinned sub-slices to retain >16 MiB live heap: base=%d pinned=%d",
			baseStats.HeapAlloc, pinnedStats.HeapAlloc)
	}
	if clonedStats.HeapAlloc >= pinnedStats.HeapAlloc-(16<<20) {
		t.Fatalf("expected bytes.Clone to release >16 MiB vs pinned: pinned=%d cloned=%d",
			pinnedStats.HeapAlloc, clonedStats.HeapAlloc)
	}

	// ── Part B: Go map never shrinks buckets after delete() vs epoch map rotation ──
	const entries = 60000
	m := make(map[int][128]byte, entries)
	for i := 0; i < entries; i++ {
		m[i] = [128]byte{byte(i)}
	}
	for i := 0; i < entries; i++ {
		delete(m, i)
	}
	runtime.GC()
	var afterDeleteStats runtime.MemStats
	runtime.ReadMemStats(&afterDeleteStats)
	if len(m) != 0 {
		t.Fatalf("expected empty map after deletes")
	}

	// Deterministic boundary: rotate/rebuild map when quiescent or over high-water ratio.
	m = make(map[int][128]byte)
	runtime.GC()
	var afterRotateStats runtime.MemStats
	runtime.ReadMemStats(&afterRotateStats)
	if len(m) != 0 {
		t.Fatalf("expected empty rotated map")
	}

	if afterDeleteStats.HeapAlloc <= afterRotateStats.HeapAlloc+(4<<20) {
		t.Fatalf("expected deleted-but-unrotated map to retain >4 MiB buckets vs rotated map: afterDelete=%d afterRotate=%d",
			afterDeleteStats.HeapAlloc, afterRotateStats.HeapAlloc)
	}
}

// gcChurnSink forces short-lived allocation slices in TestGoGomemlimitHeadroomVsThrash
// to escape to the Go heap rather than being stack-allocated by escape analysis.
var gcChurnSink []byte

// TestGoGomemlimitHeadroomVsThrash measures REAL runtime.ReadMemStats().NumGC under
// debug.SetMemoryLimit (GOMEMLIMIT) to contrast zero-headroom live-set crowding
// (GC thrashing) against headroom-preserving admission shedding (SM3b).
func TestGoGomemlimitHeadroomVsThrash(t *testing.T) {
	// Restore original GC settings on exit.
	prevLimit := debug.SetMemoryLimit(-1)
	prevGOGC := debug.SetGCPercent(100)
	defer func() {
		gcChurnSink = nil
		debug.SetMemoryLimit(prevLimit)
		debug.SetGCPercent(prevGOGC)
	}()

	// Establish baseline runtime footprint (live heap + non-heap runtime memory that
	// Go's GOMEMLIMIT pacer counts against softLimit), then grant 16 MiB of headroom.
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	baseFootprint := base.HeapAlloc + base.StackInuse + base.MSpanInuse + base.MCacheInuse + base.GCSys + base.OtherSys
	softLimit := int64(baseFootprint) + (16 << 20)
	debug.SetGCPercent(-1) // Pure GOMEMLIMIT pacing so headroom effect is isolated cleanly.
	debug.SetMemoryLimit(softLimit)

	runChurn := func(pinnedMiB int) (uint32, uint64) {
		gcChurnSink = nil
		runtime.GC()

		ballast := make([][]byte, pinnedMiB)
		for i := range ballast {
			b := make([]byte, 1<<20)
			b[0] = byte(i + 1)
			ballast[i] = b
		}
		runtime.GC()

		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		// Perform 48 MiB of real heap-escaped short-lived request allocations (128 KiB each).
		const chunkBytes = 128 << 10
		const chunks = 384 // 48 MiB total churn
		for i := 0; i < chunks; i++ {
			buf := make([]byte, chunkBytes)
			buf[0] = byte(i)
			buf[chunkBytes-1] = byte(i ^ 0x5a)
			gcChurnSink = buf
		}
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(ballast)
		gcChurnSink = nil
		ballast = nil
		runtime.GC()

		return after.NumGC - before.NumGC, after.TotalAlloc - before.TotalAlloc
	}

	// Crowded near softLimit (14 MiB pinned out of 16 MiB budget -> ~2 MiB free headroom):
	thrashCycles, thrashAlloc := runChurn(14)
	// Headroom-guarded admission (4 MiB pinned out of 16 MiB budget -> ~12 MiB free headroom):
	healthyCycles, healthyAlloc := runChurn(4)

	t.Logf("GOMEMLIMIT soak: softLimit=%d MiB | thrash(14MiB pinned): NumGC=%d TotalAlloc=%d MiB | healthy(4MiB pinned): NumGC=%d TotalAlloc=%d MiB",
		softLimit>>20, thrashCycles, thrashAlloc>>20, healthyCycles, healthyAlloc>>20)

	if thrashAlloc < (40<<20) || healthyAlloc < (40<<20) {
		t.Fatalf("expected >=40 MiB real heap churn per run: thrashAlloc=%d healthyAlloc=%d",
			thrashAlloc, healthyAlloc)
	}
	if thrashCycles == 0 || healthyCycles == 0 {
		t.Fatalf("expected non-zero GC cycles under 48 MiB churn: thrash=%d healthy=%d",
			thrashCycles, healthyCycles)
	}
	if thrashCycles <= healthyCycles*2 {
		t.Fatalf("expected crowded GOMEMLIMIT headroom to trigger >2x GC cycles: thrash=%d healthy=%d",
			thrashCycles, healthyCycles)
	}
}

// TestGoSlowConsumerPipeEvictionNoLeak tests REAL net.Pipe() fan-out streams under -race:
// a stalled subscriber that never reads is evicted once its bounded send queue saturates,
// closing its pipe and draining its writer goroutine with zero leak while healthy subscribers
// receive 100% of frames without Head-of-Line blocking (SM4b / SM5b).
func TestGoSlowConsumerPipeEvictionNoLeak(t *testing.T) {
	type subscriber struct {
		name    string
		conn    net.Conn
		queue   chan []byte
		evicted bool
		wg      sync.WaitGroup
	}

	startSub := func(name string, conn net.Conn, capSlots int) *subscriber {
		s := &subscriber{
			name:  name,
			conn:  conn,
			queue: make(chan []byte, capSlots),
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			for frame := range s.queue {
				_ = conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
				if _, err := conn.Write(frame); err != nil {
					return
				}
			}
		}()
		return s
	}

	evictSub := func(s *subscriber) {
		if s.evicted {
			return
		}
		s.evicted = true
		_ = s.conn.Close() // unblock any in-flight Write immediately
		close(s.queue)
		// Drain remaining queued frames cleanly so buffers are immediately collectible.
		for range s.queue {
		}
		s.wg.Wait()
	}

	runtime.GC()
	beforeGoroutines := runtime.NumGoroutine()

	fastServer, fastClient := net.Pipe()
	slowServer, slowClient := net.Pipe()
	defer fastClient.Close()
	defer slowClient.Close()

	// Fast reader drains every frame cleanly.
	const totalFrames = 40
	var fastReadWG sync.WaitGroup
	fastReceived := 0
	fastReadWG.Add(1)
	go func() {
		defer fastReadWG.Done()
		buf := make([]byte, 32)
		for {
			n, err := fastClient.Read(buf)
			if n > 0 {
				fastReceived++
			}
			if err != nil {
				return
			}
		}
	}()

	fastSub := startSub("fast", fastServer, 8)
	slowSub := startSub("slow", slowServer, 2)

	// Publish 40 frames; slowSub never reads, so once its 2-slot buffer fills it is evicted
	// without stalling fastSub.
	for i := 0; i < totalFrames; i++ {
		frame := []byte("frame-payload-01")
		// Healthy fast consumer receives every frame:
		fastSub.queue <- frame
		// Slow consumer uses non-blocking bounded send with deterministic eviction:
		if !slowSub.evicted {
			select {
			case slowSub.queue <- frame:
			default:
				evictSub(slowSub)
			}
		}
	}

	// Cleanly shut down healthy consumer and assert exact quiescence.
	close(fastSub.queue)
	fastSub.wg.Wait()
	fastReadWG.Wait()

	if !slowSub.evicted {
		t.Fatalf("expected stalled slow consumer to be evicted")
	}
	if fastReceived != totalFrames {
		t.Fatalf("expected healthy consumer to receive all %d frames without HoL blocking, got %d",
			totalFrames, fastReceived)
	}

	runtime.GC()
	afterGoroutines := runtime.NumGoroutine()
	if afterGoroutines > beforeGoroutines {
		t.Fatalf("slow-consumer eviction leaked goroutines: before=%d after=%d",
			beforeGoroutines, afterGoroutines)
	}
}

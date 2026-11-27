// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Paired aging anti-patterns in TypeScript/Node.js demonstrating SM2/SM3/SM4/SM5:
 * 1. BadHandleManager: leaks logical handles/timers on error & abort paths (ARB linear drift).
 * 2. BadBufferPool: recycles spike buffers without retain ceiling or slot cap (watermark ratchet).
 * 3. BadRetryController: lacks congestion shedding and retry budget (metastable collapse).
 */

export type CycleOutcome = 'ok' | 'error' | 'cancel';

export class BadHandleManager {
  private readonly liveHandles = new Set<number>();
  private nextId = 1;
  activeWork = 0;

  runOperation(outcome: CycleOutcome): void {
    const id = this.nextId++;
    this.liveHandles.add(id);
    this.activeWork += 1;
    if (outcome === 'error') {
      // ARB anti-pattern (SM2): early return on error forgets to release handle.
      this.activeWork -= 1;
      return;
    }
    if (outcome === 'cancel') {
      // ARB anti-pattern (SM4): caller returns on cancel without draining worker handle.
      this.activeWork -= 1;
      return;
    }
    this.liveHandles.delete(id);
    this.activeWork -= 1;
  }

  heldHandleCount(): number {
    return this.liveHandles.size;
  }
}

export class BadBufferPool {
  private readonly pool: Uint8Array[] = [];

  acquire(size: number): Uint8Array {
    const reused = this.pool.pop();
    if (reused && reused.byteLength >= size) {
      return reused;
    }
    return new Uint8Array(size);
  }

  release(buf: Uint8Array): void {
    // ARB anti-pattern (SM3): blindly retains spike buffers and grows pool slots without bound.
    this.pool.push(buf);
  }

  pooledSlots(): number {
    return this.pool.length;
  }

  retainedBytes(): number {
    let total = 0;
    for (const b of this.pool) total += b.byteLength;
    return total;
  }
}

export class BadRetryController {
  congested = false;
  queueDepth = 0;
  retriesPending = 0;
  shedCount = 0;

  admitFresh(): void {
    // ARB anti-pattern (SM5): admits unconditionally even when congested.
    this.queueDepth += 1;
  }

  triggerCongestion(): void {
    this.congested = true;
  }

  onTimeoutRetry(): void {
    if (this.congested && this.queueDepth > 0) {
      // ARB anti-pattern (SM5): unbounded retry amplification multiplies queue depth.
      this.queueDepth += 1;
      this.retriesPending += 1;
    }
  }

  drainStep(budget: number): void {
    // Under metastable overload, a single drain budget cannot empty an unbounded retry queue.
    let remaining = budget;
    while (remaining > 0 && this.queueDepth > 0) {
      this.queueDepth -= 1;
      if (this.retriesPending > 0) this.retriesPending -= 1;
      remaining -= 1;
    }
    if (this.queueDepth === 0) this.congested = false;
  }
}

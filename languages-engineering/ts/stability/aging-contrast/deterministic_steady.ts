// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Deterministic steady-state counterparts in TypeScript/Node.js (SM2/SM3/SM4/SM5):
 * 1. DeterministicHandleManager: guaranteed finally-cleanup across normal, error, and cancel exits.
 * 2. DeterministicBufferPool: enforces slotCap and maxRetainCap so spike payloads never poison pool.
 * 3. DeterministicRetryController: congestion-aware load shedding + explicit retry budget.
 */

import type {CycleOutcome} from './bad_aging.ts';

export class DeterministicHandleManager {
  private readonly liveHandles = new Set<number>();
  private nextId = 1;
  activeWork = 0;

  constructor(private readonly cap: number) {}

  runOperation(outcome: CycleOutcome): 'completed' | 'refused-capacity' {
    if (this.liveHandles.size >= this.cap) {
      return 'refused-capacity';
    }
    const id = this.nextId++;
    this.liveHandles.add(id);
    this.activeWork += 1;
    try {
      if (outcome === 'error') {
        throw new Error('injected-error');
      }
      if (outcome === 'cancel') {
        // Explicit synchronous cancel-drain branch before releasing ownership.
        return 'completed';
      }
      return 'completed';
    } catch {
      return 'completed';
    } finally {
      // Deterministic boundary (SM2/SM4): every exit path releases both handle and active count.
      this.liveHandles.delete(id);
      this.activeWork -= 1;
    }
  }

  heldHandleCount(): number {
    return this.liveHandles.size;
  }
}

export class DeterministicBufferPool {
  private readonly pool: Uint8Array[] = [];

  constructor(
    private readonly slotCap: number,
    private readonly maxRetainCap: number,
  ) {}

  acquire(size: number): Uint8Array {
    if (size <= this.maxRetainCap && this.pool.length > 0) {
      const reused = this.pool.pop()!;
      if (reused.byteLength >= size) {
        return reused;
      }
    }
    return new Uint8Array(size);
  }

  release(buf: Uint8Array): void {
    // Deterministic boundary (SM3): discard spike buffers above maxRetainCap and excess slots.
    if (buf.byteLength > this.maxRetainCap) {
      return;
    }
    if (this.pool.length >= this.slotCap) {
      return;
    }
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

export class DeterministicRetryController {
  congested = false;
  queueDepth = 0;
  retriesPending = 0;
  shedCount = 0;

  constructor(
    private readonly queueCap: number,
    private readonly retryBudget: number,
  ) {}

  admitFresh(): 'admitted' | 'shed' {
    if (this.congested || this.queueDepth >= this.queueCap) {
      this.shedCount += 1;
      return 'shed';
    }
    this.queueDepth += 1;
    return 'admitted';
  }

  triggerCongestion(): void {
    this.congested = true;
  }

  onTimeoutRetry(): 'retried' | 'shed' {
    if (!this.congested || this.queueDepth === 0) {
      return 'shed';
    }
    if (this.retriesPending >= this.retryBudget || this.queueDepth >= this.queueCap) {
      this.shedCount += 1;
      return 'shed';
    }
    this.queueDepth += 1;
    this.retriesPending += 1;
    return 'retried';
  }

  drainStep(budget: number): void {
    let remaining = budget;
    while (remaining > 0 && this.queueDepth > 0) {
      this.queueDepth -= 1;
      if (this.retriesPending > 0) this.retriesPending -= 1;
      remaining -= 1;
    }
    if (this.queueDepth === 0) {
      this.congested = false;
    }
  }
}

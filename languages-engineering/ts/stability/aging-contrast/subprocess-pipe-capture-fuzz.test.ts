// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import { describe, expect, it } from "bun:test";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dir, "../../../..");
const RESOLVER_CLI = resolve(REPO_ROOT, "packages/quint-modules-resolver/src/cli.ts");
const SM20_QNT = resolve(
  REPO_ROOT,
  "packages/quint-models/engineering/concurrency/subprocess-pipe-capture-envelope/SubprocessPipeCaptureEnvelope.qnt",
);

// Deterministic xorshift32 PRNG for reproducible structure-aware fuzzing.
function makeRng(seed: number): () => number {
  let x = seed >>> 0;
  return () => {
    x ^= (x << 13) >>> 0;
    x ^= x >>> 17;
    x ^= (x << 5) >>> 0;
    return (x >>> 0) / 0x100000000;
  };
}

interface HardenedPipeCapture {
  maxRetainBytes: number;
  maxLineBytes: number;
  pipeKernelCap: number;
  retainedBytes: number;
  peakRetainedBytes: number;
  discardedBytes: number;
  totalProducedBytes: number;
  pipeDeadlocks: number;
  lineCapBreaches: number;
  truncated: boolean;
}

function createHardenedCapture(
  maxRetainBytes: number,
  maxLineBytes: number,
  pipeKernelCap = 65536,
): HardenedPipeCapture {
  return {
    maxRetainBytes,
    maxLineBytes,
    pipeKernelCap,
    retainedBytes: 0,
    peakRetainedBytes: 0,
    discardedBytes: 0,
    totalProducedBytes: 0,
    pipeDeadlocks: 0,
    lineCapBreaches: 0,
    truncated: false,
  };
}

function hardenedIngestChunk(s: HardenedPipeCapture, chunkBytes: number): void {
  const headroom = Math.max(0, s.maxRetainBytes - s.retainedBytes);
  const keep = Math.min(chunkBytes, headroom);
  const discard = chunkBytes - keep;
  s.retainedBytes += keep;
  if (s.retainedBytes > s.peakRetainedBytes) {
    s.peakRetainedBytes = s.retainedBytes;
  }
  if (discard > 0) {
    s.discardedBytes += discard;
    s.truncated = true;
  }
  s.totalProducedBytes += chunkBytes;
}

function hardenedReadLine(
  s: HardenedPipeCapture,
  frameBytes: number,
): { ok: boolean; retained: number } {
  if (frameBytes > s.maxLineBytes) {
    // Reject oversize single-line frame without allocating full payload.
    return { ok: false, retained: 0 };
  }
  if (frameBytes > s.peakRetainedBytes) {
    s.peakRetainedBytes = frameBytes;
  }
  return { ok: true, retained: frameBytes };
}

interface DefectiveBufferBeforeTruncate {
  maxRetainBytes: number;
  bufferedBytes: number;
  peakRetainedBytes: number;
}

function defectiveBufferAllThenTruncate(
  maxRetainBytes: number,
  chunks: number[],
): DefectiveBufferBeforeTruncate {
  const s: DefectiveBufferBeforeTruncate = {
    maxRetainBytes,
    bufferedBytes: 0,
    peakRetainedBytes: 0,
  };
  for (const c of chunks) {
    s.bufferedBytes += c;
    if (s.bufferedBytes > s.peakRetainedBytes) {
      s.peakRetainedBytes = s.bufferedBytes;
    }
  }
  // Post-hoc truncate() happens too late — peak heap already spiked!
  s.bufferedBytes = Math.min(s.bufferedBytes, s.maxRetainBytes);
  return s;
}

interface DefectiveStopReadingPipe {
  maxRetainBytes: number;
  pipeKernelCap: number;
  retainedBytes: number;
  unreadInPipe: number;
  deadlocked: boolean;
}

function defectiveStopReadingAtCap(
  maxRetainBytes: number,
  pipeKernelCap: number,
  chunks: number[],
): DefectiveStopReadingPipe {
  const s: DefectiveStopReadingPipe = {
    maxRetainBytes,
    pipeKernelCap,
    retainedBytes: 0,
    unreadInPipe: 0,
    deadlocked: false,
  };
  for (const c of chunks) {
    if (s.retainedBytes < s.maxRetainBytes) {
      const keep = Math.min(c, s.maxRetainBytes - s.retainedBytes);
      s.retainedBytes += keep;
      s.unreadInPipe += c - keep;
    } else {
      // Stops reading once cap is hit -> kernel pipe fills and child blocks forever!
      s.unreadInPipe += c;
    }
    if (s.unreadInPipe > s.pipeKernelCap) {
      s.deadlocked = true;
      break;
    }
  }
  return s;
}

function itfInt(v: unknown): number {
  if (typeof v === "number") return v;
  if (v && typeof v === "object" && "#bigint" in v) {
    return Number((v as { "#bigint": string })["#bigint"]);
  }
  throw new Error(`Unexpected ITF int: ${JSON.stringify(v)}`);
}

describe("SM20 Subprocess Pipe Capture, Drain-to-Sink & Bounded Line Framing Fuzz + ITF MBT", () => {
  it("250 randomized runaway subprocess stdout/stderr & line-bomb schedules — hardened bounded/deadlock-free vs defective OOM/deadlock", () => {
    const rng = makeRng(0x5a20beef);
    let oomSpikesCaught = 0;
    let pipeDeadlocksCaught = 0;
    let lineBombsRejected = 0;

    for (let trial = 0; trial < 250; trial++) {
      const maxRetain = 4096 + Math.floor(rng() * 12288);
      const maxLine = Math.min(maxRetain, 1024 + Math.floor(rng() * 3072));
      const pipeKernelCap = 65536;
      const chunkCount = 12 + Math.floor(rng() * 30);
      const chunks: number[] = [];
      for (let i = 0; i < chunkCount; i++) {
        // Mix normal chunks and large runaway bursts exceeding 64 KiB pipe capacity.
        const burst = rng() < 0.35 ? 16384 + Math.floor(rng() * 32768) : 512 + Math.floor(rng() * 4096);
        chunks.push(burst);
      }

      const hardened = createHardenedCapture(maxRetain, maxLine, pipeKernelCap);
      for (const c of chunks) {
        hardenedIngestChunk(hardened, c);
      }

      // Hardened invariants hold across every single trial:
      expect(hardened.retainedBytes).toBeLessThanOrEqual(maxRetain);
      expect(hardened.peakRetainedBytes).toBeLessThanOrEqual(maxRetain);
      expect(hardened.retainedBytes + hardened.discardedBytes).toBe(hardened.totalProducedBytes);
      expect(hardened.pipeDeadlocks).toBe(0);
      expect(hardened.lineCapBreaches).toBe(0);

      // Test bounded single-line frame read (including oversized delimiter-free bomb):
      const lineLen = trial % 2 === 0 ? maxLine + 4096 + Math.floor(rng() * 131072) : Math.floor(rng() * maxLine);
      const lineRes = hardenedReadLine(hardened, lineLen);
      if (lineLen > maxLine) {
        expect(lineRes.ok).toBe(false);
        expect(lineRes.retained).toBe(0);
        lineBombsRejected++;
      } else {
        expect(lineRes.ok).toBe(true);
        expect(lineRes.retained).toBe(lineLen);
      }
      expect(hardened.peakRetainedBytes).toBeLessThanOrEqual(maxRetain);

      // Contrast against defective implementations:
      const totalBytes = chunks.reduce((a, b) => a + b, 0);
      const defectiveOom = defectiveBufferAllThenTruncate(maxRetain, chunks);
      if (totalBytes > maxRetain) {
        expect(defectiveOom.peakRetainedBytes).toBeGreaterThan(maxRetain);
        oomSpikesCaught++;
      }

      const defectiveDeadlock = defectiveStopReadingAtCap(maxRetain, pipeKernelCap, chunks);
      if (totalBytes > maxRetain + pipeKernelCap) {
        expect(defectiveDeadlock.deadlocked).toBe(true);
        pipeDeadlocksCaught++;
      }
    }

    expect(oomSpikesCaught).toBeGreaterThan(200);
    expect(pipeDeadlocksCaught).toBeGreaterThan(150);
    expect(lineBombsRejected).toBe(125);
  });

  it("Live Quint ITF MBT Replay for SM20 SubprocessPipeCaptureEnvelope (6 live traces, 100% parity)", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "sm20-itf-"));
    try {
      const proc = Bun.spawnSync(
        [
          "bun",
          RESOLVER_CLI,
          "mbt-audit",
          SM20_QNT,
          "--n-traces=6",
          "--max-steps=12",
          "--seed=42",
          "--min-coverage=1.0",
          `--out-dir=${tmpDir}`,
        ],
        { cwd: REPO_ROOT, stdout: "pipe", stderr: "pipe" },
      );
      expect(proc.exitCode).toBe(0);

      const itfFiles = readdirSync(tmpDir)
        .filter((f) => f.endsWith(".itf.json"))
        .sort();
      expect(itfFiles.length).toBe(6);

      let totalSteps = 0;
      for (const fileName of itfFiles) {
        const itfPath = join(tmpDir, fileName);
        const raw = JSON.parse(readFileSync(itfPath, "utf8")) as {
          states: Array<{
            h: {
              maxRetainBytes: unknown;
              maxLineBytes: unknown;
              childRunning: boolean;
              retainedBytes: unknown;
              peakRetainedBytes: unknown;
              discardedBytes: unknown;
              pipeDeadlocks: unknown;
              lineCapBreaches: unknown;
              cleanExits: unknown;
            };
            "mbt::actionTaken": string;
          }>;
        };

        // Independent shadow state machine mirroring SM20 formal transitions:
        let childRunning = false;
        let retainedBytes = 0;
        let peakRetainedBytes = 0;
        let discardedBytes = 0;
        let cleanExits = 0;
        const maxRetainBytes = 4;
        const maxLineBytes = 3;

        for (let stepIdx = 0; stepIdx < raw.states.length; stepIdx++) {
          const st = raw.states[stepIdx];
          const action = st["mbt::actionTaken"];
          if (stepIdx > 0) {
            switch (action) {
              case "spawnChild":
                if (!childRunning) {
                  childRunning = true;
                  retainedBytes = 0;
                  discardedBytes = 0;
                }
                break;
              case "captureBoundedChunk":
                if (childRunning && retainedBytes < maxRetainBytes) {
                  retainedBytes += 1;
                  if (retainedBytes > peakRetainedBytes) peakRetainedBytes = retainedBytes;
                }
                break;
              case "drainExcessToSink":
                if (childRunning && retainedBytes === maxRetainBytes) {
                  discardedBytes += 1;
                }
                break;
              case "readBoundedLineFrame":
                if (childRunning && maxLineBytes > peakRetainedBytes) {
                  peakRetainedBytes = maxLineBytes;
                }
                break;
              case "finishChildClean":
                if (childRunning) {
                  childRunning = false;
                  retainedBytes = 0;
                  cleanExits += 1;
                }
                break;
              default:
                throw new Error(`Unexpected SM20 MBT action: ${action}`);
            }
          }

          expect(st.h.childRunning).toBe(childRunning);
          expect(itfInt(st.h.retainedBytes)).toBe(retainedBytes);
          expect(itfInt(st.h.peakRetainedBytes)).toBe(peakRetainedBytes);
          expect(itfInt(st.h.discardedBytes)).toBe(discardedBytes);
          expect(itfInt(st.h.pipeDeadlocks)).toBe(0);
          expect(itfInt(st.h.lineCapBreaches)).toBe(0);
          expect(itfInt(st.h.cleanExits)).toBe(cleanExits);
          expect(peakRetainedBytes).toBeLessThanOrEqual(maxRetainBytes);
          totalSteps++;
        }
      }
      expect(totalSteps).toBeGreaterThanOrEqual(30);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

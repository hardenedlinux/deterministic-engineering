// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import { describe, expect, it } from "bun:test";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dir, "../../../..");
const RESOLVER_CLI = resolve(REPO_ROOT, "packages/quint-modules-resolver/src/cli.ts");
const SM21_QNT = resolve(
  REPO_ROOT,
  "packages/quint-models/engineering/storage/atomic-persistence-fsync-envelope/AtomicPersistenceFsyncEnvelope.qnt",
);

function makeRng(seed: number): () => number {
  let x = seed >>> 0;
  return () => {
    x ^= (x << 13) >>> 0;
    x ^= x >>> 17;
    x ^= (x << 5) >>> 0;
    return (x >>> 0) / 0x100000000;
  };
}

interface TempEntry {
  id: string;
  payload: string;
  fsynced: boolean;
}

class HardenedAtomicStore {
  liveContent: string;
  liveDurable: boolean;
  seq = 0;
  staged = new Map<string, TempEntry>();
  tornReads = 0;
  tempCollisions = 0;
  zeroLengthOnCrash = 0;

  constructor(initial: string) {
    this.liveContent = initial;
    this.liveDurable = true;
  }

  beginWrite(writerId: number, payload: string): string {
    this.seq += 1;
    const tmpName = `state.tmp.${writerId}.${this.seq}`;
    if (this.staged.has(tmpName)) {
      this.tempCollisions += 1;
    }
    this.staged.set(tmpName, { id: tmpName, payload, fsynced: false });
    return tmpName;
  }

  fsyncTemp(tmpName: string): void {
    const entry = this.staged.get(tmpName);
    if (entry) entry.fsynced = true;
  }

  commitRename(tmpName: string): boolean {
    const entry = this.staged.get(tmpName);
    if (!entry || !entry.fsynced) {
      return false;
    }
    this.staged.delete(tmpName);
    this.liveContent = entry.payload;
    this.liveDurable = true;
    return true;
  }

  abortWrite(tmpName: string): void {
    this.staged.delete(tmpName);
  }

  readLive(): string {
    // Live file is only ever atomically replaced with a complete fsynced JSON payload.
    const parsed = JSON.parse(this.liveContent) as { ver: number };
    if (typeof parsed.ver !== "number") {
      this.tornReads += 1;
    }
    return this.liveContent;
  }

  simulateCrash(): void {
    // Any unrenamed staged temp files are orphaned in crash image & never corrupt live file.
    this.staged.clear();
    if (!this.liveDurable || this.liveContent.length === 0) {
      this.zeroLengthOnCrash += 1;
    }
  }
}

class DefectiveSharedTmpStore {
  liveContent: string;
  liveDurable: boolean;
  sharedTmp: { payload: string; fsynced: boolean; writer: number } | null = null;
  tornReads = 0;
  tempCollisions = 0;
  zeroLengthOnCrash = 0;

  constructor(initial: string) {
    this.liveContent = initial;
    this.liveDurable = true;
  }

  writeInPlace(payload: string, crashMidWrite: boolean): void {
    if (crashMidWrite) {
      this.liveContent = payload.slice(0, Math.floor(payload.length / 2));
      this.tornReads += 1;
    } else {
      this.liveContent = payload;
    }
  }

  stageSharedTmp(writer: number, payload: string): void {
    if (this.sharedTmp !== null && this.sharedTmp.writer !== writer) {
      // Two concurrent writers overwrite the exact same `path + ".tmp"` file!
      this.tempCollisions += 1;
      this.sharedTmp = {
        payload: this.sharedTmp.payload.slice(0, 6) + payload.slice(6),
        fsynced: false,
        writer,
      };
      return;
    }
    this.sharedTmp = { payload, fsynced: false, writer };
  }

  renameWithoutFsync(): void {
    if (!this.sharedTmp) return;
    const entry = this.sharedTmp;
    this.sharedTmp = null;
    this.liveContent = entry.payload;
    this.liveDurable = entry.fsynced;
  }

  simulateCrash(): void {
    this.sharedTmp = null;
    if (!this.liveDurable) {
      this.liveContent = "";
      this.zeroLengthOnCrash += 1;
    }
  }
}

function itfInt(v: unknown): number {
  if (typeof v === "number") return v;
  if (v && typeof v === "object" && "#bigint" in v) {
    return Number((v as { "#bigint": string })["#bigint"]);
  }
  throw new Error(`Unexpected ITF int: ${JSON.stringify(v)}`);
}

describe("SM21 Crash-Safe Atomic Persistence, Unique Temp Staging & Fsync Ordering Fuzz + ITF MBT", () => {
  it("250 randomized concurrent writer/reader/crash schedules — hardened 0 torn/collisions/zero-len vs defective collapse", () => {
    const rng = makeRng(0x5a21c0de);
    let badTorn = 0;
    let badCollisions = 0;
    let badZeroLen = 0;

    for (let trial = 0; trial < 250; trial++) {
      const initPayload = JSON.stringify({ ver: 1, data: "initial-durable-checkpoint" });
      const good = new HardenedAtomicStore(initPayload);
      const bad = new DefectiveSharedTmpStore(initPayload);

      const ops = 16 + Math.floor(rng() * 16);
      const inFlightGood: string[] = [];

      for (let step = 0; step < ops; step++) {
        const ver = step + 2;
        const payload = JSON.stringify({ ver, data: `payload-${trial}-${step}` });
        const mode = rng();

        if (mode < 0.35) {
          // Concurrent dual-writer staging
          const t1 = good.beginWrite(1, payload);
          const t2 = good.beginWrite(2, JSON.stringify({ ver: ver + 100, data: `peer-${step}` }));
          inFlightGood.push(t1, t2);

          bad.stageSharedTmp(1, payload);
          bad.stageSharedTmp(2, JSON.stringify({ ver: ver + 100, data: `peer-${step}` }));
        } else if (mode < 0.65 && inFlightGood.length > 0) {
          // Fsync + atomic rename commit on hardened vs un-fsynced rename on defective
          const tmp = inFlightGood.shift()!;
          good.fsyncTemp(tmp);
          expect(good.commitRename(tmp)).toBe(true);
          good.readLive();

          bad.renameWithoutFsync();
        } else if (mode < 0.85) {
          // In-place overwrite mid-write crash hazard on defective; clean abort on hardened
          if (inFlightGood.length > 0) {
            good.abortWrite(inFlightGood.pop()!);
          }
          good.readLive();
          bad.writeInPlace(payload, true);
        } else {
          // Sudden power loss / SIGKILL crash
          good.simulateCrash();
          inFlightGood.length = 0;
          good.readLive();
          bad.simulateCrash();
        }
      }

      // Quiesce remaining hardened temp files cleanly:
      for (const tmp of inFlightGood) {
        good.abortWrite(tmp);
      }

      expect(good.staged.size).toBe(0);
      expect(good.tornReads).toBe(0);
      expect(good.tempCollisions).toBe(0);
      expect(good.zeroLengthOnCrash).toBe(0);
      expect(JSON.parse(good.readLive()).ver).toBeGreaterThanOrEqual(1);

      if (bad.tornReads > 0) badTorn += 1;
      if (bad.tempCollisions > 0) badCollisions += 1;
      if (bad.zeroLengthOnCrash > 0) badZeroLen += 1;
    }

    expect(badTorn).toBeGreaterThan(220);
    expect(badCollisions).toBeGreaterThan(220);
    expect(badZeroLen).toBeGreaterThan(180);
  });

  it("Live Quint ITF MBT Replay for SM21 AtomicPersistenceFsyncEnvelope (6 live traces, 100% parity)", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "sm21-itf-"));
    try {
      const proc = Bun.spawnSync(
        [
          "bun",
          RESOLVER_CLI,
          "mbt-audit",
          SM21_QNT,
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
        const raw = JSON.parse(readFileSync(join(tmpDir, fileName), "utf8")) as {
          states: Array<{
            h: {
              committedVer: unknown;
              activeUniqueTemps: unknown;
              maxWriters: unknown;
              tempFsyncReady: boolean;
              tornReads: unknown;
              tempCollisions: unknown;
              zeroLengthOnCrash: unknown;
              orphanTemps: unknown;
              cleanCommits: unknown;
            };
            "mbt::actionTaken": string;
          }>;
        };

        let committedVer = 1;
        let activeUniqueTemps = 0;
        const maxWriters = 2;
        let tempFsyncReady = false;
        let cleanCommits = 0;

        for (let stepIdx = 0; stepIdx < raw.states.length; stepIdx++) {
          const st = raw.states[stepIdx];
          const action = st["mbt::actionTaken"];
          if (stepIdx > 0) {
            switch (action) {
              case "stageUniqueTemp":
                if (activeUniqueTemps < maxWriters) {
                  activeUniqueTemps += 1;
                  tempFsyncReady = false;
                }
                break;
              case "fsyncStagedTemp":
                if (activeUniqueTemps > 0 && !tempFsyncReady) {
                  tempFsyncReady = true;
                }
                break;
              case "atomicRenameCommit":
                if (activeUniqueTemps > 0 && tempFsyncReady) {
                  activeUniqueTemps -= 1;
                  tempFsyncReady = false;
                  committedVer += 1;
                  cleanCommits += 1;
                }
                break;
              case "cleanupFailedTemp":
                if (activeUniqueTemps > 0) {
                  activeUniqueTemps -= 1;
                  tempFsyncReady = false;
                }
                break;
              case "crashAndRecover":
                activeUniqueTemps = 0;
                tempFsyncReady = false;
                break;
              default:
                throw new Error(`Unexpected SM21 MBT action: ${action}`);
            }
          }

          expect(itfInt(st.h.committedVer)).toBe(committedVer);
          expect(itfInt(st.h.activeUniqueTemps)).toBe(activeUniqueTemps);
          expect(st.h.tempFsyncReady).toBe(tempFsyncReady);
          expect(itfInt(st.h.tornReads)).toBe(0);
          expect(itfInt(st.h.tempCollisions)).toBe(0);
          expect(itfInt(st.h.zeroLengthOnCrash)).toBe(0);
          expect(itfInt(st.h.orphanTemps)).toBe(0);
          expect(itfInt(st.h.cleanCommits)).toBe(cleanCommits);
          totalSteps += 1;
        }
      }
      expect(totalSteps).toBeGreaterThanOrEqual(30);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 30_000);
});

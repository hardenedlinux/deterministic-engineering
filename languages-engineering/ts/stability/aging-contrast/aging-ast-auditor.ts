// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Multi-Language Structural Auditor for Software Aging Anti-Patterns (SM2/SM3/SM4/SM5).
 *
 * Detects high-signal AI-generated long-running stability hazards across:
 *   Go, Rust, TypeScript, C, and C++
 * without triggering false positives on deterministic steady-state boundaries.
 */

export type AgingLanguage = 'go' | 'rust' | 'ts' | 'c' | 'cpp';

export type AgingMechanism =
  | 'SM2-resource-leak'
  | 'SM3-watermark-ratchet'
  | 'SM4-orphan-concurrency'
  | 'SM5-metastable-overload'
  | 'SM7-ui-render-aging'
  | 'SM8-search-generation-race'
  | 'SM9-singleflight-deadlock'
  | 'SM12-ipc-half-open-reconnect'
  | 'SM13-ime-composition-race'
  | 'SM14-chaos-circuit-envelope'
  | 'SM15-search-snapshot-isolation'
  | 'SM16-search-input-sanitization'
  | 'SM17-streaming-output-budget'
  | 'SM19-task-and-pool-cancellation'
  | 'SM20-subprocess-pipe-capture'
  | 'SM21-atomic-persistence-fsync'
  | 'SM22-adversarial-sandbox-archive-confinement'
  | 'SM23-adversarial-http-redirect-ssrf'
  | 'SM24-adversarial-env-scrub-auth-timing'
  | 'SM25-single-owner-graph-governance'
  | 'SM26-control-plane-auth-governance'
  | 'SM27-policy-gate-blindspot-confinement'
  | 'SM28-plugin-grant-rollback-lease'
  | 'SM29-governance-policy-latch-antirollback'
  | 'SM30-stepup-attestation-host-effect'
  | 'SM31-storage-boundary-integrity-sync'
  | 'SM32-gitops-subprocess-confinement'
  | 'SM33-hook-policy-protocol-confinement'
  | 'SM34-runtime-env-context-confinement'
  | 'SM35-graph-witness-harness-confinement'
  | 'SM36-telemetry-watchdog-deck-vm-confinement'
  | 'SM37-process-signal-ledger-fanout-confinement'
  | 'SM38-defense-pillar-crypto-state-confinement'
  | 'SM39-tui-config-supervisor-probe-confinement';

export interface AgingFinding {
  ruleId: string;
  mechanism: AgingMechanism;
  language: AgingLanguage;
  line: number;
  message: string;
}

export interface AgingAuditReport {
  language: AgingLanguage;
  passed: boolean;
  findings: AgingFinding[];
}

function stripCommentsPreserveLines(source: string): string {
  // Replace block comments with equivalent newlines and strip single-line // comments
  // while keeping line numbering 1-based and exact.
  const withoutBlock = source.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
  return withoutBlock
    .split('\n')
    .map((line) => {
      // Avoid stripping // inside string literals like "https://..."
      let inDouble = false;
      let inSingle = false;
      let inBacktick = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i]!;
        const prev = i > 0 ? line[i - 1] : '';
        if (ch === '"' && !inSingle && !inBacktick && prev !== '\\') inDouble = !inDouble;
        else if (ch === "'" && !inDouble && !inBacktick && prev !== '\\') inSingle = !inSingle;
        else if (ch === '`' && !inDouble && !inSingle && prev !== '\\') inBacktick = !inBacktick;
        else if (ch === '/' && line[i + 1] === '/' && !inDouble && !inSingle && !inBacktick) {
          return line.slice(0, i);
        }
      }
      return line;
    })
    .join('\n');
}

function lineOfIndex(text: string, idx: number): number {
  let line = 1;
  for (let i = 0; i < idx && i < text.length; i++) {
    if (text[i] === '\n') line += 1;
  }
  return line;
}

function extractBraceBlock(text: string, startFrom: number): string {
  const open = text.indexOf('{', startFrom);
  if (open < 0) return '';
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(open, i + 1);
    }
  }
  return text.slice(open);
}

function findEnclosingLoopBlock(text: string, idx: number): string | null {
  // Walk outward from idx through enclosing `{ ... }` blocks until hitting a `func` header.
  // Returns the enclosing `for` loop block if idx is lexically inside a `for` loop in the same function.
  let depth = 0;
  for (let i = idx; i >= 0; i--) {
    const ch = text[i];
    if (ch === '}') {
      depth += 1;
    } else if (ch === '{') {
      if (depth === 0) {
        const prefix = text.slice(Math.max(0, i - 160), i);
        const lastStmtBreak = Math.max(prefix.lastIndexOf('{'), prefix.lastIndexOf('}'), prefix.lastIndexOf('\n'));
        const header = lastStmtBreak >= 0 ? prefix.slice(lastStmtBreak + 1) : prefix;
        if (/\bfor\b/.test(header) && !/\bfunc\b/.test(header)) {
          return extractBraceBlock(text, i);
        }
        if (/\bfunc\b/.test(header)) {
          return null;
        }
      } else {
        depth -= 1;
      }
    }
  }
  return null;
}

function auditGo(clean: string): AgingFinding[] {
  const findings: AgingFinding[] = [];

  // 1. time.After inside a for loop (same function) allocates an uncollected timer every iteration.
  const timeAfterRe = /\btime\.After\s*\(/g;
  let taM: RegExpExecArray | null;
  while ((taM = timeAfterRe.exec(clean)) !== null) {
    if (findEnclosingLoopBlock(clean, taM.index) !== null) {
      findings.push({
        ruleId: 'go-time-after-in-loop',
        mechanism: 'SM2-resource-leak',
        language: 'go',
        line: lineOfIndex(clean, taM.index),
        message: 'time.After() inside a loop retains uncollected timers until expiry; reuse time.NewTimer with Reset/Stop.',
      });
      break;
    }
  }

  // 2. http.Get / http.Post / httpClient.Do without Body.Close() (never match sync.Once.Do!).
  const httpMatch = /\b(?:http\.(?:Get|Post|PostForm|Head)|(?:httpClient|client|Client|http\.DefaultClient)\.Do)\s*\(/.exec(clean);
  if (httpMatch && !/\.Body\.Close\s*\(/.test(clean)) {
    findings.push({
      ruleId: 'go-unclosed-http-body',
      mechanism: 'SM2-resource-leak',
      language: 'go',
      line: lineOfIndex(clean, httpMatch.index),
      message: 'HTTP response body is never closed, leaking keep-alive sockets and readLoop/writeLoop goroutines.',
    });
  }

  // 3. Tu et al. (ASPLOS 2019): unbuffered channel + goroutine send + ctx.Done() return within the SAME function scope.
  const unbufChanRe = /make\s*\(\s*chan\s+[^,)]+\)/g;
  let unbufM: RegExpExecArray | null;
  while ((unbufM = unbufChanRe.exec(clean)) !== null) {
    const fnScope = extractEnclosingBlock(clean, unbufM.index);
    const goInFn = /\bgo\s+func\s*\(/.exec(fnScope);
    if (goInFn && /<-\s*ctx\.Done\s*\(\s*\)/.test(fnScope)) {
      const goBody = extractBraceBlock(fnScope, goInFn.index);
      const workerSelectsCtx = /\bselect\s*\{[\s\S]*?<-\s*ctx\.Done\s*\(\s*\)/.test(goBody);
      if (!workerSelectsCtx) {
        findings.push({
          ruleId: 'go-unbuffered-channel-goroutine-leak',
          mechanism: 'SM4-orphan-concurrency',
          language: 'go',
          line: lineOfIndex(clean, unbufM.index),
          message: 'Goroutine sends on unbuffered channel while caller may exit on ctx.Done(); worker leaks blocked forever.',
        });
        break;
      }
    }
  }

  // 4. Uncapped buffer pool Put / append without cap(buf) retain check in the enclosing function body.
  // Match sync.Pool-like 1-arg Put(buf) or `.pool = append(...)` (exclude multi-arg CAS/KV Put(k, v)).
  const poolPutMatch = /(?:\b(?:sync\.Pool|\w*[pP]ool)\b[\s\S]{0,120}\.Put\s*\(\s*[^,)]+\)|\.Put\s*\(\s*\w+\s*\[\s*:\s*0\s*\]\s*\)|\.pool\s*=\s*append\s*\([^)]+\))/.exec(clean);
  if (poolPutMatch) {
    const funcStart = clean.lastIndexOf('\nfunc ', poolPutMatch.index);
    const fnScope = funcStart >= 0 ? extractBraceBlock(clean, funcStart) : clean;
    if (!/\bcap\s*\(\s*\w+\s*\)\s*(?:>|>=|<=|<)/.test(fnScope)) {
      findings.push({
        ruleId: 'go-uncapped-pool-put',
        mechanism: 'SM3-watermark-ratchet',
        language: 'go',
        line: lineOfIndex(clean, poolPutMatch.index),
        message: 'Buffer returned to reusable pool without cap() ceiling check; spike buffers will poison quiescent memory.',
      });
    }
  }

  // 5. Sub-slice pinning: returning or appending `buf[:n]` from a large slice without bytes.Clone/copy.
  const subsliceMatch = /(?:return\s+\w+\s*\[\s*:\s*\d+\s*\]|append\s*\([^,]+,\s*\w+\s*\[\s*:\s*[1-9]\d*\s*\]\s*\))/.exec(clean);
  if (subsliceMatch) {
    const fnScope = extractEnclosingBlock(clean, subsliceMatch.index);
    if (!/\b(?:bytes\.Clone|slices\.Clone|copy\s*\()/.test(fnScope)) {
      findings.push({
        ruleId: 'go-subslice-pinning',
        mechanism: 'SM3-watermark-ratchet',
        language: 'go',
        line: lineOfIndex(clean, subsliceMatch.index),
        message: 'Sub-slicing a large []byte without bytes.Clone/copy pins the entire backing array across GC cycles.',
      });
    }
  }

  // 6. Unbounded goroutine fan-out inside a for loop without semaphore/SetLimit/per-iteration join.
  const goSpawnRe = /\bgo\s+(?:func\s*\(|\w+\s*\()/g;
  let gsM: RegExpExecArray | null;
  while ((gsM = goSpawnRe.exec(clean)) !== null) {
    const loopBody = findEnclosingLoopBlock(clean, gsM.index);
    if (loopBody !== null) {
      const hasBound = /(?:\b(?:SetLimit|Acquire|workerPool|maxConc|\w+\.wg\.Add)\b|\bsem\s*<-)/.test(loopBody);
      const joinsPerIter = /<-\s*\w*(?:Done|Err|Ch)\b/.test(loopBody);
      if (!hasBound && !joinsPerIter) {
        findings.push({
          ruleId: 'go-unbounded-goroutine-fanout',
          mechanism: 'SM4-orphan-concurrency',
          language: 'go',
          line: lineOfIndex(clean, gsM.index),
          message: 'Unbounded goroutine spawning inside loop without concurrency semaphore or errgroup.SetLimit.',
        });
        break;
      }
    }
  }

  // 7. Early return skipping goroutine join channel / WaitGroup drain (Marlin MyGo bridge.go pattern).
  const goJoinRe = /\bgo\s+func\s*\(/g;
  let goM: RegExpExecArray | null;
  while ((goM = goJoinRe.exec(clean)) !== null) {
    const fnScope = extractEnclosingBlock(clean, goM.index);
    const joinChanMatch = /<-\s*(\w+(?:Err|Done|Ch))\b/.exec(fnScope);
    if (joinChanMatch) {
      const joinVar = joinChanMatch[1]!;
      const deferredJoin = new RegExp(`\\bdefer\\b[\\s\\S]{0,120}<-\\s*${joinVar}\\b`).test(fnScope);
      const usesStructured = /\b(?:CloseAndDrain|errgroup|defer\s+\w+\.Wait\s*\(|\w+\.wg\.Add\s*\()\b/.test(fnScope);
      const earlyRetIdx = fnScope.search(/\bif\b[\s\S]{0,120}\breturn\s+(?:err|\w+,\s*err)\b/);
      if (!deferredJoin && !usesStructured && earlyRetIdx >= 0 && earlyRetIdx < joinChanMatch.index) {
        findings.push({
          ruleId: 'go-early-return-unjoined-goroutine',
          mechanism: 'SM4-orphan-concurrency',
          language: 'go',
          line: lineOfIndex(clean, goM.index),
          message: `Early error return skips join on <-${joinVar}, leaving background goroutine overlapping next operation.`,
        });
        break;
      }
    }
  }

  // 8. Long-lived struct/receiver map populated monotonically without delete(), len() cap, or eviction (client/session.go, wazeroir, oidc).
  const mapAssignRe = /\b(\w+)\.(records|cache|sessions|entries|history)\s*\[[^\]]+\]\s*=/g;
  const checkedMaps = new Set<string>();
  let mapM: RegExpExecArray | null;
  while ((mapM = mapAssignRe.exec(clean)) !== null) {
    const recv = mapM[1]!;
    const field = mapM[2]!;
    const key = `${recv}.${field}`;
    if (checkedMaps.has(key)) continue;
    checkedMaps.add(key);
    const isRingSlice =
      new RegExp(`%\\s*len\\s*\\(\\s*${recv}\\.${field}\\s*\\)`).test(clean) ||
      new RegExp(`\\b${field}\\s+\\[\\d*\\]`).test(clean);
    if (isRingSlice) continue;
    const hasDelete = new RegExp(`\\bdelete\\s*\\(\\s*${recv}\\.${field}\\b`).test(clean);
    const hasLenCap = new RegExp(`\\blen\\s*\\(\\s*${recv}\\.${field}\\s*\\)\\s*(?:<|<=|>=|>)`).test(clean);
    const hasEvict = /\b(?:maxRecords|maxEntries|maxSize|maxCache|evict|lru|rotateThreshold)\b/i.test(clean);
    if (!hasDelete && !hasLenCap && !hasEvict) {
      findings.push({
        ruleId: 'go-unbounded-struct-map',
        mechanism: 'SM3-watermark-ratchet',
        language: 'go',
        line: lineOfIndex(clean, mapM.index),
        message: `Long-lived map ${recv}.${field} grows monotonically without delete() or bounded eviction window.`,
      });
      break;
    }
  }

  // 9. Sidecar exec.Command.Start() + Process.Signal/Kill without Setpgid process-group isolation (sidecar.go).
  const execStartMatch = /\bexec\.Command(?:Context)?\s*\(/.exec(clean);
  if (
    execStartMatch &&
    /\.Start\s*\(\s*\)/.test(clean) &&
    /\.Process\.(?:Signal|Kill)\s*\(/.test(clean) &&
    !/\bSetpgid\b/.test(clean)
  ) {
    findings.push({
      ruleId: 'go-sidecar-missing-pgid',
      mechanism: 'SM4-orphan-concurrency',
      language: 'go',
      line: lineOfIndex(clean, execStartMatch.index),
      message: 'Sidecar process spawned without SysProcAttr{Setpgid: true}; Stop/Kill misses grandchild process trees.',
    });
  }

  // 10. Unbudgeted exponential-backoff retry loop without maxAttempts/retryBudget/MaxRestarts/MaxConsecutiveFailures ceiling.
  const backoffMulMatch = /(?:\*?backoff\s*\*=\s*2|\bbackoff\s*=\s*(?:min\s*\(\s*)?backoff\s*\*\s*2)/.exec(clean);
  if (backoffMulMatch) {
    const loopOrFnScope =
      findEnclosingLoopBlock(clean, backoffMulMatch.index) ?? extractEnclosingBlock(clean, backoffMulMatch.index);
    if (
      !/\b(?:maxAttempts|maxRetries|retryBudget|maxBackoffAttempts|MaxRestarts|maxRestarts|MaxConsecutiveFailures|maxConsecutiveFailures|maxFailures|attempts\s*>=)\b/.test(
        loopOrFnScope,
      )
    ) {
      findings.push({
        ruleId: 'go-unbudgeted-retry-loop',
        mechanism: 'SM5-metastable-overload',
        language: 'go',
        line: lineOfIndex(clean, backoffMulMatch.index),
        message: 'Exponential backoff retry loop lacks explicit retry budget / maxAttempts ceiling (metastable storm risk).',
      });
    }
  }

  // 11. Non-monotonic query generation cancellation (search_bridge.go): older dispatch cancels newer activeCancel.
  const activeGenAssign = /\b(\w+)\.activeGen\s*=\s*(\w+)/.exec(clean);
  if (activeGenAssign) {
    const fnScope = extractEnclosingBlock(clean, activeGenAssign.index);
    const recv = activeGenAssign[1]!;
    const genVar = activeGenAssign[2]!;
    const hasCancel = new RegExp(`\\b${recv}\\.activeCancel\\s*\\(`).test(fnScope);
    const hasMonotonicGuard = new RegExp(
      `\\b${genVar}\\s*(?:<|<=)\\s*${recv}\\.activeGen\\b|\\b${recv}\\.activeGen\\s*(?:>|>=)\\s*${genVar}\\b`,
    ).test(fnScope);
    if (hasCancel && !hasMonotonicGuard) {
      findings.push({
        ruleId: 'go-non-monotonic-gen-cancel',
        mechanism: 'SM8-search-generation-race',
        language: 'go',
        line: lineOfIndex(clean, activeGenAssign.index),
        message: `Async query dispatch cancels ${recv}.activeCancel and overwrites ${recv}.activeGen without rejecting older generations (${genVar} < ${recv}.activeGen).`,
      });
    }
  }

  // 12. Candidate/item slice truncated via `items[:0]` on query reset without clear() / cap() ceiling (helm_stream.go pointer pinning & ratchet).
  const sliceTruncMatch = /\b(?:BeginQuery|Reset)\s*\([^)]*\)[^{]*\{[\s\S]{0,400}?(\.items\s*=\s*[^\n]+\[\s*:\s*0\s*\])/.exec(clean);
  if (sliceTruncMatch) {
    const fnScope = extractBraceBlock(clean, sliceTruncMatch.index);
    const hasClear = /\bclear\s*\(\s*[^\n)]*items\b/.test(fnScope);
    const hasCapShrink = /\bcap\s*\(\s*[^\n)]*items\s*\)\s*>/.test(fnScope);
    if (!hasClear || !hasCapShrink) {
      findings.push({
        ruleId: 'go-slice-truncate-without-clear',
        mechanism: 'SM3-watermark-ratchet',
        language: 'go',
        line: lineOfIndex(clean, sliceTruncMatch.index),
        message: 'Long-lived candidate slice truncated with [:0] without clear() and cap() shrink ceiling pins GC string pointers and ratchets peak capacity.',
      });
    }
  }

  // 13. Reconnect method replaces active IPC/gRPC stream or connection without closing/canceling previous handle (SM12).
  const goReconnectMatch = /\bfunc\s*\(\s*(\w+)\s+\*?\w+\s*\)\s*(?:Reconnect|reconnect|ResetStream|resetStream)\s*\([^)]*\)/.exec(clean);
  if (goReconnectMatch) {
    const fnScope = extractBraceBlock(clean, goReconnectMatch.index);
    const recv = goReconnectMatch[1]!;
    const overwritesStream = new RegExp(`\\b${recv}\\.(?:stream|conn|client)\\s*=`).test(fnScope);
    const retiresOld = /\.(?:Close|CloseSend|Cancel)\s*\(|\bcancel\s*\(\s*\)/.test(fnScope);
    if (overwritesStream && !retiresOld) {
      findings.push({
        ruleId: 'go-reconnect-without-close',
        mechanism: 'SM12-ipc-half-open-reconnect',
        language: 'go',
        line: lineOfIndex(clean, goReconnectMatch.index),
        message: 'Reconnect replaces active stream/connection without closing or canceling the previous half-open handle (SM12).',
      });
    }
  }

  // 14. Subprocess stdout/stderr captured unboundedly via Output()/CombinedOutput()/io.ReadAll then truncated post-hoc (SM20).
  const goSubprocMatch = /\b(?:\w+\.(?:Output|CombinedOutput)\s*\(\s*\)|io\.ReadAll\s*\(\s*(?:stdout|stderr|pipe)\w*\s*\))/.exec(clean);
  if (goSubprocMatch) {
    const fnScope = extractEnclosingBlock(clean, goSubprocMatch.index);
    const hasPostTruncate = /\[\s*:\s*\w*(?:max|limit|cap)\w*\s*\]/i.test(fnScope);
    const hasBoundedDrain = /\b(?:io\.LimitReader|io\.Discard|LimitedBuffer|BoundedPipe|maxRetain)\b/.test(fnScope);
    if (hasPostTruncate && !hasBoundedDrain) {
      findings.push({
        ruleId: 'go-subprocess-unbounded-output',
        mechanism: 'SM20-subprocess-pipe-capture',
        language: 'go',
        line: lineOfIndex(clean, goSubprocMatch.index),
        message: 'Subprocess output is buffered unboundedly before post-hoc slice truncation; use bounded retain + io.Copy(io.Discard, ...) drain-to-sink (SM20).',
      });
    }
  }

  // 15. Go staged atomic write uses colliding `path + ".tmp"` or os.WriteFile without Sync() before os.Rename (SM21).
  const goAtomicTmpMatch = /\bos\.WriteFile\s*\(\s*\w*(?:tmp|temp)\w*\s*,/i.exec(clean);
  if (goAtomicTmpMatch) {
    const fnScope = extractEnclosingBlock(clean, goAtomicTmpMatch.index);
    const hasRename = /\bos\.Rename\s*\(/.test(fnScope);
    const hasUniqueAndSync = /\bos\.CreateTemp\s*\(/.test(fnScope) && /\.Sync\s*\(\s*\)/.test(fnScope);
    if (hasRename && !hasUniqueAndSync) {
      findings.push({
        ruleId: 'go-atomic-write-shared-tmp-or-no-fsync',
        mechanism: 'SM21-atomic-persistence-fsync',
        language: 'go',
        line: lineOfIndex(clean, goAtomicTmpMatch.index),
        message: 'Atomic file persistence uses os.WriteFile to a shared/un-fsynced temp path before os.Rename; use os.CreateTemp + Sync() + Close() + os.Rename() with failure cleanup (SM21).',
      });
    }
  }

  // 16. Go Save*File / Persist* state writer overwrites target directly via os.WriteFile without atomic rename (SM21).
  const goSaveFnMatch = /\bfunc\s+(?:\([^)]*\)\s*)?(?:Save\w*(?:File|State|Spec|Vault|Checkpoint)|Persist\w*(?:File|State|Spec|Vault|Checkpoint))\s*\([^)]*\)/.exec(clean);
  if (goSaveFnMatch) {
    const fnScope = extractBraceBlock(clean, goSaveFnMatch.index);
    const directWrite = /\bos\.WriteFile\s*\(/.exec(fnScope);
    const hasAtomicRename = /\bos\.Rename\s*\(|\bwriteAtomic|writeFileAtomic/i.test(fnScope);
    if (directWrite && !hasAtomicRename) {
      findings.push({
        ruleId: 'go-state-file-non-atomic-overwrite',
        mechanism: 'SM21-atomic-persistence-fsync',
        language: 'go',
        line: lineOfIndex(clean, goSaveFnMatch.index + directWrite.index),
        message: 'State persistence function overwrites target file in-place via os.WriteFile without unique temp staging, Sync(), and atomic os.Rename (SM21).',
      });
    }
  }

  // 17. Go untrusted manifest entry joined onto staging/root dir without root-confinement validation (SM22).
  const goJoinEntryMatch = /filepath\.Join\s*\(\s*(\w*(?:tmp|stage|root|dir)\w*)\s*,\s*filepath\.FromSlash\s*\(\s*\w*(?:entry|path)\w*\s*\)\s*\)/i.exec(clean);
  if (goJoinEntryMatch) {
    const fnScope = extractEnclosingBlock(clean, goJoinEntryMatch.index);
    const hasConfinement = /\b(?:confineRelativePath|confinePath|isWithinDir)\b|filepath\.Rel\s*\([\s\S]{0,160}\.\./.test(fnScope);
    if (!hasConfinement) {
      findings.push({
        ruleId: 'go-filepath-join-unconfined-manifest-entry',
        mechanism: 'SM22-adversarial-sandbox-archive-confinement',
        language: 'go',
        line: lineOfIndex(clean, goJoinEntryMatch.index),
        message: 'Untrusted manifest entry path is joined onto staging directory without strict relative-path and root-confinement validation (ADV-L4 traversal escape, SM22).',
      });
    }
  }

  // 18. Go tar.NewReader extraction assigns assets[...] without rejecting duplicate entries or bounding cumulative decompressed bytes (SM22).
  const goTarReaderMatch = /\btar\.NewReader\s*\(/.exec(clean);
  if (goTarReaderMatch) {
    const fnScope = extractEnclosingBlock(clean, goTarReaderMatch.index);
    const writesAssets = /\bassets\s*\[\s*[^\]\n]+\s*\]\s*=/.test(fnScope);
    const rejectsDuplicates = /\bseen\w*\s*\[\s*[^\]\n]+\]\s*|\b_,\s*(?:exists|dup|ok)\s*:=\s*assets\s*\[/.test(fnScope);
    const capsCumulative = /\btotal(?:Bytes|Extracted|Decompressed)\b/.test(fnScope);
    if (writesAssets && (!rejectsDuplicates || !capsCumulative)) {
      findings.push({
        ruleId: 'go-tar-duplicate-entry-shadowing-or-no-total-cap',
        mechanism: 'SM22-adversarial-sandbox-archive-confinement',
        language: 'go',
        line: lineOfIndex(clean, goTarReaderMatch.index),
        message: 'Tar archive extraction accepts duplicate/shadowing entries or lacks cumulative decompressed byte cap and Multistream(false) guard (ADV-L4, SM22).',
      });
    }
  }

  // 19. Go outbound &http.Client{...} constructed without fail-closed CheckRedirect policy (ADV-L4, SM23).
  if (/\bhttp\.NewRequest(?:WithContext)?\s*\(/.test(clean)) {
    const httpClientRe = /&http\.Client\s*\{/g;
    let hcMatch: RegExpExecArray | null;
    while ((hcMatch = httpClientRe.exec(clean)) !== null) {
      const litBlock = extractBraceBlock(clean, hcMatch.index);
      const fnScope = extractEnclosingBlock(clean, hcMatch.index);
      const hasRedirectGuard = /\bCheckRedirect\b/.test(litBlock) || /\b(?:CheckRedirect|noRedirectHTTPClient|newNoRedirectHTTPClient)\b/.test(fnScope);
      if (!hasRedirectGuard) {
        findings.push({
          ruleId: 'go-http-client-default-redirects',
          mechanism: 'SM23-adversarial-http-redirect-ssrf',
          language: 'go',
          line: lineOfIndex(clean, hcMatch.index),
          message: 'Outbound http.Client omits fail-closed CheckRedirect policy; 301/302/307 redirects bypass origin/HTTPS gates and enable SSRF or credential exfiltration (ADV-L4, SM23).',
        });
        break;
      }
    }
  }

  // 20. Go HTTP static file handler validates with os.Stat before http.ServeFile instead of os.Lstat symlink refusal (ADV-L4, SM23).
  const serveFileMatch = /\bhttp\.ServeFile\s*\(/.exec(clean);
  if (serveFileMatch) {
    const fnScope = extractEnclosingBlock(clean, serveFileMatch.index);
    const usesStat = /\bos\.Stat\s*\(/.test(fnScope);
    const rejectsSymlink = /\bos\.Lstat\s*\(/.test(fnScope) && /\bModeSymlink\b/.test(fnScope);
    if (usesStat && !rejectsSymlink) {
      findings.push({
        ruleId: 'go-http-servefile-stat-follows-symlink',
        mechanism: 'SM23-adversarial-http-redirect-ssrf',
        language: 'go',
        line: lineOfIndex(clean, serveFileMatch.index),
        message: 'HTTP handler checks os.Stat before http.ServeFile without os.Lstat ModeSymlink rejection; planted symlinks inside served directories leak arbitrary host files (ADV-L4, SM23).',
      });
    }
  }

  // 21. Go untrusted plugin build/perf subprocess inherits ambient host os.Environ() (ADV-L4, SM24).
  const goPluginCmdRe = /\bexec\.CommandContext\s*\(\s*[^,\n]+,\s*(?:"go"|bunBin\b)/g;
  let pluginCmdMatch: RegExpExecArray | null;
  while ((pluginCmdMatch = goPluginCmdRe.exec(clean)) !== null) {
    const fnScope = extractEnclosingBlock(clean, pluginCmdMatch.index);
    const inheritsRawEnviron = /\bos\.Environ\s*\(\s*\)/.test(fnScope);
    const usesSanitizedEnv = /\bsanitized\w*Env\s*\(|\bfiltered\w*Env\s*\(/i.test(fnScope);
    const setsExplicitEnv = /\.\s*Env\s*=/.test(fnScope);
    if (inheritsRawEnviron || (!setsExplicitEnv && !usesSanitizedEnv)) {
      findings.push({
        ruleId: 'go-untrusted-plugin-cmd-inherits-os-environ',
        mechanism: 'SM24-adversarial-env-scrub-auth-timing',
        language: 'go',
        line: lineOfIndex(clean, pluginCmdMatch.index),
        message: 'Untrusted plugin build/perf subprocess inherits ambient host os.Environ() instead of allowlist-scrubbed toolchain env, leaking API keys and bridge tokens (ADV-L4, SM24).',
      });
    }
  }

  // 22. Go auth entrypoint falls back to hardcoded dev bearer token or compares Authorization header with `==` (ADV-L4, SM26).
  const goDevTokenMatch = /MARLIN_BRIDGE_TOKEN["']?\s*\)\s*[\s\S]{0,120}"(?:marlin-dev-token|dev-token)"/.exec(clean);
  if (goDevTokenMatch) {
    findings.push({
      ruleId: 'go-shadow-default-bearer-or-timing-auth',
      mechanism: 'SM26-control-plane-auth-governance',
      language: 'go',
      line: lineOfIndex(clean, goDevTokenMatch.index),
      message: 'Go control-plane entrypoint falls back to hardcoded default dev token instead of failing closed or rotating crypto/rand ephemeral credentials (ADV-L4, SM26).',
    });
  } else {
    const goAuthEqMatch = /\b(?:authHeader|bearerHeader|gotAuth)\s*(?:==|!=)\s*(?:expectedHeader|expectedAuth|wantBearer|wantAuth)\b/.exec(clean);
    if (goAuthEqMatch && !/\b(?:subtle\.ConstantTimeCompare|ConstantTimeTokenEqual)\b/.test(clean)) {
      findings.push({
        ruleId: 'go-shadow-default-bearer-or-timing-auth',
        mechanism: 'SM26-control-plane-auth-governance',
        language: 'go',
        line: lineOfIndex(clean, goAuthEqMatch.index),
        message: 'Go control-plane auth compares Bearer Authorization headers with non-constant-time `==`/`!=` instead of subtle.ConstantTimeCompare (ADV-L4, SM26).',
      });
    }
  }

  // 23. Go verification / Quint MBT test weakens gate via t.Skip/t.Skipf on missing verification tool (ADV-L4, SM27).
  const goSkipGateMatch = /\bt\.Skipf?\s*\([^)]*(?:quint|apalache|policy|gate|mbt|itf)/i.exec(clean);
  if (goSkipGateMatch) {
    findings.push({
      ruleId: 'go-test-skip-weakens-gate',
      mechanism: 'SM27-policy-gate-blindspot-confinement',
      language: 'go',
      line: lineOfIndex(clean, goSkipGateMatch.index),
      message: 'Go verification test calls t.Skip/t.Skipf on missing formal/policy toolchain instead of resolving local binaries and failing closed via t.Fatalf (ADV-L4, SM27).',
    });
  }

  return findings;
}

function extractEnclosingBlock(text: string, idx: number): string {
  // Walk backwards from idx to find the innermost enclosing '{' of the function/method body.
  let depth = 0;
  for (let i = idx; i >= 0; i--) {
    const ch = text[i];
    if (ch === '}') depth += 1;
    else if (ch === '{') {
      if (depth === 0) return extractBraceBlock(text, i);
      depth -= 1;
    }
  }
  return text;
}

function auditRust(clean: string): AgingFinding[] {
  const findings: AgingFinding[] = [];

  // 1. Unbounded channel eliminates backpressure (including nested turbofish `::<Vec<u8>>()`).
  const unbMatch = /\bunbounded_channel(?:\s*::\s*<[^\n()]+>)?\s*\(/.exec(clean);
  if (unbMatch) {
    findings.push({
      ruleId: 'rust-unbounded-channel',
      mechanism: 'SM5-metastable-overload',
      language: 'rust',
      line: lineOfIndex(clean, unbMatch.index),
      message: 'Unbounded channel allows arbitrary producer memory accumulation under slow consumers.',
    });
  }

  // 2. Detached tokio::spawn (dropping JoinHandle does NOT cancel task!).
  // Exclude tail-expression returns inside functions returning `-> ...JoinHandle<...>`
  // and handles passed directly into a tracked task wrapper (e.g. `RuntimeTask::new(..., tokio::spawn(...))`).
  const detachedRe = /(?:let\s+_\s*=\s*tokio::spawn\s*\(|^\s*tokio::spawn\s*\()/gm;
  let detachedMatch: RegExpExecArray | null;
  while ((detachedMatch = detachedRe.exec(clean)) !== null) {
    if (/\b(?:TaskTracker|JoinSet|task_tracker)\b/.test(clean)) break;
    const prefix = clean.slice(Math.max(0, detachedMatch.index - 400), detachedMatch.index);
    const returnsJoinHandle = /->\s*[^{]*\bJoinHandle\b[^{]*\{[^;]*$/.test(prefix);
    const lineEnd = clean.indexOf('\n', detachedMatch.index);
    const snippet = clean.slice(detachedMatch.index, Math.min(clean.length, (lineEnd < 0 ? clean.length : lineEnd) + 200));
    const hasTrailingSemicolon = /\)\s*;/.test(snippet) && !/^tokio::spawn\s*\([\s\S]*?\)\s*\}/.test(detachedMatch[0] + snippet);
    if (returnsJoinHandle && !/^let\s+_/.test(detachedMatch[0]) && !hasTrailingSemicolon) {
      continue;
    }
    findings.push({
      ruleId: 'rust-detached-spawn',
      mechanism: 'SM4-orphan-concurrency',
      language: 'rust',
      line: lineOfIndex(clean, detachedMatch.index),
      message: 'Detached tokio::spawn drops JoinHandle without cancellation/quiescence tracking; use JoinSet or TaskTracker.',
    });
    break;
  }

  // 3. Vec::clear() returned to pool without capacity() ceiling check in the enclosing function.
  const poolPushMatch = /pool\.push\s*\(/.exec(clean);
  if (poolPushMatch) {
    const fnScope = extractEnclosingBlock(clean, poolPushMatch.index);
    if (/\.clear\s*\(\s*\)/.test(fnScope) && !/\.capacity\s*\(\s*\)|\.shrink_to/.test(fnScope)) {
      findings.push({
        ruleId: 'rust-vec-clear-ratchet',
        mechanism: 'SM3-watermark-ratchet',
        language: 'rust',
        line: lineOfIndex(clean, poolPushMatch.index),
        message: 'Vec/buffer cleared and returned to pool without checking capacity(); spike allocations ratchet idle RSS.',
      });
    }
  }

  // 4. mem::forget on permits/guards breaks RAII conservation.
  const forgetMatch = /\b(?:std::)?mem::forget\s*\(/.exec(clean);
  if (forgetMatch) {
    findings.push({
      ruleId: 'rust-mem-forget-leak',
      mechanism: 'SM2-resource-leak',
      language: 'rust',
      line: lineOfIndex(clean, forgetMatch.index),
      message: 'mem::forget bypasses Drop and permanently leaks owned permits/resources.',
    });
  }

  // 5. Blocking std::thread::sleep or std::fs synchronous I/O inside an async fn starves executor workers.
  const asyncFnMatch = /\basync\s+fn\s+\w+/.exec(clean);
  if (asyncFnMatch) {
    const fnBody = extractBraceBlock(clean, asyncFnMatch.index);
    const blockCall = /\b(?:std::thread::sleep|std::fs::(?:read|write|File::open))\s*\(/.exec(fnBody);
    if (blockCall && !/\bspawn_blocking\b/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-blocking-in-async',
        mechanism: 'SM4-orphan-concurrency',
        language: 'rust',
        line: lineOfIndex(clean, asyncFnMatch.index + blockCall.index),
        message: 'Blocking std::thread::sleep or std::fs call inside async fn starves async runtime workers; offload via bounded spawn_blocking.',
      });
    }
  }

  // 6. Monotonically growing state collections (artifacts, history, claimed_gates, device_results, capture_keys) without cap/eviction (ui_grpc.rs).
  const stateCollRe = /\b(\w+)\.(artifacts|graph_trajectory_history|graph_projection_records|claimed_gates|device_results|capture_keys|history|cache|records)\.(insert|push)\s*\(/g;
  let scM: RegExpExecArray | null;
  while ((scM = stateCollRe.exec(clean)) !== null) {
    const fnScope = extractEnclosingBlock(clean, scM.index);
    const hasBound = /(?:\.len\s*\(\s*\)\s*(?:>=|>)|\.pop_first\s*\(|\.pop_front\s*\(|\.remove\s*\(|\.drain\s*\(|\.truncate\s*\(|\.retain\s*\(|\bMAX_[A-Z0-9_]+\b|\bmax_(?:entries|items|bytes|history|artifacts|records)\b|\bevict\b)/.test(
      fnScope,
    );
    if (!hasBound) {
      findings.push({
        ruleId: 'rust-unbounded-state-collection',
        mechanism: 'SM3-watermark-ratchet',
        language: 'rust',
        line: lineOfIndex(clean, scM.index),
        message: `Long-lived state collection ${scM[1]}.${scM[2]} grows via .${scM[3]}() without capacity ceiling or eviction (OOM aging).`,
      });
      break;
    }
  }

  // 7. Tokio broadcast::Receiver ignoring RecvError::Lagged (silent stream termination or dropped invocations in ui_grpc.rs).
  if (/\bbroadcast::channel\s*\(|\.subscribe\s*\(\s*\)/.test(clean)) {
    const recvOkMatch = /(?:while|if)\s+let\s+Ok\s*\([^)]+\)\s*=\s*\w+\.recv\s*\(\s*\)(?:\.await)?/.exec(clean);
    if (recvOkMatch) {
      const fnScope = extractEnclosingBlock(clean, recvOkMatch.index);
      if (!/\bLagged\b/.test(fnScope)) {
        findings.push({
          ruleId: 'rust-broadcast-lag-silent-drop',
          mechanism: 'SM5-metastable-overload',
          language: 'rust',
          line: lineOfIndex(clean, recvOkMatch.index),
          message: 'Tokio broadcast receiver uses `let Ok(...)` without handling RecvError::Lagged; slow UI subscribers silently disconnect or lose frames instead of resyncing snapshot.',
        });
      }
    }
  }

  // 8. Hard session/table cap returning resource_exhausted without any eviction/removal path (marlin_mygo_host.rs 64-slot lockout).
  const capLockoutMatch = /\.len\s*\(\s*\)\s*>=\s*\d+[\s\S]{0,180}resource_exhausted/.exec(clean);
  if (
    capLockoutMatch &&
    /\.insert\s*\(/.test(clean) &&
    !/(?:\.remove\s*\(|\.pop_first\s*\(|\.retain\s*\(|\bevict\b)/.test(clean)
  ) {
    findings.push({
      ruleId: 'rust-bounded-no-eviction-lockout',
      mechanism: 'SM3-watermark-ratchet',
      language: 'rust',
      line: lineOfIndex(clean, capLockoutMatch.index),
      message: 'Bounded session/resource map enforces hard cap with resource_exhausted but has no idle eviction/removal path (permanent slot lockout).',
    });
  }

  // 9. Async single-flight in_flight AtomicBool compare_exchange(false, true) held across .await without Drop guard (search_scheduler.rs deadlock).
  const inFlightCas = /\.in_flight\s*\.\s*compare_exchange\s*\(\s*false\s*,\s*true/.exec(clean);
  if (inFlightCas) {
    const fnScope = extractEnclosingBlock(clean, inFlightCas.index);
    const hasAwait = /\.await\b/.test(fnScope);
    const hasInFlightDropGuard =
      /\bimpl\s+Drop\s+for\b[\s\S]{0,280}\.in_flight\.store\s*\(\s*false/.test(clean) ||
      /\bimpl\s+Drop\s+for\b/.test(fnScope);
    if (hasAwait && !hasInFlightDropGuard) {
      findings.push({
        ruleId: 'rust-async-inflight-no-drop-guard',
        mechanism: 'SM9-singleflight-deadlock',
        language: 'rust',
        line: lineOfIndex(clean, inFlightCas.index),
        message: 'AtomicBool in_flight flag acquired across .await without RAII Drop guard; future cancellation permanently deadlocks all coalesced search callers.',
      });
    }
  }

  // 10. Tokio Notify::notified() checked against AtomicBool without .enable() before load() (lost-wakeup race in search_scheduler.rs).
  const notifyMatch = /let\s+(?:mut\s+)?(\w+)\s*=\s*[^\n;]*\.notified\s*\(\s*\)\s*;/.exec(clean);
  if (notifyMatch) {
    const waitVar = notifyMatch[1]!;
    const fnScope = extractEnclosingBlock(clean, notifyMatch.index);
    const hasLoadBeforeAwait = new RegExp(`\\.load\\s*\\([\\s\\S]{0,160}\\b${waitVar}\\.await\\b`).test(fnScope);
    const hasEnable = new RegExp(`\\b${waitVar}\\.(?:as_mut\\s*\\(\\s*\\)\\.)?enable\\s*\\(\\s*\\)`).test(fnScope);
    if (hasLoadBeforeAwait && !hasEnable) {
      findings.push({
        ruleId: 'rust-notify-notified-unarmed-check',
        mechanism: 'SM9-singleflight-deadlock',
        language: 'rust',
        line: lineOfIndex(clean, notifyMatch.index),
        message: `Tokio Notify::notified() future '${waitVar}' is awaited after atomic state check without calling .enable() first (lost-wakeup deadlock).`,
      });
    }
  }

  // 11. Async search/DSL result applied without checking active query epoch (helm/overlay.rs SM8).
  const applyDslMatch = /\bfn\s+apply_(?:dsl|async)_result\s*\([^)]*\)/.exec(clean);
  if (applyDslMatch) {
    const fnBody = extractBraceBlock(clean, applyDslMatch.index);
    const overwritesCandidates = /\bself\.search_candidates\s*=/.test(fnBody);
    const checksEpoch = /\bself\.epoch\b/.test(fnBody) && /(?:!=|==)/.test(fnBody);
    if (overwritesCandidates && !checksEpoch) {
      findings.push({
        ruleId: 'rust-unfenced-async-search-apply',
        mechanism: 'SM8-search-generation-race',
        language: 'rust',
        line: lineOfIndex(clean, applyDslMatch.index),
        message: 'Async/DSL search result overwrites self.search_candidates without verifying query epoch fencing.',
      });
    }
  }

  // 12. Unbounded VecDeque mailbox ingestion via try_recv() without per-tier capacity ceiling (linked_ui.rs SM11).
  if (/\bVecDeque\b/.test(clean)) {
    const ingestMatch = /while\s+let\s+Ok\s*\([^)]+\)\s*=\s*[^\n]*\.try_recv\s*\(\s*\)/.exec(clean);
    if (ingestMatch) {
      const fnScope = extractEnclosingBlock(clean, ingestMatch.index);
      const pushesQueue = /_queue\.push_back\s*\(/.test(fnScope);
      const hasBound = /(?:\.len\s*\(\s*\)\s*(?:>=|>|<|<=)|\bMAX_[A-Z0-9_]+\b|\bmax_\w+|\bshed\b)/.test(fnScope);
      if (pushesQueue && !hasBound) {
        findings.push({
          ruleId: 'rust-unbounded-vecdeque-mailbox',
          mechanism: 'SM5-metastable-overload',
          language: 'rust',
          line: lineOfIndex(clean, ingestMatch.index),
          message: 'VecDeque mailbox ingests jobs from try_recv() without per-tier capacity bound or overload shedding (SM11).',
        });
      }
    }
  }

  // 13. Reconnect/stream replacement without advancing epoch or retiring previous stream (SM12).
  const rustReconnectMatch = /\bfn\s+(?:reconnect|replace_stream|reset_stream)\s*\([^)]*\)/.exec(clean);
  if (rustReconnectMatch) {
    const fnBody = extractBraceBlock(clean, rustReconnectMatch.index);
    const overwritesStream = /\bself\.(?:stream|active_stream|session_stream)\s*=/.test(fnBody);
    const retiresOrFences = /(?:\.take\s*\(\s*\)|\.abort\s*\(\s*\)|\.close\s*\(\s*\)|\bself\.(?:epoch|session_epoch)\s*\+=)/.test(fnBody);
    if (overwritesStream && !retiresOrFences) {
      findings.push({
        ruleId: 'rust-unfenced-stream-reconnect',
        mechanism: 'SM12-ipc-half-open-reconnect',
        language: 'rust',
        line: lineOfIndex(clean, rustReconnectMatch.index),
        message: 'Stream reconnect replaces active stream without taking/aborting the superseded stream or advancing session epoch (SM12).',
      });
    }
  }

  // 14. Unserialized cold-start index open or missing workspace root verification (SM15: search_tool.rs split-brain / cross-root).
  const getOrOpenMatch = /\bfn\s+get_or_open\s*\([^)]*\)/.exec(clean);
  if (getOrOpenMatch) {
    const fnBody = extractBraceBlock(clean, getOrOpenMatch.index);
    const readsInner = /\bself\.inner\.read\s*\(\s*\)/.test(fnBody);
    const callsAttach = /\bself\.attach\s*\(/.test(fnBody);
    const serializesOpen = /\b(?:open_lock|init_lock|build_lock)\b/.test(fnBody) || /\bself\.inner\.write\s*\(\s*\)/.test(fnBody);
    const verifiesRoot = /\b(?:canonical|root\s*==|==\s*root|matches_root|workspace_root)\b/.test(fnBody);
    if (readsInner && callsAttach && (!serializesOpen || !verifiesRoot)) {
      findings.push({
        ruleId: 'rust-cold-open-split-brain',
        mechanism: 'SM15-search-snapshot-isolation',
        language: 'rust',
        line: lineOfIndex(clean, getOrOpenMatch.index),
        message: 'Lazy get_or_open builds outside an init lock or skips workspace root matching, causing concurrent cold-start split-brain or cross-worktree contamination (SM15).',
      });
    }
  }

  // 15. Single-flight watch follower returns error immediately when leader drops instead of re-electing (SM15: search_scheduler.rs).
  const changedErrMatch = /if\s+\w+\.changed\s*\(\s*\)\.await\.is_err\s*\(\s*\)\s*\{[\s\S]{0,160}return\s+Err\s*\(/.exec(clean);
  if (changedErrMatch && /\bin_flight\b/.test(clean)) {
    const fnScope = extractEnclosingBlock(clean, changedErrMatch.index);
    const reelects = /\bcontinue\s*'[a-zA-Z_]\w*\b|\breelect\b|\bretry_leader\b/.test(fnScope);
    if (!reelects) {
      findings.push({
        ruleId: 'rust-singleflight-cancel-cascade',
        mechanism: 'SM15-search-snapshot-isolation',
        language: 'rust',
        line: lineOfIndex(clean, changedErrMatch.index),
        message: 'Single-flight follower fails immediately when leader watch channel closes instead of re-electing a surviving leader (SM15).',
      });
    }
  }

  // 16. PasteSelection arm bypasses search-box input byte cap declared in the same file (SM16: helm/editor.rs).
  const pasteArmMatch = /\bPasteSelection\s*=>\s*\{/.exec(clean);
  if (pasteArmMatch && /\bMAX_[A-Z0-9_]*INPUT_BYTES\b/.test(clean)) {
    const armBody = extractBraceBlock(clean, pasteArmMatch.index);
    const insertsDirectly = /\.insert_text\s*\(/.test(armBody) && !/\bself\.insert_text\s*\(/.test(armBody);
    const enforcesCap = /\b(?:MAX_[A-Z0-9_]*INPUT_BYTES|remaining|saturating_sub|sanitize_bounded)\b/.test(armBody);
    if (insertsDirectly && !enforcesCap) {
      findings.push({
        ruleId: 'rust-paste-bypasses-input-cap',
        mechanism: 'SM16-search-input-sanitization',
        language: 'rust',
        line: lineOfIndex(clean, pasteArmMatch.index),
        message: 'PasteSelection inserts yank_register directly into editor bypassing MAX_*_INPUT_BYTES cap (SM16).',
      });
    }
  }

  // 17. SSE completion aggregation ignores declared stream_output_limit (SM17: marlin-agent-stream/src/gateway.rs).
  if (/\bstream_output_limit\b/.test(clean)) {
    const sseTextPushMatch = /TurnEvent::Text\s*\(\s*\w+\s*\)\s*=>\s*(?:\{[\s\S]{0,220}?)?\btext\.push_str\s*\(/.exec(clean);
    if (sseTextPushMatch) {
      const loopScope = extractEnclosingBlock(clean, sseTextPushMatch.index);
      const checksLimit = /\b(?:stream_output_limit|output_limit|OutputLimit|enforce_stream_output_limit|check_stream_output_budget)\b/.test(loopScope);
      if (!checksLimit) {
        findings.push({
          ruleId: 'rust-sse-complete-ignores-output-limit',
          mechanism: 'SM17-streaming-output-budget',
          language: 'rust',
          line: lineOfIndex(clean, sseTextPushMatch.index),
          message: 'SSE TurnEvent aggregation appends text without enforcing configured stream_output_limit or accounting thinking deltas (SM17).',
        });
      }
    }
  }

  // 18. HTTP response buffers entire body via .bytes().await before checking MAX_* size cap (SM17: openai_http.rs).
  const reqwestBytesMatch = /\.bytes\s*\(\s*\)\s*\.await\b/.exec(clean);
  if (reqwestBytesMatch) {
    const fnScope = extractEnclosingBlock(clean, reqwestBytesMatch.index);
    const checksAfterBuffer = /\.len\s*\(\s*\)\s*>\s*(?:MAX_[A-Z0-9_]+|\w*(?:max|limit|cap)\w*)/i.test(fnScope);
    const streamsChunks = /\.chunk\s*\(\s*\)\s*\.await\b/.test(fnScope);
    if (checksAfterBuffer && !streamsChunks) {
      findings.push({
        ruleId: 'rust-http-body-buffer-before-cap',
        mechanism: 'SM17-streaming-output-budget',
        language: 'rust',
        line: lineOfIndex(clean, reqwestBytesMatch.index),
        message: 'HTTP response buffers full body via .bytes().await before checking byte cap; validate content_length() and stream via .chunk().await with pre-allocation cap enforcement (SM17).',
      });
    }
  }

  // 19. Async function stores bare JoinHandles in a Vec and awaits sequentially without abort-on-drop (SM19: marlin-agent-hooks/dispatcher.rs).
  const asyncRunsMatch = /\bfor\s+\([^)]*\b(?:task|handle)\b[^)]*\)\s+in\s+\w+\s*\{[\s\S]{0,120}?\b(?:task|handle)\.await\b/.exec(clean);
  if (asyncRunsMatch && /\bJoinHandle\b/.test(clean)) {
    const fnScope = extractEnclosingBlock(clean, asyncRunsMatch.index);
    const hasAbortGuard = /\b(?:AbortOnDrop|JoinSet|abort_all|abort_handles|DropGuard)\b/.test(clean);
    if (!hasAbortGuard && /\.push\s*\(/.test(fnScope)) {
      findings.push({
        ruleId: 'rust-async-joinhandle-vec-drop-detach',
        mechanism: 'SM19-task-and-pool-cancellation',
        language: 'rust',
        line: lineOfIndex(clean, asyncRunsMatch.index),
        message: 'Vec of bare tokio::task::JoinHandle detaches in-flight child tasks on async cancellation; wrap handles in an AbortOnDrop guard or JoinSet (SM19).',
      });
    }
  }

  // 20. JoinSet batch loop spawns unbounded tasks without a concurrency semaphore cap (SM19: marlin-agent-runtime/effect_pump.rs).
  const joinSetLoopMatch = /\bfor\s+[^\n{]+\{[\s\S]{0,220}?\bjoin_set\.spawn\s*\(/.exec(clean);
  if (joinSetLoopMatch) {
    const fnScope = extractEnclosingBlock(clean, joinSetLoopMatch.index);
    const hasConcurrencyCap = /\b(?:Semaphore|acquire_owned|MAX_CONCURRENT|max_concurrency|permits)\b/.test(fnScope);
    if (!hasConcurrencyCap) {
      findings.push({
        ruleId: 'rust-joinset-unbounded-fanout',
        mechanism: 'SM19-task-and-pool-cancellation',
        language: 'rust',
        line: lineOfIndex(clean, joinSetLoopMatch.index),
        message: 'JoinSet loop spawns unbounded concurrent tasks without a Semaphore / max_concurrency ceiling (SM19).',
      });
    }
  }

  // 21. DB ConnectionLease Drop unconditionally returns connection to pool while file runs BEGIN transactions (SM19: turso_backend.rs).
  const leaseDropMatch = /\bimpl\s+Drop\s+for\s+\w*ConnectionLease\b/.exec(clean);
  if (leaseDropMatch && /\bBEGIN\s+(?:CONCURRENT|IMMEDIATE|DEFERRED|EXCLUSIVE)\b/i.test(clean)) {
    const dropBody = extractBraceBlock(clean, leaseDropMatch.index);
    const returnsConn = /\.(?:send|try_send)\s*\(\s*connection\s*\)/.test(dropBody);
    const guardsDirty = /\b(?:dirty|in_transaction|tx_active|poisoned|is_clean|discard|rollback|autocommit)\b/i.test(dropBody);
    if (returnsConn && !guardsDirty) {
      findings.push({
        ruleId: 'rust-pool-lease-returns-dirty-tx',
        mechanism: 'SM19-task-and-pool-cancellation',
        language: 'rust',
        line: lineOfIndex(clean, leaseDropMatch.index),
        message: 'ConnectionLease::drop unconditionally returns DB connection to pool without discarding or rolling back uncommitted transactions cancelled mid-flight (SM19).',
      });
    }
  }

  // 20. Subprocess stdout/stderr buffered unboundedly via wait_with_output()+truncate() or pipe read_to_end() without cap/drain-to-sink (SM20).
  const waitTruncMatch = /\bwait_with_output\s*\(\s*\)/.exec(clean);
  if (waitTruncMatch) {
    const fnScope = extractEnclosingBlock(clean, waitTruncMatch.index);
    const postTruncates = /\b(?:stdout|stderr)\.truncate\s*\(/.test(fnScope);
    const usesBoundedWait = /\bwait_with_bounded_output\b/.test(fnScope);
    if (postTruncates && !usesBoundedWait) {
      findings.push({
        ruleId: 'rust-subprocess-buffer-before-truncate',
        mechanism: 'SM20-subprocess-pipe-capture',
        language: 'rust',
        line: lineOfIndex(clean, waitTruncMatch.index),
        message: 'wait_with_output() buffers unbounded subprocess stdout/stderr into heap before calling .truncate(); enforce bounded capture with drain-to-sink (SM20).',
      });
    }
  } else {
    const pipeReadEndMatch = /\b(?:stdout|stderr|stream)\w*(?:\.inner)?\.read_to_end\s*\(\s*&mut\s+\w+\s*\)/.exec(clean);
    if (pipeReadEndMatch) {
      const fnScope = extractEnclosingBlock(clean, pipeReadEndMatch.index);
      const isChildPipe = /\b(?:child\.stdout|child\.stderr|ChildStdout|ChildStderr|LeasedPipe)\b/.test(clean);
      const hasBound = /\.take\s*\(\s*[^)\s]|\b(?:max_bytes|max_output_bytes|MAX_\w*OUTPUT|drain_to_sink|read_bounded)\b/i.test(fnScope);
      if (isChildPipe && !hasBound) {
        findings.push({
          ruleId: 'rust-subprocess-buffer-before-truncate',
          mechanism: 'SM20-subprocess-pipe-capture',
          language: 'rust',
          line: lineOfIndex(clean, pipeReadEndMatch.index),
          message: 'Child process pipe uses unbounded read_to_end(&mut bytes) without byte cap and drain-to-sink; runaway stdout/stderr causes OOM (SM20).',
        });
      }
    }
  }

  // 21. Subprocess stdout/stderr BufReader::read_line without .take(MAX_*) single-line cap (SM20).
  const readLineMatch = /\.read_line\s*\(\s*&mut\s+\w+\s*\)/.exec(clean);
  if (readLineMatch) {
    const fnScope = extractEnclosingBlock(clean, readLineMatch.index);
    const isPipeReader = /\bBufReader::new\s*\(\s*(?:stdout|stderr|child_out|pipe)\b/.test(fnScope);
    const hasTakeCap = /\.take\s*\(\s*[^)\s]|\b(?:MAX_\w*LINE|max_line_bytes|read_bounded_line)\b/i.test(fnScope);
    if (isPipeReader && !hasTakeCap) {
      findings.push({
        ruleId: 'rust-subprocess-unbounded-read-line',
        mechanism: 'SM20-subprocess-pipe-capture',
        language: 'rust',
        line: lineOfIndex(clean, readLineMatch.index),
        message: 'Subprocess BufReader::read_line() lacks a .take(MAX_LINE_BYTES) cap; a delimiter-free runaway line exhausts heap memory (SM20).',
      });
    }
  }

  // 22. Rust atomic write uses fs::write(&tmp, ...) + fs::rename without unique temp name or sync_all() (SM21).
  const rustTmpWriteMatch = /\b(?:std::)?fs::write\s*\(\s*&?\s*(?:tmp|temp)\w*\s*,/i.exec(clean);
  if (rustTmpWriteMatch) {
    const fnScope = extractEnclosingBlock(clean, rustTmpWriteMatch.index);
    const hasRename = /\b(?:std::)?fs::rename\s*\(/.test(fnScope);
    const hasSync = /\.sync_all\s*\(\s*\)|\.sync_data\s*\(\s*\)/.test(fnScope);
    const hasUnique = /\b(?:process::id|AtomicU64|NamedTempFile|create_new\s*\(\s*true\s*\)|subsec_nanos)\b/.test(fnScope);
    if (hasRename && (!hasSync || !hasUnique)) {
      findings.push({
        ruleId: 'rust-atomic-write-shared-tmp-or-no-fsync',
        mechanism: 'SM21-atomic-persistence-fsync',
        language: 'rust',
        line: lineOfIndex(clean, rustTmpWriteMatch.index),
        message: 'Atomic file persistence uses fs::write to a shared or un-fsynced temp path before fs::rename; use unique create_new(true) temp file + write_all + sync_all() + rename with error cleanup (SM21).',
      });
    }
  }

  // 23. Rust file sandbox resolves target via lexical root.join(&normalized) without symlink_metadata/canonicalize confinement (SM22).
  const sandboxJoinMatch = /\bself\.root\.join\s*\(\s*&?\w+\s*\)/.exec(clean);
  if (sandboxJoinMatch && /\bstruct\s+\w*Sandbox\b/.test(clean)) {
    const fnScope = extractEnclosingBlock(clean, sandboxJoinMatch.index);
    const checksSymlinkOrCanon = /\b(?:symlink_metadata|canonicalize|is_symlink|resolve_confined\w*|verify_confined\w*)\b/.test(fnScope);
    if (!checksSymlinkOrCanon) {
      findings.push({
        ruleId: 'rust-sandbox-lexical-only-no-symlink-check',
        mechanism: 'SM22-adversarial-sandbox-archive-confinement',
        language: 'rust',
        line: lineOfIndex(clean, sandboxJoinMatch.index),
        message: 'File sandbox relies solely on lexical path normalization without symlink_metadata/canonicalize checks; intermediate or leaf symlinks escape sandbox root (ADV-L4, SM22).',
      });
    }
  }

  // 24. Rust reqwest::Client::builder() constructed without explicit fail-closed redirect::Policy::none()/custom (ADV-L4, SM23).
  const reqwestBuilderMatch = /\breqwest::Client::builder\s*\(\s*\)/.exec(clean);
  if (reqwestBuilderMatch) {
    const fnScope = extractEnclosingBlock(clean, reqwestBuilderMatch.index);
    const hasRedirectPolicy = /\.redirect\s*\(\s*[\s\S]{0,80}(?:Policy::none|Policy::custom|redirect_policy)/.test(fnScope);
    if (!hasRedirectPolicy) {
      findings.push({
        ruleId: 'rust-reqwest-client-default-redirects',
        mechanism: 'SM23-adversarial-http-redirect-ssrf',
        language: 'rust',
        line: lineOfIndex(clean, reqwestBuilderMatch.index),
        message: 'reqwest::Client::builder() inherits default 10-hop redirect following; 307/302 redirects leak prompts/Bearer credentials and enable internal SSRF (ADV-L4, SM23).',
      });
    }
  }

  // 25. Rust sandbox/tool subprocess spawner inherits ambient host environment without .env_clear() allowlist scrubbing (ADV-L4, SM24).
  const rustToolCmdMatch = /\b(?:tokio::process::Command|AsyncCommand)::new\s*\(\s*(?:&payload\.program|request\.program\.as_str\(\))\s*\)/.exec(clean);
  if (rustToolCmdMatch) {
    const fnScope = extractEnclosingBlock(clean, rustToolCmdMatch.index);
    const scrubsEnv = /\.env_clear\s*\(\s*\)|\bapply_scrubbed_env\b|\bscrub_command_env\b/.test(fnScope);
    if (!scrubsEnv) {
      findings.push({
        ruleId: 'rust-sandbox-spawn-inherits-ambient-env',
        mechanism: 'SM24-adversarial-env-scrub-auth-timing',
        language: 'rust',
        line: lineOfIndex(clean, rustToolCmdMatch.index),
        message: 'Sandboxed tool subprocess inherits ambient host environment variables without .env_clear() + explicit safe allowlist, leaking API keys and bridge tokens (ADV-L4, SM24).',
      });
    }
  }

  // 26. Rust Bearer authorization check compares token string via short-circuit `==` instead of constant-time comparison (ADV-L4, SM24).
  const bearerFnMatch = /\bfn\s+check_bearer_header\b/.exec(clean);
  if (bearerFnMatch) {
    const fnBody = extractBraceBlock(clean, bearerFnMatch.index);
    const hasPlainEq = /\bactual\s*==\s*expected\b|\bexpected\s*==\s*actual\b/.test(fnBody);
    const hasConstTime = /\b(?:constant_time_eq|ct_eq|ConstantTimeEq)\b/.test(fnBody);
    if (hasPlainEq && !hasConstTime) {
      findings.push({
        ruleId: 'rust-bearer-auth-non-constant-time-eq',
        mechanism: 'SM24-adversarial-env-scrub-auth-timing',
        language: 'rust',
        line: lineOfIndex(clean, bearerFnMatch.index),
        message: 'Bearer authorization header verification uses short-circuit `==` instead of constant-time byte comparison and non-empty guard (CWE-208, ADV-L4, SM24).',
      });
    }
  }

  // 27. Rust production AtomicEffectExecutor executes SandboxRun without GovernanceAdmissionGate / ExecutionCircuitBreaker authorization (ADV-L4, SM25).
  const atomicExecImplMatch = /\bimpl(?:<[^>]+>)?\s+AtomicEffectExecutor\s+for\s+\w*CompositeAtomicEffectExecutor\b/.exec(clean);
  if (atomicExecImplMatch) {
    const implBody = extractBraceBlock(clean, atomicExecImplMatch.index);
    const runsSandbox = /\bAtomicEffect::SandboxRun\b/.test(implBody);
    const gatesGovernance = /\b(?:authorize_side_effect|authorize_atomic_effect|governance_gate|execution_breaker)\b/.test(implBody);
    if (runsSandbox && !gatesGovernance) {
      findings.push({
        ruleId: 'rust-production-effect-executor-missing-governance-gate',
        mechanism: 'SM25-single-owner-graph-governance',
        language: 'rust',
        line: lineOfIndex(clean, atomicExecImplMatch.index),
        message: 'Production CompositeAtomicEffectExecutor executes AtomicEffect::SandboxRun without consulting GovernanceAdmissionGate or ExecutionCircuitBreaker (disconnected governance bypass, ADV-L4, SM25).',
      });
    }
  }

  // 28. Rust GraphEngine TaskActorKernelExecutor dispatches steps without GovernanceAdmissionGate / ExecutionCircuitBreaker enforcement (ADV-L4, SM25).
  const taskActorImplMatch = /\bimpl(?:<[^>]+>)?\s+TaskActorKernelExecutor\b/.exec(clean);
  if (taskActorImplMatch) {
    const implBody = extractBraceBlock(clean, taskActorImplMatch.index);
    const dispatches = /\bfn\s+dispatch_and_reconcile\b/.test(implBody);
    const gatesGovernance = /\b(?:authorize_dispatch|authorize_side_effect|governance_gate|execution_breaker)\b/.test(implBody);
    if (dispatches && !gatesGovernance) {
      findings.push({
        ruleId: 'rust-task-actor-kernel-missing-governance-gate',
        mechanism: 'SM25-single-owner-graph-governance',
        language: 'rust',
        line: lineOfIndex(clean, taskActorImplMatch.index),
        message: 'GraphEngine TaskActorKernelExecutor dispatches admitted TaskActor steps without consulting GovernanceAdmissionGate or ExecutionCircuitBreaker (ADV-L4, SM25).',
      });
    }
  }

  // 29. Rust kernel facade re-exports legacy LoopProgram engine un-deprecated alongside canonical GraphEngine TaskActorKernelExecutor (ADV-L4, SM25).
  if (/\bpub\s+use\s+task_actor_executor::/.test(clean)) {
    const legacyExportMatch = /\bpub\s+use\s+(?:loop_machine|loop_program_side_effects)::\{/.exec(clean);
    if (legacyExportMatch) {
      const prefix = clean.slice(Math.max(0, legacyExportMatch.index - 220), legacyExportMatch.index);
      const isDeprecated = /#\[deprecated\b/.test(prefix);
      if (!isDeprecated) {
        findings.push({
          ruleId: 'rust-legacy-loop-engine-unretired-shadow-surface',
          mechanism: 'SM25-single-owner-graph-governance',
          language: 'rust',
          line: lineOfIndex(clean, legacyExportMatch.index),
          message: 'Kernel exports legacy LoopProgram engine alongside canonical GraphEngine TaskActorKernelExecutor without #[deprecated] retirement boundary, inviting additive dual-engine drift (ADV-L4, SM25).',
        });
      }
    }
  }

  // 30. Rust binary entrypoint defines shadow non-constant-time `check_bearer` or hardcoded `"marlin-dev-token"` fallback (ADV-L4, SM26).
  const shadowBearerFnMatch = /\bfn\s+check_bearer\s*\([^)]*\)/.exec(clean);
  if (shadowBearerFnMatch) {
    const fnBody = extractBraceBlock(clean, shadowBearerFnMatch.index);
    const hasPlainEq = /\.to_str\s*\(\s*\)\.ok\s*\(\s*\)\s*==\s*Some\s*\(/.test(fnBody);
    const usesCanonicalCt = /\b(?:constant_time_eq|ct_eq|check_bearer_header)\b/.test(fnBody);
    if (hasPlainEq && !usesCanonicalCt) {
      findings.push({
        ruleId: 'rust-shadow-entrypoint-bearer-auth',
        mechanism: 'SM26-control-plane-auth-governance',
        language: 'rust',
        line: lineOfIndex(clean, shadowBearerFnMatch.index),
        message: 'Binary entrypoint defines shadow check_bearer using non-constant-time `==` instead of canonical MyGoBridgeHost::check_bearer_header (ADV-L4, SM26).',
      });
    }
  }
  const hardcodedDevTokenMatch = /MARLIN_BRIDGE_TOKEN"\s*\)\s*\.unwrap_or(?:_else)?\s*\([^)]*"marlin-dev-token"/.exec(clean);
  if (hardcodedDevTokenMatch) {
    findings.push({
      ruleId: 'rust-shadow-entrypoint-bearer-auth',
      mechanism: 'SM26-control-plane-auth-governance',
      language: 'rust',
      line: lineOfIndex(clean, hardcodedDevTokenMatch.index),
      message: 'Host entrypoint falls back to hardcoded "marlin-dev-token" on MARLIN_BRIDGE_TOKEN instead of fail-closed non-loopback & blank-token resolution (ADV-L4, SM26).',
    });
  }

  // 31. Rust `check_bearer_header` validates `!expected.trim().is_empty()` without verifying non-empty credential after `"Bearer "` prefix (ADV-L4, SM26).
  const checkBearerHeaderMatch = /\bfn\s+check_bearer_header\s*\([^)]*\)/.exec(clean);
  if (checkBearerHeaderMatch) {
    const fnBody = extractBraceBlock(clean, checkBearerHeaderMatch.index);
    const checksAuthHeader = /\.get\s*\(\s*"authorization"\s*\)/.test(fnBody);
    const checksTrimEmpty = /\bexpected\.trim\s*\(\s*\)\.is_empty\s*\(\s*\)/.test(fnBody);
    const checksBearerPayload = /(?:strip_prefix\s*\(\s*"Bearer\s+"|\bbearer_credential\b|\bextract_bearer_token\b|\bsplit_once\b)/.test(fnBody);
    if (checksAuthHeader && checksTrimEmpty && !checksBearerPayload) {
      findings.push({
        ruleId: 'rust-empty-bearer-prefix-bypass',
        mechanism: 'SM26-control-plane-auth-governance',
        language: 'rust',
        line: lineOfIndex(clean, checkBearerHeaderMatch.index),
        message: 'check_bearer_header checks expected.trim().is_empty() without verifying a non-blank credential after the "Bearer " prefix, admitting empty "Bearer " headers (ADV-L4, SM26).',
      });
    }
  }

  // 32. Rust control-plane mutating/streaming gRPC RPC omits fail-closed governance E-Stop gate (ADV-L4, SM26).
  const rpcGovTargets = [
    /\basync\s+fn\s+submit_scoped_panel_action\s*\(/g,
    /\basync\s+fn\s+install_signed_release\s*\(/g,
    /\basync\s+fn\s+enable_workflow\s*\(/g,
    /\basync\s+fn\s+stream_turn\s*\(/g,
    /\basync\s+fn\s+start_session_turn\s*\(/g,
  ];
  const isControlPlaneServer = /\bimpl(?:<[^>]+>)?\s+(?:PluginHostService|app_server_server::AppServer|AppServer)\s+for\s+(?:MyGoBridgeHost|AppServer)\b/.test(clean);
  if (isControlPlaneServer) {
    for (const rpcRe of rpcGovTargets) {
      let rpcM: RegExpExecArray | null;
      while ((rpcM = rpcRe.exec(clean)) !== null) {
        const fnBody = extractBraceBlock(clean, rpcM.index);
        const checksAuth = /(?:\bself\.check_auth|\(self\.authorize\))\s*\(/.test(fnBody);
        const checksGovEstop = /\b(?:check_governance_admitted|ensure_governance_live|check_governance_estop|governance_gate)\b/.test(fnBody);
        if (checksAuth && !checksGovEstop) {
          findings.push({
            ruleId: 'rust-control-plane-rpc-missing-estop-gate',
            mechanism: 'SM26-control-plane-auth-governance',
            language: 'rust',
            line: lineOfIndex(clean, rpcM.index),
            message: 'Mutating or LLM-streaming control-plane gRPC RPC checks Bearer auth but omits fail-closed GovernanceAdmissionGate E-Stop enforcement (ADV-L4, SM26).',
          });
          break;
        }
      }
      if (findings.some((f) => f.ruleId === 'rust-control-plane-rpc-missing-estop-gate')) break;
    }
  }

  // 33. Rust release-gate runner spawns unscrubbed login shell `Command::new("sh").arg("-lc")` with unbounded `.output()` (ADV-L4, SM26).
  const loginShellMatch = /\bCommand::new\s*\(\s*"(?:\/bin\/)?sh"\s*\)\s*\.arg\s*\(\s*"-lc"\s*\)/.exec(clean);
  if (loginShellMatch) {
    findings.push({
      ruleId: 'rust-release-gate-unscrubbed-login-shell',
      mechanism: 'SM26-control-plane-auth-governance',
      language: 'rust',
      line: lineOfIndex(clean, loginShellMatch.index),
      message: 'Release-gate runner spawns login shell `sh -lc` inheriting ambient host secrets and unbounded output instead of env_clear() + allowlist + bounded non-login shell (ADV-L4, SM26).',
    });
  } else {
    const releaseRunMatch = /\bfn\s+run_release_gate_command\s*\([^)]*\)/.exec(clean);
    if (releaseRunMatch) {
      const fnBody = extractBraceBlock(clean, releaseRunMatch.index);
      const spawnsSh = /\bCommand::new\s*\(\s*"(?:\/bin\/)?sh"\s*\)/.test(fnBody);
      const scrubsEnv =
        /\.env_clear\s*\(\s*\)/.test(fnBody) ||
        (/\bapply_scrubbed\w*env\s*\(/i.test(fnBody) && /\.env_clear\s*\(\s*\)/.test(clean));
      if (spawnsSh && !scrubsEnv) {
        findings.push({
          ruleId: 'rust-release-gate-unscrubbed-login-shell',
          mechanism: 'SM26-control-plane-auth-governance',
          language: 'rust',
          line: lineOfIndex(clean, releaseRunMatch.index),
          message: 'run_release_gate_command spawns `sh` without env_clear() secret scrubbing, leaking host API keys into persisted release diagnostics (ADV-L4, SM26).',
        });
      }
    }
  }

  // 34. Rust ASP policy gate downgraded via unexplained `advice = allow` / `mode = allow|off` or `#[ignore]` on enforce_asp_rust (ADV-L4, SM27).
  const aspGateDowngradeMatch =
    /\basp_rust_cargo_test_gate!\s*\([^)]*(?:\badvice\s*=\s*allow\b|\bmode\s*=\s*(?:allow|off)\b)/.exec(clean) ||
    /#\[ignore[^\]]*\]\s*(?:pub\s+)?(?:async\s+)?fn\s+enforce_asp_rust/.exec(clean);
  if (aspGateDowngradeMatch) {
    const gateSnippet = clean.slice(aspGateDowngradeMatch.index, aspGateDowngradeMatch.index + 420);
    const isAuditableInfoOnly =
      /\bwith_cargo_test_advice_allow_explanation\s*\(/.test(gateSnippet) &&
      !/\bmode\s*=\s*(?:warn|allow|off)\b/.test(gateSnippet);
    if (!isAuditableInfoOnly) {
      findings.push({
        ruleId: 'rust-policy-gate-downgraded-or-ignored',
        mechanism: 'SM27-policy-gate-blindspot-confinement',
        language: 'rust',
        line: lineOfIndex(clean, aspGateDowngradeMatch.index),
        message: 'ASP Rust policy gate is downgraded (`advice = allow` / `mode = allow`) or disabled via `#[ignore]`, blinding architectural enforcement (ADV-L4, SM27).',
      });
    }
  }

  // 35. Rust binary entrypoint (`fn main`) carries fat server/control-plane implementation (>= 8 helper fns) instead of delegating to an owned library module (ADV-L4, SM27).
  const mainFnMatch = /\b(?:async\s+)?fn\s+main\s*\(\s*\)/.exec(clean);
  if (mainFnMatch && !/\b(?:criterion_group!|criterion_main!|Criterion::default)\b/.test(clean)) {
    const beforeTests = clean.split(/#\[cfg\s*\(\s*test\s*\)\]/)[0] ?? clean;
    const helperFns = beforeTests.match(/^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?!main\b)[a-zA-Z_]\w*\s*(?:<[^>]*>)?\s*\(/gm) ?? [];
    const hasControlPlaneSurface = /\b(?:Server::builder|TcpListener::bind|tonic::|AppServer|MyGoBridgeHost|MarlinSchemeHostClient)\b/.test(beforeTests);
    if (helperFns.length >= 8 && hasControlPlaneSurface) {
      findings.push({
        ruleId: 'rust-binary-entrypoint-fat-shadow-logic',
        mechanism: 'SM27-policy-gate-blindspot-confinement',
        language: 'rust',
        line: lineOfIndex(clean, mainFnMatch.index),
        message: `Binary entrypoint defines ${helperFns.length} control-plane helper functions directly alongside fn main(); extract implementation into an owned library module to prevent shadow drift (ADV-L4, SM27).`,
      });
    }
  }

  // 36. Rust policy harness suppresses workspace policy failure or Cargo cycle panic via catch_unwind / .ok() (ADV-L4, SM27).
  const maskedPolicyMatch =
    /\b(?:catch_unwind|let\s+_\s*=)[\s\S]{0,160}\b(?:workspace_policy\w*|enforce_asp_rust\w*|run_workspace_policy\w*)\b/.exec(clean);
  if (maskedPolicyMatch) {
    findings.push({
      ruleId: 'rust-workspace-policy-failure-masked',
      mechanism: 'SM27-policy-gate-blindspot-confinement',
      language: 'rust',
      line: lineOfIndex(clean, maskedPolicyMatch.index),
      message: 'Workspace policy gate invocation masks errors or cycle panics via catch_unwind / `let _ =` instead of failing closed (ADV-L4, SM27).',
    });
  }

  // 37. Rust PanelPluginHost::enable_panel ignores stored capability grants or set_project_grants omits revocation closure (ADV-L4, SM28).
  const enablePanelMatch = /\bfn\s+enable_panel\s*\([^)]*\)/.exec(clean);
  if (enablePanelMatch && /\bgrants\b/.test(clean)) {
    const fnBody = extractBraceBlock(clean, enablePanelMatch.index);
    const checksGrants = /\b(?:self\.grants|granted_caps|MissingCapability|ensure_required_capabilities|required_capabilities)\b/.test(fnBody);
    if (!checksGrants) {
      findings.push({
        ruleId: 'rust-panel-enable-ignores-grants',
        mechanism: 'SM28-plugin-grant-rollback-lease',
        language: 'rust',
        line: lineOfIndex(clean, enablePanelMatch.index),
        message: 'PanelPluginHost::enable_panel activates panel contribution without enforcing required capability grants from self.grants (decorative grant bypass, ADV-L4, SM28).',
      });
    }
  }
  const setGrantsMatch = /\bfn\s+set_project_grants\s*\([^)]*\)/.exec(clean);
  if (setGrantsMatch && !findings.some((f) => f.ruleId === 'rust-panel-enable-ignores-grants')) {
    const fnBody = extractBraceBlock(clean, setGrantsMatch.index);
    const insertsGrants = /\bself\.grants\.insert\s*\(/.test(fnBody);
    const validatesAndCloses =
      /\b(?:has_capability|capabilities\s*\(\s*\)|InvalidDeclaration)\b/.test(fnBody) &&
      /\b(?:active_by_key|activations|close_revoked\w*|revoke_active\w*|closed\s*=\s*true)\b/.test(fnBody);
    if (insertsGrants && !validatesAndCloses) {
      findings.push({
        ruleId: 'rust-panel-enable-ignores-grants',
        mechanism: 'SM28-plugin-grant-rollback-lease',
        language: 'rust',
        line: lineOfIndex(clean, setGrantsMatch.index),
        message: 'PanelPluginHost::set_project_grants stores capability grants without validating declared capabilities and atomically closing active generations on revocation (ADV-L4, SM28).',
      });
    }
  }

  // 38. Rust PanelPluginHost::install blindly overwrites installed releases without anti-rollback & publisher continuity (ADV-L4, SM28).
  const panelInstallMatch = /\bfn\s+install\s*\([^)]*SignedPanelRelease/.exec(clean);
  if (panelInstallMatch) {
    const fnBody = extractBraceBlock(clean, panelInstallMatch.index);
    const overwritesRelease = /\bself\.releases\.insert\s*\(/.test(fnBody);
    const guardsRollbackAndPublisher =
      /\b(?:version\s*\(\s*\)|ConflictingRelease)\b/.test(fnBody) &&
      /\b(?:publisher|attestation\s*\(\s*\))\b/.test(fnBody);
    if (overwritesRelease && !guardsRollbackAndPublisher) {
      findings.push({
        ruleId: 'rust-panel-install-blind-overwrite-no-antirollback',
        mechanism: 'SM28-plugin-grant-rollback-lease',
        language: 'rust',
        line: lineOfIndex(clean, panelInstallMatch.index),
        message: 'PanelPluginHost::install blindly overwrites self.releases without checking monotonic version anti-rollback and publisher continuity (ADV-L4, SM28).',
      });
    }
  }

  // 39. Rust UnifiedPanelManifest::validate omits entry_path confinement check while PanelDescriptor defines entry_path (ADV-L4, SM28).
  const unifiedManifestValidateMatch = /\bimpl\s+UnifiedPanelManifest\b[\s\S]{0,120}\bfn\s+validate\s*\(\s*&self\s*\)/.exec(clean);
  if (unifiedManifestValidateMatch && /\bentry_path\b/.test(clean)) {
    const fnBody = extractBraceBlock(clean, unifiedManifestValidateMatch.index + unifiedManifestValidateMatch[0].length - 1);
    const validatesEntryPath = /\b(?:entry_path|validate_confined_entry_path|is_confined_entry_path)\b/.test(fnBody);
    if (!validatesEntryPath) {
      findings.push({
        ruleId: 'rust-panel-manifest-unvalidated-entry-path',
        mechanism: 'SM28-plugin-grant-rollback-lease',
        language: 'rust',
        line: lineOfIndex(clean, unifiedManifestValidateMatch.index),
        message: 'UnifiedPanelManifest::validate omits entry_path traversal/absolute-path confinement validation, admitting signed traversal paths like ../../etc/passwd (ADV-L4, SM28).',
      });
    }
  }

  // 40. Rust device bridge accepts forged lease_id in update_device_capabilities or omits E-Stop gate on ApprovalGateService / open_device_channel (ADV-L4, SM28).
  const updateDevCapsMatch = /\bfn\s+update_device_capabilities\s*\([^)]*\)/.exec(clean);
  if (updateDevCapsMatch) {
    const fnBody = extractBraceBlock(clean, updateDevCapsMatch.index);
    const insertsCaps = /\bself\.device_capabilities\.insert\s*\(/.test(fnBody);
    const checksBoundLease = /\b(?:active_leases|lease_to_device|registered_leases)\b/.test(fnBody);
    if (insertsCaps && !checksBoundLease) {
      findings.push({
        ruleId: 'rust-device-channel-forged-lease-or-estop-bypass',
        mechanism: 'SM28-plugin-grant-rollback-lease',
        language: 'rust',
        line: lineOfIndex(clean, updateDevCapsMatch.index),
        message: 'update_device_capabilities inserts unverified lease_id directly into device_capabilities without registered active_leases lookup, enabling forged-lease eviction DoS (ADV-L4, SM28).',
      });
    }
  }
  if (!findings.some((f) => f.ruleId === 'rust-device-channel-forged-lease-or-estop-bypass')) {
    const isGateOrDeviceService = /\bimpl(?:<[^>]+>)?\s+(?:ApprovalGateService|DeviceBridgeService)\s+for\s+MyGoBridgeHost\b/.test(clean);
    if (isGateOrDeviceService) {
      const gateDeviceRpcs = [
        /\basync\s+fn\s+submit_tool_review_decision\s*\(/g,
        /\basync\s+fn\s+submit_graph_human_decision\s*\(/g,
        /\basync\s+fn\s+open_device_channel\s*\(/g,
      ];
      for (const re of gateDeviceRpcs) {
        let m: RegExpExecArray | null;
        while ((m = re.exec(clean)) !== null) {
          const fnBody = extractBraceBlock(clean, m.index);
          const checksAuth = /\bself\.check_auth\s*\(/.test(fnBody);
          const checksGov = /\b(?:ensure_governance_live|check_governance_admitted|governance_gate)\b/.test(fnBody);
          if (checksAuth && !checksGov) {
            findings.push({
              ruleId: 'rust-device-channel-forged-lease-or-estop-bypass',
              mechanism: 'SM28-plugin-grant-rollback-lease',
              language: 'rust',
              line: lineOfIndex(clean, m.index),
              message: 'ApprovalGateService / DeviceBridgeService RPC checks Bearer auth but omits fail-closed ensure_governance_live E-Stop enforcement before dispatching device/gate actions (ADV-L4, SM28).',
            });
            break;
          }
        }
        if (findings.some((f) => f.ruleId === 'rust-device-channel-forged-lease-or-estop-bypass')) break;
      }
    }
  }

  // 41. Rust find_idempotent_action matches idempotency_key without verifying exact action_name & args_digest (ADV-L4, SM28).
  const findIdemMatch = /\bfn\s+find_idempotent_action\s*\([^)]*\)/.exec(clean);
  if (findIdemMatch) {
    const fnBody = extractBraceBlock(clean, findIdemMatch.index);
    const checksKey = /\bidempotency_key\b/.test(fnBody);
    const checksPayload = /\baction_name\b/.test(fnBody) && /\b(?:args_digest|payload_digest)\b/.test(fnBody);
    if (checksKey && !checksPayload) {
      findings.push({
        ruleId: 'rust-idempotency-replay-ignores-payload-digest',
        mechanism: 'SM28-plugin-grant-rollback-lease',
        language: 'rust',
        line: lineOfIndex(clean, findIdemMatch.index),
        message: 'find_idempotent_action matches only idempotency_key without verifying action_name and args_digest, silently returning stale receipts on conflicting replay payloads (ADV-L4, SM28).',
      });
    }
  }

  // 42. Rust CompiledCedarPolicy::matches evaluates `unless_clauses` with `!= Some(false)` unconditionally,
  //     making `forbid ... unless` fail OPEN when a required exemption context key is missing (None) (ADV-L4, SM29).
  const cedarMatchesMatch = /\bfn\s+matches\s*\(\s*&self\s*,\s*\w+\s*:\s*&CedarEvaluationRequest\s*\)/.exec(clean);
  if (cedarMatchesMatch) {
    const fnBody = extractBraceBlock(clean, cedarMatchesMatch.index);
    const hasUnlessLoop = /\bunless_clauses\b[\s\S]{0,220}\beval_condition_block\s*\([^)]*\)\s*!=\s*Some\s*\(\s*false\s*\)/.test(fnBody);
    const handlesForbidStrict =
      /\bCedarEffect::Forbid\b/.test(fnBody) &&
      /\beval_condition_block\s*\([^)]*\)\s*==\s*Some\s*\(\s*true\s*\)/.test(fnBody);
    if (hasUnlessLoop && !handlesForbidStrict) {
      findings.push({
        ruleId: 'rust-cedar-forbid-unless-missing-key-failopen',
        mechanism: 'SM29-governance-policy-latch-antirollback',
        language: 'rust',
        line: lineOfIndex(clean, cedarMatchesMatch.index),
        message: 'CompiledCedarPolicy::matches evaluates unless_clauses with != Some(false) for all effects, silently waiving forbid policies when a context key is missing (None -> fail-open, ADV-L4, SM29).',
      });
    }
  }

  // 43. Rust rearm_by_verified_human clears retracted_derivations, resurrecting invalidated Bi-Temporal TM conclusions (ADV-L4, SM29).
  const rearmHumanMatch = /\bfn\s+rearm_by_verified_human\s*\([^)]*\)/.exec(clean);
  if (rearmHumanMatch) {
    const fnBody = extractBraceBlock(clean, rearmHumanMatch.index);
    if (/\bretracted_(?:derivations|conclusions)\s*\.\s*clear\s*\(\s*\)/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-governance-rearm-clears-retracted-derivations',
        mechanism: 'SM29-governance-policy-latch-antirollback',
        language: 'rust',
        line: lineOfIndex(clean, rearmHumanMatch.index),
        message: 'rearm_by_verified_human clears retracted_derivations, allowing permanently invalidated Bi-Temporal Truth Maintenance derivations to be resurrected after re-arm (ADV-L4, SM29).',
      });
    }
  }

  // 44. Rust synchronize_proof_envelope checks only revocation_epoch < floor without rejecting same-epoch policy_revision rollback (ADV-L4, SM29).
  const syncProofMatch = /\bfn\s+synchronize_proof_envelope\s*\([^)]*\)/.exec(clean);
  if (syncProofMatch) {
    const fnBody = extractBraceBlock(clean, syncProofMatch.index);
    const assignsRevision = /\bpolicy_revision\s*=\s*envelope\.policy_revision\b/.test(fnBody);
    const checksRevisionRollback = /\benvelope\.policy_revision\s*<\s*\w+\.policy_revision\b/.test(fnBody);
    if (assignsRevision && !checksRevisionRollback) {
      findings.push({
        ruleId: 'rust-governance-sync-ignores-same-epoch-revision-rollback',
        mechanism: 'SM29-governance-policy-latch-antirollback',
        language: 'rust',
        line: lineOfIndex(clean, syncProofMatch.index),
        message: 'synchronize_proof_envelope overwrites policy_revision and fences without rejecting same-epoch lower policy_revision replays, enabling rollback of ASCENT fences and Cedar forbids (ADV-L4, SM29).',
      });
    }
  }

  // 45. Rust ExecutionCircuitBreaker::restore_durable_state allows same-epoch pre-trip replay to clear active E-Stop latch (ADV-L4, SM29).
  const restoreDurableMatch = /\bfn\s+restore_durable_state\s*\([^)]*\)/.exec(clean);
  if (restoreDurableMatch) {
    const fnBody = extractBraceBlock(clean, restoreDurableMatch.index);
    const overwritesTripped = /\b\w+\.tripped\s*=\s*tripped\s*;/.test(fnBody);
    const blocksSameEpochUntrip =
      /\btrip_epoch\s*==\s*\w+\.trip_epoch\b[\s\S]{0,120}\b\w+\.tripped\b[\s\S]{0,80}!\s*tripped\b/.test(fnBody);
    if (overwritesTripped && !blocksSameEpochUntrip) {
      findings.push({
        ruleId: 'rust-breaker-restore-untrips-same-epoch-estop',
        mechanism: 'SM29-governance-policy-latch-antirollback',
        language: 'rust',
        line: lineOfIndex(clean, restoreDurableMatch.index),
        message: 'restore_durable_state overwrites guard.tripped without forbidding same-epoch (trip_epoch == guard.trip_epoch) pre-trip checkpoints from silently clearing an active E-Stop latch (ADV-L4, SM29).',
      });
    }
  }

  // 46. Rust durable checkpoint from_canonical_bytes compares SHA-256 integrity tag via non-constant-time `!=` (ADV-L4, SM29).
  const fromCanonicalMatch = /\bfn\s+from_canonical_bytes\s*\([^)]*\)/.exec(clean);
  if (fromCanonicalMatch) {
    const fnBody = extractBraceBlock(clean, fromCanonicalMatch.index);
    const usesSha256 = /\b(?:governance_)?sha256_bytes\s*\(/.test(fnBody);
    const shortCircuitTagCmp = /\bif\s+(?:tag\s*!=\s*(?:expected_tag|expected)|(?:expected_tag|expected)\s*!=\s*tag)\b/.test(fnBody);
    if (usesSha256 && shortCircuitTagCmp) {
      const isFactStore = /\bGovernanceFactStore\b/.test(clean) && !/\bGovernanceDurableCheckpoint\b/.test(clean);
      findings.push({
        ruleId: isFactStore
          ? 'rust-fact-store-unbounded-mutate-or-timing-tag'
          : 'rust-checkpoint-sha256-non-constant-time-tag',
        mechanism: isFactStore
          ? 'SM30-stepup-attestation-host-effect'
          : 'SM29-governance-policy-latch-antirollback',
        language: 'rust',
        line: lineOfIndex(clean, fromCanonicalMatch.index),
        message: isFactStore
          ? 'GovernanceFactStore::from_canonical_bytes verifies MGF1 SHA-256 tag via short-circuit `!=` instead of constant-time comparison (ADV-L4, SM30).'
          : 'from_canonical_bytes verifies durable checkpoint SHA-256 integrity tag using short-circuit `!=` instead of constant-time full-length byte comparison (ADV-L4, SM29).',
      });
    }
  }

  // 47. Rust parse_verified_step_up_actor accepts weak arbitrary acr= strings or omits worker/scheme-sandbox agent prefixes (ADV-L4, SM30).
  const stepUpMatch = /\bfn\s+parse_verified_step_up_actor\s*\([^)]*\)/.exec(clean);
  if (stepUpMatch) {
    const fnBody = extractBraceBlock(clean, stepUpMatch.index);
    const checksMfaAllowlist = /\b(?:is_verified_mfa_acr|urn:ietf:params:oauth:acr:mfa)\b/.test(fnBody);
    const checksWorkerPrefix = /\b(?:infer_actor_roles|worker)\b/.test(fnBody);
    if (!checksMfaAllowlist || !checksWorkerPrefix) {
      findings.push({
        ruleId: 'rust-stepup-actor-weak-acr-or-prefix-gap',
        mechanism: 'SM30-stepup-attestation-host-effect',
        language: 'rust',
        line: lineOfIndex(clean, stepUpMatch.index),
        message: 'parse_verified_step_up_actor accepts arbitrary non-empty acr= strings or omits worker/scheme-sandbox non-human prefixes, enabling spoofed E-Stop re-arm (ADV-L4, SM30).',
      });
    }
  }

  // 48. Rust run_one_atomic_effect leaves SchemeAtomicEffect::LlmComplete ungated under E-Stop or CasPut unprotected on reserved governance keys (ADV-L4, SM30).
  const runAtomicMatch = /\basync\s+fn\s+run_one_atomic_effect\s*\([^)]*\)/.exec(clean);
  if (runAtomicMatch) {
    const fnBody = extractBraceBlock(clean, runAtomicMatch.index);
    const hasLlmArm = /\bSchemeAtomicEffect::LlmComplete\b/.test(fnBody);
    const hasCasPutArm = /\bSchemeAtomicEffect::CasPut\b/.test(fnBody);
    const gatesLlm = /\bauthorize_llm_effect\b/.test(fnBody);
    const guardsReservedCas = /\bis_reserved_governance_cas_key\b/.test(fnBody);
    if ((hasLlmArm && !gatesLlm) || (hasCasPutArm && !guardsReservedCas)) {
      findings.push({
        ruleId: 'rust-scheme-effect-llm-or-cas-ungated',
        mechanism: 'SM30-stepup-attestation-host-effect',
        language: 'rust',
        line: lineOfIndex(clean, runAtomicMatch.index),
        message: 'run_one_atomic_effect dispatches LlmComplete without E-Stop governance mediation or permits CasPut to overwrite reserved governance checkpoint keys (ADV-L4, SM30).',
      });
    }
  }

  // 49. Rust gate_watcher / ui_cmd_watcher breaks permanently on broadcast RecvError::Lagged via `Err(_) => break` (ADV-L4, SM30).
  const broadcastWatcherRe = /\b(?:gate_rx|ui_cmd_rx)\s*\.\s*recv\s*\(\s*\)\s*=>\s*match\s+\w+\s*\{[\s\S]{0,160}Err\s*\(\s*_\s*\)\s*=>\s*break\b/g;
  const watcherLagMatch = broadcastWatcherRe.exec(clean);
  if (watcherLagMatch) {
    findings.push({
      ruleId: 'rust-broadcast-watcher-breaks-on-lag',
      mechanism: 'SM30-stepup-attestation-host-effect',
      language: 'rust',
      line: lineOfIndex(clean, watcherLagMatch.index),
      message: 'Control-plane broadcast watcher (gate_rx / ui_cmd_rx) matches `Err(_) => break`, permanently killing E-Stop & Step-Up Re-Arm handling on RecvError::Lagged (ADV-L4, SM30).',
    });
  }

  // 50. Rust mutate_facts_and_build_request inserts unboundedly into GovernanceFactStore past MGF1 4096-entry deserialization cap (ADV-L4, SM30).
  const mutateFactsMatch = /\bfn\s+mutate_facts_and_build_request\s*\([^)]*\)/.exec(clean);
  if (mutateFactsMatch && !findings.some((f) => f.ruleId === 'rust-fact-store-unbounded-mutate-or-timing-tag')) {
    const fnBody = extractBraceBlock(clean, mutateFactsMatch.index);
    const insertsFacts = /\bmeta\.facts\.\w+\.insert\s*\(/.test(fnBody);
    const enforcesCap = /\b(?:MAX_FACT_STORE_ENTRIES|ensure_fact_capacity|check_fact_capacity)\b/.test(fnBody);
    if (insertsFacts && !enforcesCap) {
      findings.push({
        ruleId: 'rust-fact-store-unbounded-mutate-or-timing-tag',
        mechanism: 'SM30-stepup-attestation-host-effect',
        language: 'rust',
        line: lineOfIndex(clean, mutateFactsMatch.index),
        message: 'mutate_facts_and_build_request inserts into GovernanceFactStore without enforcing MGF1 deserialization capacity cap (4096), enabling self-inflicted restart deserialization bombs (ADV-L4, SM30).',
      });
    }
  }

  // 51. Rust handle_claimed_gate_decision_durable silently swallows persist_to_cas error with `let _ =` after re-arm (ADV-L4, SM30).
  const handleDurableGateMatch = /\basync\s+fn\s+handle_claimed_gate_decision_durable\s*(?:<[^>]+>)?\s*\([^)]*\)/.exec(clean);
  if (handleDurableGateMatch) {
    const fnBody = extractBraceBlock(clean, handleDurableGateMatch.index);
    if (/\blet\s+_\s*=\s*self\.persist_to_cas\s*\(/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-rearm-cas-persist-error-swallowed',
        mechanism: 'SM30-stepup-attestation-host-effect',
        language: 'rust',
        line: lineOfIndex(clean, handleDurableGateMatch.index),
        message: 'handle_claimed_gate_decision_durable silently swallows persist_to_cas errors via `let _ =` after re-arming, desynchronizing live armed state from durable Turso CAS WAL (ADV-L4, SM30).',
      });
    }
  }

  // 52. Rust validated storage/session newtypes deriving Serde `Deserialize` directly bypass `::new()`/`try_new()` bounds & non-blank checks (ADV-L4, SM31).
  const serdeNewtypeRe = /#\[derive\([^\]]*\bDeserialize\b[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*pub\s+struct\s+(StoragePageLimit|SessionId|\$name)\s*\(\s*(?:u16|String)\s*\)\s*;/g;
  let serdeNewtypeMatch: RegExpExecArray | null;
  while ((serdeNewtypeMatch = serdeNewtypeRe.exec(clean)) !== null) {
    const attrSlice = serdeNewtypeMatch[0];
    if (
      serdeNewtypeMatch[1] === '$name' &&
      !/(?:Result\s*<\s*Self|Option\s*<\s*Self|trim\s*\(\s*\)\s*\.\s*is_empty|\btry_new\b)/.test(
        clean.slice(serdeNewtypeMatch.index, serdeNewtypeMatch.index + 600),
      )
    ) {
      continue;
    }
    if (!/#\[serde\([^)]*\b(?:try_from|deserialize_with)\b/.test(attrSlice)) {
      findings.push({
        ruleId: 'rust-serde-derive-bypasses-validated-newtype',
        mechanism: 'SM31-storage-boundary-integrity-sync',
        language: 'rust',
        line: lineOfIndex(clean, serdeNewtypeMatch.index),
        message: `Validated storage/session newtype ${serdeNewtypeMatch[1]} derives Serde Deserialize directly without try_from/custom validation, allowing 0/65535 page limits or empty/blank IDs to bypass ::new() invariants (ADV-L4, SM31).`,
      });
    }
  }

  // 53. Rust put_artifact inserts record.body without validating size_bytes == body.len() and cryptographic sha256:<64-hex> binding (ADV-L4, SM31).
  const putArtifactMatch = /\bfn\s+put_artifact\s*(?:<[^>]+>)?\s*\([^)]*\)/.exec(clean);
  if (putArtifactMatch) {
    const fnBody = extractBraceBlock(clean, putArtifactMatch.index);
    const hasRecordImpl = /\b(?:INSERT\s+OR\s+IGNORE\s+INTO\s+artifacts|state\.artifacts\.insert)\b/.test(fnBody);
    const validatesArtifact = /\b(?:validate_artifact_record|record\.size_bytes\s*!=\s*record\.body\.len\(\))\b/.test(fnBody);
    if (hasRecordImpl && !validatesArtifact) {
      findings.push({
        ruleId: 'rust-put-artifact-unchecked-size-or-digest',
        mechanism: 'SM31-storage-boundary-integrity-sync',
        language: 'rust',
        line: lineOfIndex(clean, putArtifactMatch.index),
        message: 'put_artifact stores artifacts without verifying size_bytes == body.len() (i64 wrap hazard) and cryptographic sha256:<64-hex> payload integrity (ADV-L4, SM31).',
      });
    }
  }

  // 54. Rust TursoSyncRemoteUrl::new admits arbitrary remote cleartext http:// URLs or omits userinfo/CRLF refusal (ADV-L4, SM31).
  const syncUrlImplMatch = /\bimpl\s+TursoSyncRemoteUrl\b/.exec(clean);
  if (syncUrlImplMatch) {
    const implBody = extractBraceBlock(clean, syncUrlImplMatch.index);
    const allowsHttp = /starts_with\s*\(\s*"http:\/\/"\s*\)/.test(implBody);
    const enforcesLoopbackAndAuthority = /\b(?:is_loopback_sync_host|localhost|127\.0\.0\.1)\b/.test(implBody) && /@/.test(implBody);
    if (allowsHttp && !enforcesLoopbackAndAuthority) {
      findings.push({
        ruleId: 'rust-sync-remote-url-admits-cleartext-http',
        mechanism: 'SM31-storage-boundary-integrity-sync',
        language: 'rust',
        line: lineOfIndex(clean, syncUrlImplMatch.index),
        message: 'TursoSyncRemoteUrl::new accepts remote cleartext http:// URLs or fails to block embedded @ userinfo / CRLF smuggling carrying TursoSyncAuthToken (ADV-L4, SM31).',
      });
    }
  }

  // 55. Rust TursoContextIndex::rebuild overwrites already-applied context_locators on matching same-revision receipt instead of verifying immutability (ADV-L4, SM31).
  const rebuildMatch = /\basync\s+fn\s+rebuild\s*\([^)]*\)/.exec(clean);
  if (rebuildMatch) {
    const fnBody = extractBraceBlock(clean, rebuildMatch.index);
    const deletesLocators = /DELETE\s+FROM\s+context_locators\s+WHERE\s+repo/.test(fnBody);
    const checksFinalizedReplay = /\bContextIndexUpdate::Replayed\b/.test(fnBody);
    if (deletesLocators && !checksFinalizedReplay) {
      findings.push({
        ruleId: 'rust-context-index-rebuild-overwrites-applied-rev',
        mechanism: 'SM31-storage-boundary-integrity-sync',
        language: 'rust',
        line: lineOfIndex(clean, rebuildMatch.index),
        message: 'TursoContextIndex::rebuild deletes and overwrites context_locators when re-invoked at an already-finalized (sequence, receipt) instead of enforcing Replayed vs. Conflict immutability (ADV-L4, SM31).',
      });
    }
  }

  // 56. Rust compare_and_swap_artifact_pointer calls non-idempotent insert_visibility_receipt, crashing conflict retries and split-braining committed pointers on PK collision (ADV-L4, SM31).
  const casPtrMatch = /\bfn\s+compare_and_swap_artifact_pointer\s*(?:<[^>]+>)?\s*\([^)]*\)/.exec(clean);
  if (casPtrMatch) {
    const fnBody = extractBraceBlock(clean, casPtrMatch.index);
    if (/\binsert_visibility_receipt\s*\(/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-cas-pointer-non-idempotent-audit-receipt',
        mechanism: 'SM31-storage-boundary-integrity-sync',
        language: 'rust',
        line: lineOfIndex(clean, casPtrMatch.index),
        message: 'compare_and_swap_artifact_pointer uses non-idempotent insert_visibility_receipt with deterministic receipt_id, crashing repeated conflict retries with UNIQUE errors and split-braining committed pointers (ADV-L4, SM31).',
      });
    }
  }

  // 57. Rust GIT_REPOSITORY_OVERRIDES omits GIT_CONFIG_GLOBAL, GIT_EXEC_PATH, or GIT_SSH_COMMAND, allowing ambient env command execution & URL hijack (ADV-L4, SM32).
  const gitOverridesMatch = /\bpub\s+const\s+GIT_REPOSITORY_OVERRIDES\s*:\s*&\s*\[\s*&str\s*\]\s*=\s*&\[[\s\S]*?\];/.exec(clean);
  if (gitOverridesMatch) {
    const block = gitOverridesMatch[0];
    if (
      !block.includes('"GIT_CONFIG_GLOBAL"') ||
      !block.includes('"GIT_EXEC_PATH"') ||
      !block.includes('"GIT_SSH_COMMAND"')
    ) {
      findings.push({
        ruleId: 'rust-gitops-incomplete-env-override-strip',
        mechanism: 'SM32-gitops-subprocess-confinement',
        language: 'rust',
        line: lineOfIndex(clean, gitOverridesMatch.index),
        message: 'GIT_REPOSITORY_OVERRIDES omits GIT_CONFIG_GLOBAL, GIT_EXEC_PATH, or GIT_SSH_COMMAND, letting ambient Git config/exec overrides hijack GitOps subprocesses (ADV-L4, SM32).',
      });
    }
  }

  // 58. Rust ProcessWorkingCopyCommandRunner omits core.fsmonitor=false / DISABLED_FSMONITOR lockdown across Git and Worktrunk subprocesses (ADV-L4, SM32).
  const wcRunnerImplMatch = /\bimpl\s+WorkingCopyCommandRunner\s+for\s+ProcessWorkingCopyCommandRunner\b/.exec(clean);
  if (wcRunnerImplMatch) {
    const implBody = extractBraceBlock(clean, wcRunnerImplMatch.index);
    if (!/\b(?:DISABLED_FSMONITOR|core\.fsmonitor=false)\b/.test(implBody)) {
      findings.push({
        ruleId: 'rust-gitops-provider-missing-fsmonitor-lockdown',
        mechanism: 'SM32-gitops-subprocess-confinement',
        language: 'rust',
        line: lineOfIndex(clean, wcRunnerImplMatch.index),
        message: 'ProcessWorkingCopyCommandRunner omits core.fsmonitor=false / DISABLED_FSMONITOR lockdown, allowing hostile repository .git/config fsmonitor commands to execute during worktree operations (ADV-L4, SM32).',
      });
    }
  }

  // 59. Rust working-copy command projection accepts unvalidated dash-prefixed branch/id targets OR retention plan_sweep joins unsanitized working_copy.id into snapshot_root (ADV-L4, SM32).
  const wtSwitchMatch = /\bfn\s+worktrunk_switch\s*\([^)]*\)/.exec(clean);
  if (wtSwitchMatch) {
    const fnBody = extractBraceBlock(clean, wtSwitchMatch.index);
    const pushesRawTarget = /branch_or_id_target\s*\(\s*working_copy\s*\)/.test(fnBody);
    const validatesArg = /\b(?:validate_branch_or_id_target|validate_working_copy_target|validate_branch_name|validate_base_ref)\s*\(/.test(fnBody);
    if (pushesRawTarget && !validatesArg) {
      findings.push({
        ruleId: 'rust-gitops-unvalidated-projection-arg-or-snapshot-path',
        mechanism: 'SM32-gitops-subprocess-confinement',
        language: 'rust',
        line: lineOfIndex(clean, wtSwitchMatch.index),
        message: 'worktrunk_switch projects branch_or_id_target without rejecting leading "-" CLI option injection or control characters (ADV-L4, SM32).',
      });
    }
  }
  const planSweepMatch = /\bpub\s+fn\s+plan_sweep\s*\([^)]*\)/.exec(clean);
  if (planSweepMatch) {
    const fnBody = extractBraceBlock(clean, planSweepMatch.index);
    const rawSnapshotJoin = /snapshot_root\.join\s*\(\s*format!\s*\(\s*"\{\}\.patch"\s*,\s*working_copy\.id\.as_str\(\)\s*\)\s*\)/.test(fnBody);
    const validatesSnapshotId = /\b(?:confined_snapshot_path|is_safe_snapshot_stem|validate_snapshot_id)\s*\(/.test(fnBody);
    if (rawSnapshotJoin && !validatesSnapshotId) {
      findings.push({
        ruleId: 'rust-gitops-unvalidated-projection-arg-or-snapshot-path',
        mechanism: 'SM32-gitops-subprocess-confinement',
        language: 'rust',
        line: lineOfIndex(clean, planSweepMatch.index),
        message: 'WorkingCopyRetentionPolicy::plan_sweep joins unsanitized working_copy.id into snapshot_root, enabling ../../ and absolute path traversal escapes (ADV-L4, SM32).',
      });
    }
  }

  // 60. Rust working-copy provider runner/probe calls unbounded .output().await without timeout, stdout/stderr byte cap, or kill_on_drop(true) (ADV-L4, SM32).
  const providerImplRe = /\bimpl(?:\s+WorkingCopyCommandRunner\s+for)?\s+(?:ProcessWorkingCopyCommandRunner|WorkingCopyProviderExecutableProbeCommand)\b/g;
  let providerImplMatch: RegExpExecArray | null;
  while ((providerImplMatch = providerImplRe.exec(clean)) !== null) {
    const implBody = extractBraceBlock(clean, providerImplMatch.index);
    const rawOutputMatch = /\.output\s*\(\s*\)\s*\.await\b/.exec(implBody);
    if (rawOutputMatch) {
      findings.push({
        ruleId: 'rust-gitops-unbounded-provider-output-no-kill-on-drop',
        mechanism: 'SM32-gitops-subprocess-confinement',
        language: 'rust',
        line: lineOfIndex(clean, providerImplMatch.index + rawOutputMatch.index),
        message: 'Working-copy provider subprocess calls unbounded .output().await without execution timeout, stdout/stderr byte cap, stdin(Stdio::null()), or kill_on_drop(true) (ADV-L4, SM32).',
      });
    }
  }

  // 61. Rust JoinSet::join_next() panic propagation via .expect()/.unwrap() crashes parallel GitOps coordinator instead of isolating failed workers into rejected receipts (ADV-L4, SM32).
  const joinNextMatch = /\bJoinSet\b/.test(clean)
    ? /(?:joined\s*\.\s*(?:expect|unwrap)\s*\(|\.\s*join_next\s*\(\s*\)\s*\.await[\s\S]{0,120}\.\s*(?:expect|unwrap)\s*\()/.exec(clean)
    : null;
  if (joinNextMatch) {
    findings.push({
      ruleId: 'rust-gitops-joinset-worker-panic-expect',
      mechanism: 'SM32-gitops-subprocess-confinement',
      language: 'rust',
      line: lineOfIndex(clean, joinNextMatch.index),
      message: 'JoinSet::join_next() calls .expect()/.unwrap() on JoinError, crashing the parallel coordinator when a worker panics instead of emitting a rejected receipt via join_next_with_id() (ADV-L4, SM32).',
    });
  }

  // 62. Rust HookConfigurationEnvelope / HookPolicyConfiguration omits deny_unknown_fields on fail-open ObserveOnly TOML default or reads TOML unboundedly (ADV-L4, SM33).
  const hookCfgStructRe = /#\[serde\([^\]]*\bdefault\b[^\]]*\)\]\s*pub\s+struct\s+(HookConfigurationEnvelope|HookPolicyConfiguration|HookRegistrationDefaults)\b/g;
  let hookCfgMatch: RegExpExecArray | null;
  while ((hookCfgMatch = hookCfgStructRe.exec(clean)) !== null) {
    if (!/\bdeny_unknown_fields\b/.test(hookCfgMatch[0])) {
      findings.push({
        ruleId: 'rust-hook-config-failopen-unknown-fields',
        mechanism: 'SM33-hook-policy-protocol-confinement',
        language: 'rust',
        line: lineOfIndex(clean, hookCfgMatch.index),
        message: `${hookCfgMatch[1]} uses #[serde(default)] without deny_unknown_fields, letting unknown/misspelled TOML keys silently fall back to ObserveOnly (ADV-L4, SM33).`,
      });
    }
  }

  // 63. Rust HookRegistry::register pushes duplicate hook_id entries leaving sticky ghost hooks after disable/unregister, OR run_permitted_hook_registrations spawns unbounded Async hooks (ADV-L4, SM33).
  const hookRegImplMatch = /\bimpl\s+HookRegistry\b/.exec(clean);
  if (hookRegImplMatch) {
    const implBody = extractBraceBlock(clean, hookRegImplMatch.index);
    const registerMatch = /\bpub\s+fn\s+register\s*\([^)]*\)/.exec(implBody);
    if (registerMatch) {
      const fnBody = extractBraceBlock(implBody, registerMatch.index);
      const pushes = /self\.registrations\s*\.push\s*\(\s*registration\s*\)/.test(fnBody);
      const deduplicates = /self\.registrations\s*\.retain\s*\(/.test(fnBody);
      if (pushes && !deduplicates) {
        findings.push({
          ruleId: 'rust-hook-registry-duplicate-shadow-or-unbounded-async',
          mechanism: 'SM33-hook-policy-protocol-confinement',
          language: 'rust',
          line: lineOfIndex(clean, hookRegImplMatch.index + registerMatch.index),
          message: 'HookRegistry::register pushes duplicate hook_id entries without deduplicating existing IDs, leaving shadow ghost hooks executing after set_enabled(false) or unregister (ADV-L4, SM33).',
        });
      }
    }
  }
  const runHooksMatch = /\basync\s+fn\s+run_permitted_hook_registrations\s*\([^)]*\)/.exec(clean);
  if (runHooksMatch) {
    const fnBody = extractBraceBlock(clean, runHooksMatch.index);
    if (
      /HookExecutionMode::Async/.test(fnBody) &&
      !/\b(?:Semaphore|MAX_CONCURRENT_ASYNC_HOOKS)\b/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-hook-registry-duplicate-shadow-or-unbounded-async',
        mechanism: 'SM33-hook-policy-protocol-confinement',
        language: 'rust',
        line: lineOfIndex(clean, runHooksMatch.index),
        message: 'run_permitted_hook_registrations spawns unbounded concurrent HookExecutionMode::Async tasks without a Semaphore concurrency cap (ADV-L4, SM33).',
      });
    }
  }

  // 64. Rust apply_dynamic_decision_action overwrites Rust trust-floor rejection reasons (UntrustedRejected / ModifiedRejected) with ExtensionDeferred / ExtensionRejected (ADV-L4, SM33).
  const dynDecisionMatch = /\bfn\s+apply_dynamic_decision_action\s*\([^)]*\)/.exec(clean);
  if (dynDecisionMatch) {
    const fnBody = extractBraceBlock(clean, dynDecisionMatch.index);
    const mutatesReason = /decision\.reason\s*=/.test(fnBody);
    const preservesTrustFloor = /\b(?:UntrustedRejected|ModifiedRejected|is_trust_floor_rejection)\b/.test(fnBody);
    if (mutatesReason && !preservesTrustFloor) {
      findings.push({
        ruleId: 'rust-hook-dynamic-action-masks-trust-rejection',
        mechanism: 'SM33-hook-policy-protocol-confinement',
        language: 'rust',
        line: lineOfIndex(clean, dynDecisionMatch.index),
        message: 'apply_dynamic_decision_action overwrites UntrustedRejected/ModifiedRejected audit reasons with extension Defer/Deny reasons instead of keeping Rust trust rejections immutable (ADV-L4, SM33).',
      });
    }
  }

  // 65. Rust SubAgentSpawnConfigSet profile validation omits contradictory read_only+workspace_write and zero-budget checks (ADV-L4, SM33).
  const validateProfilesMatch = /\bfn\s+validate_unique_profiles\s*\([^)]*\)/.exec(clean);
  if (validateProfilesMatch) {
    const fnBody = extractBraceBlock(clean, validateProfilesMatch.index);
    const checksContradiction = /\b(?:validate_sub_agent_policy|read_only\s*&&[\s\S]{0,40}workspace_write)\b/.test(fnBody);
    if (!checksContradiction) {
      findings.push({
        ruleId: 'rust-subagent-policy-unchecked-contradiction-or-budget',
        mechanism: 'SM33-hook-policy-protocol-confinement',
        language: 'rust',
        line: lineOfIndex(clean, validateProfilesMatch.index),
        message: 'SubAgentSpawnConfigSet profile validation omits contradictory read_only && workspace_write, zero-budget, and recursive max_depth checks (ADV-L4, SM33).',
      });
    }
  }

  // 66. Rust RuntimeSessionId derives Serde Deserialize bypassing try_new, OR ModelEndpoint::validate_selector_boundaries omits control-char/URL-meta refusal (ADV-L4, SM33).
  const runtimeSessRe = /#\[derive\([^\]]*\bDeserialize\b[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*pub\s+struct\s+RuntimeSessionId\s*\(\s*String\s*\)\s*;/g;
  const runtimeSessMatch = runtimeSessRe.exec(clean);
  if (runtimeSessMatch && !/#\[serde\([^)]*\b(?:try_from|deserialize_with)\b/.test(runtimeSessMatch[0])) {
    findings.push({
      ruleId: 'rust-protocol-session-serde-bypass-or-endpoint-injection',
      mechanism: 'SM33-hook-policy-protocol-confinement',
      language: 'rust',
      line: lineOfIndex(clean, runtimeSessMatch.index),
      message: 'RuntimeSessionId derives Serde Deserialize directly without try_new validation, admitting empty/blank/control-char/traversal session IDs (ADV-L4, SM33).',
    });
  }
  const selectorBoundariesMatch = /\bfn\s+validate_selector_boundaries\s*\([^)]*\)/.exec(clean);
  if (selectorBoundariesMatch) {
    const fnBody = extractBraceBlock(clean, selectorBoundariesMatch.index);
    if (!/\b(?:is_control|has_unsafe_endpoint_chars)\b/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-protocol-session-serde-bypass-or-endpoint-injection',
        mechanism: 'SM33-hook-policy-protocol-confinement',
        language: 'rust',
        line: lineOfIndex(clean, selectorBoundariesMatch.index),
        message: 'ModelEndpoint::validate_selector_boundaries checks only "/" and omits control-character, whitespace, and URL meta-character (?, #, @, \\, ..) injection refusal (ADV-L4, SM33).',
      });
    }
  }

  // 67. Rust apply_direnv_json admits loader hijacks (LD_PRELOAD/DYLD_INSERT_LIBRARIES/BASH_ENV) or denylisted vars, OR direnv_output buffers stdout unboundedly without timeout (ADV-L4, SM34).
  const applyDirenvMatch = /\bfn\s+apply_direnv_json\s*\([^)]*\)/.exec(clean);
  if (applyDirenvMatch) {
    const fnBody = extractBraceBlock(clean, applyDirenvMatch.index);
    if (
      /Value::String/.test(fnBody) &&
      !/\b(?:is_disallowed_direnv_export_key|LD_PRELOAD|DYLD_INSERT_LIBRARIES)\b/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-direnv-export-loader-hijack-or-unbounded-output',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'rust',
        line: lineOfIndex(clean, applyDirenvMatch.index),
        message: 'apply_direnv_json blindly inserts direnv JSON exports without rejecting loader hijacks (LD_PRELOAD/DYLD_INSERT_LIBRARIES/BASH_ENV), shell denylist vars, or malformed env keys/values (ADV-L4, SM34).',
      });
    }
  }
  const direnvOutMatch = /\basync\s+fn\s+direnv_output\s*\([^)]*\)/.exec(clean);
  if (direnvOutMatch) {
    const fnBody = extractBraceBlock(clean, direnvOutMatch.index);
    if (/\.wait_with_output\s*\(\s*\)\s*\.await/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-direnv-export-loader-hijack-or-unbounded-output',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'rust',
        line: lineOfIndex(clean, direnvOutMatch.index),
        message: 'direnv_output calls unbounded child.wait_with_output().await without stdout byte cap or execution timeout (ADV-L4, SM34).',
      });
    }
  }

  // 68. Rust direnv_cwd accepts escaping/symlinked Explicit .envrc paths, OR resolve_sub_agent accepts escaping home_path overrides (ADV-L4, SM34).
  const direnvCwdMatch = /\bfn\s+direnv_cwd\s*\([^)]*\)/.exec(clean);
  if (direnvCwdMatch) {
    const fnBody = extractBraceBlock(clean, direnvCwdMatch.index);
    if (
      /RuntimeEnvrcPolicy::Explicit/.test(fnBody) &&
      !/\b(?:symlink_metadata|confine_explicit_envrc|validate_envrc_file)\b/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-envrc-unconfined-explicit-path-or-subagent-home',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'rust',
        line: lineOfIndex(clean, direnvCwdMatch.index),
        message: 'direnv_cwd accepts RuntimeEnvrcPolicy::Explicit paths without confining to cwd/project root or rejecting symlinked .envrc files (ADV-L4, SM34).',
      });
    }
  }
  const resolveSubAgentMatch = /\bpub\s+fn\s+resolve_sub_agent\s*\([^)]*\)/.exec(clean);
  if (resolveSubAgentMatch) {
    const fnBody = extractBraceBlock(clean, resolveSubAgentMatch.index);
    if (
      /request\.home_path/.test(fnBody) &&
      !/\b(?:validate_child_home_path|UnsafeChildHomePath|Component::ParentDir)\b/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-envrc-unconfined-explicit-path-or-subagent-home',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'rust',
        line: lineOfIndex(clean, resolveSubAgentMatch.index),
        message: 'resolve_sub_agent accepts arbitrary request.home_path overrides without confining child home under parent_home (ADV-L4, SM34).',
      });
    }
  }

  // 69. Rust FileSystemOrgSourceStore reads/writes documents with lexical-only validation without symlink_metadata confinement or document size cap (ADV-L4, SM34).
  const fsOrgStoreImplMatch = /\bimpl\s+OrgSourceStore\s+for\s+FileSystemOrgSourceStore\b/.exec(clean);
  if (fsOrgStoreImplMatch) {
    const implBody = extractBraceBlock(clean, fsOrgStoreImplMatch.index);
    if (
      /fs::read_to_string/.test(implBody) &&
      !/\b(?:verify_confined_no_symlinks|symlink_metadata|MAX_ORG_DOCUMENT_BYTES)\b/.test(implBody)
    ) {
      findings.push({
        ruleId: 'rust-org-store-lexical-only-no-symlink-check',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'rust',
        line: lineOfIndex(clean, fsOrgStoreImplMatch.index),
        message: 'FileSystemOrgSourceStore uses lexical-only path resolution and unbounded fs::read_to_string without symlink confinement, allowing outside-root read/write escapes (ADV-L4, SM34).',
      });
    }
  }

  // 70. Rust OrgGovernanceLedger::register_snapshot permits generation rollback/stale leases, OR SharedContextGovernanceLedger::create_channel resets existing channel epoch/taint (ADV-L4, SM34).
  const regSnapMatch = /\bpub\s+fn\s+register_snapshot\s*\([^)]*\)/.exec(clean);
  if (regSnapMatch) {
    const fnBody = extractBraceBlock(clean, regSnapMatch.index);
    if (
      /self\.sources\.insert\s*\(/.test(fnBody) &&
      !/\b(?:GenerationRollback|existing\.generation\s*>=)\b/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-org-governance-snapshot-rollback-or-channel-reset',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'rust',
        line: lineOfIndex(clean, regSnapMatch.index),
        message: 'OrgGovernanceLedger::register_snapshot overwrites self.sources without rejecting same/lower generation rollbacks or active-lease staleness (ADV-L4, SM34).',
      });
    }
  }
  const createChanMatch = /\bpub\s+fn\s+create_channel\s*(?:<[^>]+>)?\s*\([^)]*\)/.exec(clean);
  if (createChanMatch) {
    const fnBody = extractBraceBlock(clean, createChanMatch.index);
    if (
      /self\.channels\.insert\s*\(/.test(fnBody) &&
      !/self\.channels\s*\.\s*(?:get|contains_key|entry)\s*\(/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-org-governance-snapshot-rollback-or-channel-reset',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'rust',
        line: lineOfIndex(clean, createChanMatch.index),
        message: 'SharedContextGovernanceLedger::create_channel unconditionally overwrites existing channel state, resetting acl_epoch to 1 and wiping tainted=true (ADV-L4, SM34).',
      });
    }
  }

  // 71. Rust assemble_two_zone_gateway_messages compares envelope.kv_prefix_digest without recomputing compute_kv_prefix_digest(&envelope.frozen_prefix) (ADV-L4, SM34).
  const twoZoneMatch = /\bpub\s+fn\s+assemble_two_zone_gateway_messages\s*\([^)]*\)/.exec(clean);
  if (twoZoneMatch) {
    const fnBody = extractBraceBlock(clean, twoZoneMatch.index);
    if (
      /envelope\.kv_prefix_digest/.test(fnBody) &&
      !/compute_kv_prefix_digest\s*\(\s*&envelope\.frozen_prefix\s*\)/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-two-zone-kv-prefix-unverified-content-digest',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'rust',
        line: lineOfIndex(clean, twoZoneMatch.index),
        message: 'assemble_two_zone_gateway_messages trusts envelope.kv_prefix_digest without recomputing compute_kv_prefix_digest(&envelope.frozen_prefix), enabling Zone-1 System prompt injection with a copied digest (ADV-L4, SM34).',
      });
    }
  }

  // 72. Rust sealed AgentGraph witness / FencingEpoch derives Serde Deserialize bypassing admission gates, OR reconcile_marlin_execution_receipt admits Settled on Detached scopes (ADV-L4, SM35).
  const sealedWitnessRe = /#\[derive\([^\]]*\bDeserialize\b[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*pub\s+struct\s+(AdmittedGovernedContext|AdmittedMarlinDispatch|FencingEpoch)\b/g;
  let sealedMatch: RegExpExecArray | null;
  while ((sealedMatch = sealedWitnessRe.exec(clean)) !== null) {
    if (!/#\[serde\([^)]*\b(?:try_from|deserialize_with)\b/.test(sealedMatch[0])) {
      findings.push({
        ruleId: 'rust-graph-witness-serde-bypass-or-detached-settle',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, sealedMatch.index),
        message: `${sealedMatch[1]} derives Serde Deserialize directly without admission validation, allowing forged JSON to bypass fail-closed graph witness and epoch invariants (ADV-L4, SM35).`,
      });
    }
  }
  const reconcileMatch = /\bpub\s+fn\s+reconcile_marlin_execution_receipt\s*\([^)]*\)/.exec(clean);
  if (reconcileMatch) {
    const fnBody = extractBraceBlock(clean, reconcileMatch.index);
    if (
      /ExecutionReceiptStatus::Settled/.test(fnBody) &&
      !/TaskActorScopeMode::Detached/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-graph-witness-serde-bypass-or-detached-settle',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, reconcileMatch.index),
        message: 'reconcile_marlin_execution_receipt settles TaskActorScopeMode::Detached cursors without refusing Detached settlement or checking fencing epoch exhaustion (ADV-L4, SM35).',
      });
    }
  }

  // 73. Rust AgentGraph planning edge_condition_matches unconditionally returns true for PolicyDecision(_), OR policy_scoped_candidate_edges accepts duplicate edge IDs (ADV-L4, SM35).
  const edgeCondMatch = /\bfn\s+edge_condition_matches\s*\([^)]*\)/.exec(clean);
  if (edgeCondMatch) {
    const fnBody = extractBraceBlock(clean, edgeCondMatch.index);
    if (/AgentEdgeCondition::PolicyDecision\s*\(\s*_\s*\)\s*=>\s*true\b/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-graph-planning-policy-decision-bypass-or-dup-edge',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, edgeCondMatch.index),
        message: 'edge_condition_matches returns true unconditionally for AgentEdgeCondition::PolicyDecision(_), admitting policy-gated edges in Deterministic/CapabilityFirst graphs without any policy receipt (ADV-L4, SM35).',
      });
    }
  }
  const policyScopedMatch = /\bfn\s+policy_scoped_candidate_edges\s*\([^)]*\)/.exec(clean);
  if (policyScopedMatch) {
    const fnBody = extractBraceBlock(clean, policyScopedMatch.index);
    if (
      /policy_receipt\.candidate_edges/.test(fnBody) &&
      !/\b(?:seen_edges|HashSet|BTreeSet)\b/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-graph-planning-policy-decision-bypass-or-dup-edge',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, policyScopedMatch.index),
        message: 'policy_scoped_candidate_edges accepts duplicate candidate_edges or PolicyDecision edges lacking GerbilPolicyReceipt evidence (ADV-L4, SM35).',
      });
    }
  }

  // 74. Rust CompiledHarnessGovernanceGate::classify_capability lets caller declared_capability or "search" substring override destructive tool names (ADV-L4, SM35).
  const classifyCapMatch = /\bfn\s+classify_capability\s*\([^)]*\)/.exec(clean);
  if (classifyCapMatch) {
    const fnBody = extractBraceBlock(clean, classifyCapMatch.index);
    const hasDestructiveCheck = /\b(?:is_destructive_tool_name|is_write_tool_name)\b/.test(fnBody);
    if (!hasDestructiveCheck) {
      findings.push({
        ruleId: 'rust-harness-cedar-capability-spoof-or-case-bypass',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, classifyCapMatch.index),
        message: 'classify_capability trusts caller declared_capability or "search" substring before checking destructive tool tokens, letting search_exec/exec_command/rm_file bypass read-only Cedar policies (ADV-L4, SM35).',
      });
    }
  }

  // 75. Rust intent_case_artifact safe_relative_path admits empty/"." paths OR materialized_artifact_path writes without symlink confinement (ADV-L4, SM35).
  const safeRelMatch = /\bfn\s+safe_relative_path\s*\([^)]*\)/.exec(clean);
  if (safeRelMatch) {
    const fnBody = extractBraceBlock(clean, safeRelMatch.index);
    if (!/relative\.as_os_str\(\)\.is_empty\s*\(\s*\)/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-harness-artifact-lexical-only-or-empty-path',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, safeRelMatch.index),
        message: 'safe_relative_path accepts empty or "." relative paths, resolving directly to output_root (ADV-L4, SM35).',
      });
    }
  }
  const matArtMatch = /\bfn\s+materialized_artifact_path\s*\([^)]*\)/.exec(clean);
  if (matArtMatch) {
    const fnBody = extractBraceBlock(clean, matArtMatch.index);
    if (!/\b(?:verify_confined_no_symlinks|symlink_metadata)\b/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-harness-artifact-lexical-only-or-empty-path',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, matArtMatch.index),
        message: 'materialized_artifact_path performs lexical-only path joining without symlink confinement, allowing symlink escapes outside output_root (ADV-L4, SM35).',
      });
    }
  }

  // 76. Rust LiveWeaverTomlConfig::load reads unbounded TOML without symlink check, OR resolve_route_with accepts unsafe ambient credential_env / unbounded timeout_seconds (ADV-L4, SM35).
  const weaverCfgImplMatch = /\bimpl\s+LiveWeaverTomlConfig\b/.exec(clean);
  if (weaverCfgImplMatch) {
    const implBody = extractBraceBlock(clean, weaverCfgImplMatch.index);
    if (
      /fs::read_to_string/.test(implBody) &&
      !/\b(?:MAX_WEAVER_CONFIG_BYTES|symlink_metadata)\b/.test(implBody)
    ) {
      findings.push({
        ruleId: 'rust-weaver-config-unbounded-read-or-unsafe-cred-env',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, weaverCfgImplMatch.index),
        message: 'LiveWeaverTomlConfig::load performs unbounded fs::read_to_string without symlink refusal or size cap (ADV-L4, SM35).',
      });
    }
    if (
      /profile\.credential_env/.test(implBody) &&
      !/\b(?:validate_credential_env_name|is_safe_credential_env)\b/.test(implBody)
    ) {
      findings.push({
        ruleId: 'rust-weaver-config-unbounded-read-or-unsafe-cred-env',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'rust',
        line: lineOfIndex(clean, weaverCfgImplMatch.index),
        message: 'LiveWeaverTomlConfig::resolve_route_with reads profile.credential_env without rejecting ambient system/loader env names (PATH/HOME/LD_PRELOAD) or invalid timeout_seconds (ADV-L4, SM35).',
      });
    }
  }

  // 77. Rust OpenTelemetry::otlp_http admits remote cleartext http:// endpoints without loopback-only restriction (ADV-L4, SM36).
  const otlpHttpMatch = /\bfn\s+otlp_http\s*\([^)]*\)/.exec(clean);
  if (otlpHttpMatch) {
    const fnBody = extractBraceBlock(clean, otlpHttpMatch.index);
    const checksLoopback = /\b(?:is_loopback_otlp_host|validate_otlp_endpoint|is_loopback)\b/.test(fnBody);
    if (!checksLoopback) {
      findings.push({
        ruleId: 'rust-otlp-cleartext-remote-endpoint',
        mechanism: 'SM36-telemetry-watchdog-deck-vm-confinement',
        language: 'rust',
        line: lineOfIndex(clean, otlpHttpMatch.index),
        message: 'OpenTelemetry::otlp_http admits remote cleartext http:// collectors without restricting plaintext HTTP to loopback hosts or validating service/target labels (ADV-L4, SM36).',
      });
    }
  }

  // 78. Rust self-reexec / host-observer sidecar spawns Command::new(env::current_exe()?) via .spawn() without .env_clear() (ADV-L4, SM36).
  const selfExecCmdMatch = /Command::new\s*\(\s*(?:std::)?env::current_exe\s*\(\s*\)\??\s*\)/.exec(clean);
  if (selfExecCmdMatch) {
    const fnScope = extractEnclosingBlock(clean, selfExecCmdMatch.index);
    if (
      /\.spawn\s*\(\s*\)/.test(fnScope) &&
      !/\.env_clear\s*\(\s*\)|\bapply_scrubbed_env\b|\bscrub_command_env\b/.test(fnScope)
    ) {
      findings.push({
        ruleId: 'rust-host-observer-unscrubbed-env',
        mechanism: 'SM36-telemetry-watchdog-deck-vm-confinement',
        language: 'rust',
        line: lineOfIndex(clean, selfExecCmdMatch.index),
        message: 'Sidecar subprocess spawned via Command::new(env::current_exe()) inherits ambient host secrets and dynamic-loader env vars without .env_clear() (ADV-L4, SM36).',
      });
    }
  }

  // 79. Rust HostObserver::drain_pulses trusts sender-supplied timestamps without rejecting future (> monotonic_ns()) values (ADV-L4, SM36).
  const drainPulsesMatch = /\bfn\s+drain_pulses\s*\([^)]*\)/.exec(clean);
  if (drainPulsesMatch) {
    const fnBody = extractBraceBlock(clean, drainPulsesMatch.index);
    const updatesLast = /clock\.last\s*=\s*Some\s*\(/.test(fnBody);
    const boundsFutureTs = /timestamp\s*>\s*now|\bmonotonic_ns\s*\(\s*\)/.test(fnBody);
    if (updatesLast && !boundsFutureTs) {
      findings.push({
        ruleId: 'rust-watchdog-future-timestamp-blinding',
        mechanism: 'SM36-telemetry-watchdog-deck-vm-confinement',
        language: 'rust',
        line: lineOfIndex(clean, drainPulsesMatch.index),
        message: 'HostObserver::drain_pulses trusts sender-supplied timestamps without rejecting future values (> monotonic_ns()), allowing u64::MAX datagrams to permanently blind HeartbeatMissed (ADV-L4, SM36).',
      });
    }
  }

  // 80. Rust Deck single-VM owner::receive inserts into control.modules/timers without capacity bounds, OR DeckContextModule::timer omits MAX_TIMER_DELAY_US ceiling (ADV-L4, SM36).
  const deckReceiveMatch = /\bfn\s+receive\s*\([\s\S]{0,300}?control:\s*&mut\s+Controls/.exec(clean);
  if (deckReceiveMatch) {
    const fnBody = extractBraceBlock(clean, deckReceiveMatch.index);
    const insertsState = /control\.modules\.insert\s*\(/.test(fnBody) && /control\.timers\.insert\s*\(/.test(fnBody);
    const hasCaps = /\b(?:max_active_modules|MAX_ACTIVE_MODULES)\b/.test(fnBody) && /\b(?:max_active_timers|MAX_ACTIVE_TIMERS)\b/.test(fnBody);
    if (insertsState && !hasCaps) {
      findings.push({
        ruleId: 'rust-deck-vm-unbounded-controls-or-timer-delay',
        mechanism: 'SM36-telemetry-watchdog-deck-vm-confinement',
        language: 'rust',
        line: lineOfIndex(clean, deckReceiveMatch.index),
        message: 'Deck single-VM owner::receive inserts into control.modules and control.timers without enforcing bounded module/timer capacity ceilings (ADV-L4, SM36).',
      });
    }
  }
  const deckTimerFnMatch = /\bpub\s+async\s+fn\s+timer\s*\(\s*&self\s*,\s*delay:\s*Duration\s*\)/.exec(clean);
  if (deckTimerFnMatch) {
    const fnBody = extractBraceBlock(clean, deckTimerFnMatch.index);
    if (!/\bMAX_TIMER_DELAY_US\b/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-deck-vm-unbounded-controls-or-timer-delay',
        mechanism: 'SM36-telemetry-watchdog-deck-vm-confinement',
        language: 'rust',
        line: lineOfIndex(clean, deckTimerFnMatch.index),
        message: 'DeckContextModule::timer accepts unbounded u64 microsecond delays without MAX_TIMER_DELAY_US ceiling, letting callers pin native VM timer slots indefinitely (ADV-L4, SM36).',
      });
    }
  }

  // 81. Rust POSIX libc::kill(-pgid, ...) omits > 1 / self-PID / host-PGID guard, exposing kill(0) self-group suicide and kill(-1) user-wide process kill (ADV-L4, SM37).
  const posixFnRe = /\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+\s*(?:<[^>]*>)?\s*\([^)]*\)[^{;]*\{/g;
  let posixFnMatch: RegExpExecArray | null;
  while ((posixFnMatch = posixFnRe.exec(clean)) !== null) {
    const fnBody = extractBraceBlock(clean, posixFnMatch.index + posixFnMatch[0].length - 1);
    const negKill = /libc::kill\s*\(\s*-\s*\w+\s*,/.exec(fnBody);
    if (!negKill) continue;
    const guardsProtected =
      /\b(?:validate_signalable_unix_target|validate_unix_pgid|validate_signalable_pid|is_protected_pid)\b|(?:<=\s*1|<\s*2)/.test(
        fnBody,
      );
    if (!guardsProtected) {
      findings.push({
        ruleId: 'rust-posix-kill-unguarded-zero-or-init',
        mechanism: 'SM37-process-signal-ledger-fanout-confinement',
        language: 'rust',
        line: lineOfIndex(clean, posixFnMatch.index + posixFnMatch[0].length - 1 + negKill.index),
        message: 'libc::kill(-pgid, ...) lacks a > 1 and host-PID/PGID guard; pgid=0 triggers kill(0) killing caller process group and pgid=1 triggers kill(-1) killing every user process (ADV-L4, SM37).',
      });
      break;
    }
  }

  // 82. Rust matches_recorded_start_time returns true on None (fail-open PID reuse) during post-restart orphan reconciliation (ADV-L4, SM37).
  const startTimeMatch = /\bfn\s+matches_recorded_start_time\s*\([^)]*\)/.exec(clean);
  if (startTimeMatch) {
    const fnBody = extractBraceBlock(clean, startTimeMatch.index);
    if (/\bNone\s*=>\s*true\b/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-reconcile-missing-start-time-failopen',
        mechanism: 'SM37-process-signal-ledger-fanout-confinement',
        language: 'rust',
        line: lineOfIndex(clean, startTimeMatch.index),
        message: 'matches_recorded_start_time returns true when os_start_time_secs is None, allowing unfingerprinted or forged ledger records to signal unrelated live PIDs (ADV-L4, SM37).',
      });
    }
  }

  // 83. Rust FileProcessLedgerStore::read_snapshot_unlocked reads ledger unboundedly or omits O_NOFOLLOW / schema_version checks (ADV-L4, SM37).
  const ledgerReadMatch = /\bfn\s+read_snapshot_unlocked\s*\([^)]*\)/.exec(clean);
  if (ledgerReadMatch) {
    const fnBody = extractBraceBlock(clean, ledgerReadMatch.index);
    const hasCap = /\bMAX_LEDGER_FILE_BYTES\b/.test(fnBody);
    const checksSchema = /\bschema_version\s*!=\s*FILE_LEDGER_SCHEMA_VERSION\b/.test(fnBody);
    const rejectsSymlink = /\b(?:O_NOFOLLOW|open_no_follow|verify_ledger_path_no_symlinks)\b/.test(fnBody);
    if (!hasCap || !checksSchema || !rejectsSymlink) {
      findings.push({
        ruleId: 'rust-process-ledger-symlink-or-unbounded-read',
        mechanism: 'SM37-process-signal-ledger-fanout-confinement',
        language: 'rust',
        line: lineOfIndex(clean, ledgerReadMatch.index),
        message: 'FileProcessLedgerStore::read_snapshot_unlocked lacks O_NOFOLLOW symlink refusal, MAX_LEDGER_FILE_BYTES read cap, or FILE_LEDGER_SCHEMA_VERSION validation (ADV-L4, SM37).',
      });
    }
  }

  // 84. Rust working-copy sub-agent fanout omits hard MAX_WORKING_COPY_FANOUT_PARALLELISM ceiling OR cancel_remaining_work returns after abort_all() without awaiting task drain (ADV-L4, SM37).
  const fanoutCapMatch = /\bfn\s+effective_working_copy_fanout_parallelism\s*\([^)]*\)/.exec(clean);
  if (fanoutCapMatch) {
    const fnBody = extractBraceBlock(clean, fanoutCapMatch.index);
    if (!/\bMAX_WORKING_COPY_FANOUT_PARALLELISM\b/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-fanout-unbounded-parallelism-or-undrained-abort',
        mechanism: 'SM37-process-signal-ledger-fanout-confinement',
        language: 'rust',
        line: lineOfIndex(clean, fanoutCapMatch.index),
        message: 'effective_working_copy_fanout_parallelism omits hard MAX_WORKING_COPY_FANOUT_PARALLELISM ceiling, allowing unbounded concurrent sub-agent spawns (ADV-L4, SM37).',
      });
    }
  }
  const cancelRemMatch = /\bfn\s+cancel_remaining_work\s*\([^)]*\)/.exec(clean);
  if (cancelRemMatch) {
    const fnBody = extractBraceBlock(clean, cancelRemMatch.index);
    if (
      /abort_all\s*\(\s*\)/.test(fnBody) &&
      !/join_next(?:_with_id)?\s*\(\s*\)\s*\.await/.test(fnBody)
    ) {
      findings.push({
        ruleId: 'rust-fanout-unbounded-parallelism-or-undrained-abort',
        mechanism: 'SM37-process-signal-ledger-fanout-confinement',
        language: 'rust',
        line: lineOfIndex(clean, cancelRemMatch.index),
        message: 'cancel_remaining_work calls abort_all() without awaiting join_next to drain aborted tasks before returning (ADV-L4, SM37).',
      });
    }
  }

  // 85. Rust B16 KeyRotationShreddingGate::shred_retired_epoch allows future-epoch (> active_epoch) or epoch-0 tombstoning DoS, OR admit_rewrap allows epoch 0 / uncommitted source epochs (ADV-L4, SM38).
  const shredRetiredMatch = /\bfn\s+shred_retired_epoch\s*\([^)]*\)/.exec(clean);
  if (shredRetiredMatch) {
    const fnBody = extractBraceBlock(clean, shredRetiredMatch.index);
    const guardsZero = /\bepoch\s*==\s*0\b/.test(fnBody);
    const guardsFuture = /\bepoch\s*(?:>=|>)\s*self\.active_epoch\b/.test(fnBody);
    if (/self\.shredded_epochs\.insert\s*\(/.test(fnBody) && (!guardsZero || !guardsFuture)) {
      findings.push({
        ruleId: 'rust-b16-future-epoch-shred-or-epoch0-rewrap',
        mechanism: 'SM38-defense-pillar-crypto-state-confinement',
        language: 'rust',
        line: lineOfIndex(clean, shredRetiredMatch.index),
        message: 'shred_retired_epoch omits epoch == 0 or epoch > self.active_epoch checks, letting callers tombstone future epochs to permanently DoS rotate_to_epoch (ADV-L4, SM38).',
      });
    }
  }
  const admitRewrapMatch = /\bfn\s+admit_rewrap\s*\([^)]*\)/.exec(clean);
  if (admitRewrapMatch) {
    const fnBody = extractBraceBlock(clean, admitRewrapMatch.index);
    const guardsEpoch0OrLive =
      /claim\.from_epoch\s*==\s*0/.test(fnBody) ||
      /self\.epoch_commitments\.contains_key\s*\(\s*&claim\.from_epoch\s*\)/.test(fnBody);
    if (/claim\.from_epoch/.test(fnBody) && !guardsEpoch0OrLive) {
      findings.push({
        ruleId: 'rust-b16-future-epoch-shred-or-epoch0-rewrap',
        mechanism: 'SM38-defense-pillar-crypto-state-confinement',
        language: 'rust',
        line: lineOfIndex(clean, admitRewrapMatch.index),
        message: 'admit_rewrap omits from_epoch == 0 and live epoch_commitments membership checks, admitting rewrap from non-existent epoch 0 (ADV-L4, SM38).',
      });
    }
  }

  // 86. Rust B18 ZkSelectiveDisclosureGate matches forbidden_secret_fields case-sensitively without trim, OR issue_challenge_nonce omits consumed_challenges anti-replay and blank-nonce checks (ADV-L4, SM38).
  const zkImplMatch = /\bimpl\s+ZkSelectiveDisclosureGate\b/.exec(clean);
  if (zkImplMatch) {
    const implBody = extractBraceBlock(clean, zkImplMatch.index);
    const admitDiscMatch = /\bfn\s+admit_disclosure\s*\([^)]*\)/.exec(implBody);
    if (admitDiscMatch) {
      const fnBody = extractBraceBlock(implBody, admitDiscMatch.index);
      if (/self\.forbidden_secret_fields\.contains\s*\(\s*field\s*\)/.test(fnBody)) {
        findings.push({
          ruleId: 'rust-b18-zk-case-secret-bypass-or-nonce-replay',
          mechanism: 'SM38-defense-pillar-crypto-state-confinement',
          language: 'rust',
          line: lineOfIndex(clean, zkImplMatch.index + admitDiscMatch.index),
          message: 'ZkSelectiveDisclosureGate::admit_disclosure checks forbidden_secret_fields.contains(field) without trim/ASCII case-folding, letting "RAW_PII" or " raw_pii " leak secrets (ADV-L4, SM38).',
        });
      }
    }
    const issueNonceMatch = /\bfn\s+issue_challenge_nonce\s*\([^)]*\)/.exec(implBody);
    if (issueNonceMatch) {
      const fnBody = extractBraceBlock(implBody, issueNonceMatch.index);
      const tracksConsumed = /\b(?:consumed_challenges|spent_challenges)\b/.test(fnBody);
      const rejectsBlank = /\.trim\s*\(\s*\)[\s\S]{0,80}\.is_empty\s*\(\s*\)/.test(fnBody);
      if (/self\.pending_challenges\.insert\s*\(/.test(fnBody) && (!tracksConsumed || !rejectsBlank)) {
        findings.push({
          ruleId: 'rust-b18-zk-case-secret-bypass-or-nonce-replay',
          mechanism: 'SM38-defense-pillar-crypto-state-confinement',
          language: 'rust',
          line: lineOfIndex(clean, zkImplMatch.index + issueNonceMatch.index),
          message: 'ZkSelectiveDisclosureGate::issue_challenge_nonce lacks blank-nonce refusal or consumed_challenges anti-replay tracking (ADV-L4, SM38).',
        });
      }
    }
  }

  // 87. Rust B14 SupplyChainProvenanceGate compares builder_a_id == builder_b_id without trim/case-folding, OR register_pinned_dependency blindly overwrites pins / ignores CVE tombstones (ADV-L4, SM38).
  const scImplMatch = /\bimpl\s+SupplyChainProvenanceGate\b/.exec(clean);
  if (scImplMatch) {
    const implBody = extractBraceBlock(clean, scImplMatch.index);
    const admitBuildMatch = /\bfn\s+admit_build\s*\([^)]*\)/.exec(implBody);
    if (admitBuildMatch) {
      const fnBody = extractBraceBlock(implBody, admitBuildMatch.index);
      if (/claim\.builder_a_id\s*==\s*claim\.builder_b_id/.test(fnBody)) {
        findings.push({
          ruleId: 'rust-b14-builder-case-spoof-or-pin-overwrite',
          mechanism: 'SM38-defense-pillar-crypto-state-confinement',
          language: 'rust',
          line: lineOfIndex(clean, scImplMatch.index + admitBuildMatch.index),
          message: 'SupplyChainProvenanceGate::admit_build compares builder_a_id == builder_b_id without trim/case-folding, allowing single-builder 2-builder parity spoofing (ADV-L4, SM38).',
        });
      }
    }
    const regPinMatch = /\bfn\s+register_pinned_dependency\s*\([^)]*\)/.exec(implBody);
    if (regPinMatch) {
      const fnBody = extractBraceBlock(implBody, regPinMatch.index);
      const checksExistingPin = /self\.allowlist_pins\.get\s*\(/.test(fnBody);
      const checksCve = /self\.cve_tombstones\.get\s*\(/.test(fnBody);
      if (/self\.allowlist_pins\.insert\s*\(/.test(fnBody) && (!checksExistingPin || !checksCve)) {
        findings.push({
          ruleId: 'rust-b14-builder-case-spoof-or-pin-overwrite',
          mechanism: 'SM38-defense-pillar-crypto-state-confinement',
          language: 'rust',
          line: lineOfIndex(clean, scImplMatch.index + regPinMatch.index),
          message: 'SupplyChainProvenanceGate::register_pinned_dependency overwrites allowlist_pins without checking existing pin immutability or CVE tombstones (ADV-L4, SM38).',
        });
      }
    }
  }

  // 88. Rust B20 FederatedOrgReciprocityGate::register_treaty overwrites active dispute_freeze_active or rolls back treaty_epoch, OR checks org equality without trim/case-folding (ADV-L4, SM38).
  const fedOrgImplMatch = /\bimpl\s+FederatedOrgReciprocityGate\b/.exec(clean);
  if (fedOrgImplMatch) {
    const implBody = extractBraceBlock(clean, fedOrgImplMatch.index);
    const regTreatyMatch = /\bfn\s+register_treaty\s*\([^)]*\)/.exec(implBody);
    if (regTreatyMatch) {
      const fnBody = extractBraceBlock(implBody, regTreatyMatch.index);
      const guardsOverwrite =
        /self\.treaties\.get\s*\(/.test(fnBody) &&
        /dispute_freeze_active/.test(fnBody) &&
        /treaty_epoch/.test(fnBody);
      const rawOrgEq = /treaty\.org_a\s*==\s*treaty\.org_b/.test(fnBody);
      if (/self\.treaties\.insert\s*\(/.test(fnBody) && (!guardsOverwrite || rawOrgEq)) {
        findings.push({
          ruleId: 'rust-b20-treaty-freeze-wipe-or-self-case-spoof',
          mechanism: 'SM38-defense-pillar-crypto-state-confinement',
          language: 'rust',
          line: lineOfIndex(clean, fedOrgImplMatch.index + regTreatyMatch.index),
          message: 'FederatedOrgReciprocityGate::register_treaty overwrites treaties without preserving active dispute_freeze_active / monotonic treaty_epoch, or compares org_a == org_b without trim/case-folding (ADV-L4, SM38).',
        });
      }
    }
    const admitFedMatch = /\bfn\s+admit_federated_op\s*\([^)]*\)/.exec(implBody);
    if (admitFedMatch) {
      const fnBody = extractBraceBlock(implBody, admitFedMatch.index);
      if (/claim\.origin_org\s*==\s*claim\.target_org/.test(fnBody)) {
        findings.push({
          ruleId: 'rust-b20-treaty-freeze-wipe-or-self-case-spoof',
          mechanism: 'SM38-defense-pillar-crypto-state-confinement',
          language: 'rust',
          line: lineOfIndex(clean, fedOrgImplMatch.index + admitFedMatch.index),
          message: 'FederatedOrgReciprocityGate::admit_federated_op compares origin_org == target_org without trim/case-folding, allowing self-reciprocity spoofing (ADV-L4, SM38).',
        });
      }
    }
  }

  // 89. Rust B21 compute_shard_merkle_root duplicates odd trailing leaves (CVE-2012-2459 second-preimage malleability), OR B9 verify_tree_head_progression accepts forged non-empty root at tree_size == 0 (ADV-L4, SM38).
  const shardMerkleMatch = /\bfn\s+compute_shard_merkle_root\s*\([^)]*\)/.exec(clean);
  if (shardMerkleMatch) {
    const fnBody = extractBraceBlock(clean, shardMerkleMatch.index);
    if (/pair\.len\s*\(\s*\)\s*==\s*2[\s\S]{0,60}else\s*\{\s*pair\[0\]\s*\}/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-merkle-odd-leaf-duplication-or-empty-head-unverified',
        mechanism: 'SM38-defense-pillar-crypto-state-confinement',
        language: 'rust',
        line: lineOfIndex(clean, shardMerkleMatch.index),
        message: 'compute_shard_merkle_root duplicates trailing odd Merkle nodes (CVE-2012-2459 malleability: root([A,B,C]) == root([A,B,C,C])); use RFC 6962 largest_power_of_two_less_than binary tree without leaf duplication (ADV-L4, SM38).',
      });
    }
  }
  const treeHeadMatch = /\bfn\s+verify_tree_head_progression\s*\([^)]*\)/.exec(clean);
  if (treeHeadMatch) {
    const fnBody = extractBraceBlock(clean, treeHeadMatch.index);
    const hasZeroBranch = /prev\.tree_size\s*==\s*0/.test(fnBody);
    const verifiesEmptyRoot =
      /governance_sha256_bytes\s*\(\s*&\[\s*\]\s*\)|mth\s*\(\s*&\[\s*\]\s*\)|EMPTY_TREE_ROOT/.test(fnBody);
    if (hasZeroBranch && !verifiesEmptyRoot) {
      findings.push({
        ruleId: 'rust-merkle-odd-leaf-duplication-or-empty-head-unverified',
        mechanism: 'SM38-defense-pillar-crypto-state-confinement',
        language: 'rust',
        line: lineOfIndex(clean, treeHeadMatch.index),
        message: 'verify_tree_head_progression accepts prev.tree_size == 0 without verifying prev.root_hash == SHA256("") and proof size parity, admitting forged empty tree heads (ADV-L4, SM38).',
      });
    }
  }

  // 90. Rust TUI Config::load reads TOML unboundedly / follows symlinks, catalog_with omits timeout ceiling, OR ModelProfile::route reads arbitrary ambient credential_env (ADV-L4, SM39).
  const tuiCfgStructPresent =
    /\bpub\s+struct\s+Config\b/.test(clean) &&
    /\bcredential_env\s*:\s*String\b/.test(clean) &&
    /\btimeout_seconds\s*:\s*u64\b/.test(clean);
  if (tuiCfgStructPresent) {
    const cfgImplMatch = /\bimpl\s+Config\b/.exec(clean);
    if (cfgImplMatch) {
      const implBody = extractBraceBlock(clean, cfgImplMatch.index);
      if (
        /fs::read_to_string/.test(implBody) &&
        !/\b(?:MAX_TUI_CONFIG_BYTES|symlink_metadata|O_NOFOLLOW)\b/.test(implBody)
      ) {
        findings.push({
          ruleId: 'rust-tui-config-unbounded-read-or-unsafe-cred-env',
          mechanism: 'SM39-tui-config-supervisor-probe-confinement',
          language: 'rust',
          line: lineOfIndex(clean, cfgImplMatch.index),
          message: 'TUI Config::load performs unbounded symlink-following fs::read_to_string without MAX_TUI_CONFIG_BYTES cap or symlink refusal (ADV-L4, SM39).',
        });
      }
      if (
        /Duration::from_secs\s*\(\s*self\.timeout_seconds\s*\)/.test(implBody) &&
        !/\b(?:MAX_TUI_TIMEOUT_SECONDS|validate_timeout_seconds)\b/.test(implBody)
      ) {
        findings.push({
          ruleId: 'rust-tui-config-unbounded-read-or-unsafe-cred-env',
          mechanism: 'SM39-tui-config-supervisor-probe-confinement',
          language: 'rust',
          line: lineOfIndex(clean, cfgImplMatch.index),
          message: 'TUI Config::catalog_with passes unvalidated self.timeout_seconds (0 or multi-year) directly to Client::new without MAX_TUI_TIMEOUT_SECONDS bounds (ADV-L4, SM39).',
        });
      }
    }
    const profileImplMatch = /\bimpl\s+ModelProfile\b/.exec(clean);
    if (profileImplMatch) {
      const implBody = extractBraceBlock(clean, profileImplMatch.index);
      if (
        /read_env\s*\(\s*&self\.credential_env\s*\)/.test(implBody) &&
        !/\b(?:validate_tui_credential_env|validate_credential_env_name|is_safe_credential_env)\b/.test(implBody)
      ) {
        findings.push({
          ruleId: 'rust-tui-config-unbounded-read-or-unsafe-cred-env',
          mechanism: 'SM39-tui-config-supervisor-probe-confinement',
          language: 'rust',
          line: lineOfIndex(clean, profileImplMatch.index),
          message: 'TUI ModelProfile::route reads self.credential_env without rejecting ambient OS/loader variables (PATH/HOME/LD_PRELOAD/SSH_AUTH_SOCK) (ADV-L4, SM39).',
        });
      }
    }
  }

  // 91. Rust spawn_managed_asp_gateway inherits ambient env without .env_clear(), omits boot timeout, or omits strict loopback endpoint validation; discover_asp_gateway_binary searches relative PATH (ADV-L4, SM39).
  const aspSpawnMatch = /\bfn\s+spawn_managed_asp_gateway(?:_with_timeout)?\s*\([^)]*\)/.exec(clean);
  if (aspSpawnMatch) {
    const fnBody = extractBraceBlock(clean, aspSpawnMatch.index);
    const hasEnvScrub = /\.env_clear\s*\(\s*\)|\bapply_scrubbed_asp_env\b/.test(fnBody);
    const hasBootTimeout = /\b(?:ASP_GATEWAY_BOOT_TIMEOUT|read_bounded_boot_line_with_timeout|boot_timeout)\b/.test(fnBody);
    const validatesEndpoint = /\bvalidate_managed_asp_endpoint\b/.test(fnBody);
    if (!hasEnvScrub || !hasBootTimeout || !validatesEndpoint) {
      findings.push({
        ruleId: 'rust-asp-supervisor-unscrubbed-env-hang-or-ssrf',
        mechanism: 'SM39-tui-config-supervisor-probe-confinement',
        language: 'rust',
        line: lineOfIndex(clean, aspSpawnMatch.index),
        message: 'spawn_managed_asp_gateway omits .env_clear() secret scrubbing, bounded boot timeout, or strict loopback host:port validation (ADV-L4, SM39).',
      });
    }
  }
  const aspDiscoverMatch = /\bfn\s+discover_asp_gateway_binary\s*\([^)]*\)/.exec(clean);
  if (aspDiscoverMatch) {
    const fnBody = extractBraceBlock(clean, aspDiscoverMatch.index);
    if (/env::split_paths/.test(fnBody) && !/\.is_absolute\s*\(\s*\)/.test(fnBody)) {
      findings.push({
        ruleId: 'rust-asp-supervisor-unscrubbed-env-hang-or-ssrf',
        mechanism: 'SM39-tui-config-supervisor-probe-confinement',
        language: 'rust',
        line: lineOfIndex(clean, aspDiscoverMatch.index),
        message: 'discover_asp_gateway_binary searches relative PATH entries (such as "."), enabling untrusted-repo ./asp-gateway hijack (ADV-L4, SM39).',
      });
    }
  }

  // 92. Rust RuntimeProbe::start opens MARLIN_TUI_RUNTIME_METRICS_FILE via File::create (symlink overwrite) or writes CSV rows indefinitely without MAX_RUNTIME_PROBE_BYTES (ADV-L4, SM39).
  const probeImplMatch = /\bimpl\s+RuntimeProbe\b/.exec(clean);
  if (probeImplMatch) {
    const implBody = extractBraceBlock(clean, probeImplMatch.index);
    const usesRawCreate = /File::create\s*\(/.test(implBody);
    const hasNoFollowAndCap =
      /\b(?:open_confined_probe_file|O_NOFOLLOW)\b/.test(implBody) &&
      /\bMAX_RUNTIME_PROBE_BYTES\b/.test(implBody);
    if (usesRawCreate || !hasNoFollowAndCap) {
      findings.push({
        ruleId: 'rust-runtime-probe-symlink-or-unbounded-file',
        mechanism: 'SM39-tui-config-supervisor-probe-confinement',
        language: 'rust',
        line: lineOfIndex(clean, probeImplMatch.index),
        message: 'RuntimeProbe opens metrics output with symlink-following File::create or omits MAX_RUNTIME_PROBE_BYTES cumulative write cap (ADV-L4, SM39).',
      });
    }
  }

  // 93. Rust bootstrap::resolve_local_scheme_prefix prioritizes untrusted cwd/scheme over binary-owned repo or follows symlinks (ADV-L4, SM39).
  const bootstrapMatch = /\bfn\s+resolve_local_scheme_prefix\s*\([^)]*\)/.exec(clean);
  if (bootstrapMatch) {
    const fnBody = extractBraceBlock(clean, bootstrapMatch.index);
    const cwdFirst = /let\s+mut\s+candidates\s*=\s*vec!\[\s*cwd\.join\s*\(\s*"scheme"\s*\)\s*\]/.test(fnBody);
    const checksSymlink = /\b(?:symlink_metadata|is_non_symlink_scheme_package)\b/.test(clean);
    if (cwdFirst || !checksSymlink) {
      findings.push({
        ruleId: 'rust-bootstrap-cwd-precedence-or-symlink-scheme',
        mechanism: 'SM39-tui-config-supervisor-probe-confinement',
        language: 'rust',
        line: lineOfIndex(clean, bootstrapMatch.index),
        message: 'resolve_local_scheme_prefix prioritizes untrusted CWD ./scheme ahead of binary-owned repository or follows symlinked Scheme prefixes (ADV-L4, SM39).',
      });
    }
  }

  return findings;
}

function auditTypeScript(clean: string): AgingFinding[] {
  const findings: AgingFinding[] = [];

  // 1. Uncaptured setInterval never cleared.
  const intervalMatch = /^\s*setInterval\s*\(/m.exec(clean);
  if (intervalMatch && !/\bclearInterval\s*\(/.test(clean)) {
    findings.push({
      ruleId: 'ts-unbounded-interval',
      mechanism: 'SM2-resource-leak',
      language: 'ts',
      line: lineOfIndex(clean, intervalMatch.index),
      message: 'setInterval handle is uncaptured and never cleared via clearInterval, leaking timer callbacks indefinitely.',
    });
  }

  // 2. Unbounded retry loop without explicit retry budget / maxAttempts guard.
  const whileTrueMatch = /\bwhile\s*\(\s*true\s*\)\s*\{/.exec(clean);
  if (
    whileTrueMatch &&
    /\bcatch\b/.test(clean.slice(whileTrueMatch.index)) &&
    !/(?:maxRetries|retryBudget|attempts\s*[<>]=?|remaining\s*[<>]=?)/.test(clean)
  ) {
    findings.push({
      ruleId: 'ts-unbounded-retry-loop',
      mechanism: 'SM5-metastable-overload',
      language: 'ts',
      line: lineOfIndex(clean, whileTrueMatch.index),
      message: 'Unbounded while(true) catch-retry loop lacks explicit retry budget; causes metastable overload storms.',
    });
  }

  // 3. Uncapped buffer pool push without byteLength / maxRetain ceiling check in enclosing method body.
  const pushPoolMatch = /this\.pool\.push\s*\(/.exec(clean);
  if (pushPoolMatch) {
    const fnScope = extractEnclosingBlock(clean, pushPoolMatch.index);
    if (!/(?:byteLength\s*>|maxRetain|slotCap)/.test(fnScope)) {
      findings.push({
        ruleId: 'ts-uncapped-pool-push',
        mechanism: 'SM3-watermark-ratchet',
        language: 'ts',
        line: lineOfIndex(clean, pushPoolMatch.index),
        message: 'Buffer pushed to reusable pool without byteLength or slot ceiling check (watermark ratchet).',
      });
    }
  }

  // 4. Event listener registered without corresponding removal or AbortSignal.
  const listenerMatch = /\.(?:on|addEventListener)\s*\(/.exec(clean);
  if (
    listenerMatch &&
    !/(?:\.(?:off|removeListener|removeEventListener)\s*\(|signal\s*:)/.test(clean)
  ) {
    findings.push({
      ruleId: 'ts-unremoved-listener',
      mechanism: 'SM2-resource-leak',
      language: 'ts',
      line: lineOfIndex(clean, listenerMatch.index),
      message: 'Event listener registered without removeEventListener/off or AbortSignal cleanup.',
    });
  }

  // 5. Unbounded Promise.all(items.map(...)) fan-out without concurrency cap / chunking.
  const promiseAllMatch = /\bPromise\.all\s*\(\s*\w+\.map\s*\(/.exec(clean);
  if (promiseAllMatch) {
    const fnScope = extractEnclosingBlock(clean, promiseAllMatch.index);
    if (!/\b(?:maxConcurrency|chunk|batchSize|limit|semaphore|pLimit)\b/i.test(fnScope)) {
      findings.push({
        ruleId: 'ts-unbounded-promise-all-fanout',
        mechanism: 'SM5-metastable-overload',
        language: 'ts',
        line: lineOfIndex(clean, promiseAllMatch.index),
        message: 'Unbounded Promise.all(items.map(...)) fan-out lacks concurrency ceiling; spikes memory and downstream overload.',
      });
    }
  }

  // 6. Unbounded Map/cache .set() without eviction or size ceiling.
  const cacheSetMatch = /\b(?:cache|memo|sessions|store)\.set\s*\(/.exec(clean);
  if (cacheSetMatch) {
    const fnScope = extractEnclosingBlock(clean, cacheSetMatch.index);
    if (!/(?:\.delete\s*\(|\.clear\s*\(|maxSize|maxEntries|cap|evict)/i.test(fnScope)) {
      findings.push({
        ruleId: 'ts-unbounded-map-cache',
        mechanism: 'SM3-watermark-ratchet',
        language: 'ts',
        line: lineOfIndex(clean, cacheSetMatch.index),
        message: 'Map cache grows via .set() without max-size check or eviction; leaks heap monotonically over uptime.',
      });
    }
  }

  // 7. Streaming O(N^2) full-transcript Markdown/HTML innerHTML re-parse on every delta (MyGo src/main.ts).
  const innerHtmlReparseMatch = /\.innerHTML\s*=\s*(?:renderMarkdown|DOMPurify\.sanitize|marked\.parse)\s*\(/.exec(clean);
  if (
    innerHtmlReparseMatch &&
    /\+=\s*\w+/.test(clean) &&
    !/\b(?:incremental|renderDeltaBlock|appendBlock|blockCache|maxRenderWindow)\b/i.test(clean)
  ) {
    findings.push({
      ruleId: 'ts-streaming-full-innerhtml-reparse',
      mechanism: 'SM7-ui-render-aging',
      language: 'ts',
      line: lineOfIndex(clean, innerHtmlReparseMatch.index),
      message: 'Streaming delta triggers full-transcript Markdown/innerHTML re-parse (O(N^2) main-thread stall); use incremental block rendering.',
    });
  }

  // 8. Unbounded DOM row append without viewport virtualization / node window cap (MyGo src/main.ts).
  const domAppendMatch = /\b(?:messages|transcript|logList|feed)\.appendChild\s*\(/.exec(clean);
  if (
    domAppendMatch &&
    !/\b(?:maxVisibleNodes|maxDomNodes|windowCap|virtualWindow|firstElementChild\??\.remove|removeChild)\b/.test(clean)
  ) {
    findings.push({
      ruleId: 'ts-unbounded-dom-append',
      mechanism: 'SM7-ui-render-aging',
      language: 'ts',
      line: lineOfIndex(clean, domAppendMatch.index),
      message: 'Streaming/chat container appends DOM nodes without bounded viewport window pruning; DOM heap and layout latency grow linearly with uptime.',
    });
  }

  // 9. Entity deletion path omits cascade cleanup on per-entity side Map (drafts / queues in MyGo src/main.ts).
  const deleteCallMatch = /\b(?:deleteSession|removeSession|closeSession)\s*\(/.exec(clean);
  if (deleteCallMatch) {
    const sideMapRe = /\b(drafts|queues|metadata|tabStates)\.set\s*\(/g;
    const checked = new Set<string>();
    let sm: RegExpExecArray | null;
    while ((sm = sideMapRe.exec(clean)) !== null) {
      const mapName = sm[1]!;
      if (checked.has(mapName)) continue;
      checked.add(mapName);
      const hasCascadeDelete = new RegExp(`\\b${mapName}\\.delete\\s*\\(`).test(clean);
      if (!hasCascadeDelete) {
        findings.push({
          ruleId: 'ts-orphan-sidemap-on-delete',
          mechanism: 'SM3-watermark-ratchet',
          language: 'ts',
          line: lineOfIndex(clean, sm.index),
          message: `Side map '${mapName}' is populated per session but never cleaned via ${mapName}.delete() when sessions are deleted.`,
        });
        break;
      }
    }
  }

  // 10. Interactive search/input Enter handler submits without IME isComposing gate (SM13).
  const enterHandlerMatch = /\b(?:onKeyDown|handleKeyDown|keydown)\b[\s\S]{0,220}?(?:\.key\s*===?\s*['"]Enter['"])/.exec(clean);
  if (enterHandlerMatch) {
    const fnScope = extractEnclosingBlock(clean, enterHandlerMatch.index);
    const callsSubmit = /\b(?:submit|search|runQuery|dispatchQuery|executeSearch)\w*\s*\(/.test(fnScope);
    const checksIme = /\b(?:isComposing|composing|keyCode\s*===?\s*229)\b/.test(fnScope);
    if (callsSubmit && !checksIme) {
      findings.push({
        ruleId: 'ts-ime-unguarded-enter-submit',
        mechanism: 'SM13-ime-composition-race',
        language: 'ts',
        line: lineOfIndex(clean, enterHandlerMatch.index),
        message: 'Enter key handler submits search query without checking isComposing/composing; causes premature raw-preedit submission during CJK IME input (SM13).',
      });
    }
  }

  // 11. IME-aware input clears focus on blur without canceling active composition/preedit (SM13).
  if (/\b(?:compositionstart|compositionupdate|preedit)\b/.test(clean)) {
    const blurMatch = /\b(?:onBlur|handleBlur)\s*\([^)]*\)/.exec(clean);
    if (blurMatch) {
      const fnScope = extractBraceBlock(clean, blurMatch.index);
      const setsUnfocused = /\bfocused\s*=\s*false\b/.test(fnScope);
      const cancelsIme = /\b(?:composing\s*=\s*false|preedit\s*=\s*['"]['"]|cancelComposition)\b/.test(fnScope);
      if (setsUnfocused && !cancelsIme) {
        findings.push({
          ruleId: 'ts-ime-blur-orphan-preedit',
          mechanism: 'SM13-ime-composition-race',
          language: 'ts',
          line: lineOfIndex(clean, blurMatch.index),
          message: 'Input blur handler clears focused state without canceling active IME composition/preedit, leaving orphaned preedit state (SM13).',
        });
      }
    }
  }

  // 12. Search/input clipboard paste handler appends clipboardData without byte/length cap or control-char stripping (SM16).
  const pasteEvMatch = /addEventListener\s*\(\s*['"]paste['"]/.exec(clean);
  if (pasteEvMatch) {
    const fnScope = extractEnclosingBlock(clean, pasteEvMatch.index);
    const readsClipboard = /clipboardData/.test(fnScope);
    const hasCap = /\b(?:slice\s*\(\s*0\s*,|maxLen|maxLength|maxBytes|MAX_\w+|truncate|sanitize)\b/i.test(fnScope);
    if (readsClipboard && !hasCap) {
      findings.push({
        ruleId: 'ts-search-input-uncapped-paste',
        mechanism: 'SM16-search-input-sanitization',
        language: 'ts',
        line: lineOfIndex(clean, pasteEvMatch.index),
        message: 'Clipboard paste handler writes clipboardData directly into input/query without length cap or control-char sanitization (SM16).',
      });
    }
  }

  // 13. Fetch response buffers entire payload via .text()/.arrayBuffer()/.bytes() before checking byte cap (SM17).
  const tsFullReadMatch = /\bawait\s+\w+\.(?:text|arrayBuffer|bytes)\s*\(\s*\)/.exec(clean);
  if (tsFullReadMatch) {
    const fnScope = extractEnclosingBlock(clean, tsFullReadMatch.index);
    const checksAfterRead = /(?:\.length|\.byteLength)\s*>\s*(?:MAX_[A-Z0-9_]+|\w*(?:max|limit|cap)\w*)/i.test(fnScope);
    const streamsReader = /\bgetReader\s*\(\s*\)/.test(fnScope);
    if (checksAfterRead && !streamsReader) {
      findings.push({
        ruleId: 'ts-http-body-buffer-before-cap',
        mechanism: 'SM17-streaming-output-budget',
        language: 'ts',
        line: lineOfIndex(clean, tsFullReadMatch.index),
        message: 'HTTP response buffers full body via .text()/.arrayBuffer() before checking size limit; pre-check Content-Length and stream via resp.body.getReader() with pre-allocation byte budget (SM17).',
      });
    }
  }

  // 14. TS control-plane bridge RPC admits mutating action without checking active E-Stop breaker or spawns unscrubbed `sh -lc` (ADV-L4, SM26).
  const tsRpcMatch = /\b(?:async\s+)?(?:function\s+)?(?:submitScopedPanelAction|dispatchControlAction)\s*\([^)]*\)/.exec(clean);
  if (tsRpcMatch) {
    const fnBody = extractBraceBlock(clean, tsRpcMatch.index);
    const checksAuth = /\b(?:checkAuth|verifyBearer|requireAuth)\s*\(/.test(fnBody);
    const checksEstop = /\b(?:emergencyStop|breakerTripped|isTripped|governanceGate|ensureGovernanceLive)\b/.test(fnBody);
    if (checksAuth && !checksEstop) {
      findings.push({
        ruleId: 'ts-control-plane-rpc-missing-estop-or-unscrubbed-shell',
        mechanism: 'SM26-control-plane-auth-governance',
        language: 'ts',
        line: lineOfIndex(clean, tsRpcMatch.index),
        message: 'Control-plane RPC handler validates auth token but omits fail-closed E-Stop / governance gate enforcement before admitting mutating actions (ADV-L4, SM26).',
      });
    }
  }

  // 15. TS policy/CI gate runner masks policy gate failure (`|| true`, `continueOnError: true`, or swallowing catch returning passed: true) (ADV-L4, SM27).
  const tsMaskedGateMatch =
    /\b(?:workspace_policy|rust-dev-gate|enforce_asp_rust|policyGate)\b[\s\S]{0,180}(?:\|\|\s*true\b|continueOnError\s*:\s*true|catch\s*(?:\([^)]*\))?\s*\{[\s\S]{0,80}return\s+\{\s*passed\s*:\s*true)/.exec(clean);
  if (tsMaskedGateMatch) {
    findings.push({
      ruleId: 'ts-policy-gate-swallows-failure',
      mechanism: 'SM27-policy-gate-blindspot-confinement',
      language: 'ts',
      line: lineOfIndex(clean, tsMaskedGateMatch.index),
      message: 'Policy-gate runner swallows failure via `|| true`, `continueOnError: true`, or catch-returning `passed: true`, creating a silent blind spot (ADV-L4, SM27).',
    });
  }

  // 16. TS workspace policy auditor admits crate graph without checking for cyclic dependency SCCs (ADV-L4, SM27).
  const wsAuditFnMatch = /\b(?:async\s+)?function\s+auditWorkspacePolicy\s*\([^)]*\)/.exec(clean);
  if (wsAuditFnMatch) {
    const fnBody = extractBraceBlock(clean, wsAuditFnMatch.index);
    const checksCycles = /\b(?:cyclicSccs|countCyclicSccs|detectCycles|hasCycle|toposort)\b/.test(fnBody);
    const returnsPassed = /\bpassed\s*:\s*true\b|\breturn\s+true\b/.test(fnBody);
    if (returnsPassed && !checksCycles) {
      findings.push({
        ruleId: 'ts-workspace-dep-cycle-unverified',
        mechanism: 'SM27-policy-gate-blindspot-confinement',
        language: 'ts',
        line: lineOfIndex(clean, wsAuditFnMatch.index),
        message: 'Workspace policy auditor returns passed without verifying acyclic workspace dependency graph (cyclicSccs == 0), risking cycle-blinded policy gates (ADV-L4, SM27).',
      });
    }
  }

  // 17. TS plugin/panel activation ignores capability grants or idempotency replay ignores payload digest (ADV-L4, SM28).
  const tsFindIdemMatch = /\bfunction\s+findIdempotentAction\s*\([^)]*\)/.exec(clean);
  if (tsFindIdemMatch) {
    const fnBody = extractBraceBlock(clean, tsFindIdemMatch.index);
    const matchesKey = /\bidempotencyKey\b/.test(fnBody);
    const checksPayload = /\bactionName\b/.test(fnBody) && /\b(?:argsDigest|payloadDigest)\b/.test(fnBody);
    if (matchesKey && !checksPayload) {
      findings.push({
        ruleId: 'ts-panel-grant-or-idempotency-bypass',
        mechanism: 'SM28-plugin-grant-rollback-lease',
        language: 'ts',
        line: lineOfIndex(clean, tsFindIdemMatch.index),
        message: 'findIdempotentAction matches idempotencyKey without verifying actionName and argsDigest, allowing conflicting payload replay (ADV-L4, SM28).',
      });
    }
  }

  // 18. TS Cedar policy matcher waives forbid-unless on undefined/null missing context keys (ADV-L4, SM29).
  const tsCedarMatch = /\bfunction\s+matchesCedarPolicy\s*\([^)]*\)/.exec(clean);
  if (tsCedarMatch) {
    const fnBody = extractBraceBlock(clean, tsCedarMatch.index + tsCedarMatch[0].length);
    const hasUnless = /\bunlessClauses\b[\s\S]{0,220}evalConditionBlock\s*\([^)]*\)\s*!==\s*false\b/.test(fnBody);
    const handlesForbidStrict =
      /['"]forbid['"]/.test(fnBody) &&
      /\bevalConditionBlock\s*\([^)]*\)\s*===\s*true\b/.test(fnBody);
    if (hasUnless && !handlesForbidStrict) {
      findings.push({
        ruleId: 'ts-cedar-forbid-unless-failopen',
        mechanism: 'SM29-governance-policy-latch-antirollback',
        language: 'ts',
        line: lineOfIndex(clean, tsCedarMatch.index),
        message: 'matchesCedarPolicy waives unlessClauses whenever evalConditionBlock !== false, silently disabling forbid policies when a context key is missing (ADV-L4, SM29).',
      });
    }
  }

  // 19. TS Step-Up MFA attestation parser checks only non-empty acr without an explicit MFA ACR allowlist (ADV-L4, SM30).
  const tsStepUpMatch = /\bfunction\s+parseVerifiedStepUpHuman\s*\([^)]*\)/.exec(clean);
  if (tsStepUpMatch) {
    const fnBody = extractBraceBlock(clean, tsStepUpMatch.index + tsStepUpMatch[0].length);
    const hasAcrCheck = /\bacr\b/.test(fnBody);
    const hasAllowlist = /\b(?:isAllowlistedMfaAcr|ALLOWLISTED_MFA_ACRS|urn:ietf:params:oauth:acr:mfa)\b/.test(fnBody);
    if (hasAcrCheck && !hasAllowlist) {
      findings.push({
        ruleId: 'ts-stepup-weak-acr-nonempty-only',
        mechanism: 'SM30-stepup-attestation-host-effect',
        language: 'ts',
        line: lineOfIndex(clean, tsStepUpMatch.index),
        message: 'parseVerifiedStepUpHuman accepts any non-empty acr string without validating against an explicit RFC 9470 / NIST MFA ACR allowlist (ADV-L4, SM30).',
      });
    }
  }

  // 24. TS parseSyncRemoteUrl accepts arbitrary remote cleartext http:// URLs without loopback restriction or userinfo refusal (ADV-L4, SM31).
  const tsSyncUrlMatch = /\bfunction\s+parseSyncRemoteUrl\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsSyncUrlMatch) {
    const fnBody = extractBraceBlock(clean, tsSyncUrlMatch.index + tsSyncUrlMatch[0].length - 1);
    const admitsHttp = /http:\/\//.test(fnBody) || /===?\s*['"]http['"]/.test(fnBody);
    const guardsLoopbackAndUserinfo = /\b(?:localhost|127\.0\.0\.1)\b/.test(fnBody) && /@/.test(fnBody);
    if (admitsHttp && !guardsLoopbackAndUserinfo) {
      findings.push({
        ruleId: 'ts-remote-sync-url-admits-cleartext-http',
        mechanism: 'SM31-storage-boundary-integrity-sync',
        language: 'ts',
        line: lineOfIndex(clean, tsSyncUrlMatch.index),
        message: 'parseSyncRemoteUrl accepts remote cleartext http:// URLs or omits @ userinfo smuggling refusal (ADV-L4, SM31).',
      });
    }
  }

  // 25. TS buildGitWorktreeArgs omits core.fsmonitor=false or leading "-" option-injection checks on branch/baseRef (ADV-L4, SM32).
  const tsGitWtMatch = /\bfunction\s+buildGitWorktreeArgs\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsGitWtMatch) {
    const fnBody = extractBraceBlock(clean, tsGitWtMatch.index + tsGitWtMatch[0].length - 1);
    const hasFsmonitorOff = /core\.fsmonitor=false/.test(fnBody);
    const rejectsDash = /startsWith\s*\(\s*['"]-['"]\s*\)/.test(fnBody);
    if (!hasFsmonitorOff || !rejectsDash) {
      findings.push({
        ruleId: 'ts-gitops-unconfined-env-or-arg-injection',
        mechanism: 'SM32-gitops-subprocess-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsGitWtMatch.index),
        message: 'buildGitWorktreeArgs omits core.fsmonitor=false lockdown or fails to reject dash-prefixed branch/baseRef CLI option injection (ADV-L4, SM32).',
      });
    }
  }

  // 26. TS applyHookDynamicDecision overwrites UntrustedRejected/ModifiedRejected audit reasons instead of preserving trust-floor rejections (ADV-L4, SM33).
  const tsHookDecMatch = /\bfunction\s+applyHookDynamicDecision\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsHookDecMatch) {
    const fnBody = extractBraceBlock(clean, tsHookDecMatch.index + tsHookDecMatch[0].length - 1);
    if (!/\b(?:UntrustedRejected|ModifiedRejected)\b/.test(fnBody)) {
      findings.push({
        ruleId: 'ts-hook-config-failopen-or-trust-mask',
        mechanism: 'SM33-hook-policy-protocol-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsHookDecMatch.index),
        message: 'applyHookDynamicDecision overwrites Rust trust-floor rejection reasons (UntrustedRejected/ModifiedRejected) with extension Defer/Deny reasons (ADV-L4, SM33).',
      });
    }
  }

  // 27. TS assembleTwoZonePrompt compares kvPrefixDigest without recomputing computeKvPrefixDigest(envelope.frozenPrefix) (ADV-L4, SM34).
  const tsTwoZoneMatch = /\bfunction\s+assembleTwoZonePrompt\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsTwoZoneMatch) {
    const fnBody = extractBraceBlock(clean, tsTwoZoneMatch.index + tsTwoZoneMatch[0].length - 1);
    if (!/computeKvPrefixDigest\s*\(\s*envelope\.frozenPrefix\s*\)/.test(fnBody)) {
      findings.push({
        ruleId: 'ts-two-zone-prefix-or-direnv-loader-bypass',
        mechanism: 'SM34-runtime-env-context-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsTwoZoneMatch.index),
        message: 'assembleTwoZonePrompt trusts envelope.kvPrefixDigest without recomputing computeKvPrefixDigest(envelope.frozenPrefix), enabling Zone-1 prompt injection with a copied digest (ADV-L4, SM34).',
      });
    }
  }

  // 28. TS classifyHarnessToolCapability trusts declaredCapability or "search" substring before checking isDestructiveToolName (ADV-L4, SM35).
  const tsClassifyToolMatch = /\bfunction\s+classifyHarnessToolCapability\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsClassifyToolMatch) {
    const fnBody = extractBraceBlock(clean, tsClassifyToolMatch.index + tsClassifyToolMatch[0].length - 1);
    if (!/\bisDestructiveToolName\s*\(/.test(fnBody)) {
      findings.push({
        ruleId: 'ts-harness-tool-capability-spoof-or-witness-bypass',
        mechanism: 'SM35-graph-witness-harness-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsClassifyToolMatch.index),
        message: 'classifyHarnessToolCapability trusts declaredCapability or "search" substring without checking isDestructiveToolName first (ADV-L4, SM35).',
      });
    }
  }

  // 29. TS validateOtlpEndpoint allows cleartext remote http:// without loopback check, OR acceptWatchdogPulse omits future timestamp bound (ADV-L4, SM36).
  const tsOtlpMatch = /\bfunction\s+validateOtlpEndpoint\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsOtlpMatch) {
    const fnBody = extractBraceBlock(clean, tsOtlpMatch.index + tsOtlpMatch[0].length - 1);
    if (/['"]http:['"]/.test(fnBody) && !/\b(?:isLoopbackHost|localhost|127\.0\.0\.1)\b/.test(fnBody)) {
      findings.push({
        ruleId: 'ts-otlp-cleartext-remote-or-watchdog-future-ts',
        mechanism: 'SM36-telemetry-watchdog-deck-vm-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsOtlpMatch.index),
        message: 'validateOtlpEndpoint permits remote cleartext http:// collectors without restricting plaintext HTTP to loopback hosts (ADV-L4, SM36).',
      });
    }
  }

  // 30. TS signalProcessGroup calls process.kill(-pgid, ...) without guarding pgid <= 1 (kill(0)/kill(-1)) (ADV-L4, SM37).
  const tsNegKillMatch = /process\.kill\s*\(\s*-\s*\w+\s*,/.exec(clean);
  if (tsNegKillMatch) {
    const fnScope = extractEnclosingBlock(clean, tsNegKillMatch.index);
    if (!/(?:<=\s*1|<\s*2|\bvalidateSignalTarget\b)/.test(fnScope)) {
      findings.push({
        ruleId: 'ts-posix-kill-unguarded-zero-or-init',
        mechanism: 'SM37-process-signal-ledger-fanout-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsNegKillMatch.index),
        message: 'process.kill(-pgid, ...) lacks a > 1 guard; pgid=0 kills caller process group and pgid=1 kills all user processes (ADV-L4, SM37).',
      });
    }
  }

  // 31. TS checkForbiddenDisclosedFields matches forbidden secrets without trim/toLowerCase normalization, OR computeShardMerkleRoot duplicates odd trailing Merkle leaves (ADV-L4, SM38).
  const tsForbiddenMatch = /\bfunction\s+checkForbiddenDisclosedFields\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsForbiddenMatch) {
    const fnBody = extractBraceBlock(clean, tsForbiddenMatch.index + tsForbiddenMatch[0].length - 1);
    if (/\.has\s*\(\s*\w+\s*\)/.test(fnBody) && !/(?:\.trim\s*\(\s*\)|\.toLowerCase\s*\(\s*\))/.test(fnBody)) {
      findings.push({
        ruleId: 'ts-defense-pillar-case-bypass-or-merkle-dup',
        mechanism: 'SM38-defense-pillar-crypto-state-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsForbiddenMatch.index),
        message: 'checkForbiddenDisclosedFields checks forbidden secret membership without trim/toLowerCase normalization, allowing case/whitespace secret over-disclosure bypass (ADV-L4, SM38).',
      });
    }
  }
  const tsMerkleMatch = /\bfunction\s+computeShardMerkleRoot\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsMerkleMatch) {
    const fnBody = extractBraceBlock(clean, tsMerkleMatch.index + tsMerkleMatch[0].length - 1);
    if (/level\[\s*i\s*\+\s*1\s*\]\s*\?\?\s*level\[\s*i\s*\]|pair\[1\]\s*\?\?\s*pair\[0\]/.test(fnBody)) {
      findings.push({
        ruleId: 'ts-defense-pillar-case-bypass-or-merkle-dup',
        mechanism: 'SM38-defense-pillar-crypto-state-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsMerkleMatch.index),
        message: 'computeShardMerkleRoot duplicates trailing odd Merkle nodes (CVE-2012-2459 second-preimage malleability) instead of RFC 6962 largest-power-of-two splitting (ADV-L4, SM38).',
      });
    }
  }

  // 32. TS loadTuiConfig reads ambient OS/loader credentialEnv without allowlist/denylist validation, OR discoverGatewayBinary searches relative PATH entries (ADV-L4, SM39).
  const tsTuiCfgMatch = /\bfunction\s+resolveTuiCredentialEnv\s*\([^)]*\)(?:\s*:\s*[^{]+)?\{/.exec(clean);
  if (tsTuiCfgMatch) {
    const fnBody = extractBraceBlock(clean, tsTuiCfgMatch.index + tsTuiCfgMatch[0].length - 1);
    if (/process\.env\[/.test(fnBody) && !/\b(?:isSafeCredentialEnv|AMBIENT_SYSTEM_ENV|LD_PRELOAD)\b/.test(fnBody)) {
      findings.push({
        ruleId: 'ts-tui-config-ambient-cred-or-relative-path-bin',
        mechanism: 'SM39-tui-config-supervisor-probe-confinement',
        language: 'ts',
        line: lineOfIndex(clean, tsTuiCfgMatch.index),
        message: 'resolveTuiCredentialEnv reads process.env[name] without rejecting ambient OS/loader variables (PATH/HOME/LD_PRELOAD) (ADV-L4, SM39).',
      });
    }
  }

  return findings;
}

function auditC(clean: string): AgingFinding[] {
  const findings: AgingFinding[] = [];

  // 1. malloc/calloc/fopen followed by a non-null-check early error return without free/fclose/goto cleanup.
  const allocMatch = /\b(\w+)\s*=\s*(?:malloc|calloc|fopen)\s*\(/.exec(clean);
  if (allocMatch) {
    const varName = allocMatch[1]!;
    const afterAlloc = clean.slice(allocMatch.index);
    const usesGotoCleanup = /\bgoto\s+\w*clean/i.test(afterAlloc);
    if (!usesGotoCleanup) {
      const retRegex = /if\s*\(([^)]*)\)\s*\{?\s*return\s+(?:-1|NULL|false|1)\s*;/g;
      let m: RegExpExecArray | null;
      while ((m = retRegex.exec(afterAlloc)) !== null) {
        const cond = m[1]!.trim();
        // Skip legitimate allocation-failure NULL checks (`!buf`, `buf == NULL`).
        if (cond === `!${varName}` || cond === `${varName} == NULL` || cond === `NULL == ${varName}`) {
          continue;
        }
        const beforeEarlyRet = afterAlloc.slice(0, m.index);
        if (!/\b(?:free|fclose)\s*\(/.test(beforeEarlyRet)) {
          findings.push({
            ruleId: 'c-early-return-resource-leak',
            mechanism: 'SM2-resource-leak',
            language: 'c',
            line: lineOfIndex(clean, allocMatch.index + m.index),
            message: 'Early error return after allocation/open skips free/fclose; use single goto cleanup boundary.',
          });
          break;
        }
      }
    }
  }

  // 2. Unbounded pool byte accumulation without max_retain_cap check in enclosing function.
  const poolAccMatch = /pooled_bytes\s*\+=/.exec(clean);
  if (poolAccMatch) {
    const fnScope = extractEnclosingBlock(clean, poolAccMatch.index);
    if (!/max_retain_cap/.test(fnScope)) {
      findings.push({
        ruleId: 'c-uncapped-pool-return',
        mechanism: 'SM3-watermark-ratchet',
        language: 'c',
        line: lineOfIndex(clean, poolAccMatch.index),
        message: 'Pool accumulates returned bytes without max_retain_cap guard (watermark ratchet).',
      });
    }
  }

  return findings;
}

function auditCpp(clean: string): AgingFinding[] {
  const findings: AgingFinding[] = [];

  // 1. std::thread(...).detach() breaks structured concurrency quiescence.
  const detachMatch = /\.detach\s*\(\s*\)/.exec(clean);
  if (detachMatch && /\bthread\b/.test(clean)) {
    findings.push({
      ruleId: 'cpp-detached-thread',
      mechanism: 'SM4-orphan-concurrency',
      language: 'cpp',
      line: lineOfIndex(clean, detachMatch.index),
      message: 'Detached std::thread breaks scope quiescence; prefer std::jthread or explicit join barrier.',
    });
  }

  // 2. std::vector::clear() returned to pool without capacity() check in enclosing method body.
  const pushMatch = /pool\.push_back\s*\(/.exec(clean);
  if (pushMatch) {
    const fnScope = extractEnclosingBlock(clean, pushMatch.index);
    if (/\.clear\s*\(\s*\)/.test(fnScope) && !/\.capacity\s*\(\s*\)|\.shrink_to_fit\s*\(\s*\)/.test(fnScope)) {
      findings.push({
        ruleId: 'cpp-vector-clear-ratchet',
        mechanism: 'SM3-watermark-ratchet',
        language: 'cpp',
        line: lineOfIndex(clean, pushMatch.index),
        message: 'std::vector cleared and returned to pool without capacity() ceiling check; retains peak spike memory.',
      });
    }
  }

  // 3. std::unordered_map clear/erase without bucket shrink / rehash(0) or swap rotation.
  const umapMatch = /\bunordered_map\b/.exec(clean);
  if (umapMatch && /\.clear\s*\(\s*\)/.test(clean) && !/(?:\.rehash\s*\(\s*0\s*\)|\.swap\s*\(|max_buckets|bucket_count)/.test(clean)) {
    findings.push({
      ruleId: 'cpp-unordered-map-bucket-ratchet',
      mechanism: 'SM3-watermark-ratchet',
      language: 'cpp',
      line: lineOfIndex(clean, umapMatch.index),
      message: 'std::unordered_map::clear() retains peak bucket array allocation; rotate via swap or rehash(0) at quiescence.',
    });
  }

  return findings;
}

export function detectAgingLanguage(filePath: string): AgingLanguage | null {
  const lower = filePath.toLowerCase();
  if (lower.endsWith('.go')) return 'go';
  if (lower.endsWith('.rs')) return 'rust';
  if (lower.endsWith('.ts') || lower.endsWith('.tsx') || lower.endsWith('.js') || lower.endsWith('.mjs')) {
    return 'ts';
  }
  if (lower.endsWith('.c') || lower.endsWith('.h')) return 'c';
  if (lower.endsWith('.cpp') || lower.endsWith('.cc') || lower.endsWith('.cxx') || lower.endsWith('.hpp') || lower.endsWith('.hh')) {
    return 'cpp';
  }
  return null;
}

export interface FileAgingAuditReport extends AgingAuditReport {
  fileName: string;
}

export function auditFileForAging(fileName: string, source: string): FileAgingAuditReport | null {
  const lang = detectAgingLanguage(fileName);
  if (!lang) return null;
  const base = auditSoftwareAging(lang, source);
  return {fileName, ...base};
}

export function auditSoftwareAging(language: AgingLanguage, source: string): AgingAuditReport {
  const clean = stripCommentsPreserveLines(source);
  let findings: AgingFinding[];
  switch (language) {
    case 'go':
      findings = auditGo(clean);
      break;
    case 'rust':
      findings = auditRust(clean);
      break;
    case 'ts':
      findings = auditTypeScript(clean);
      break;
    case 'c':
      findings = auditC(clean);
      break;
    case 'cpp':
      findings = auditCpp(clean);
      break;
  }
  return {
    language,
    passed: findings.length === 0,
    findings,
  };
}

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
  | 'SM26-control-plane-auth-governance';

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

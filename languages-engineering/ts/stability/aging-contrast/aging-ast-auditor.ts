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
  | 'SM16-search-input-sanitization';

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

  // 10. Search/input clipboard paste handler appends clipboardData without byte/length cap or control-char stripping (SM16).
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

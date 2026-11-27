// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * 20-Case Cross-Language AI Software Aging Evaluation Cohort (SA01-SA20).
 *
 * Independent gold policy:
 *   - 14 aging-trap negative cases across Go, Rust, TypeScript, C, and C++ (must Refuse with exact ruleId)
 *   - 6 clean deterministic steady-state positive controls including live repository sources (must Pass with 0 findings)
 */

import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {auditSoftwareAging, type AgingLanguage} from './aging-ast-auditor.ts';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');

interface GoldCase {
  id: string;
  language: AgingLanguage;
  expectedPass: boolean;
  expectedRuleId?: string;
  source: string;
}

const COHORT: GoldCase[] = [
  // ── Go aging traps (SA01-SA04) ──
  {
    id: 'SA01',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-time-after-in-loop',
    source: `
func pollLoop(ch <-chan int) {
  for {
    select {
    case v := <-ch:
      _ = v
    case <-time.After(5 * time.Second):
      return
    }
  }
}`,
  },
  {
    id: 'SA02',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-unclosed-http-body',
    source: `
func fetchStatus(url string) (int, error) {
  resp, err := http.Get(url)
  if err != nil { return 0, err }
  return resp.StatusCode, nil
}`,
  },
  {
    id: 'SA03',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-unbuffered-channel-goroutine-leak',
    source: readFileSync(
      resolve(REPO_ROOT, 'languages-engineering/go/stability/aging-contrast/bad_aging.go'),
      'utf8',
    ),
  },
  {
    id: 'SA04',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-uncapped-pool-put',
    source: `
func releaseBuf(p *sync.Pool, buf []byte) {
  p.Put(buf[:0])
}`,
  },

  // ── Rust aging traps (SA05-SA08) ──
  {
    id: 'SA05',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-unbounded-channel',
    source: `
fn start_pipeline() {
  let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
  let _ = (tx, rx);
}`,
  },
  {
    id: 'SA06',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-detached-spawn',
    source: `
fn fire_and_forget(req: Vec<u8>) {
  tokio::spawn(async move { process(req).await; });
}`,
  },
  {
    id: 'SA07',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-vec-clear-ratchet',
    source: `
fn release_vec(pool: &mut Vec<Vec<u8>>, mut buf: Vec<u8>) {
  buf.clear();
  pool.push(buf);
}`,
  },
  {
    id: 'SA08',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-mem-forget-leak',
    source: `
fn drop_guard_bad(permit: OwnedPermit) {
  std::mem::forget(permit);
}`,
  },

  // ── TypeScript / Node.js aging traps (SA09-SA12) ──
  {
    id: 'SA09',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-unbounded-interval',
    source: `
export function startPoller() {
  setInterval(() => { refreshCache(); }, 1000);
}`,
  },
  {
    id: 'SA10',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-unbounded-retry-loop',
    source: `
export async function fetchForever(url: string) {
  while (true) {
    try { return await fetch(url); } catch { continue; }
  }
}`,
  },
  {
    id: 'SA11',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-uncapped-pool-push',
    source: readFileSync(
      resolve(REPO_ROOT, 'languages-engineering/ts/stability/aging-contrast/bad_aging.ts'),
      'utf8',
    ),
  },
  {
    id: 'SA12',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-unremoved-listener',
    source: `
export function watchStream(emitter: EventEmitter, cb: () => void) {
  emitter.on('data', cb);
}`,
  },

  // ── C / C++ aging traps (SA13-SA16) ──
  {
    id: 'SA13',
    language: 'c',
    expectedPass: false,
    expectedRuleId: 'c-early-return-resource-leak',
    source: `
int load_frame(size_t n, int invalid) {
  void *buf = malloc(n);
  if (!buf) return -1;
  if (invalid) return -1;
  free(buf);
  return 0;
}`,
  },
  {
    id: 'SA14',
    language: 'c',
    expectedPass: false,
    expectedRuleId: 'c-uncapped-pool-return',
    source: readFileSync(
      resolve(REPO_ROOT, 'languages-engineering/c/stability/aging-contrast/bad_aging.c'),
      'utf8',
    ),
  },
  {
    id: 'SA15',
    language: 'cpp',
    expectedPass: false,
    expectedRuleId: 'cpp-detached-thread',
    source: `
void launch_bg() {
  std::thread worker([]() { run_job(); });
  worker.detach();
}`,
  },
  {
    id: 'SA16',
    language: 'cpp',
    expectedPass: false,
    expectedRuleId: 'cpp-vector-clear-ratchet',
    source: readFileSync(
      resolve(REPO_ROOT, 'languages-engineering/cpp/stability/aging-contrast/bad_aging.hpp'),
      'utf8',
    ),
  },

  // ── Clean deterministic steady-state positive controls across all 5 languages (SA17-SA20 + live sources) ──
  {
    id: 'SA17',
    language: 'go',
    expectedPass: true,
    source: readFileSync(
      resolve(REPO_ROOT, 'languages-engineering/go/stability/aging-contrast/deterministic_steady.go'),
      'utf8',
    ),
  },
  {
    id: 'SA18',
    language: 'ts',
    expectedPass: true,
    source: readFileSync(
      resolve(REPO_ROOT, 'languages-engineering/ts/stability/aging-contrast/deterministic_steady.ts'),
      'utf8',
    ),
  },
  {
    id: 'SA19',
    language: 'c',
    expectedPass: true,
    source: readFileSync(
      resolve(REPO_ROOT, 'languages-engineering/c/stability/aging-contrast/deterministic_steady.c'),
      'utf8',
    ),
  },
  {
    id: 'SA20',
    language: 'cpp',
    expectedPass: true,
    source: readFileSync(
      resolve(REPO_ROOT, 'languages-engineering/cpp/stability/aging-contrast/deterministic_steady.hpp'),
      'utf8',
    ),
  },

  // ── Wave-2 Aging Traps (SA21-SA26): sub-slice pinning, unbounded fanout, async blocking, map bloat ──
  {
    id: 'SA21',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-subslice-pinning',
    source: `
func extractHeader(slab []byte) []byte {
  return slab[:16]
}`,
  },
  {
    id: 'SA22',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-unbounded-goroutine-fanout',
    source: `
func fanoutAll(items []int) {
  for _, item := range items {
    go processItem(item)
  }
}`,
  },
  {
    id: 'SA23',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-blocking-in-async',
    source: `
async fn poll_worker() {
  std::thread::sleep(std::time::Duration::from_secs(1));
}`,
  },
  {
    id: 'SA24',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-unbounded-promise-all-fanout',
    source: `
export async function fetchBatch(urls: string[]) {
  return Promise.all(urls.map((u) => fetch(u)));
}`,
  },
  {
    id: 'SA25',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-unbounded-map-cache',
    source: `
export function remember(cache: Map<string, Uint8Array>, k: string, v: Uint8Array) {
  cache.set(k, v);
}`,
  },
  {
    id: 'SA26',
    language: 'cpp',
    expectedPass: false,
    expectedRuleId: 'cpp-unordered-map-bucket-ratchet',
    source: `
void reset_table(std::unordered_map<int, std::string>& tbl) {
  tbl.clear();
}`,
  },

  // ── Wave-2 Clean Steady-State Positive Controls (SA27-SA30) ──
  {
    id: 'SA27',
    language: 'go',
    expectedPass: true,
    source: `
func extractHeaderSafe(slab []byte) []byte {
  return bytes.Clone(slab[:16])
}`,
  },
  {
    id: 'SA28',
    language: 'rust',
    expectedPass: true,
    source: `
async fn poll_worker_safe() {
  tokio::task::spawn_blocking(|| { std::thread::sleep(std::time::Duration::from_millis(5)); }).await.ok();
}`,
  },
  {
    id: 'SA29',
    language: 'ts',
    expectedPass: true,
    source: `
export function rememberBounded(cache: Map<string, Uint8Array>, k: string, v: Uint8Array, maxSize: number) {
  if (cache.size >= maxSize) {
    const first = cache.keys().next().value;
    if (first !== undefined) cache.delete(first);
  }
  cache.set(k, v);
}`,
  },
  {
    id: 'SA30',
    language: 'cpp',
    expectedPass: true,
    source: `
void reset_table_safe(std::unordered_map<int, std::string>& tbl) {
  tbl.clear();
  tbl.rehash(0);
}`,
  },

  // ── Wave-3 Downstream Marlin / MyGo / UI Aging Traps (SA31-SA40) ──
  {
    id: 'SA31',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-unbounded-state-collection',
    source: `
fn upload_artifact(st: &mut BridgeState, id: String, buf: Vec<u8>) {
  st.artifacts.insert(id, buf);
}`,
  },
  {
    id: 'SA32',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-broadcast-lag-silent-drop',
    source: `
async fn watch_workbench(tx: tokio::sync::broadcast::Sender<Snap>) {
  let mut rx = tx.subscribe();
  while let Ok(snap) = rx.recv().await {
    forward(snap);
  }
}`,
  },
  {
    id: 'SA33',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-bounded-no-eviction-lockout',
    source: `
fn open_session(guard: &mut BTreeMap<String, Session>, id: String) -> Result<(), Status> {
  if guard.len() >= 64 {
    return Err(Status::resource_exhausted("host session limit reached"));
  }
  guard.insert(id, Session::new());
  Ok(())
}`,
  },
  {
    id: 'SA34',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-early-return-unjoined-goroutine',
    source: `
func followTurn(ctx context.Context, emit func(string) error) error {
  events := make(chan string, 16)
  followErr := make(chan error, 1)
  go func() {
    defer close(events)
    followErr <- stream(ctx, events)
  }()
  for ev := range events {
    if err := emit(ev); err != nil {
      return err
    }
  }
  return <-followErr
}`,
  },
  {
    id: 'SA35',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-unbounded-struct-map',
    source: `
func (m *SessionManager) Record(id, text string) {
  m.records[id] = text
}`,
  },
  {
    id: 'SA36',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-sidecar-missing-pgid',
    source: `
func spawnSidecar(bin string) (*exec.Cmd, error) {
  cmd := exec.Command(bin)
  if err := cmd.Start(); err != nil { return nil, err }
  _ = cmd.Process.Signal(syscall.SIGTERM)
  return cmd, nil
}`,
  },
  {
    id: 'SA37',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-unbudgeted-retry-loop',
    source: `
func sendForever(ctx context.Context) error {
  backoff := 100 * time.Millisecond
  for {
    if err := call(ctx); err == nil { return nil }
    timer := time.NewTimer(backoff)
    select { case <-ctx.Done(): timer.Stop(); return ctx.Err(); case <-timer.C: }
    if backoff < 2*time.Second { backoff *= 2 }
  }
}`,
  },
  {
    id: 'SA38',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-streaming-full-innerhtml-reparse',
    source: `
export function flushMarkdown(row: { raw: string; text: HTMLElement }, delta: string) {
  row.raw += delta;
  row.text.innerHTML = renderMarkdown(row.raw);
}`,
  },
  {
    id: 'SA39',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-unbounded-dom-append',
    source: `
export function addAssistantRow(messages: HTMLElement) {
  const root = document.createElement('div');
  messages.appendChild(root);
}`,
  },
  {
    id: 'SA40',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-orphan-sidemap-on-delete',
    source: `
const drafts = new Map<string, string>();
export function saveDraft(id: string, text: string) { drafts.set(id, text); }
export async function removeChat(id: string) { await ChatService.deleteSession(id); }`,
  },

  // ── Wave-3 Clean Marlin/MyGo/UI Steady-State Controls (SA41-SA45) ──
  {
    id: 'SA41',
    language: 'rust',
    expectedPass: true,
    source: `
fn upload_artifact_bounded(st: &mut BridgeState, id: String, buf: Vec<u8>) {
  if st.artifacts.len() >= MAX_ARTIFACTS {
    st.artifacts.pop_first();
  }
  st.artifacts.insert(id, buf);
}
async fn watch_workbench_resync(tx: tokio::sync::broadcast::Sender<Snap>) {
  let mut rx = tx.subscribe();
  loop {
    match rx.recv().await {
      Ok(snap) => forward(snap),
      Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => resync_snapshot(),
      Err(_) => break,
    }
  }
}`,
  },
  {
    id: 'SA42',
    language: 'go',
    expectedPass: true,
    source: `
func followTurnStructured(ctx context.Context, emit func(string) error) error {
  events := make(chan string, 16)
  followCtx, cancel := context.WithCancel(ctx)
  followErr := make(chan error, 1)
  go func() {
    defer close(events)
    followErr <- stream(followCtx, events)
  }()
  defer func() { cancel(); <-followErr }()
  for ev := range events {
    if err := emit(ev); err != nil {
      return err
    }
  }
  return nil
}`,
  },
  {
    id: 'SA43',
    language: 'go',
    expectedPass: true,
    source: `
func spawnSidecarIsolated(bin string) (*exec.Cmd, error) {
  cmd := exec.Command(bin)
  cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
  if err := cmd.Start(); err != nil { return nil, err }
  _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
  return cmd, nil
}`,
  },
  {
    id: 'SA44',
    language: 'ts',
    expectedPass: true,
    source: `
export function appendWindowedRow(messages: HTMLElement, maxVisibleNodes: number) {
  const root = document.createElement('div');
  messages.appendChild(root);
  while (messages.children.length > maxVisibleNodes) {
    messages.firstElementChild?.remove();
  }
}
export function appendBlockIncremental(container: HTMLElement, blockHtml: string) {
  const block = document.createElement('div');
  block.innerHTML = renderDeltaBlock(blockHtml);
  container.appendChild(block);
}`,
  },
  {
    id: 'SA45',
    language: 'ts',
    expectedPass: true,
    source: `
const drafts = new Map<string, string>();
export function saveDraft(id: string, text: string) { drafts.set(id, text); }
export async function removeChat(id: string) {
  drafts.delete(id);
  await ChatService.deleteSession(id);
}`,
  },

  // ── Wave-4 Real-World Calibration Controls (SA46-SA50, derived from 224-file marlin-mygo scan) ──
  {
    id: 'SA46',
    language: 'go',
    expectedPass: true,
    source: `
func (r *WebViewRuntime) ensureRules() {
  r.rulesOnce.Do(func() { compileRules() })
}`,
  },
  {
    id: 'SA47',
    language: 'go',
    expectedPass: true,
    source: `
func (c *ArtifactCAS) PutVerified(mime string, data []byte) error {
  return c.Put(mime, data)
}`,
  },
  {
    id: 'SA48',
    language: 'go',
    expectedPass: true,
    source: `
func (s *Sheet) memo(key string, st Style) {
  if len(s.cache) < 512 {
    s.cache[key] = st
  }
}`,
  },
  {
    id: 'SA49',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-unbounded-struct-map',
    source: `
func (e *ModuleEngine) CompileOrGet(sum [32]byte, compiled Module) Module {
  e.cache[sum] = compiled
  return compiled
}`,
  },
  {
    id: 'SA50',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-unbounded-struct-map',
    source: `
func (c *JWKSCache) Fetch(url string, set KeySet) KeySet {
  c.entries[url] = set
  return set
}`,
  },

  // ── Wave-5 Search Stability & Single-Flight Concurrency Controls (SA51-SA60) ──
  {
    id: 'SA51',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-async-inflight-no-drop-guard',
    source: `
async fn ensure_synced(&self) {
  if self.in_flight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
    return;
  }
  run_blocking_sync().await;
  self.in_flight.store(false, Ordering::Release);
  self.notify.notify_waiters();
}`,
  },
  {
    id: 'SA52',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-notify-notified-unarmed-check',
    source: `
async fn wait_inflight(&self) {
  let notified = self.notify.notified();
  if self.in_flight.load(Ordering::Acquire) {
    notified.await;
  }
}`,
  },
  {
    id: 'SA53',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-unfenced-async-search-apply',
    source: `
fn apply_dsl_result(&mut self, rows: Vec<HelmCandidate>) {
  self.search_candidates = rows;
  self.rebuild_view();
}`,
  },
  {
    id: 'SA54',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-non-monotonic-gen-cancel',
    source: `
func (b *RustSearchBridge) QueryAsync(gen uint64) {
  ctx, cancel := context.WithCancel(context.Background())
  b.mu.Lock()
  if b.activeCancel != nil {
    b.activeCancel()
  }
  b.activeCancel = cancel
  b.activeGen = gen
  b.mu.Unlock()
  _ = ctx
}`,
  },
  {
    id: 'SA55',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-slice-truncate-without-clear',
    source: `
func (e *HelmEngine) BeginQuery(q string) {
  for i := range e.sources {
    e.sources[i].items = e.sources[i].items[:0]
  }
}`,
  },
  {
    id: 'SA56',
    language: 'rust',
    expectedPass: true,
    source: `
struct SyncLeaderGuard<'a> { coord: &'a Coord }
impl Drop for SyncLeaderGuard<'_> {
  fn drop(&mut self) {
    self.coord.in_flight.store(false, Ordering::Release);
    self.coord.notify.notify_waiters();
  }
}
async fn ensure_synced(&self) {
  if self.in_flight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
    let notified = self.notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    if self.in_flight.load(Ordering::Acquire) {
      notified.await;
    }
    return;
  }
  let _guard = SyncLeaderGuard { coord: self };
  run_blocking_sync().await;
}`,
  },
  {
    id: 'SA57',
    language: 'rust',
    expectedPass: true,
    source: `
fn apply_dsl_result(&mut self, expected_epoch: u64, rows: Vec<HelmCandidate>) {
  if expected_epoch != self.epoch {
    return;
  }
  self.search_candidates = rows;
  self.rebuild_view();
}`,
  },
  {
    id: 'SA58',
    language: 'go',
    expectedPass: true,
    source: `
func (b *RustSearchBridge) QueryAsync(gen uint64) {
  ctx, cancel := context.WithCancel(context.Background())
  b.mu.Lock()
  if gen < b.activeGen {
    b.mu.Unlock()
    cancel()
    return
  }
  if b.activeCancel != nil {
    b.activeCancel()
  }
  b.activeCancel = cancel
  b.activeGen = gen
  b.mu.Unlock()
  _ = ctx
}`,
  },
  {
    id: 'SA59',
    language: 'go',
    expectedPass: true,
    source: `
func (e *HelmEngine) BeginQuery(q string) {
  for i := range e.sources {
    clear(e.sources[i].items)
    if cap(e.sources[i].items) > 4096 {
      e.sources[i].items = nil
    } else {
      e.sources[i].items = e.sources[i].items[:0]
    }
  }
}`,
  },
  {
    id: 'SA60',
    language: 'ts',
    expectedPass: true,
    source: `
export function appendSearchViewport(list: HTMLElement, maxVisibleNodes: number) {
  const row = document.createElement('div');
  list.appendChild(row);
  while (list.children.length > maxVisibleNodes) {
    list.firstElementChild?.remove();
  }
}`,
  },

  // ── Wave-6 Priority-Isolated Mailbox (SM11) & Empirical Marlin Calibration Controls (SA61-SA68) ──
  {
    id: 'SA61',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-unbounded-vecdeque-mailbox',
    source: `
struct LinkedSearchDslMailbox {
  rx: tokio::sync::mpsc::Receiver<Job>,
  fast_queue: std::collections::VecDeque<Job>,
}
impl LinkedSearchDslMailbox {
  fn ingest_pending(&mut self) {
    while let Ok(job) = self.rx.try_recv() {
      self.fast_queue.push_back(job);
    }
  }
}`,
  },
  {
    id: 'SA62',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-unbounded-goroutine-fanout',
    source: `
func (s *FederationSupervisor) ProbeAll(ctx context.Context, metas []Meta) {
  var wg sync.WaitGroup
  for _, m := range metas {
    wg.Add(1)
    go func(id string) {
      defer wg.Done()
      ping(ctx, id)
    }(m.ID)
  }
  wg.Wait()
}`,
  },
  {
    id: 'SA63',
    language: 'go',
    expectedPass: true,
    source: `
func (r *Recorder) Start(ctx context.Context) {
  for {
    select { case <-ctx.Done(): return }
  }
}
func (r *Recorder) Stop(doneCh <-chan struct{}) {
  select {
  case <-doneCh:
  case <-time.After(500 * time.Millisecond):
  }
}`,
  },
  {
    id: 'SA64',
    language: 'go',
    expectedPass: true,
    source: `
func wireUI(items []string, probe func()) {
  for _, item := range items {
    _ = item
  }
  onClick := func() {
    go func() { probe() }()
  }
  _ = onClick
}`,
  },
  {
    id: 'SA65',
    language: 'go',
    expectedPass: true,
    source: `
func (d *Driver) loop(ctx context.Context) {
  for {
    if ctx.Err() != nil { return }
    hbCtx, hbCancel := context.WithCancel(ctx)
    hbDone := make(chan struct{})
    go func() {
      defer close(hbDone)
      <-hbCtx.Done()
    }()
    hbCancel()
    <-hbDone
  }
}`,
  },
  {
    id: 'SA66',
    language: 'go',
    expectedPass: true,
    source: `
func (r *ResilientSidecar) recoverLoop() {
  backoff := 50 * time.Millisecond
  for attempt := 1; ; attempt++ {
    if r.cfg.MaxRestarts > 0 && attempt > r.cfg.MaxRestarts {
      return
    }
    backoff *= 2
  }
}`,
  },
  {
    id: 'SA67',
    language: 'go',
    expectedPass: true,
    source: `
type FrameScheduler struct {
  history []time.Duration
  histPos int
}
func (s *FrameScheduler) Record(d time.Duration) {
  s.history[s.histPos] = d
  s.histPos = (s.histPos + 1) % len(s.history)
}`,
  },
  {
    id: 'SA68',
    language: 'rust',
    expectedPass: true,
    source: `
const MAX_FAST_DSL_JOBS: usize = 64;
struct LinkedSearchDslMailbox {
  fast_rx: tokio::sync::mpsc::Receiver<Job>,
  fast_queue: std::collections::VecDeque<Job>,
}
impl LinkedSearchDslMailbox {
  fn ingest_pending(&mut self) {
    while let Ok(job) = self.fast_rx.try_recv() {
      if self.fast_queue.len() >= MAX_FAST_DSL_JOBS {
        self.fast_queue.retain(|j| !j.reply.is_closed());
      }
      if self.fast_queue.len() < MAX_FAST_DSL_JOBS {
        self.fast_queue.push_back(job);
      }
    }
  }
}`,
  },

  // ── Wave-7 Adversarial IPC Half-Open & IME Composition Traps + Positive Controls (SA69-SA76, SM12-SM14) ──
  {
    id: 'SA69',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-reconnect-without-close',
    source: `
func (c *BridgeClient) Reconnect(dial func() Stream) {
  c.stream = dial()
}`,
  },
  {
    id: 'SA70',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-unfenced-stream-reconnect',
    source: `
impl GrpcBridge {
  fn reconnect(&mut self, next: StreamHandle) {
    self.stream = Some(next);
  }
}`,
  },
  {
    id: 'SA71',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-ime-unguarded-enter-submit',
    source: `
export function onKeyDown(event: KeyboardEvent, runQuery: () => void) {
  if (event.key === 'Enter') {
    runQuery();
  }
}`,
  },
  {
    id: 'SA72',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-ime-blur-orphan-preedit',
    source: `
class SearchBox {
  focused = true;
  composing = false;
  preedit = '';
  onCompositionStart() { this.composing = true; }
  onBlur() {
    this.focused = false;
  }
}`,
  },
  {
    id: 'SA73',
    language: 'go',
    expectedPass: true,
    source: `
func (c *BridgeClient) Reconnect(dial func() Stream) {
  if c.stream != nil {
    _ = c.stream.Close()
  }
  c.epoch++
  c.stream = dial()
}`,
  },
  {
    id: 'SA74',
    language: 'rust',
    expectedPass: true,
    source: `
impl GrpcBridge {
  fn reconnect(&mut self, next: StreamHandle) {
    if let Some(old) = self.stream.take() {
      old.abort();
    }
    self.session_epoch += 1;
    self.stream = Some(next);
  }
}`,
  },
  {
    id: 'SA75',
    language: 'ts',
    expectedPass: true,
    source: `
export function onKeyDown(event: KeyboardEvent, runQuery: () => void) {
  if (event.isComposing || event.keyCode === 229) return;
  if (event.key === 'Enter') {
    runQuery();
  }
}`,
  },
  {
    id: 'SA76',
    language: 'ts',
    expectedPass: true,
    source: `
class SearchBox {
  focused = true;
  composing = false;
  preedit = '';
  onCompositionStart() { this.composing = true; }
  onBlur() {
    this.focused = false;
    this.composing = false;
    this.preedit = '';
  }
}`,
  },

  // ── Wave-8 Search Index Snapshot Isolation & Single-Flight Follower Re-Election (SA77-SA80, SM15) ──
  {
    id: 'SA77',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-cold-open-split-brain',
    source: `
impl SharedSearchIndexSlot {
  pub fn get_or_open(&self, workspace: &Path) -> Arc<RwLock<WorkspaceSearchIndex>> {
    if let Ok(guard) = self.inner.read() {
      if let Some(existing) = guard.as_ref() {
        return existing.clone();
      }
    }
    let opened = Arc::new(RwLock::new(open_index(workspace)));
    self.attach(opened.clone());
    opened
  }
}`,
  },
  {
    id: 'SA78',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-singleflight-cancel-cascade',
    source: `
impl SingleFlightQueryCache {
  async fn wait_or_lead(&self, key: String, mut rx: watch::Receiver<Option<Result<String, String>>>) -> Result<String, String> {
    let _ = &self.in_flight;
    loop {
      if let Some(res) = rx.borrow().clone() {
        return res;
      }
      if rx.changed().await.is_err() {
        return Err("coalesced search query cancelled".to_owned());
      }
    }
  }
}`,
  },
  {
    id: 'SA79',
    language: 'rust',
    expectedPass: true,
    source: `
impl SharedSearchIndexSlot {
  pub fn get_or_open(&self, workspace: &Path) -> Arc<RwLock<WorkspaceSearchIndex>> {
    let canonical = canonicalize_root(workspace);
    if let Ok(guard) = self.inner.read() {
      if let Some(existing) = guard.as_ref() {
        if existing.workspace_root == canonical {
          return existing.index.clone();
        }
      }
    }
    let _open_guard = self.open_lock.lock();
    if let Ok(guard) = self.inner.read() {
      if let Some(existing) = guard.as_ref() {
        if existing.workspace_root == canonical {
          return existing.index.clone();
        }
      }
    }
    let opened = Arc::new(RwLock::new(open_index(&canonical)));
    self.attach(opened.clone());
    opened
  }
}`,
  },
  {
    id: 'SA80',
    language: 'rust',
    expectedPass: true,
    source: `
impl SingleFlightQueryCache {
  async fn wait_or_lead(&self, key: String, mut rx: watch::Receiver<Option<Result<String, String>>>) -> Result<String, String> {
    let _ = &self.in_flight;
    'election: loop {
      if let Some(res) = rx.borrow().clone() {
        return res;
      }
      if rx.changed().await.is_err() {
        continue 'election;
      }
    }
  }
}`,
  },

  // ── Wave-9 Search-Box Input Sanitization & Bounded Clipboard Paste Cap (SA81-SA84, SM16) ──
  {
    id: 'SA81',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-paste-bypasses-input-cap',
    source: `
const MAX_HELM_INPUT_BYTES: usize = 2_048;
impl HelmOverlay {
  fn edit(&mut self, action: Action, yank_register: &mut String) {
    match action {
      Action::PasteSelection => {
        let clean: String = yank_register.chars().filter(|c| !c.is_control()).collect();
        self.editor.insert_text(&clean);
      }
      _ => {}
    }
  }
}`,
  },
  {
    id: 'SA82',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-search-input-uncapped-paste',
    source: `
export function bindSearchPaste(input: HTMLInputElement, ac: AbortController) {
  input.addEventListener('paste', (ev: ClipboardEvent) => {
    const pasted = ev.clipboardData?.getData('text') ?? '';
    input.value += pasted;
  }, { signal: ac.signal });
}`,
  },
  {
    id: 'SA83',
    language: 'rust',
    expectedPass: true,
    source: `
const MAX_HELM_INPUT_BYTES: usize = 2_048;
impl HelmOverlay {
  fn edit(&mut self, action: Action, yank_register: &mut String) {
    match action {
      Action::PasteSelection => {
        self.insert_text(yank_register);
      }
      _ => {}
    }
  }
}`,
  },
  {
    id: 'SA84',
    language: 'ts',
    expectedPass: true,
    source: `
const MAX_SEARCH_CHARS = 2048;
export function bindSearchPaste(input: HTMLInputElement, ac: AbortController) {
  input.addEventListener('paste', (ev: ClipboardEvent) => {
    const raw = ev.clipboardData?.getData('text') ?? '';
    const clean = raw.replace(/[\\u0000-\\u001f]/g, '').slice(0, MAX_SEARCH_CHARS);
    input.value = (input.value + clean).slice(0, MAX_SEARCH_CHARS);
  }, { signal: ac.signal });
}`,
  },

  // ── Wave-10 Streaming Output Budget, Pre-Allocation Cap & Thinking Accounting (SA85-SA90, SM17) ──
  {
    id: 'SA85',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-sse-complete-ignores-output-limit',
    source: `
struct WeaverModelGateway {
  stream_output_limit: Option<usize>,
}
impl WeaverModelGateway {
  async fn complete_sse(&self, mut stream: TurnStream) -> Result<String, String> {
    let mut text = String::new();
    while let Some(event) = stream.next().await {
      match event {
        TurnEvent::Text(delta) => text.push_str(&delta),
        TurnEvent::Thinking(_) => {}
        TurnEvent::Finished => return Ok(text),
      }
    }
    Err("incomplete".into())
  }
}`,
  },
  {
    id: 'SA86',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-http-body-buffer-before-cap',
    source: `
const MAX_OPENAI_HTTP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
async fn read_completion(resp: reqwest::Response) -> Result<Vec<u8>, String> {
  let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
  if bytes.len() > MAX_OPENAI_HTTP_RESPONSE_BYTES {
    return Err("exceeded 4 MiB limit".into());
  }
  Ok(bytes.to_vec())
}`,
  },
  {
    id: 'SA87',
    language: 'ts',
    expectedPass: false,
    expectedRuleId: 'ts-http-body-buffer-before-cap',
    source: `
const MAX_LLM_RESPONSE_BYTES = 4 * 1024 * 1024;
export async function fetchCompletion(url: string): Promise<string> {
  const resp = await fetch(url);
  const body = await resp.text();
  if (body.length > MAX_LLM_RESPONSE_BYTES) {
    throw new Error('response exceeded safety limit');
  }
  return body;
}`,
  },
  {
    id: 'SA88',
    language: 'rust',
    expectedPass: true,
    source: `
struct WeaverModelGateway {
  stream_output_limit: Option<usize>,
}
impl WeaverModelGateway {
  async fn complete_sse(&self, mut stream: TurnStream) -> Result<String, String> {
    let mut text = String::new();
    let mut thinking_bytes = 0usize;
    while let Some(event) = stream.next().await {
      match event {
        TurnEvent::Text(delta) => {
          if let Some(limit) = self.stream_output_limit {
            if text.len().saturating_add(thinking_bytes).saturating_add(delta.len()) > limit {
              return Err("OutputLimit".into());
            }
          }
          text.push_str(&delta);
        }
        TurnEvent::Thinking(delta) => {
          if let Some(limit) = self.stream_output_limit {
            if text.len().saturating_add(thinking_bytes).saturating_add(delta.len()) > limit {
              return Err("OutputLimit".into());
            }
          }
          thinking_bytes += delta.len();
        }
        TurnEvent::Finished => return Ok(text),
      }
    }
    Err("incomplete".into())
  }
}`,
  },
  {
    id: 'SA89',
    language: 'rust',
    expectedPass: true,
    source: `
const MAX_OPENAI_HTTP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
async fn read_completion(mut resp: reqwest::Response) -> Result<Vec<u8>, String> {
  if resp.content_length().is_some_and(|n| n > MAX_OPENAI_HTTP_RESPONSE_BYTES as u64) {
    return Err("exceeded 4 MiB limit".into());
  }
  let mut buf = Vec::new();
  while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
    if buf.len().checked_add(chunk.len()).is_none_or(|n| n > MAX_OPENAI_HTTP_RESPONSE_BYTES) {
      return Err("exceeded 4 MiB limit".into());
    }
    buf.extend_from_slice(&chunk);
  }
  Ok(buf)
}`,
  },
  {
    id: 'SA90',
    language: 'ts',
    expectedPass: true,
    source: `
const MAX_LLM_RESPONSE_BYTES = 4 * 1024 * 1024;
export async function fetchCompletion(url: string): Promise<Uint8Array> {
  const resp = await fetch(url);
  const declared = Number(resp.headers.get('content-length') ?? '0');
  if (declared > MAX_LLM_RESPONSE_BYTES) throw new Error('exceeded limit');
  const reader = resp.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      if (total + value.byteLength > MAX_LLM_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('exceeded limit');
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return new Uint8Array(total);
}`,
  },

  // ── Wave-11 Structured Task Abort-on-Drop, Dirty DB Pool Lease & Bounded Fan-Out (SA91-SA96, SM19) ──
  {
    id: 'SA91',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-async-joinhandle-vec-drop-detach',
    source: `
async fn dispatch_hooks(regs: Vec<Reg>) -> Vec<Summary> {
  let mut async_runs: Vec<(Reg, tokio::task::JoinHandle<Summary>)> = Vec::new();
  for r in regs {
    let task = tokio::spawn(async move { r.exec().await });
    async_runs.push((r, task));
  }
  let mut out = Vec::new();
  for (r, task) in async_runs {
    if let Ok(s) = task.await { out.push(s); }
  }
  out
}`,
  },
  {
    id: 'SA92',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-joinset-unbounded-fanout',
    source: `
async fn run_atomic_effect_batch(effects: Vec<Effect>) -> Vec<Receipt> {
  let mut join_set = tokio::task::JoinSet::new();
  for (idx, effect) in effects.into_iter().enumerate() {
    join_set.spawn(async move { (idx, execute(effect).await) });
  }
  let mut out = Vec::new();
  while let Some(res) = join_set.join_next().await {
    if let Ok((_, r)) = res { out.push(r); }
  }
  out
}`,
  },
  {
    id: 'SA93',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-pool-lease-returns-dirty-tx',
    source: `
struct TursoConnectionLease {
  connection: Option<Conn>,
  sender: tokio::sync::mpsc::Sender<Conn>,
}
impl Drop for TursoConnectionLease {
  fn drop(&mut self) {
    if let Some(connection) = self.connection.take() {
      let _ = self.sender.try_send(connection);
    }
  }
}
async fn begin_tx(conn: &Conn) {
  let _ = conn.execute("BEGIN CONCURRENT", ()).await;
}`,
  },
  {
    id: 'SA94',
    language: 'rust',
    expectedPass: true,
    source: `
struct AbortOnDropHandle<T>(Option<tokio::task::JoinHandle<T>>);
impl<T> Drop for AbortOnDropHandle<T> {
  fn drop(&mut self) {
    if let Some(handle) = self.0.take() { handle.abort(); }
  }
}
async fn dispatch_hooks(regs: Vec<Reg>) -> Vec<Summary> {
  let mut async_runs = Vec::new();
  for r in regs {
    let task = AbortOnDropHandle(Some(tokio::spawn(async move { r.exec().await })));
    async_runs.push((r, task));
  }
  let mut out = Vec::new();
  for (r, mut task) in async_runs {
    let res = task.0.as_mut().unwrap().await;
    task.0 = None;
    if let Ok(s) = res { out.push(s); }
  }
  out
}`,
  },
  {
    id: 'SA95',
    language: 'rust',
    expectedPass: true,
    source: `
const MAX_CONCURRENT_ATOMIC_EFFECTS: usize = 16;
async fn run_atomic_effect_batch(effects: Vec<Effect>) -> Vec<Receipt> {
  let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_ATOMIC_EFFECTS));
  let mut join_set = tokio::task::JoinSet::new();
  for (idx, effect) in effects.into_iter().enumerate() {
    let permit = permits.clone().acquire_owned().await.unwrap();
    join_set.spawn(async move {
      let _permit = permit;
      (idx, execute(effect).await)
    });
  }
  let mut out = Vec::new();
  while let Some(res) = join_set.join_next().await {
    if let Ok((_, r)) = res { out.push(r); }
  }
  out
}`,
  },
  {
    id: 'SA96',
    language: 'rust',
    expectedPass: true,
    source: `
struct TursoConnectionLease {
  connection: Option<Conn>,
  sender: tokio::sync::mpsc::Sender<Conn>,
  tx_active: bool,
}
impl Drop for TursoConnectionLease {
  fn drop(&mut self) {
    if let Some(connection) = self.connection.take() {
      if !self.tx_active {
        let _ = self.sender.try_send(connection);
      }
    }
  }
}
async fn begin_tx(conn: &Conn) {
  let _ = conn.execute("BEGIN CONCURRENT", ()).await;
}`,
  },
  // --- SM20: Bounded subprocess pipe capture, drain-to-sink & bounded line framing (SA97-SA102) ---
  {
    id: 'SA97',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-subprocess-buffer-before-truncate',
    source: `
async fn run_sandbox(child: ManagedChild, max_bytes: usize) -> (Vec<u8>, Vec<u8>) {
  let output = child.wait_with_output().await.unwrap();
  let mut stdout = output.stdout;
  let mut stderr = output.stderr;
  stdout.truncate(max_bytes);
  stderr.truncate(max_bytes);
  (stdout, stderr)
}`,
  },
  {
    id: 'SA98',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-subprocess-unbounded-read-line',
    source: `
fn read_boot_handshake(stdout: std::process::ChildStdout) -> Option<String> {
  let mut reader = std::io::BufReader::new(stdout);
  let mut line = String::new();
  if reader.read_line(&mut line).ok().unwrap_or(0) == 0 {
    return None;
  }
  Some(line)
}`,
  },
  {
    id: 'SA99',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-subprocess-unbounded-output',
    source: `
package runner
import "os/exec"
func runBounded(cmd *exec.Cmd, maxBytes int) ([]byte, error) {
  out, err := cmd.CombinedOutput()
  if len(out) > maxBytes {
    out = out[:maxBytes]
  }
  return out, err
}`,
  },
  {
    id: 'SA100',
    language: 'rust',
    expectedPass: true,
    source: `
async fn run_sandbox_safe(child: ManagedChild, max_bytes: usize) -> (Vec<u8>, Vec<u8>) {
  let output = child.wait_with_bounded_output(max_bytes).await.unwrap();
  (output.stdout, output.stderr)
}`,
  },
  {
    id: 'SA101',
    language: 'rust',
    expectedPass: true,
    source: `
const MAX_ASP_BOOT_LINE_BYTES: u64 = 64 * 1024;
fn read_boot_handshake_safe(stdout: std::process::ChildStdout) -> Option<String> {
  use std::io::{BufRead, Read};
  let mut reader = std::io::BufReader::new(stdout).take(MAX_ASP_BOOT_LINE_BYTES + 1);
  let mut line = String::new();
  let n = reader.read_line(&mut line).ok()?;
  if n == 0 || (n as u64) > MAX_ASP_BOOT_LINE_BYTES {
    return None;
  }
  Some(line)
}`,
  },
  {
    id: 'SA102',
    language: 'go',
    expectedPass: true,
    source: `
package runner
import (
  "bytes"
  "io"
  "os/exec"
)
func runBoundedSafe(cmd *exec.Cmd, maxBytes int64) ([]byte, error) {
  stdout, err := cmd.StdoutPipe()
  if err != nil { return nil, err }
  if err := cmd.Start(); err != nil { return nil, err }
  var buf bytes.Buffer
  _, _ = io.Copy(&buf, io.LimitReader(stdout, maxBytes))
  _, _ = io.Copy(io.Discard, stdout)
  return buf.Bytes(), cmd.Wait()
}`,
  },
  // --- SM21: Crash-safe atomic persistence, unique temp staging & fsync ordering (SA103-SA108) ---
  {
    id: 'SA103',
    language: 'rust',
    expectedPass: false,
    expectedRuleId: 'rust-atomic-write-shared-tmp-or-no-fsync',
    source: `
fn save_checkpoint_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
  let tmp = path.with_extension("checkpoint.tmp");
  std::fs::write(&tmp, bytes)?;
  std::fs::rename(&tmp, path)?;
  Ok(())
}`,
  },
  {
    id: 'SA104',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-atomic-write-shared-tmp-or-no-fsync',
    source: `
package vault
import "os"
func writeAtomicBytes(path string, data []byte) error {
  tmp := path + ".tmp"
  if err := os.WriteFile(tmp, data, 0o600); err != nil {
    return err
  }
  return os.Rename(tmp, path)
}`,
  },
  {
    id: 'SA105',
    language: 'go',
    expectedPass: false,
    expectedRuleId: 'go-state-file-non-atomic-overwrite',
    source: `
package shell
import (
  "os"
  "path/filepath"
)
func SaveLayoutSpecFile(path string, raw []byte) error {
  if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
    return err
  }
  return os.WriteFile(path, raw, 0o644)
}`,
  },
  {
    id: 'SA106',
    language: 'rust',
    expectedPass: true,
    source: `
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
static SEQ: AtomicU64 = AtomicU64::new(0);
fn save_checkpoint_file_safe(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
  let seq = SEQ.fetch_add(1, Ordering::Relaxed);
  let tmp = path.with_extension(format!("checkpoint.{}.{seq}.tmp", std::process::id()));
  let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
  f.write_all(bytes)?;
  f.sync_all()?;
  drop(f);
  std::fs::rename(&tmp, path)?;
  Ok(())
}`,
  },
  {
    id: 'SA107',
    language: 'go',
    expectedPass: true,
    source: `
package vault
import (
  "os"
  "path/filepath"
)
func writeAtomicBytesSafe(path string, data []byte) error {
  f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
  if err != nil { return err }
  tmp := f.Name()
  defer os.Remove(tmp)
  if _, err := f.Write(data); err != nil { _ = f.Close(); return err }
  if err := f.Sync(); err != nil { _ = f.Close(); return err }
  if err := f.Close(); err != nil { return err }
  return os.Rename(tmp, path)
}`,
  },
  {
    id: 'SA108',
    language: 'go',
    expectedPass: true,
    source: `
package shell
import (
  "os"
  "path/filepath"
)
func SaveLayoutSpecFile(path string, raw []byte) error {
  if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
    return err
  }
  return writeFileAtomically(path, raw, 0o644)
}`,
  },
];

describe('Multi-Language Software Aging AST Auditor Benchmark (SA01-SA108)', () => {
  test('achieves 108/108 exact independent-gold match (tp=61, tn=47, fp=0, fn=0) across Go, Rust, TS, C, C++', () => {
    let tp = 0;
    let tn = 0;
    let fp = 0;
    let fn = 0;

    for (const c of COHORT) {
      const report = auditSoftwareAging(c.language, c.source);
      if (c.expectedPass) {
        if (report.passed) tn += 1;
        else fp += 1;
        expect(report.passed, `${c.id} expected pass, got ${JSON.stringify(report.findings)}`).toBe(true);
      } else {
        if (!report.passed) tp += 1;
        else fn += 1;
        expect(report.passed, `${c.id} expected refusal (${c.expectedRuleId})`).toBe(false);
        expect(
          report.findings.some((f) => f.ruleId === c.expectedRuleId),
          `${c.id} missing expected rule ${c.expectedRuleId}, got ${JSON.stringify(report.findings)}`,
        ).toBe(true);
      }
    }

    expect({tp, tn, fp, fn}).toEqual({tp: 61, tn: 47, fp: 0, fn: 0});
  });

  test('clean Rust deterministic buffer pool & bounded retry passes with 0 findings', () => {
    const cleanRust = `
fn release_vec(pool: &mut Vec<Vec<u8>>, mut buf: Vec<u8>, max_retain: usize, slot_cap: usize) {
  buf.clear();
  if buf.capacity() > max_retain || pool.len() >= slot_cap {
    drop(buf);
    return;
  }
  pool.push(buf);
}`;
    const report = auditSoftwareAging('rust', cleanRust);
    expect(report.passed).toBe(true);
    expect(report.findings).toEqual([]);
  });
});

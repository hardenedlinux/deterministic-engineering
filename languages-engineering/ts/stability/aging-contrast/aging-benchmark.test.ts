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
];

describe('Multi-Language Software Aging AST Auditor Benchmark (SA01-SA80)', () => {
  test('achieves 80/80 exact independent-gold match (tp=47, tn=33, fp=0, fn=0) across Go, Rust, TS, C, C++', () => {
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

    expect({tp, tn, fp, fn}).toEqual({tp: 47, tn: 33, fp: 0, fn: 0});
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

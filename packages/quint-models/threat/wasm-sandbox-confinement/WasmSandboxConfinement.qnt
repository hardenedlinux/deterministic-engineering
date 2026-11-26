// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.wasm-sandbox-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel wasm-bounds-check step=stepBoundsBypass max-steps=6 itf="h.maxAccessedAddr >= h.guestMemSize"
// @countermodel wasi-capability-handle step=stepAmbientFdForgery max-steps=6 itf="not(subseteq(h.usedHandles, h.grantedHandles))"
// @countermodel preopen-path-confinement step=stepPathTraversal max-steps=6 itf="h.hostRootEscaped == true"
// Limits: Finite Wasm linear-memory and WASI handle/path abstraction; does not model Spectre v1 speculative execution, JIT compiler miscompilation, or kernel symlink race TOCTOU.
module wasm_sandbox_confinement {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { guestMemSize: int, grantedHandles: Set[int], maxAccessedAddr: int, usedHandles: Set[int], hostRootEscaped: bool }
  var h: State
  action init = h' = { guestMemSize: 64, grantedHandles: Set(1), maxAccessedAddr: 0, usedHandles: Set(), hostRootEscaped: false }
  action guestMemAccessAs(addr: int): bool = if ((addr >= 0 and addr < h.guestMemSize)) h' = h.with("maxAccessedAddr", if (addr > h.maxAccessedAddr) addr else h.maxAccessedAddr) else h' = h
  action guestMemAccess = { nondet addr = Set(0, 32, 63, 100).oneOf()
    guestMemAccessAs(addr) }
  action guestHostcallAs(handle: int, escapesRoot: bool): bool = if ((h.grantedHandles.contains(handle) and not(escapesRoot))) h' = h.with("usedHandles", h.usedHandles.union(Set(handle))).with("hostRootEscaped", (h.hostRootEscaped or escapesRoot)) else h' = h
  action guestHostcall = { nondet handle = Set(1, 2, 3).oneOf()
    nondet escapesRoot = Set(false, true).oneOf()
    guestHostcallAs(handle, escapesRoot) }
  action grantNetHandle = if (not(h.grantedHandles.contains(2))) h' = h.with("grantedHandles", h.grantedHandles.union(Set(2))) else h' = h
  action step = any { guestMemAccess, guestHostcall, grantNetHandle }
  val safety = (h.maxAccessedAddr < h.guestMemSize and h.usedHandles.subseteq(h.grantedHandles) and not(h.hostRootEscaped))
  // Countermodel threat.wasm-sandbox-confinement.bounds-check-bypass (dropped guard: wasm-bounds-check)
  action guestMemNoBounds(addr: int): bool = if (true) h' = h.with("maxAccessedAddr", if (addr > h.maxAccessedAddr) addr else h.maxAccessedAddr) else h' = h
  action stepBoundsBypass = any { step, { nondet addr = Set(0, 32, 63, 100).oneOf()
    guestMemNoBounds(addr) } }
  // Countermodel threat.wasm-sandbox-confinement.ambient-fd-forgery (dropped guard: wasi-capability-handle)
  action guestHostcallNoCap(handle: int, escapesRoot: bool): bool = if ((true and not(escapesRoot))) h' = h.with("usedHandles", h.usedHandles.union(Set(handle))).with("hostRootEscaped", (h.hostRootEscaped or escapesRoot)) else h' = h
  action stepAmbientFdForgery = any { step, { nondet handle = Set(1, 2, 3).oneOf()
    nondet escapesRoot = Set(false, true).oneOf()
    guestHostcallNoCap(handle, escapesRoot) } }
  // Countermodel threat.wasm-sandbox-confinement.preopen-path-traversal (dropped guard: preopen-path-confinement)
  action guestHostcallNoPathConfine(handle: int, escapesRoot: bool): bool = if ((h.grantedHandles.contains(handle) and true)) h' = h.with("usedHandles", h.usedHandles.union(Set(handle))).with("hostRootEscaped", (h.hostRootEscaped or escapesRoot)) else h' = h
  action stepPathTraversal = any { step, { nondet handle = Set(1, 2, 3).oneOf()
    nondet escapesRoot = Set(false, true).oneOf()
    guestHostcallNoPathConfine(handle, escapesRoot) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validSandboxAccessTest = init.then(guestMemAccessAs(63)).then(guestHostcallAs(1, false)).then(all { assert(h.maxAccessedAddr == 63), assert(h.usedHandles.contains(1)), assert(safety), h' = h })
  run oobAndPathTraversalBlockedTest = init.then(guestMemAccessAs(100)).then(guestHostcallAs(3, false)).then(guestHostcallAs(1, true)).then(all { assert(h.maxAccessedAddr == 0), assert(h.usedHandles == Set()), assert(not(h.hostRootEscaped)), assert(safety), h' = h })
  run boundsBypassCountermodelTest = init.then(guestMemNoBounds(100)).then(checkUnsafe)
  run ambientFdCountermodelTest = init.then(guestHostcallNoCap(3, false)).then(checkUnsafe)
  run pathTraversalCountermodelTest = init.then(guestHostcallNoPathConfine(1, true)).then(checkUnsafe)
}

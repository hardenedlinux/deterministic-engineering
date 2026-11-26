;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Capability-Based WebAssembly / WASI Sandbox Confinement threat model.
;;; Co-located Yuanxu unit: single source of truth alongside WasmSandboxConfinement.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export WasmSandboxConfinementModel
        BoundsCheckBypassCountermodel
        AmbientFdForgeryCountermodel
        PreopenPathTraversalCountermodel)

(.def (WasmSandboxConfinementModel @ AuthorityCurrentnessModel)
  identity: 'threat.execution.wasm-sandbox-confinement
  family: 'threat.execution.wasm-sandbox-confinement
  title: "WebAssembly / WASI Capability Sandbox & Preopen Root Confinement"
  subdomain: 'quint.threat.execution
  papers:
  '(("A. Haas, A. Rossberg, D. L. Schuff, B. L. Titzer et al. (ACM PLDI 2017)"
     "Bringing the Web up to Speed with WebAssembly: linear-memory bounds safety and control-flow isolation.")
    ("S. Narayan, C. Disselkoen, T. Garfinkel et al. (USENIX Security 2020)"
     "Retrofitting Fine Grain Isolation in the Firefox Renderer (RLBox).")
    ("M. S. Miller (Johns Hopkins PhD Thesis 2006) & Linux openat2(RESOLVE_BENEATH)"
     "Object-capability non-ambient handles and preopened directory root confinement."))
  quint-module: "wasm_sandbox_confinement"
  quint-file: "WasmSandboxConfinement.qnt"
  domain-dir: "threat/execution/wasm-sandbox-confinement"
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
  rules:
  '((wasm-bounds-check WASM-MEM-BOUNDS quint)
    (wasi-capability-handle WASI-OCAP-HANDLE quint)
    (preopen-path-confinement WASI-OPENAT2-ROOT quint))
  dependencies:
  '((WASM-MEM-BOUNDS source)
    (WASM-MEM-BOUNDS profile)
    (WASM-MEM-BOUNDS method)
    (WASI-OCAP-HANDLE source)
    (WASI-OCAP-HANDLE profile)
    (WASI-OCAP-HANDLE method)
    (WASI-OPENAT2-ROOT source)
    (WASI-OPENAT2-ROOT profile)
    (WASI-OPENAT2-ROOT method))
  invariant: "A sandboxed guest module never accesses memory beyond guestMemSize, never invokes ungranted host handles, and never escapes its preopened directory root."
  parameters: '()
  state:
  '((guestMemSize "int" "64")
    (grantedHandles "Set[int]" "Set(1)")
    (maxAccessedAddr "int" "0")
    (usedHandles "Set[int]" "Set()")
    (hostRootEscaped "bool" "false"))
  guards:
  '((wasm-bounds-check (and (>= addr 0) (< addr (. h guestMemSize))))
    (wasi-capability-handle (contains (. h grantedHandles) handle))
    (preopen-path-confinement (not escapesRoot)))
  transitions:
  '((guestMemAccessAs
      (action guestMemAccessAs ((addr "int")) "bool"
        (if (guard wasm-bounds-check (and (>= addr 0) (< addr (. h guestMemSize))))
          (set-h (maxAccessedAddr (if (> addr (. h maxAccessedAddr))
                                    addr
                                    (. h maxAccessedAddr))))
          (keep-h))))
    (guestMemAccess
      (action guestMemAccess ()
        (nondet ((addr (set 0 32 63 100)))
          (call guestMemAccessAs addr))))
    (guestHostcallAs
      (action guestHostcallAs ((handle "int") (escapesRoot "bool")) "bool"
        (if (and (guard wasi-capability-handle (contains (. h grantedHandles) handle))
                 (guard preopen-path-confinement (not escapesRoot)))
          (set-h (usedHandles (union (. h usedHandles) (set handle)))
                 (hostRootEscaped (or (. h hostRootEscaped) escapesRoot)))
          (keep-h))))
    (guestHostcall
      (action guestHostcall ()
        (nondet ((handle (set 1 2 3))
                 (escapesRoot (set #f #t)))
          (call guestHostcallAs handle escapesRoot))))
    (grantNetHandle
      (action grantNetHandle ()
        (if (not (contains (. h grantedHandles) 2))
          (set-h (grantedHandles (union (. h grantedHandles) (set 2))))
          (keep-h))))
    (step
      (action step ()
        (any guestMemAccess guestHostcall grantNetHandle))))
  safety:
  '(and (< (. h maxAccessedAddr) (. h guestMemSize))
        (subseteq (. h usedHandles) (. h grantedHandles))
        (not (. h hostRootEscaped)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (validSandboxAccessTest
      (run validSandboxAccessTest
        (then init (call guestMemAccessAs 63) (call guestHostcallAs 1 #f)
              (all (assert (= (. h maxAccessedAddr) 63))
                   (assert (contains (. h usedHandles) 1))
                   (assert safety)
                   (keep-h)))))
    (oobAndPathTraversalBlockedTest
      (run oobAndPathTraversalBlockedTest
        (then init (call guestMemAccessAs 100)
              (call guestHostcallAs 3 #f)
              (call guestHostcallAs 1 #t)
              (all (assert (= (. h maxAccessedAddr) 0))
                   (assert (= (. h usedHandles) (set)))
                   (assert (not (. h hostRootEscaped)))
                   (assert safety)
                   (keep-h)))))
    (boundsBypassCountermodelTest
      (run boundsBypassCountermodelTest
        (then init (call guestMemNoBounds 100) checkUnsafe)))
    (ambientFdCountermodelTest
      (run ambientFdCountermodelTest
        (then init (call guestHostcallNoCap 3 #f) checkUnsafe)))
    (pathTraversalCountermodelTest
      (run pathTraversalCountermodelTest
        (then init (call guestHostcallNoPathConfine 1 #t) checkUnsafe))))
  countermodels:
  (list BoundsCheckBypassCountermodel
        AmbientFdForgeryCountermodel
        PreopenPathTraversalCountermodel)
  limits: "Finite Wasm linear-memory and WASI handle/path abstraction; does not model Spectre v1 speculative execution, JIT compiler miscompilation, or kernel symlink race TOCTOU.")

(.def (BoundsCheckBypassCountermodel @ WasmSandboxConfinementModel)
  identity: 'threat.execution.wasm-sandbox-confinement.bounds-check-bypass
  dropped-guard: 'wasm-bounds-check
  step-action: "stepBoundsBypass"
  derive-from-transition: 'guestMemAccessAs
  derive-action-name: 'guestMemNoBounds
  derive-step-call: '(nondet ((addr (set 0 32 63 100)))
                       (call guestMemNoBounds addr))
  expected-itf-predicate: "h.maxAccessedAddr >= h.guestMemSize")

(.def (AmbientFdForgeryCountermodel @ WasmSandboxConfinementModel)
  identity: 'threat.execution.wasm-sandbox-confinement.ambient-fd-forgery
  dropped-guard: 'wasi-capability-handle
  step-action: "stepAmbientFdForgery"
  derive-from-transition: 'guestHostcallAs
  derive-action-name: 'guestHostcallNoCap
  derive-step-call: '(nondet ((handle (set 1 2 3))
                              (escapesRoot (set #f #t)))
                       (call guestHostcallNoCap handle escapesRoot))
  expected-itf-predicate: "not(subseteq(h.usedHandles, h.grantedHandles))")

(.def (PreopenPathTraversalCountermodel @ WasmSandboxConfinementModel)
  identity: 'threat.execution.wasm-sandbox-confinement.preopen-path-traversal
  dropped-guard: 'preopen-path-confinement
  step-action: "stepPathTraversal"
  derive-from-transition: 'guestHostcallAs
  derive-action-name: 'guestHostcallNoPathConfine
  derive-step-call: '(nondet ((handle (set 1 2 3))
                              (escapesRoot (set #f #t)))
                       (call guestHostcallNoPathConfine handle escapesRoot))
  expected-itf-predicate: "h.hostRootEscaped == true")

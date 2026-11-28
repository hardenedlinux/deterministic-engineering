;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Capability-Based WebAssembly / WASI Sandbox Confinement threat model.
;;; Co-located Yuanxu unit: single source of truth alongside WasmSandboxConfinement.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export WasmSandboxConfinementModel)

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
  limits: "Finite Wasm linear-memory and WASI handle/path abstraction; does not model Spectre v1 speculative execution, JIT compiler miscompilation, or kernel symlink race TOCTOU.")

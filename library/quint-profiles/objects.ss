;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Formal 3-Axis Orthogonal Quint Profile Namespace (RFC 45-111 & Yuanxu Design 165).
;;; Every profile is a first-class POO value exported by this owning module:
;;;   1. assurance.*  — HOW thoroughly to verify (tool-agnostic verification tier)
;;;   2. bound.*      — WHAT finite search-bound envelope (diameter-based, zero magic numbers in names)
;;;   3. governance.* — NON-NEGOTIABLE Band-5 monotonic assurance floor (meet lattice)
(import :clan/poo/object
        (only-in :clan/poo/type validate)
        (only-in :tao3k/yuanxu/module-system/convergence/types
                 make-slot-spec make-global-profile by-tag)
        (only-in :tao3k/yuanxu/module-system/convergence/bridge
                 converge-selected-graph apply-graph-runtime-overlay)
        (only-in :deterministic-engineering/library/quint-methods/types
                 QuintProfileType))
(export QuintModelSlotSpecs
        QuintModelDefaultSlots
        QuintStatelessModelDefaultSlots
        QuintModelGovernanceFloor
        QuintAssuranceProfiles
        QuintBoundProfiles
        QuintGovernanceProfiles
        QuintProfileRegistry
        converge-quint-graph
        apply-quint-runtime-profile
        quint-model->verification-profile)

;; Monotonic boolean meet: once #t is demanded (e.g. by Band 5 GovernanceFloor),
;; no peer or override can weaken it back to #f.
(def (monotonic-require-meet a b)
  (or a b))

;; Standardized Yuanxu Design 165 slot contracts shared by all co-located Quint models.
(def QuintModelSlotSpecs
  (list
    (make-slot-spec 'verify-depth
      stage: 'assembly
      combiner: 'exclusive
      default: 12)
    (make-slot-spec 'countermodel-depth
      stage: 'assembly
      combiner: 'exclusive
      default: 6)
    (make-slot-spec 'require-countermodels?
      stage: 'assembly
      combiner: 'meet
      default: #f
      meet: monotonic-require-meet)
    (make-slot-spec 'require-emergent-invariants?
      stage: 'assembly
      combiner: 'meet
      default: #f
      meet: monotonic-require-meet)
    (make-slot-spec 'verification-mode
      stage: 'runtime
      combiner: 'exclusive
      default: 'bounded-proof
      allowed: '(syntax-only deterministic-trace bounded-proof mbt-oracle))
    (make-slot-spec 'seed
      stage: 'runtime
      combiner: 'exclusive
      default: 7)))

(def QuintModelDefaultSlots
  (.o verify-depth: 12
      countermodel-depth: 6
      require-countermodels?: #t
      require-emergent-invariants?: #t
      verification-mode: 'bounded-proof
      seed: 7))

;; Defaults for pure/stateless reference Quint models (no countermodel floor).
(def QuintStatelessModelDefaultSlots
  (.o verify-depth: 12
      countermodel-depth: 4
      require-countermodels?: #f ;; defense-audit:allow-negative-control
      require-emergent-invariants?: #f ;; defense-audit:allow-negative-control
      verification-mode: 'deterministic-trace
      seed: 7))

;; Band 5 Monotonic Security/Assurance Floor for stateful Quint models.
(def QuintModelGovernanceFloor
  (.o require-countermodels?: #t
      require-emergent-invariants?: #t))

;; ── Axis 1: assurance.* (HOW thoroughly to verify; runtime-switchable without recompiling) ──
(def QuintAssuranceProfiles
  (.o
    syntax-only:
    (make-global-profile 'assurance.syntax-only
      (list (by-tag 'quint.model))
      (.o verification-mode: 'syntax-only))
    deterministic-trace:
    (make-global-profile 'assurance.deterministic-trace
      (list (by-tag 'quint.model))
      (.o verification-mode: 'deterministic-trace))
    bounded-proof:
    (make-global-profile 'assurance.bounded-proof
      (list (by-tag 'quint.model))
      (.o verification-mode: 'bounded-proof))
    mbt-oracle:
    (make-global-profile 'assurance.mbt-oracle
      (list (by-tag 'quint.property.mbt-ready))
      (.o verification-mode: 'mbt-oracle))))

;; ── Axis 2: bound.* (WHAT finite diameter envelope; no tool names or magic integers) ──
(def QuintBoundProfiles
  (.o
    fast:
    (make-global-profile 'bound.fast
      (list (by-tag 'quint.model))
      (.o verify-depth: 6 countermodel-depth: 4))
    standard:
    (make-global-profile 'bound.standard
      (list (by-tag 'quint.model))
      (.o verify-depth: 12 countermodel-depth: 6))
    compact:
    (.o verify-depth: 10 countermodel-depth: 6)
    extended-counterexample:
    (.o verify-depth: 10 countermodel-depth: 9)
    deep-counterexample:
    (.o verify-depth: 12 countermodel-depth: 9)))

;; ── Axis 3: governance.* (Band 4a/5 monotonic assurance floors) ──
(def QuintGovernanceProfiles
  (.o
    mandatory-countermodels:
    (make-global-profile 'governance.mandatory-countermodels
      (list (by-tag 'quint.property.stateful))
      (.o require-countermodels?: #t))
    zero-trust-assurance:
    (make-global-profile 'governance.zero-trust-assurance
      (list (by-tag 'quint.property.stateful))
      (.o require-countermodels?: #t
          require-emergent-invariants?: #t))))

;; Canonical dotted-namespace registry auto-discovered via profile-catalog: on QuintProfiles.
;; Uses object<-alist so dotted symbols ('assurance.bounded-proof) are flat keys,
;; while QuintAssuranceProfiles / QuintBoundProfiles / QuintGovernanceProfiles remain
;; clean nested POO objects for direct Scheme callers.
(def QuintProfileRegistry
  (object<-alist
    (list
      (cons 'assurance.syntax-only (.get QuintAssuranceProfiles syntax-only))
      (cons 'assurance.deterministic-trace (.get QuintAssuranceProfiles deterministic-trace))
      (cons 'assurance.bounded-proof (.get QuintAssuranceProfiles bounded-proof))
      (cons 'assurance.mbt-oracle (.get QuintAssuranceProfiles mbt-oracle))
      (cons 'bound.fast (.get QuintBoundProfiles fast))
      (cons 'bound.standard (.get QuintBoundProfiles standard))
      (cons 'bound.compact (.get QuintBoundProfiles compact))
      (cons 'bound.extended-counterexample (.get QuintBoundProfiles extended-counterexample))
      (cons 'bound.deep-counterexample (.get QuintBoundProfiles deep-counterexample))
      (cons 'governance.mandatory-countermodels (.get QuintGovernanceProfiles mandatory-countermodels))
      (cons 'governance.zero-trust-assurance (.get QuintGovernanceProfiles zero-trust-assurance)))))

(def (converge-quint-graph graph (extra-registry #f))
  (converge-selected-graph graph
    global-profile-registry: extra-registry
    module-profile-registry: extra-registry))

(def (apply-quint-runtime-profile graph assembly-result runtime-overrides)
  (apply-graph-runtime-overlay graph assembly-result runtime-overrides))

;; Project a validated QuintProfileType directly from a model + optional converged Yuanxu slots.
(def (quint-model->verification-profile target-model (effective-slots #f))
  (def pos-depth
    (cond
      ((and effective-slots (.slot? effective-slots 'verify-depth))
       (.ref effective-slots 'verify-depth))
      ((.slot? target-model 'verify-depth) (.get target-model verify-depth))
      (else 12)))
  (def neg-depth
    (cond
      ((and effective-slots (.slot? effective-slots 'countermodel-depth))
       (.ref effective-slots 'countermodel-depth))
      ((.slot? target-model 'countermodel-depth) (.get target-model countermodel-depth))
      (else 6)))
  (def seed-val
    (if (and effective-slots (.slot? effective-slots 'seed))
      (.ref effective-slots 'seed)
      7))
  (def req-cm?
    (if (and effective-slots (.slot? effective-slots 'require-countermodels?))
      (.ref effective-slots 'require-countermodels?)
      (and (pair? (.get target-model countermodels)) #t)))
  (validate QuintProfileType
    (.o identity: (.get target-model identity)
        model: target-model
        seed: seed-val
        positive-depth: pos-depth
        negative-depth: neg-depth
        require-countermodels?: req-cm?)))

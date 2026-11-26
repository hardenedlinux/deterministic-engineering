;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure declarative ASCENT Datalog programs for Multi-Method Verification (10.154).
;;; Dedicated rule file: contains ONLY stratified finite `define-program` rules
;;; (MR01-MR06 pre-flight governance and ER01-ER04 post-execution evidence admission).
;;; Zero I/O, zero JSON parsing, zero session plumbing.
(import
  :gerbil-ascent/rules/func
  (only-in :gerbil-ascent/rules/declaration rule-module-program))
(export
  MultiMethodGovernanceDeclaration
  MultiMethodGovernanceProgram
  make-multi-method-governance-program
  VerificationEvidenceAdmissionDeclaration
  VerificationEvidenceAdmissionProgram
  make-verification-evidence-admission-program
  IncrementalReuseDeclaration
  IncrementalReuseProgram
  make-incremental-reuse-program)

;; ── Phase 1: Pre-Execution Multi-Method Governance Rules (MR01-MR06) ──
(define-program
  (make-multi-method-governance-program)
  (sources
   subject_obligation
   subject_factor
   method_allows_claim
   flow_step
   flow_dag_edge
   step_produces
   step_consumes
   step_requires_premise
   step_supports_premise
   correspondence_bridge
   stateful_quint_step
   step_countermodel
   declared_os_containment)
  (outputs
   mr_finding
   mr01_finding
   mr02_finding
   mr03_open_premise
   mr04_finding
   mr05_finding
   mr06_finding
   artifact_edge_satisfied
   runnable_admitted)
  (relation subject_obligation ((subject string?) (obligation string?) (claim_kind string?)))
  (relation subject_factor ((subject string?) (factor string?)))
  (relation method_allows_claim ((method string?) (claim_kind string?)))
  (relation flow_step ((step string?) (subject string?) (obligation string?) (method string?) (claim_kind string?)))
  (relation flow_dag_edge ((from_step string?) (to_step string?)))
  (relation step_produces ((step string?) (artifact string?)))
  (relation step_consumes ((step string?) (artifact string?)))
  (relation step_requires_premise ((step string?) (premise string?)))
  (relation step_supports_premise ((step string?) (premise string?)))
  (relation correspondence_bridge ((obligation string?) (method_a string?) (method_b string?)))
  (relation stateful_quint_step ((step string?)))
  (relation step_countermodel ((step string?) (guard_id string?)))
  (relation declared_os_containment ((subject string?) (platform string?) (strategy string?)))

  (relation artifact_edge_satisfied ((step string?) (artifact string?)))
  (relation mr01_finding ((subject string?) (step string?) (reason string?)))
  (relation mr02_finding ((subject string?) (obligation string?) (reason string?)))
  (relation mr03_open_premise ((subject string?) (step string?) (premise string?)))
  (relation mr04_finding ((subject string?) (step string?) (artifact string?)))
  (relation mr05_finding ((subject string?) (step string?) (reason string?)))
  (relation mr06_finding ((subject string?) (subject_id string?) (reason string?)))
  (relation mr_finding ((rule string?) (subject string?) (detail string?)))
  (relation runnable_admitted ((subject string?)))

  ;; MR01: method family is not authorized for declared claim-kind.
  ((mr01_finding S Step (lit "unauthorized-claim-kind"))
   <--
   (flow_step Step S O M K)
   (not (method_allows_claim M K)))

  ;; MR02: duplicate method coverage on same (obligation, claim-kind) without bridge.
  ((mr02_finding S O (lit "duplicate-method-without-bridge"))
   <--
   (flow_step St1 S O M1 K)
   (flow_step St2 S O M2 K)
   (if (M1 M2) (not (equal? M1 M2)))
   (not (correspondence_bridge O M1 M2))
   (not (correspondence_bridge O M2 M1)))

  ;; MR03: required premise without any supporting step stays visibly open.
  ((mr03_open_premise S Step P)
   <--
   (flow_step Step S _ _ _)
   (step_requires_premise Step P)
   (not (step_supports_premise _ P)))

  ;; MR04: consumed artifact must be produced by a predecessor in the Fun-Flow DAG.
  ((artifact_edge_satisfied To A)
   <--
   (flow_dag_edge From To)
   (step_produces From A)
   (step_consumes To A))
  ((mr04_finding S Step A)
   <--
   (flow_step Step S _ _ _)
   (step_consumes Step A)
   (not (artifact_edge_satisfied Step A)))

  ;; MR05: stateful Quint target must declare at least one countermodel (Band-5 floor).
  ((mr05_finding S Step (lit "missing-mandatory-countermodel"))
   <--
   (flow_step Step S _ _ _)
   (stateful_quint_step Step)
   (not (step_countermodel Step _)))

  ;; MR06: owns-subprocess-tree requires declared OS containment + os-sigkill-oracle.
  ((mr06_finding S S (lit "missing-os-containment"))
   <--
   (subject_factor S (lit "owns-subprocess-tree"))
   (not (declared_os_containment S _ _)))
  ((mr06_finding S S (lit "missing-sigkill-oracle"))
   <--
   (subject_factor S (lit "owns-subprocess-tree"))
   (not (flow_step _ S _ _ (lit "os-sigkill-oracle"))))

  ;; Unified MR finding summary.
  ((mr_finding (lit "MR01") S Step) <-- (mr01_finding S Step _))
  ((mr_finding (lit "MR02") S O) <-- (mr02_finding S O _))
  ((mr_finding (lit "MR04") S Step) <-- (mr04_finding S Step _))
  ((mr_finding (lit "MR05") S Step) <-- (mr05_finding S Step _))
  ((mr_finding (lit "MR06") S Reason) <-- (mr06_finding S _ Reason))

  ((runnable_admitted S)
   <--
   (subject_obligation S _ _)
   (not (mr_finding _ S _)))
  (bounds 4096 4096 4096))

(def MultiMethodGovernanceDeclaration (make-multi-method-governance-program))
(def MultiMethodGovernanceProgram (rule-module-program MultiMethodGovernanceDeclaration))

;; ── Phase 2: Post-Execution Evidence Admission Rules (ER01-ER04) ──
(define-program
  (make-verification-evidence-admission-program)
  (sources
   subject_obligation
   method_allows_claim
   flow_step
   step_requires_premise
   step_supports_premise
   step_evidence)
  (outputs
   obligation_passed
   premise_verified
   er01_missing_evidence
   er02_failed_step
   er03_unverified_premise
   er04_method_mismatch
   er_finding
   verification_admitted)
  (relation subject_obligation ((subject string?) (obligation string?) (claim_kind string?)))
  (relation method_allows_claim ((method string?) (claim_kind string?)))
  (relation flow_step ((step string?) (subject string?) (obligation string?) (method string?) (claim_kind string?)))
  (relation step_requires_premise ((step string?) (premise string?)))
  (relation step_supports_premise ((step string?) (premise string?)))
  (relation step_evidence ((step string?) (obligation string?) (method string?) (claim_kind string?) (outcome string?) (detail string?)))

  (relation obligation_passed ((subject string?) (obligation string?) (claim_kind string?)))
  (relation premise_verified ((premise string?)))
  (relation er01_missing_evidence ((subject string?) (obligation string?) (claim_kind string?)))
  (relation er02_failed_step ((subject string?) (step string?) (outcome string?)))
  (relation er03_unverified_premise ((subject string?) (step string?) (premise string?)))
  (relation er04_method_mismatch ((step string?) (method string?) (claim_kind string?)))
  (relation er_finding ((rule string?) (target string?) (detail string?)))
  (relation verification_admitted ((subject string?)))

  ((obligation_passed S O K)
   <--
   (subject_obligation S O K)
   (flow_step Step S O M K)
   (step_evidence Step O M K (lit "pass") _))

  ((premise_verified P)
   <--
   (step_supports_premise SupStep P)
   (step_evidence SupStep _ _ _ (lit "pass") _))

  ;; ER01: declared obligation lacks passing runtime evidence from its step.
  ((er01_missing_evidence S O K)
   <--
   (subject_obligation S O K)
   (not (obligation_passed S O K)))

  ;; ER02: executed step produced a non-pass outcome.
  ((er02_failed_step S Step Outcome)
   <--
   (flow_step Step S _ _ _)
   (step_evidence Step _ _ _ Outcome _)
   (if (Outcome) (not (equal? Outcome "pass"))))

  ;; ER03: required premise lacks a passing supporting step at runtime.
  ((er03_unverified_premise S Step P)
   <--
   (flow_step Step S _ _ _)
   (step_requires_premise Step P)
   (not (premise_verified P)))

  ;; ER04: observed evidence claims an unauthorized (method, claim-kind) pair.
  ((er04_method_mismatch Step M K)
   <--
   (step_evidence Step _ M K _ _)
   (not (method_allows_claim M K)))

  ((er_finding (lit "ER01") S O) <-- (er01_missing_evidence S O _))
  ((er_finding (lit "ER02") S Step) <-- (er02_failed_step S Step _))
  ((er_finding (lit "ER03") S P) <-- (er03_unverified_premise S _ P))
  ((er_finding (lit "ER04") Step M) <-- (er04_method_mismatch Step M _))

  ((verification_admitted S)
   <--
   (subject_obligation S _ _)
   (not (er_finding _ S _))
   (not (er04_method_mismatch _ _ _)))
  (bounds 4096 4096 4096))

(def VerificationEvidenceAdmissionDeclaration (make-verification-evidence-admission-program))
(def VerificationEvidenceAdmissionProgram (rule-module-program VerificationEvidenceAdmissionDeclaration))

;; ── Phase 3: Content-Addressed Incremental Cache Reuse & Selective Invalidation (IR01-IR04) ──
;; Computes the exact pending vs reusable step frontier via stratified fixed-point
;; over input digests, DAG artifact edges, and M1/M3 mutability boundaries (10.153 F2 / 10.154 M5).
(define-program
  (make-incremental-reuse-program)
  (sources
   flow_step
   flow_dag_edge
   step_mutability
   reuse_policy
   step_input_digest
   cached_witness
   cached_witness_input)
  (outputs
   step_has_passing_cache
   step_input_dirty
   step_invalidated
   step_pending
   step_reusable)
  (relation flow_step ((step string?) (subject string?) (obligation string?) (method string?) (claim_kind string?)))
  (relation flow_dag_edge ((from_step string?) (to_step string?)))
  (relation step_mutability ((step string?) (mutability string?)))
  (relation reuse_policy ((flag string?)))
  (relation step_input_digest ((step string?) (input_key string?) (digest string?)))
  (relation cached_witness ((step string?) (obligation string?) (method string?) (claim_kind string?) (outcome string?) (detail string?)))
  (relation cached_witness_input ((step string?) (input_key string?) (digest string?)))

  (relation step_has_passing_cache ((step string?)))
  (relation input_mismatch ((step string?) (input_key string?)))
  (relation input_missing_in_cache ((step string?) (input_key string?)))
  (relation input_extra_in_cache ((step string?) (input_key string?)))
  (relation step_input_dirty ((step string?)))
  (relation step_invalidated ((step string?) (reason string?)))
  (relation step_pending ((step string?)))
  (relation step_reusable ((step string?)))

  ;; A cached witness is usable only if its (step, obligation, method, claim_kind)
  ;; matches the current flow_step and its recorded outcome is "pass".
  ((step_has_passing_cache Step)
   <--
   (flow_step Step _ O M K)
   (cached_witness Step O M K (lit "pass") _))

  ;; Exact bidirectional input-closure comparison (detects edits, additions, and deletions).
  ((input_mismatch Step Key)
   <--
   (step_input_digest Step Key D1)
   (cached_witness_input Step Key D2)
   (if (D1 D2) (not (equal? D1 D2))))

  ((input_missing_in_cache Step Key)
   <--
   (step_input_digest Step Key _)
   (not (cached_witness_input Step Key _)))

  ((input_extra_in_cache Step Key)
   <--
   (cached_witness_input Step Key _)
   (not (step_input_digest Step Key _)))

  ((step_input_dirty Step) <-- (input_mismatch Step _))
  ((step_input_dirty Step) <-- (input_missing_in_cache Step _))
  ((step_input_dirty Step) <-- (input_extra_in_cache Step _))

  ;; IR01: missing or non-pass cached witness forces execution.
  ((step_invalidated Step (lit "IR01-no-passing-cache"))
   <--
   (flow_step Step _ _ _ _)
   (not (step_has_passing_cache Step)))

  ;; IR02: any changed, added, or removed input digest invalidates the step.
  ((step_invalidated Step (lit "IR02-input-digest-changed"))
   <--
   (flow_step Step _ _ _ _)
   (step_input_dirty Step))

  ;; IR03: transitive DAG invalidation across artifact-handoff edges (e.g., Quint -> Rust MBT/Oracle).
  ((step_invalidated To (lit "IR03-upstream-dag-invalidated"))
   <--
   (flow_dag_edge From To)
   (step_invalidated From _))

  ;; IR04: M3 mutable-root boundary cannot claim M1 immutable cache reuse when fresh M3 policy is set.
  ((step_invalidated Step (lit "IR04-m3-mutable-root-refresh"))
   <--
   (flow_step Step _ _ _ _)
   (step_mutability Step (lit "M3-mutable-root"))
   (reuse_policy (lit "require-fresh-m3")))

  ;; Partition every declared step into exactly pending or reusable.
  ((step_pending Step)
   <--
   (flow_step Step _ _ _ _)
   (step_invalidated Step _))

  ((step_reusable Step)
   <--
   (flow_step Step _ _ _ _)
   (not (step_invalidated Step _)))
  (bounds 4096 4096 4096))

(def IncrementalReuseDeclaration (make-incremental-reuse-program))
(def IncrementalReuseProgram (rule-module-program IncrementalReuseDeclaration))

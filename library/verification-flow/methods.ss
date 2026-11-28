;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Unified pure CLOS Runnable protocol (runnable-inputs / runnable-flow /
;;; runnable-admit) and ASCENT-gated Fun-Flow DAG manifest projection (10.154).
;;; Backed by reusable combinators in `func.ss`. Zero I/O, zero subprocess execution.
(import
  :clan/poo/object
  (only-in :clan/poo/type validate)
  (only-in :clan/poo/mop/clos/generic-syntax .defgeneric .defmethod)
  (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
           flow->dag-receipt
           flow->dag-runtime-manifest)
  "types.ss"
  "objects.ss"
  "func.ss"
  "rules.ss")
(export
  runnable-inputs
  runnable-flow
  runnable-admit
  adapter-result->raw-receipt
  receipt-tree->evidence-records
  subject->dag-receipt
  subject->dag-runtime-manifest)

(.defgeneric runnable-inputs (target profile))
(.defgeneric runnable-flow (target profile policy))
(.defgeneric runnable-admit (target receipt))

(def (target-admit target receipt-or-adapter)
  ((make-step-admitter (.get target obligation)
                       (.get (.get target family) identity)
                       (.get target claim-kind))
   receipt-or-adapter))

(def (target-external-flow target op extra-payload profile policy)
  (make-external-admit-flow
    (.get target identity)
    op
    (append (list (cons 'family (.get (.get target family) identity)))
            extra-payload
            (list (cons 'profile profile) (cons 'policy policy)))
    VerificationInputEnvelopeType
    VerificationEvidenceRecordType
    (lambda (raw) (runnable-admit target raw))))

;; ── Quint Runnable methods ──
(.defmethod (runnable-inputs (target (prototype QuintRunnableTarget.)) profile)
  (list (cons 'quint-file (.get target quint-file))
        (cons 'quint-module (.get target quint-module))
        (cons 'profile profile)
        (cons 'inputs (.get target inputs))))

(.defmethod (runnable-flow (target (prototype QuintRunnableTarget.)) profile policy)
  (target-external-flow target 'run-quint-plan
    (list (cons 'quint-file (.get target quint-file))
          (cons 'quint-module (.get target quint-module))
          (cons 'countermodels (.get target countermodels)))
    profile policy))

(.defmethod (runnable-admit (target (prototype QuintRunnableTarget.)) receipt)
  (target-admit target receipt))

;; ── LeanPoo Runnable methods ──
(.defmethod (runnable-inputs (target (prototype LeanPooRunnableTarget.)) profile)
  (list (cons 'lake-root (.get target lake-root))
        (cons 'lean-module (.get target lean-module))
        (cons 'refines-core (.get target refines-core))
        (cons 'profile profile)
        (cons 'inputs (.get target inputs))))

(.defmethod (runnable-flow (target (prototype LeanPooRunnableTarget.)) profile policy)
  (target-external-flow target 'run-lean-lake-check
    (list (cons 'lake-root (.get target lake-root))
          (cons 'lean-module (.get target lean-module))
          (cons 'require-zero-sorry (.get target require-zero-sorry?)))
    profile policy))

(.defmethod (runnable-admit (target (prototype LeanPooRunnableTarget.)) receipt)
  (target-admit target receipt))

;; ── Source-Contract Runnable methods ──
(.defmethod (runnable-inputs (target (prototype SourceContractRunnableTarget.)) profile)
  (list (cons 'subject-dir (.get target subject-dir))
        (cons 'tool (.get target tool))
        (cons 'profile profile)
        (cons 'inputs (.get target inputs))))

(.defmethod (runnable-flow (target (prototype SourceContractRunnableTarget.)) profile policy)
  (target-external-flow target 'run-source-contract
    (list (cons 'subject-dir (.get target subject-dir))
          (cons 'tool (.get target tool)))
    profile policy))

(.defmethod (runnable-admit (target (prototype SourceContractRunnableTarget.)) receipt)
  (target-admit target receipt))

;; ── Native OS Fault-Oracle Runnable methods ──
(.defmethod (runnable-inputs (target (prototype NativeOracleRunnableTarget.)) profile)
  (list (cons 'crate-dir (.get target crate-dir))
        (cons 'fault-controls (.get target fault-controls))
        (cons 'profile profile)
        (cons 'inputs (.get target inputs))))

(.defmethod (runnable-flow (target (prototype NativeOracleRunnableTarget.)) profile policy)
  (target-external-flow target 'run-contained-oracle
    (list (cons 'crate-dir (.get target crate-dir))
          (cons 'fault-controls (.get target fault-controls)))
    profile policy))

(.defmethod (runnable-admit (target (prototype NativeOracleRunnableTarget.)) receipt)
  (target-admit target receipt))

;; ── ASCENT MR01-MR06 Gated Fun-Flow DAG Projections ──
(def (require-governance-admitted! subject)
  (validate VerificationSubjectType subject)
  (def sources (subject->governance-sources subject))
  (def result (reason-multi-method-governance sources))
  (def findings ((.ref result 'rows-of) 'mr_finding))
  (unless (null? findings)
    (error "multi-method governance MR01-MR06 refused verification flow" findings))
  result)

(def (subject->dag-receipt subject)
  (require-governance-admitted! subject)
  (flow->dag-receipt (.get subject dag-flow)))

(def (subject->dag-runtime-manifest subject request-id)
  (require-governance-admitted! subject)
  (flow->dag-runtime-manifest (.get subject dag-flow) request-id))

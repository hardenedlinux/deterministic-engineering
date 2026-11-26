;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero-Glue SysML v2 -> Fun-Flow DAG Compiler & 3rd Subject (`lease-fencing-token`) Tests.
;;; Verifies:
;;; 1. Pure `sysml-projected->compiled-subjects` compiles ALL 3 engineering subjects
;;;    (`process-tree-reclamation`, `backpressure-memory`, `lease-fencing-token`)
;;;    directly from live OpenSysML `api-json` with ZERO per-subject Scheme glue,
;;;    passes ASCENT MR01-MR06, and emits valid Fun-Flow DAG receipts & manifests.
;;; 2. Live 2-engine Fun-Flow Cold -> Warm SHA-256 cached execution on the 3rd
;;;    subject `lease-fencing-token`:
;;;    - `lfQuintTarget` (Apalache bounded verify + countermodel + 100% MBT + 10 ITF export)
;;;    - `lfLeanPooTarget` (`Core.Order` + `Core.Transport` + `Engineering.LeaseFencing`, 6 theorems, 0 sorryAx)
;;;    - Upstream Fun-Flow Replay Validation (`replayValid = #t`) + ASCENT ER01-ER04 Admission.
(import :std/test
        :std/encoding/json
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 flow-dag-receipt-kind
                 replay-report-valid?
                 replay-report-reasons
                 +flow-dag-runtime-manifest-schema+)
        :deterministic-engineering/library/verification-flow/rules
        :deterministic-engineering/library/verification-flow/sysml-compiler
        :deterministic-engineering/library/verification-flow/methods
        "../../../support/verification-flow-runner.ss")
(export verification-flow-sysml-compiler-and-lease-fencing-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def verification-flow-sysml-compiler-and-lease-fencing-test
  (test-suite "Zero-glue SysML v2 -> Fun-Flow DAG compiler and 3rd subject lease-fencing-token"
    (test-case "live SysML v2 compiles all 3 subjects into valid Fun-Flow DAGs and manifests with zero Scheme glue"
      (def sysml-path
        (path-expand
          "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
          repo-root))
      (def json-text (run-process (list "sysml" "-convert" "api-json" sysml-path)))
      (def parsed (call-with-input-string json-text (cut read-json <> object-as-hash: #t)))
      (def projected (sysml-api-json->governance-facts parsed))
      (def compiled (sysml-projected->compiled-subjects projected))
      (check-equal? (length compiled) 5)
      (for-each
        (lambda (spec-expect)
          (def skey (car spec-expect))
          (def expected-steps (cadr spec-expect))
          (def hit (assq skey compiled))
          (check (pair? hit) => #t)
          (def bundle (cdr hit))
          (def subj (.get bundle subject))
          (check-equal? (length (.get subj steps)) expected-steps)
          (check-equal? (length (.get bundle mutability)) expected-steps)
          (check-equal? (length (.get bundle input-files)) expected-steps)
          (def gov-res (reason-multi-method-governance (subject->governance-sources subj)))
          (check-equal? ((.ref gov-res 'rows-of) 'mr_finding) '())
          (check-equal? ((.ref gov-res 'rows-of) 'mr03_open_premise) '())
          (def receipt (subject->dag-receipt subj))
          (check-equal? (cdr (assoc 'kind receipt)) flow-dag-receipt-kind)
          (def manifest (subject->dag-runtime-manifest subj (string-append "req-compile-" (symbol->string skey))))
          (check-equal? (cdr (assoc 'schema manifest)) +flow-dag-runtime-manifest-schema+))
        '((process-tree-reclamation 4)
          (backpressure-memory 4)
          (lease-fencing-token 2)
          (c-boundary-conservation 2)
          (meta-governance-soundness 1))))

    (test-case "live 2-engine Fun-Flow run on SysML-compiled lease-fencing-token passes Apalache+MBT, LeanPoo Core.Order+Transport, Replay, ER01-ER04, and Cold->Warm cache reuse"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def cache-dir (path-expand "m5-lease-fencing-cache-test" tmp-parent))
      (run-process (list "rm" "-rf" cache-dir))
      (create-directory* cache-dir)

      ;; Phase 1 — Cold run: executes lfQuintTarget + lfLeanPooTarget compiled directly from SysML v2.
      (let ((r1 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'lease-fencing-token
                  cache-dir: cache-dir
                  request-id: "req-lf-1-cold")))
        (def mr-admitted ((.ref (.get r1 mr-result) 'rows-of) 'runnable_admitted))
        (check (and (member '("engineering.lifecycle.process-tree-reclamation") mr-admitted) #t) => #t)
        (check (and (member '("engineering.concurrency.backpressure-memory") mr-admitted) #t) => #t)
        (check (and (member '("engineering.concurrency.lease-fencing-token") mr-admitted) #t) => #t)
        (check-equal? (cdr (assoc 'schema (.get r1 dag-manifest)))
                      +flow-dag-runtime-manifest-schema+)
        (check-equal? (replay-report-valid? (.get r1 replay-report)) #t)
        (check-equal? (replay-report-reasons (.get r1 replay-report)) '())
        (check-equal? (length (.get r1 evidence-records)) 2)
        (for-each (lambda (ev) (check-equal? (.get ev outcome) 'pass)) (.get r1 evidence-records))
        (def er1 (.get r1 er-result))
        (check-equal? ((.ref er1 'rows-of) 'er_finding) '())
        (check-equal? (length ((.ref er1 'rows-of) 'obligation_passed)) 2)
        (check-equal? ((.ref er1 'rows-of) 'verification_admitted)
                      '(("engineering.concurrency.lease-fencing-token")))
        (check-equal? (length (.get (.get r1 cache-summary) executed)) 2)
        (check-equal? (.get (.get r1 cache-summary) reused) '()))
      (##gc)

      ;; Phase 2 — Warm run: 0 engines spawned, 2/2 reused from SHA-256 cache!
      (let ((r2 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'lease-fencing-token
                  cache-dir: cache-dir
                  request-id: "req-lf-2-warm")))
        (check-equal? (replay-report-valid? (.get r2 replay-report)) #t)
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'er_finding) '())
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'verification_admitted)
                      '(("engineering.concurrency.lease-fencing-token")))
        (check-equal? (.get (.get r2 cache-summary) executed) '())
        (check-equal? (length (.get (.get r2 cache-summary) reused)) 2)))))

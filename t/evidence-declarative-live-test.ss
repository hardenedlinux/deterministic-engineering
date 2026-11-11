;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; -*- Gerbil -*-
;;; Real QNT/TLC outputs, independent BFS/trace oracles and native exchanges.
(import :std/test :std/encoding/json :clan/poo/object :gerbil-ascent/program/session
        (only-in :std/misc/ports read-all-as-string)
        (only-in :agentic-ai-lab/modules/temporal-causality/trajectory/ascent-ledger ascent-trajectory)

        "../library/backpressure-memory/objects.ss"
        "../library/rust-resources/objects.ss"
        "../library/backpressure-tokio-rayon/objects.ss"
        "../library/rust-resources/methods.ss"
        "../library/evidence/func.ss")
(import :deterministic-engineering/init)
(def Cap2Profile (.get deterministic-engineering.init.exports Library gateway-profiles profiles Cap2Profile))
(def LifecycleProfile (.get deterministic-engineering.init.exports Library resource-lifecycle-profiles profiles LifecycleProfile))
(def LargerPayloadProfile (.get deterministic-engineering.init.exports Library resource-lifecycle-profiles profiles LargerPayloadProfile))
(export evidence-declarative-live-test)
(def selected-method-references
  (map (lambda (key) (method-ref (.ref RustMethodDefinitions key))) '(native quint lean)))
(def selected-integration-reference
  (method-ref (.get RustMethodDefinitions integration)))
(def (rows result relation) ((.get result rows-of) relation))
(def (load-json path) (call-with-input-file path (cut read-json <> object-as-hash: #t)))
(def (write-text path text) (call-with-output-file (list path: path truncate: #t) (cut display text <>)))
(def (append-result! trajectory result)
  (def source (hash-ref (ascent-trajectory (hash ("action" "snapshot") ("trajectory" trajectory))) "sourceIdentity"))
  (ascent-trajectory (hash ("action" "append") ("trajectory" trajectory)
                           ("event" (hash ("id" (resource-result-id result)) ("kind" "evidence") ("sourceIdentity" source)
                                          ("resultReference" (resource-result-reference result)) ("pathIdentity" (resource-result-claim result)))))))
(def evidence-declarative-live-test
  (test-suite "Actual evidence registration after declarative projection"
    (test-case "real pass and counter retain frozen cuts, reuse and currentness boundaries"
      (def root (getenv "LIBRARY_METHOD_ROOT"))
      (def tool (getenv "LIBRARY_QUINT"))
      (def source (path-expand "library/backpressure-memory/model.qnt" root))
      (def rule-source (path-expand "library/evidence/func.ss" root))
      (def model (specialize-backpressure BackpressureModel selected-method-references))
      (def pass (resource-run-qnt root LifecycleProfile tool (path-expand "pass" root)))
      (def counter (resource-run-qnt root LifecycleProfile tool (path-expand "counter" root) 'early-release))
      (def pass-record (resource-result-record pass))
      (def counter-record (resource-result-record counter))
      (check-equal? (hash-ref (hash-ref (load-json (hash-ref pass-record "reviewPath")) "oracle") "safe") #t)
      (check-equal? (hash-ref (hash-ref counter-record "observation") "outcome") "fail")
      (check-equal? (hash-ref (hash-ref (load-json (hash-ref counter-record "reviewPath")) "oracle") "violation") #t)
      (def session (open-resource-review model LifecycleProfile 'live "cut/live"
                                         (resource-real-scopes root LifecycleProfile 'live source)))
      (def trajectory (hash-ref (ascent-trajectory (hash ("action" "open") ("task" "declarative-live")
                                                         ("sourceIdentity" "cut/live"))) "trajectory"))
      (append-result! trajectory pass)
      (resource-register-results! session (list pass) trajectory rule-source)
      (def frozen (gerbil-ascent-session-run session))
      (check-equal? (length (rows frozen 'support)) 1)
      (check-equal? (length (rows frozen 'witness)) 1)
      (check-equal? (rows frozen 'counter) '())
      (check-equal? (rows frozen 'support)
                    (list (list 'live 'BP-O02 (string->symbol (resource-result-id pass))
                                (resource-result-reference pass)
                                (string-append "sha256:" (resource-digest-file (hash-ref pass-record "reviewPath"))))))
      ;; A workload-only change retains this model-only witness, without reissuing it.
      (gerbil-ascent-session-replace-sources! session
                                              (list (cons 'application (list (list 'larger "cut/larger" (.get model identity))))
                                                    (cons 'factor (map (cut list 'larger <>) (.get LargerPayloadProfile factors)))
                                                    (cons 'scope (resource-real-scopes root LargerPayloadProfile 'larger source))))
      (def reused (gerbil-ascent-session-run session))
      (check-equal? (caar (rows reused 'support)) 'larger)
      (check-equal? (cadddr (car (rows reused 'support))) (resource-result-reference pass))
      ;; A changed finite model basis cannot reuse that support.
      (gerbil-ascent-session-replace-sources! session
                                              (list (cons 'application (list (list 'capacity "cut/capacity" (.get model identity))))
                                                    (cons 'factor (map (cut list 'capacity <>) (.get Cap2Profile factors)))
                                                    (cons 'scope (resource-real-scopes root Cap2Profile 'capacity source))))
      (def changed (gerbil-ascent-session-run session))
      (check-equal? (rows changed 'support) '())
      (check-equal? (and (member '(capacity BP-O02 quint) (rows changed 'pending)) #t) #t)
      ;; Admit the actual counter only under its own early-release interpretation.
      (gerbil-ascent-session-replace-sources! session
                                              (list (cons 'application (list (list 'negative "cut/negative" (.get model identity))))
                                                    (cons 'factor (map (cut list 'negative <>) (.get LifecycleProfile factors)))
                                                    (cons 'scope (resource-real-scopes root LifecycleProfile 'negative source 'early-release))))
      (append-result! trajectory counter)
      (resource-register-results! session (list pass counter) trajectory rule-source)
      (def negative (gerbil-ascent-session-run session))
      (check-equal? (rows negative 'counter)
                    (list (list 'negative 'BP-O02 (string->symbol (resource-result-id counter))
                                (resource-result-reference counter)
                                (string-append "sha256:" (resource-digest-file (hash-ref counter-record "reviewPath"))))))
      (check-equal? (rows negative 'support) '())
      (check-equal? (and (member '(negative BP-O02 quint) (rows negative 'pending)) #t) #t)
      (check-equal? (length (rows negative 'witness)) 2)
      (check-equal? (length (rows frozen 'witness)) 1)
      (check-equal? (rows frozen 'application) '((live "cut/live" rust.resources.backpressure-memory)))
      (check-equal? (rows frozen 'counter) '())
      ;; Repeated registration retains history without duplicate rows.
      (resource-register-results! session (list pass counter) trajectory rule-source)
      (check-equal? (length (rows (gerbil-ascent-session-run session) 'witness)) 2)
      (def declaration (path-expand "library/rust-resources/objects.ss" root))
      (def before (call-with-input-file declaration read-all-as-string))
      (try
       (write-text declaration (string-append before "\n;; changed declaration bytes\n"))
       (check-exception (resource-register-results! session (list pass counter) trajectory rule-source) error?)
       (check-equal? (length (rows (gerbil-ascent-session-run session) 'witness)) 2)
       (finally (write-text declaration before)))
      (resource-result-current! pass)
      (resource-register-results! session (list pass counter) trajectory rule-source)
      (check-equal? (length (rows (gerbil-ascent-session-run session) 'counter)) 1))))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Development projection script: projects Scheme POO threat models into
;;; packages/quint-models/ with plan.json, receipt.json, and REUSE sidecars.
;;; All filesystem I/O lives here; library/quint-methods/ remains pure.
(import
  :clan/poo/object
  :std/encoding/json
  :std/crypto/digest
  :std/encoding/hex
  :std/misc/ports
  :std/misc/process
  "../../library/threat-capabilities/objects.ss"
  "../../library/authority-currentness/objects.ss"
  "../../library/effect-handoff/objects.ss"
  "../../library/effect-containment/objects.ss"
  "../../library/state-rollback/objects.ss"
  "../../library/zero-trust-pep-pdp/objects.ss"
  "../../library/workload-identity-rotation/objects.ss"
  "../../library/microsegmentation-egress/objects.ss"
  "../../library/oauth-token-lifecycle/objects.ss"
  "../../library/gc-tricolor-barrier/objects.ss"
  "../../library/gc-safepoint-handshake/objects.ss"
  "../../library/parallel-epoch-reclamation/objects.ss"
  "../../library/parallel-work-stealing/objects.ss"
  "../../library/concurrency-structured-cancel/objects.ss"
  "../../library/quint-methods/objects.ss"
  "../../library/quint-methods/methods.ss"
  "../../library/threat-model-profiles/objects.ss")
(export project-all-quint-models!)

;; REUSE-IgnoreStart
(def license-sidecar
  "SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors\nSPDX-License-Identifier: LGPL-2.1-or-later\n")
;; REUSE-IgnoreEnd

(def (sha256-hex-string text)
  (hex-encode (sha256 (string->utf8 text))))

(def (sha256-hex-file path)
  (hex-encode (sha256 (read-file-u8vector path))))

(def (step->json-hash step)
  (def h (hash ("label" (.get step label))
               ("command" (.get step command))
               ("expectedExit" (.get step expected-exit))
               ("kind" (.get step kind))))
  (when (.slot? step 'dropped-guard)
    (hash-put! h "droppedGuard" (.get step dropped-guard)))
  (when (.slot? step 'expected-itf-predicate)
    (hash-put! h "expectedItfPredicate" (.get step expected-itf-predicate)))
  h)

(def (plan->json-hash plan)
  (hash ("module" (.get plan module))
        ("file" (.get plan file))
        ("quintVersion" (.get plan quint-version))
        ("apalacheVersion" (.get plan apalache-version))
        ("seed" (.get plan seed))
        ("positiveDepth" (.get plan positive-depth))
        ("negativeDepth" (.get plan negative-depth))
        ("timeout" (.get plan timeout))
        ("steps" (map step->json-hash (.get plan steps)))))

(def (write-json-with-license! path value)
  (call-with-output-file path
    (lambda (port)
      (write-json port value)
      (newline port)))
  (call-with-output-file (string-append path ".license")
    (lambda (port) (display license-sidecar port))))

(def (git-head-sha repo-root)
  (string-trim-eol
    (run-process '("git" "rev-parse" "HEAD") directory: repo-root)))

(def (string-trim-eol s)
  (let loop ((end (string-length s)))
    (if (and (> end 0) (char-whitespace? (string-ref s (- end 1))))
      (loop (- end 1))
      (substring s 0 end))))

(def threat-entries
  (list
    (list CapabilitiesModel
          (.get ThreatModelProfiles threat-capabilities)
          '("library/threat-capabilities/objects.ss" "library/quint-methods/methods.ss"))
    (list AuthorityCurrentnessModel
          (.get ThreatModelProfiles authority-currentness)
          '("library/authority-currentness/objects.ss" "library/quint-methods/methods.ss"))
    (list EffectHandoffModel
          (.get ThreatModelProfiles effect-handoff)
          '("library/effect-handoff/objects.ss" "library/authority-currentness/objects.ss"
            "library/quint-methods/methods.ss"))
    (list EffectContainmentModel
          (.get ThreatModelProfiles effect-containment)
          '("library/effect-containment/objects.ss" "library/authority-currentness/objects.ss"
            "library/quint-methods/methods.ss"))
    (list StateRollbackModel
          (.get ThreatModelProfiles exact-effect-host)
          '("library/state-rollback/objects.ss" "library/effect-handoff/objects.ss"
            "library/authority-currentness/objects.ss" "library/quint-methods/methods.ss"))
    (list ZeroTrustPepPdpModel
          (.get ThreatModelProfiles zero-trust-pep-pdp)
          '("library/zero-trust-pep-pdp/objects.ss" "library/authority-currentness/objects.ss"
            "library/quint-methods/methods.ss"))
    (list WorkloadIdentityRotationModel
          (.get ThreatModelProfiles workload-identity-rotation)
          '("library/workload-identity-rotation/objects.ss" "library/authority-currentness/objects.ss"
            "library/quint-methods/methods.ss"))
    (list MicrosegmentationEgressModel
          (.get ThreatModelProfiles microsegmentation-egress)
          '("library/microsegmentation-egress/objects.ss" "library/authority-currentness/objects.ss"
            "library/quint-methods/methods.ss"))
    (list OAuthTokenLifecycleModel
          (.get ThreatModelProfiles oauth-token-lifecycle)
          '("library/oauth-token-lifecycle/objects.ss" "library/authority-currentness/objects.ss"
            "library/quint-methods/methods.ss"))
    (list TricolorWriteBarrierModel
          (.get ThreatModelProfiles gc-tricolor-barrier)
          '("library/gc-tricolor-barrier/objects.ss" "library/quint-methods/methods.ss"))
    (list SafepointHandshakeModel
          (.get ThreatModelProfiles gc-safepoint-handshake)
          '("library/gc-safepoint-handshake/objects.ss" "library/quint-methods/methods.ss"))
    (list EpochReclamationModel
          (.get ThreatModelProfiles parallel-epoch-reclamation)
          '("library/parallel-epoch-reclamation/objects.ss" "library/quint-methods/methods.ss"))
    (list WorkStealingDequeModel
          (.get ThreatModelProfiles parallel-work-stealing)
          '("library/parallel-work-stealing/objects.ss" "library/quint-methods/methods.ss"))
    (list StructuredCancelModel
          (.get ThreatModelProfiles concurrency-structured-cancel)
          '("library/concurrency-structured-cancel/objects.ss" "library/quint-methods/methods.ss"))))

(def (project-all-quint-models! repo-root)
  (def head-sha (git-head-sha repo-root))
  (def pkg-root (path-expand "packages/quint-models" repo-root))
  (for-each
    (lambda (entry)
      (def model (car entry))
      (def profile (cadr entry))
      (def source-paths (caddr entry))
      (def out-dir (path-expand (.get model domain-dir) pkg-root))
      (create-directory* out-dir)
      (def qnt-text (quint-module model))
      (def qnt-file (.get model quint-file))
      (def qnt-path (path-expand qnt-file out-dir))
      (call-with-output-file qnt-path (lambda (p) (display qnt-text p)))
      (def plan (quint-plan model profile DefaultQuintPolicy))
      (def plan-path (path-expand "plan.json" out-dir))
      (write-json-with-license! plan-path (plan->json-hash plan))
      (def src-digests (make-hash-table))
      (for-each
        (lambda (rel)
          (hash-put! src-digests rel (sha256-hex-file (path-expand rel repo-root))))
        source-paths)
      (def art-digests (make-hash-table))
      (hash-put! art-digests qnt-file (sha256-hex-string qnt-text))
      (hash-put! art-digests "plan.json" (sha256-hex-file plan-path))
      (def receipt
        (hash ("status" "Projection receipt only; no verifier execution verdict")
              ("deSourceCommit" head-sha)
              ("modelIdentity" (symbol->string (.get model identity)))
              ("quintVersion" (.get DefaultQuintPolicy quint-version))
              ("sources" src-digests)
              ("artifacts" art-digests)))
      (write-json-with-license! (path-expand "receipt.json" out-dir) receipt))
    threat-entries)
  ;; Also publish the maintained engineering/concurrency/backpressure-memory Quint model (D3).
  (def bp-src-rel "languages-engineering/quint/concurrency/backpressure-memory/model.qnt")
  (def bp-src (path-expand bp-src-rel repo-root))
  (when (file-exists? bp-src)
    (let ()
      (def bp-dir (path-expand "engineering/concurrency/backpressure-memory" pkg-root))
      (create-directory* bp-dir)
      (def bp-text (read-file-string bp-src))
      (def bp-qnt (path-expand "BackpressureOwners.qnt" bp-dir))
      (call-with-output-file bp-qnt (lambda (p) (display bp-text p)))
      (def bp-plan
        (hash ("module" "BackpressureOwners")
              ("file" "BackpressureOwners.qnt")
              ("quintVersion" (.get DefaultQuintPolicy quint-version))
              ("apalacheVersion" (.get DefaultQuintPolicy apalache-version))
              ("seed" 7)
              ("positiveDepth" 12)
              ("negativeDepth" 4)
              ("timeout" 120)
              ("steps" (list (hash ("label" "typecheck")
                                   ("command" '("typecheck" "BackpressureOwners.qnt"))
                                   ("expectedExit" 0)
                                   ("kind" "typecheck"))))))
      (def bp-plan-path (path-expand "plan.json" bp-dir))
      (write-json-with-license! bp-plan-path bp-plan)
      (def bp-src-digests (make-hash-table))
      (hash-put! bp-src-digests bp-src-rel (sha256-hex-file bp-src))
      (write-json-with-license!
        (path-expand "receipt.json" bp-dir)
        (hash ("status" "Projection receipt only; no verifier execution verdict")
              ("deSourceCommit" head-sha)
              ("modelIdentity" "engineering.concurrency.backpressure-memory")
              ("quintVersion" (.get DefaultQuintPolicy quint-version))
              ("sources" bp-src-digests)
              ("artifacts"
               (hash ("BackpressureOwners.qnt" (sha256-hex-string bp-text))
                     ("plan.json" (sha256-hex-file bp-plan-path)))))))))

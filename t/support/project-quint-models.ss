;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Development projection script: projects Scheme POO threat and engineering
;;; models into packages/quint-models/ as self-contained pure .qnt files with
;;; embedded verification directives (zero plan.json / receipt.json in Git).
;;; All filesystem I/O lives here; library/quint-methods/ remains pure.
(import
  :clan/poo/object
  :std/misc/ports
  "../../library/threat-capabilities/objects.ss"
  "../../library/authority-currentness/objects.ss"
  "../../library/effect-handoff/objects.ss"
  "../../library/effect-containment/objects.ss"
  "../../library/state-rollback/objects.ss"
  "../../library/zero-trust-pep-pdp/objects.ss"
  "../../library/workload-identity-rotation/objects.ss"
  "../../library/microsegmentation-egress/objects.ss"
  "../../library/oauth-token-lifecycle/objects.ss"
  "../../library/oidc-federation/objects.ss"
  "../../library/device-authorization/objects.ss"
  "../../library/governance-sod/objects.ss"
  "../../library/data-lineage-disclosure/objects.ss"
  "../../library/oauth-revocation-recovery/objects.ss"
  "../../library/gc-tricolor-barrier/objects.ss"
  "../../library/gc-safepoint-handshake/objects.ss"
  "../../library/parallel-epoch-reclamation/objects.ss"
  "../../library/parallel-work-stealing/objects.ss"
  "../../library/concurrency-structured-cancel/objects.ss"
  "../../library/quint-methods/objects.ss"
  "../../library/quint-methods/methods.ss"
  "../../library/threat-model-profiles/objects.ss")
(export project-all-quint-models!)

(def threat-entries
  (list
    (list CapabilitiesModel (.get ThreatModelProfiles threat-capabilities))
    (list AuthorityCurrentnessModel (.get ThreatModelProfiles authority-currentness))
    (list EffectHandoffModel (.get ThreatModelProfiles effect-handoff))
    (list EffectContainmentModel (.get ThreatModelProfiles effect-containment))
    (list StateRollbackModel (.get ThreatModelProfiles exact-effect-host))
    (list ZeroTrustPepPdpModel (.get ThreatModelProfiles zero-trust-pep-pdp))
    (list WorkloadIdentityRotationModel (.get ThreatModelProfiles workload-identity-rotation))
    (list MicrosegmentationEgressModel (.get ThreatModelProfiles microsegmentation-egress))
    (list OAuthTokenLifecycleModel (.get ThreatModelProfiles oauth-token-lifecycle))
    (list OidcFederationModel (.get ThreatModelProfiles oidc-federation))
    (list DeviceAuthorizationModel (.get ThreatModelProfiles device-authorization))
    (list GovernanceSodModel (.get ThreatModelProfiles governance-sod))
    (list DataLineageDisclosureModel (.get ThreatModelProfiles data-lineage-disclosure))
    (list OAuthRevocationRecoveryModel (.get ThreatModelProfiles oauth-revocation-recovery))
    (list TricolorWriteBarrierModel (.get ThreatModelProfiles gc-tricolor-barrier))
    (list SafepointHandshakeModel (.get ThreatModelProfiles gc-safepoint-handshake))
    (list EpochReclamationModel (.get ThreatModelProfiles parallel-epoch-reclamation))
    (list WorkStealingDequeModel (.get ThreatModelProfiles parallel-work-stealing))
    (list StructuredCancelModel (.get ThreatModelProfiles concurrency-structured-cancel))))

(def (ensure-qnt-header text identity)
  (if (string-contains text "// @quint-model ")
    text
    (let ((lines (string-split text #\newline)))
      (let loop ((rest lines) (acc '()) (inserted? #f))
        (cond
         ((null? rest) (string-join (reverse acc) "\n"))
         ((and (not inserted?)
               (not (string-prefix? "//" (car rest))))
          (loop rest
                (append (list "// @quint-version 0.33.0"
                              (string-append "// @quint-model " identity))
                        acc)
                #t))
         (else
          (loop (cdr rest) (cons (car rest) acc) inserted?)))))))

(def (project-all-quint-models! repo-root)
  (def pkg-root (path-expand "packages/quint-models" repo-root))
  (for-each
    (lambda (entry)
      (def model (car entry))
      (def profile (cadr entry))
      (def out-dir (path-expand (.get model domain-dir) pkg-root))
      (create-directory* out-dir)
      ;; Validate sealed profile + plan contract in memory without emitting JSON files.
      (quint-plan model profile DefaultQuintPolicy)
      (def qnt-text (quint-module model))
      (def qnt-path (path-expand (.get model quint-file) out-dir))
      (call-with-output-file qnt-path (lambda (p) (display qnt-text p))))
    threat-entries)
  ;; Also publish the maintained engineering/concurrency/backpressure-memory Quint model (D3).
  (def bp-src (path-expand "languages-engineering/quint/concurrency/backpressure-memory/model.qnt" repo-root))
  (when (file-exists? bp-src)
    (let ()
      (def bp-dir (path-expand "engineering/concurrency/backpressure-memory" pkg-root))
      (create-directory* bp-dir)
      (def bp-text (ensure-qnt-header (read-file-string bp-src) "engineering.concurrency.backpressure-memory"))
      (def bp-qnt (path-expand "BackpressureOwners.qnt" bp-dir))
      (call-with-output-file bp-qnt (lambda (p) (display bp-text p))))))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B1 (10.158): Autonomous Multi-Agent Release Governance,
;;; Separation of Duties (SoD), Canary SLO Monitoring, and Durable Merkle Rollback.
;;; Proves three business-critical safety invariants:
;;;   1. Author Agent can never self-approve production promotion (sodViolations == 0).
;;;   2. Production promotion requires a pinned M1 pre-release rollback cut (unpinnedPromotions == 0).
;;;   3. Promotion is blocked during emergency freeze or canary SLO breach (revokedOrBreachedPromotions == 0),
;;;      while rollback preserves 100% of forensic evidence (forensicHistoryIntact).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ReleaseSodRollbackModel
        SelfApprovalSodCountermodel
        UnpinnedPromotionCountermodel
        EmergencyFreezeBypassCountermodel)

(.def (ReleaseSodRollbackModel @ ThreatModel.)
  identity: 'engineering.defense.release-sod-rollback
  family: 'engineering.defense.release-sod-rollback
  title: "Autonomous Release Governance: Separation of Duties, Canary & Durable Rollback"
  subdomain: 'quint.engineering.defense
  papers:
  '(("D. D. Clark & D. R. Wilson (IEEE S&P 1987)"
     "A Comparison of Commercial and Military Computer Security Policies: Separation of Duties and Well-Formed Transactions.")
    ("Deterministic Engineering (10.153 / 10.156 / 10.158)"
     "Autonomous AI release gating combining SoD, pinned M1 rollback cuts, live M3 emergency freeze, and forensic preservation."))
  quint-module: "release_sod_rollback"
  quint-file: "ReleaseSodRollback.qnt"
  domain-dir: "engineering/defense/release-sod-rollback"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((release-sod-safe DE-REL-SAFE quint)
    (release-sod-countermodel DE-REL-COUNTER quint))
  dependencies:
  '((DE-REL-SAFE source)
    (DE-REL-SAFE profile)
    (DE-REL-SAFE method)
    (DE-REL-COUNTER source)
    (DE-REL-COUNTER profile)
    (DE-REL-COUNTER method))
  invariant: "Forensic evidence stays intact across rollbacks, no author self-approves production promotion (sodViolations == 0), no promotion occurs without a pinned M1 pre-release cut (unpinnedPromotions == 0), and no promotion bypasses independent audit, emergency freeze, or canary SLO health (revokedOrBreachedPromotions == 0)."
  parameters: '()
  state:
  '((authorId "int" "1")
    (approverId "int" "0")
    (independentAuditPassed "bool" "false")
    (preReleaseCutPinned "bool" "false")
    (authorityRevoked "bool" "false")
    (canarySloBreached "bool" "false")
    (promotedToProd "bool" "false")
    (rolledBack "bool" "false")
    (forensicHistoryIntact "bool" "true")
    (sodViolations "int" "0")
    (unpinnedPromotions "int" "0")
    (revokedOrBreachedPromotions "int" "0"))
  guards:
  '((enforce-separation-of-duties (and (!= (. h approverId) 0) (!= (. h approverId) (. h authorId))))
    (require-pinned-rollback-cut (. h preReleaseCutPinned))
    (forbid-revoked-or-breached-promotion
      (and (. h independentAuditPassed) (not (. h authorityRevoked)) (not (. h canarySloBreached)))))
  transitions:
  '((authorSelfApproveAttempt
      (action authorSelfApproveAttempt ()
        (if (and (= (. h approverId) 0) (not (. h promotedToProd)))
          (set-h (approverId (. h authorId)))
          (keep-h))))
    (independentApprove
      (action independentApprove ()
        (if (and (!= (. h approverId) 2) (not (. h promotedToProd)))
          (set-h (approverId 2))
          (keep-h))))
    (passReleaseAudit
      (action passReleaseAudit ()
        (if (not (. h independentAuditPassed))
          (set-h (independentAuditPassed #t))
          (keep-h))))
    (pinPreReleaseCut
      (action pinPreReleaseCut ()
        (if (not (. h preReleaseCutPinned))
          (set-h (preReleaseCutPinned #t))
          (keep-h))))
    (triggerEmergencyFreeze
      (action triggerEmergencyFreeze ()
        (if (not (. h authorityRevoked))
          (set-h (authorityRevoked #t))
          (keep-h))))
    (detectCanaryBreach
      (action detectCanaryBreach ()
        (if (not (. h canarySloBreached))
          (set-h (canarySloBreached #t))
          (keep-h))))
    (promoteToProduction
      (action promoteToProduction ()
        (if (and (not (. h promotedToProd))
                 (guard enforce-separation-of-duties
                   (and (!= (. h approverId) 0) (!= (. h approverId) (. h authorId))))
                 (guard require-pinned-rollback-cut (. h preReleaseCutPinned))
                 (guard forbid-revoked-or-breached-promotion
                   (and (. h independentAuditPassed)
                        (not (. h authorityRevoked))
                        (not (. h canarySloBreached)))))
          (set-h (promotedToProd #t)
                 (sodViolations
                   (if (and (!= (. h approverId) 0) (!= (. h approverId) (. h authorId)))
                     (. h sodViolations)
                     (+ (. h sodViolations) 1)))
                 (unpinnedPromotions
                   (if (. h preReleaseCutPinned)
                     (. h unpinnedPromotions)
                     (+ (. h unpinnedPromotions) 1)))
                 (revokedOrBreachedPromotions
                   (if (and (. h independentAuditPassed)
                            (not (. h authorityRevoked))
                            (not (. h canarySloBreached)))
                     (. h revokedOrBreachedPromotions)
                     (+ (. h revokedOrBreachedPromotions) 1))))
          (keep-h))))
    (rollbackToPinnedCut
      (action rollbackToPinnedCut ()
        (if (and (. h promotedToProd) (. h preReleaseCutPinned) (not (. h rolledBack)))
          (set-h (promotedToProd #f)
                 (rolledBack #t))
          (keep-h))))
    (step
      (action step ()
        (any authorSelfApproveAttempt independentApprove passReleaseAudit pinPreReleaseCut
             triggerEmergencyFreeze detectCanaryBreach promoteToProduction rollbackToPinnedCut))))
  safety:
  '(and (. h forensicHistoryIntact)
        (= (. h sodViolations) 0)
        (= (. h unpinnedPromotions) 0)
        (= (. h revokedOrBreachedPromotions) 0))
  traces:
  '((governedPromotionAndDurableRollbackSafeTest
      (run governedPromotionAndDurableRollbackSafeTest
        (then init passReleaseAudit pinPreReleaseCut independentApprove
              promoteToProduction detectCanaryBreach rollbackToPinnedCut
              (all (assert safety)
                   (assert (. h rolledBack))
                   (assert (not (. h promotedToProd)))
                   (assert (. h forensicHistoryIntact))
                   (keep-h)))))
    (selfApprovalViolatesSodTest
      (run selfApprovalViolatesSodTest
        (then init passReleaseAudit pinPreReleaseCut authorSelfApproveAttempt promoteSelfApproved
              (all (assert (not safety))
                   (assert (> (. h sodViolations) 0))
                   (keep-h)))))
    (unpinnedPromotionViolatesSafetyTest
      (run unpinnedPromotionViolatesSafetyTest
        (then init passReleaseAudit independentApprove promoteWithoutCut
              (all (assert (not safety))
                   (assert (> (. h unpinnedPromotions) 0))
                   (keep-h)))))
    (freezeBypassViolatesSafetyTest
      (run freezeBypassViolatesSafetyTest
        (then init pinPreReleaseCut independentApprove triggerEmergencyFreeze promoteIgnoreFreeze
              (all (assert (not safety))
                   (assert (> (. h revokedOrBreachedPromotions) 0))
                   (keep-h))))))
  countermodels:
  (list SelfApprovalSodCountermodel
        UnpinnedPromotionCountermodel
        EmergencyFreezeBypassCountermodel)
  limits: "Finite single-release SoD, canary SLO, and pre-release Merkle rollback abstraction; does not model multi-region traffic shifting, non-reversible database schema drops, or external DNS propagation lag.")

(.def (SelfApprovalSodCountermodel @ ReleaseSodRollbackModel)
  identity: 'engineering.defense.release-sod-rollback.self-approval
  dropped-guard: 'enforce-separation-of-duties
  step-action: "stepSelfApproval"
  derive-from-transition: 'promoteToProduction
  derive-action-name: 'promoteSelfApproved
  expected-itf-predicate: "h.sodViolations > 0")

(.def (UnpinnedPromotionCountermodel @ ReleaseSodRollbackModel)
  identity: 'engineering.defense.release-sod-rollback.unpinned-promotion
  dropped-guard: 'require-pinned-rollback-cut
  step-action: "stepUnpinnedPromotion"
  derive-from-transition: 'promoteToProduction
  derive-action-name: 'promoteWithoutCut
  expected-itf-predicate: "h.unpinnedPromotions > 0")

(.def (EmergencyFreezeBypassCountermodel @ ReleaseSodRollbackModel)
  identity: 'engineering.defense.release-sod-rollback.freeze-bypass
  dropped-guard: 'forbid-revoked-or-breached-promotion
  step-action: "stepFreezeBypass"
  derive-from-transition: 'promoteToProduction
  derive-action-name: 'promoteIgnoreFreeze
  expected-itf-predicate: "h.revokedOrBreachedPromotions > 0")

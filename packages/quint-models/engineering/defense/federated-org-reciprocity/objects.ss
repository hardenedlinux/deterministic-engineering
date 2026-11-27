;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B20 (10.199 / 10.200): Multi-Org Federated Reciprocity &
;;; Cross-Domain Dispute Arbitration.
;;; Proves three multi-org federation safety invariants:
;;;   1. Ratified Bilateral Treaty Fence: cross-org operations require an active ratified
;;;      bilateral treaty (unratifiedTreatyViolations == 0).
;;;   2. Bilateral Countersignature Fence: BOTH originating and target sovereign
;;;      organizations must countersign (unilateralSignViolations == 0).
;;;   3. Active Dispute-Freeze Preemption: any active cross-org dispute freeze immediately
;;;      halts bilateral admission (disputeFreezeViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export FederatedOrgReciprocityModel
        UnratifiedTreatyCountermodel
        UnilateralSignCountermodel
        DisputeFreezeCountermodel)

(.def (FederatedOrgReciprocityModel @ ThreatModel.)
  identity: 'engineering.defense.federated-org-reciprocity
  family: 'engineering.defense.federated-org-reciprocity
  title: "Multi-Org Federated Reciprocity & Cross-Domain Dispute Arbitration"
  subdomain: 'quint.engineering.defense
  papers:
  '(("OASIS Cross-Enterprise Trust & Federated Governance Protocols"
     "Bilateral reciprocity agreements and multi-org cryptographic countersigning.")
    ("BFT Multi-Domain Interoperability & Dispute-Freeze Arbitration"
     "Fail-closed preemption of cross-organization execution during active legal/compliance disputes.")
    ("Deterministic Engineering (10.199 / 10.200)"
     "Bilateral Ed25519 reciprocity, ratified treaties, and dispute-freeze preemption."))
  quint-module: "federated_org_reciprocity"
  quint-file: "FederatedOrgReciprocity.qnt"
  domain-dir: "engineering/defense/federated-org-reciprocity"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((federated-org-safe DE-FORP-SAFE quint)
    (federated-org-countermodel DE-FORP-COUNTER quint))
  dependencies:
  '((DE-FORP-SAFE source)
    (DE-FORP-SAFE profile)
    (DE-FORP-SAFE method)
    (DE-FORP-COUNTER source)
    (DE-FORP-COUNTER profile)
    (DE-FORP-COUNTER method))
  invariant: "Cross-org federated operation admission requires a ratified bilateral treaty (unratifiedTreatyViolations == 0), countersignatures from BOTH origin and target orgs (unilateralSignViolations == 0), and no active dispute freeze (disputeFreezeViolations == 0)."
  parameters: '()
  state:
  '((treatyRatified "bool" "false")
    (originOrgSigned "bool" "false")
    (targetOrgSigned "bool" "false")
    (disputeFreezeActive "bool" "false")
    (admittedFedOps "int" "0")
    (unratifiedTreatyViolations "int" "0")
    (unilateralSignViolations "int" "0")
    (disputeFreezeViolations "int" "0"))
  guards:
  '((require-treaty-ratified (. h treatyRatified))
    (require-bilateral-countersigs (and (. h originOrgSigned) (. h targetOrgSigned)))
    (require-no-dispute-freeze (not (. h disputeFreezeActive))))
  transitions:
  '((ratifyBilateralTreaty
      (action ratifyBilateralTreaty ()
        (if (not (. h treatyRatified))
          (set-h (treatyRatified #t))
          (keep-h))))
    (originOrgSign
      (action originOrgSign ()
        (if (not (. h originOrgSigned))
          (set-h (originOrgSigned #t))
          (keep-h))))
    (targetOrgSign
      (action targetOrgSign ()
        (if (not (. h targetOrgSigned))
          (set-h (targetOrgSigned #t))
          (keep-h))))
    (raiseDisputeFreeze
      (action raiseDisputeFreeze ()
        (if (not (. h disputeFreezeActive))
          (set-h (disputeFreezeActive #t))
          (keep-h))))
    (resolveDisputeFreeze
      (action resolveDisputeFreeze ()
        (if (. h disputeFreezeActive)
          (set-h (disputeFreezeActive #f))
          (keep-h))))
    (admitFederatedOp
      (action admitFederatedOp ()
        (if (and (< (. h admittedFedOps) 2)
                 (guard require-treaty-ratified (. h treatyRatified))
                 (guard require-bilateral-countersigs (and (. h originOrgSigned) (. h targetOrgSigned)))
                 (guard require-no-dispute-freeze (not (. h disputeFreezeActive))))
          (set-h (admittedFedOps (+ (. h admittedFedOps) 1))
                 (unratifiedTreatyViolations
                   (if (. h treatyRatified)
                     (. h unratifiedTreatyViolations)
                     (+ (. h unratifiedTreatyViolations) 1)))
                 (unilateralSignViolations
                   (if (and (. h originOrgSigned) (. h targetOrgSigned))
                     (. h unilateralSignViolations)
                     (+ (. h unilateralSignViolations) 1)))
                 (disputeFreezeViolations
                   (if (not (. h disputeFreezeActive))
                     (. h disputeFreezeViolations)
                     (+ (. h disputeFreezeViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any ratifyBilateralTreaty originOrgSign targetOrgSign
             raiseDisputeFreeze resolveDisputeFreeze admitFederatedOp))))
  safety:
  '(and (= (. h unratifiedTreatyViolations) 0)
        (= (. h unilateralSignViolations) 0)
        (= (. h disputeFreezeViolations) 0))
  traces:
  '((cleanFederatedOpTest
      (run cleanFederatedOpTest
        (then init ratifyBilateralTreaty originOrgSign targetOrgSign admitFederatedOp
              (all (assert safety)
                   (assert (= (. h admittedFedOps) 1))
                   (keep-h)))))
    (unratifiedTreatyViolatesSafetyTest
      (run unratifiedTreatyViolatesSafetyTest
        (then init originOrgSign targetOrgSign admitOpUnratified
              (all (assert (not safety))
                   (assert (> (. h unratifiedTreatyViolations) 0))
                   (keep-h)))))
    (unilateralSignViolatesSafetyTest
      (run unilateralSignViolatesSafetyTest
        (then init ratifyBilateralTreaty originOrgSign admitOpUnilateral
              (all (assert (not safety))
                   (assert (> (. h unilateralSignViolations) 0))
                   (keep-h)))))
    (disputeFreezeViolatesSafetyTest
      (run disputeFreezeViolatesSafetyTest
        (then init ratifyBilateralTreaty originOrgSign targetOrgSign raiseDisputeFreeze admitOpFrozen
              (all (assert (not safety))
                   (assert (> (. h disputeFreezeViolations) 0))
                   (keep-h))))))
  countermodels:
  (list UnratifiedTreatyCountermodel
        UnilateralSignCountermodel
        DisputeFreezeCountermodel)
  limits: "Bounded bilateral reciprocity and dispute-freeze state machine; arbitrary member org registries, self-reciprocity anti-spoofing, and treaty epoch expiration are proved unboundedly in FederatedOrgReciprocity.lean.")

(.def (UnratifiedTreatyCountermodel @ FederatedOrgReciprocityModel)
  identity: 'engineering.defense.federated-org-reciprocity.unratified-treaty
  dropped-guard: 'require-treaty-ratified
  step-action: "stepUnratifiedTreaty"
  derive-from-transition: 'admitFederatedOp
  derive-action-name: 'admitOpUnratified
  expected-itf-predicate: "h.unratifiedTreatyViolations > 0")

(.def (UnilateralSignCountermodel @ FederatedOrgReciprocityModel)
  identity: 'engineering.defense.federated-org-reciprocity.unilateral-sign
  dropped-guard: 'require-bilateral-countersigs
  step-action: "stepUnilateralSign"
  derive-from-transition: 'admitFederatedOp
  derive-action-name: 'admitOpUnilateral
  expected-itf-predicate: "h.unilateralSignViolations > 0")

(.def (DisputeFreezeCountermodel @ FederatedOrgReciprocityModel)
  identity: 'engineering.defense.federated-org-reciprocity.dispute-freeze
  dropped-guard: 'require-no-dispute-freeze
  step-action: "stepDisputeFreeze"
  derive-from-transition: 'admitFederatedOp
  derive-action-name: 'admitOpFrozen
  expected-itf-predicate: "h.disputeFreezeViolations > 0")

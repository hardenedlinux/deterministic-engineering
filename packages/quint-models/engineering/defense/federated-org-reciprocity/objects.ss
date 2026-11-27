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
(export FederatedOrgReciprocityModel)

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
  limits: "Bounded bilateral reciprocity and dispute-freeze state machine; arbitrary member org registries, self-reciprocity anti-spoofing, and treaty epoch expiration are proved unboundedly in FederatedOrgReciprocity.lean.")

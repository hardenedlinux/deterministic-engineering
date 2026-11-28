;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B19 (10.197 / 10.198): Cross-Region Sovereign Data-Residency &
;;; Geo-Fenced AI Governance (GDPR Chapter V Adequacy / SCC Transfer Permits & LLM
;;; Inference-Endpoint Residency Fencing).
;;; Proves three sovereign data-residency safety invariants:
;;;   1. Target Region Allowlist Fence: storage placement is only admitted inside
;;;      allowed non-sanctioned sovereign jurisdictions (sanctionedPlacementViolations == 0).
;;;   2. LLM Inference-Endpoint Residency Fence: inference routing never escapes the
;;;      allowed sovereign boundary (inferenceEscapeViolations == 0).
;;;   3. Cross-Border Adequacy/SCC Transfer Permit Fence: cross-region data egress
;;;      requires an explicit valid transfer permit while intra-region ops need none
;;;      (unpermittedEgressViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export GeoResidencySovereigntyModel)

(.def (GeoResidencySovereigntyModel @ ThreatModel.)
  identity: 'engineering.defense.geo-residency-sovereignty
  family: 'engineering.defense.geo-residency-sovereignty
  title: "Cross-Region Sovereign Data-Residency & Geo-Fenced Governance"
  subdomain: 'quint.engineering.defense
  papers:
  '(("EU GDPR Chapter V (Articles 44-49)"
     "Transfers of personal data to third countries via Adequacy Decisions and Standard Contractual Clauses.")
    ("NIST SP 800-53 & EU AI Act Sovereign Compute Residency"
     "Jurisdictional pinning of both storage partitions and LLM inference endpoints.")
    ("Deterministic Engineering (10.197 / 10.198)"
     "Ed25519 regional sovereignty attestations, cross-border transfer permits, and anti-P4 intra-region sufficiency."))
  quint-module: "geo_residency_sovereignty"
  quint-file: "GeoResidencySovereignty.qnt"
  domain-dir: "engineering/defense/geo-residency-sovereignty"
  rules:
  '((geo-residency-safe DE-GRSV-SAFE quint)
    (geo-residency-countermodel DE-GRSV-COUNTER quint))
  dependencies:
  '((DE-GRSV-SAFE source)
    (DE-GRSV-SAFE profile)
    (DE-GRSV-SAFE method)
    (DE-GRSV-COUNTER source)
    (DE-GRSV-COUNTER profile)
    (DE-GRSV-COUNTER method))
  invariant: "Sovereign placement admission requires allowed non-sanctioned target region (sanctionedPlacementViolations == 0), allowed inference endpoint region (inferenceEscapeViolations == 0), and valid cross-border adequacy/SCC permit whenever transfer crosses borders (unpermittedEgressViolations == 0)."
  limits: "Bounded regional residency and transfer-permit abstraction; arbitrary jurisdiction allowlists, sanctioned sets, revoked authorities, and anti-P4 intra-region sufficiency are proved unboundedly in GeoResidencyAndSovereignty.lean.")

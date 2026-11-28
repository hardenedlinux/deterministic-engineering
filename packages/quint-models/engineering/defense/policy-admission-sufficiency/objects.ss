;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F2 / G3: Evidence sufficiency vs. policy-required direct boundary records and method admission
;;; (20.17 HA/AH & 20.18 OP/BR/AM / 10.153).
;;; Proves:
;;;   1. When policy does not demand a direct boundary record, sufficient existing history qualifies
;;;      without inventing redundant receipt formats (anti-P3/P4 bloat).
;;;   2. When authentic policy requires a direct record (BR01) or closed method admission (AM01/AM02),
;;;      history-only or unadmitted bindings cannot silently qualify (anti-P1 weakening).
;;;   3. Refusing an unadmitted or forbidden association preserves authentic original method bytes (AM02).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PolicyAdmissionSufficiencyModel)

(.def (PolicyAdmissionSufficiencyModel @ ThreatModel.)
  identity: 'engineering.defense.policy-admission-sufficiency
  family: 'engineering.defense.policy-admission-sufficiency
  title: "Evidence Sufficiency vs. Policy-Required Checks & Method Admission (20.17-20.18)"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (20.17 HA/AH & 20.18 OP/BR/AM)"
     "Sufficient existing evidence stops redundant format demands, while authentic mandatory policy clauses and method admission mappings remain strictly enforced.")
    ("Deterministic Engineering (10.153)"
     "G3 Monotonic governance floor vs. M1 sufficiency stopping."))
  quint-module: "policy_admission_sufficiency"
  quint-file: "PolicyAdmissionSufficiency.qnt"
  domain-dir: "engineering/defense/policy-admission-sufficiency"
  rules:
  '((policy-sufficiency-safe DE-POL-SAFE quint)
    (policy-sufficiency-countermodel DE-POL-COUNTER quint))
  dependencies:
  '((DE-POL-SAFE source)
    (DE-POL-SAFE profile)
    (DE-POL-SAFE method)
    (DE-POL-COUNTER source)
    (DE-POL-COUNTER profile)
    (DE-POL-COUNTER method))
  invariant: "Refusing an offered binding never deletes authentic original method bytes; a policy-qualified verdict always has sufficient underlying history, an admitted method mapping (status == 1), and a direct boundary record whenever authentic policy requires one."
  limits: "Finite single-verdict policy-admission and sufficiency abstraction (methodAdmissionStatus: 0=unknown, 1=admitted, 2=forbidden); does not model multi-tenant delegation chains or cryptographic receipt verification.")

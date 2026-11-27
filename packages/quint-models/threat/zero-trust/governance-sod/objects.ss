;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Governance Separation of Duties (SoD) and Veto precedence threat model.
;;; Co-located Yuanxu unit: single source of truth alongside GovernanceSod.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects AuthorityCurrentnessModel))
(export GovernanceSodModel)

(.def (GovernanceSodModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust.governance-sod
  family: 'threat.zero-trust.governance-sod
  title: "Governance Separation of Duties (SoD) & Forbid-Veto Precedence"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("D. D. Clark & D. R. Wilson (IEEE S&P 1987)"
     "A Comparison of Commercial and Military Computer Security Policies: dual-control Separation of Duties.")
    ("R. Simon & M. E. Zurko (IEEE CSFW 1997)"
     "Separation of Duty in Role-Based Environments: dynamic history-based SoD and deny-overrides precedence."))
  quint-module: "governance_sod"
  quint-file: "GovernanceSod.qnt"
  domain-dir: "threat/zero-trust/governance-sod"
  rules:
  '((sod-distinct-actor GOV-SOD-ACTOR quint)
    (veto-precedence GOV-VETO-PREC quint))
  dependencies:
  '((GOV-SOD-ACTOR source)
    (GOV-SOD-ACTOR profile)
    (GOV-SOD-ACTOR method)
    (GOV-VETO-PREC source)
    (GOV-VETO-PREC profile)
    (GOV-VETO-PREC method))
  invariant: "An action executes only with a distinct approver (approver != proposer) and zero active forbid vetoes."
  limits: "Finite two-principal governance abstraction; does not model cryptographic identity attestation or multi-quorum threshold committees.")

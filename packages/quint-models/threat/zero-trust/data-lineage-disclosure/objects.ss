;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Cumulative Data Disclosure and Singling-Out Ledger threat model.
;;; Co-located Yuanxu unit: single source of truth alongside DataLineageDisclosure.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects AuthorityCurrentnessModel))
(export DataLineageDisclosureModel)

(.def (DataLineageDisclosureModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust.data-lineage-disclosure
  family: 'threat.zero-trust.data-lineage-disclosure
  title: "Cumulative Data Disclosure & k-Anonymity Singling-Out Ledger"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("L. Sweeney (IJUFKS 2002)"
     "k-Anonymity: A Model for Protecting Privacy — preventing linkage singling-out below cardinality floor k.")
    ("A. Cohen & K. Nissim (PNAS 2020)"
     "Towards Formalizing the GDPR's Notion of Singling Out."))
  quint-module: "data_lineage_disclosure"
  quint-file: "DataLineageDisclosure.qnt"
  domain-dir: "threat/zero-trust/data-lineage-disclosure"
  rules:
  '((k-anonymity-narrowing DATA-KANON-FLOOR quint)
    (disclosure-budget DATA-BUDGET-CAP quint))
  dependencies:
  '((DATA-KANON-FLOOR source)
    (DATA-KANON-FLOOR profile)
    (DATA-KANON-FLOOR method)
    (DATA-BUDGET-CAP source)
    (DATA-BUDGET-CAP profile)
    (DATA-BUDGET-CAP method))
  invariant: "Cumulative query narrowing never shrinks the compatible candidate set below k=2 and total disclosures never exceed budget."
  limits: "Finite cardinality-based singling-out indicator (k=2 over 4 records); does not provide differential privacy or inference resistance against auxiliary side-information.")

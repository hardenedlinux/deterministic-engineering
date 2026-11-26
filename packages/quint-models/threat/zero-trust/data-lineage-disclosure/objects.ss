;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Cumulative Data Disclosure and Singling-Out Ledger threat model.
;;; Co-located Yuanxu unit: single source of truth alongside DataLineageDisclosure.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects AuthorityCurrentnessModel))
(export DataLineageDisclosureModel
        SinglingOutCountermodel
        BudgetOverrunCountermodel)

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
  quint-imports:
  '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
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
  parameters: '()
  state:
  '((possibleIds "Set[int]" "Set(1, 2, 3, 4)")
    (disclosures "int" "0"))
  guards:
  '((k-anonymity-narrowing (>= (size (intersect (. h possibleIds) cand)) 2))
    (disclosure-budget (< (. h disclosures) 2)))
  transitions:
  '((discloseSet
      (action discloseSet ((cand "Set[int]")) "bool"
        (if (and (guard disclosure-budget (< (. h disclosures) 2))
                 (guard k-anonymity-narrowing
                        (>= (size (intersect (. h possibleIds) cand)) 2)))
          (set-h (possibleIds (intersect (. h possibleIds) cand))
                 (disclosures (+ (. h disclosures) 1)))
          (keep-h))))
    (disclose
      (action disclose ()
        (nondet ((cand (set (set 1 2 3) (set 2 3 4) (set 1 2) (set 2 4))))
          (call discloseSet cand))))
    (step
      (action step ()
        (any disclose))))
  safety:
  '(and (>= (size (. h possibleIds)) 2)
        (<= (. h disclosures) 2))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (validNarrowingAboveFloorTest
      (run validNarrowingAboveFloorTest
        (then init
              (call discloseSet (set 1 2 3))
              (call discloseSet (set 2 3 4))
              (all (assert (= (size (. h possibleIds)) 2))
                   (assert safety)
                   (keep-h)))))
    (singlingOutQueryRejectedTest
      (run singlingOutQueryRejectedTest
        (then init
              (call discloseSet (set 1 2))
              (call discloseSet (set 2 4))
              (all (assert (= (size (. h possibleIds)) 2))
                   (assert (= (. h disclosures) 1))
                   (assert safety)
                   (keep-h)))))
    (singlingOutCountermodelTest
      (run singlingOutCountermodelTest
        (then init
              (call discloseSet (set 1 2))
              (call discloseUnchecked (set 2 4))
              checkUnsafe))))
  countermodels:
  (list SinglingOutCountermodel
        BudgetOverrunCountermodel)
  limits: "Finite cardinality-based singling-out indicator (k=2 over 4 records); does not provide differential privacy or inference resistance against auxiliary side-information.")

(.def (SinglingOutCountermodel @ DataLineageDisclosureModel)
  identity: 'threat.zero-trust.data-lineage-disclosure.singling-out
  dropped-guard: 'k-anonymity-narrowing
  step-action: "stepSinglingOut"
  derive-from-transition: 'discloseSet
  derive-action-name: 'discloseUnchecked
  derive-step-call: '(nondet ((cand (set (set 1 2 3) (set 2 3 4) (set 1 2) (set 2 4))))
                       (call discloseUnchecked cand))
  expected-itf-predicate: "size(h.possibleIds) < 2")

(.def (BudgetOverrunCountermodel @ DataLineageDisclosureModel)
  identity: 'threat.zero-trust.data-lineage-disclosure.budget-overrun
  dropped-guard: 'disclosure-budget
  step-action: "stepBudgetOverrun"
  derive-from-transition: 'discloseSet
  derive-action-name: 'discloseOverBudget
  derive-step-call: '(nondet ((cand (set (set 1 2 3) (set 2 3 4) (set 1 2) (set 2 4))))
                       (call discloseOverBudget cand))
  expected-itf-predicate: "h.disclosures > 2")

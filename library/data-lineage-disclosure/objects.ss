;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Cumulative Data Disclosure and Singling-Out Ledger threat model.
;;; Models finite candidate-set narrowing across repeated queries with minimum
;;; k-anonymity floor (k >= 2) and bounded disclosure budget.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export DataLineageDisclosureModel
        SinglingOutCountermodel
        BudgetOverrunCountermodel)

(.def (DataLineageDisclosureModel @ AuthorityCurrentnessModel)
  identity: 'threat.data-lineage-disclosure
  family: 'threat.data-lineage-disclosure
  quint-module: "data_lineage_disclosure"
  quint-file: "DataLineageDisclosure.qnt"
  domain-dir: "threat/data-lineage-disclosure"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((k-anonymity-narrowing DATA-KANON-FLOOR quint)
           (disclosure-budget DATA-BUDGET-CAP quint))
  dependencies: '((DATA-KANON-FLOOR source) (DATA-KANON-FLOOR profile) (DATA-KANON-FLOOR method)
                  (DATA-BUDGET-CAP source) (DATA-BUDGET-CAP profile) (DATA-BUDGET-CAP method))
  invariant: "Cumulative query narrowing never shrinks the compatible candidate set below k=2 and total disclosures never exceed budget."
  parameters: '()
  state: '((possibleIds "Set[int]" "Set(1, 2, 3, 4)")
           (disclosures "int" "0")
           (unsafe "bool" "false"))
  guards: '((k-anonymity-narrowing "size(h.possibleIds.intersect(cand)) >= 2")
            (disclosure-budget "h.disclosures < 2"))
  transitions:
  '((discloseSet "action discloseSet(cand: Set[int]): bool = if (h.disclosures < 2 and size(h.possibleIds.intersect(cand)) >= 2)\n    h' = h.with(\"possibleIds\", h.possibleIds.intersect(cand)).with(\"disclosures\", h.disclosures + 1)\n    else h' = h")
    (disclose "action disclose = { nondet cand = Set(Set(1, 2, 3), Set(2, 3, 4), Set(1, 2), Set(2, 4)).oneOf()\n    discloseSet(cand) }")
    (step "action step = any { disclose }"))
  safety: "not(h.unsafe) and size(h.possibleIds) >= 2 and h.disclosures <= 2"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (validNarrowingAboveFloorTest "run validNarrowingAboveFloorTest = init.then(discloseSet(Set(1, 2, 3))).then(discloseSet(Set(2, 3, 4))).then(all { assert(size(h.possibleIds) == 2), assert(safety), h' = h })")
    (singlingOutQueryRejectedTest "run singlingOutQueryRejectedTest = init.then(discloseSet(Set(1, 2))).then(discloseSet(Set(2, 4))).then(all { assert(size(h.possibleIds) == 2), assert(h.disclosures == 1), assert(safety), h' = h })")
    (singlingOutCountermodelTest "run singlingOutCountermodelTest = init.then(discloseSet(Set(1, 2))).then(discloseUnchecked(Set(2, 4))).then(checkUnsafe)"))
  countermodels: (list SinglingOutCountermodel BudgetOverrunCountermodel)
  limits: "Finite cardinality-based singling-out indicator (k=2 over 4 records); does not provide differential privacy or inference resistance against auxiliary side-information.")

(.def (SinglingOutCountermodel @ DataLineageDisclosureModel)
  identity: 'threat.data-lineage-disclosure.singling-out
  dropped-guard: 'k-anonymity-narrowing
  step-action: "stepSinglingOut"
  counter-action: "action discloseUnchecked(cand: Set[int]): bool = if (h.disclosures < 2)\n    h' = h.with(\"possibleIds\", h.possibleIds.intersect(cand)).with(\"disclosures\", h.disclosures + 1).with(\"unsafe\", h.unsafe or size(h.possibleIds.intersect(cand)) < 2)\n    else h' = h\n  action stepSinglingOut = any { step, discloseUnchecked(Set(2, 4)) }"
  expected-itf-predicate: "h.unsafe == true")

(.def (BudgetOverrunCountermodel @ DataLineageDisclosureModel)
  identity: 'threat.data-lineage-disclosure.budget-overrun
  dropped-guard: 'disclosure-budget
  step-action: "stepBudgetOverrun"
  counter-action: "action discloseOverBudget = h' = h.with(\"disclosures\", h.disclosures + 1).with(\"unsafe\", h.unsafe or h.disclosures >= 2)\n  action stepBudgetOverrun = any { step, discloseOverBudget }"
  expected-itf-predicate: "h.disclosures > 2")

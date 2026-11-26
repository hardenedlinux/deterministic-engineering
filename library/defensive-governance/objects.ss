;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; G2 AI Agent Defensive-Hallucination Controls (pure POO object declarations).
(import :clan/poo/object
        (only-in :clan/poo/type validate)
        "types.ss")
(export AgentDefensiveHallucinationControls)

(def AgentDefensiveHallucinationControls
  (map (lambda (ctrl) (validate AgentHallucinationControlType ctrl))
    (list
      (.o identity: 'g2.silent-fallback-insertion
          hallucination-class: 'silent-fallback
          symptom: "Agent inserts try/catch or default-empty return to silence failing checks instead of fixing the broken invariant."
          mechanical-refusal: "Refuse success-shaped fallback on SetupDefect/Refuted in F1 epistemic lattice & C4 contrast tests."
          governing-contract: 'engineering.defense.epistemic-state-lattice)
      (.o identity: 'g2.floor-weakening
          hallucination-class: 'floor-weakening
          symptom: "Agent overrides require-countermodels?, use-time witness, or assertions downward to achieve a green build."
          mechanical-refusal: "Band-5 monotonic meet combiner in Yuanxu Design 165 rejects any peer weakening of governance floors."
          governing-contract: 'defense-profiles)
      (.o identity: 'g2.redundant-defensive-glue
          hallucination-class: 'redundant-defensive-glue
          symptom: "Agent copies redundant null/bounds/wrapper checks across internal functions without discharging a new obligation."
          mechanical-refusal: "F3 guard-necessity audit + G1 five-tuple admission reject guards lacking witness/owner/obligation."
          governing-contract: 'quint-methods.audit-guards)
      (.o identity: 'g2.fabricated-evidence
          hallucination-class: 'fabricated-evidence
          symptom: "Agent substitutes confident prose, unexecuted receipt names, or style preferences for genuine authority/checker records."
          mechanical-refusal: "F1/F2 ASCENT revalidation distinguishes absent evidence (PendingMethod/PendingScope) from Proven and rejects ungrounded re-closure."
          governing-contract: 'defensive-governance.bounded-revalidation))))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Loader-owned qualification tests for library/defensive-governance:
;;; G1 five-tuple guard admission, G2 AI Agent defensive-hallucination controls,
;;; and F1/F2 live executable ASCENT BoundedRevalidationProgram.
(import :std/test
        :clan/poo/object
        (only-in :clan/poo/type validate TypeError?)
        :deterministic-engineering/library/defensive-governance/types
        :deterministic-engineering/library/defensive-governance/objects
        :deterministic-engineering/library/defensive-governance/func
        :deterministic-engineering/library/defensive-governance/interface)
(export defensive-governance-ascent-test)

(def (rows r name) ((.ref r 'rows-of) name))

(def defensive-governance-ascent-test
  (test-suite "defensive-governance G1 5-tuple, G2 hallucination controls, and F1/F2 ASCENT revalidation"
    (test-case "G1 five-tuple guard admission validates complete records and refuses M3 immutable-reuse claims"
      (validate DefensiveGovernanceScopeType (.get DefensiveGovernance core exports))
      (def valid-guard
        (.o guard-id: 'check-authority-at-use
            obligation: "Reject effect dispatch when consumption-time authority is revoked."
            owner: 'unknown-effect-retry
            scoped-failure: "Execution under revoked live authority (TOCTOU)."
            witness-kind: 'apalache-countermodel
            witness-ref: "UnknownEffectRetry.qnt::stepToctouRevokedUse"
            affected-consumer: 'effect-gateway
            mutability: 'M3-mutable-root
            pathology-prevented: 'P2-misplaced
            claims-immutable-reuse?: #f))
      (check-equal? (.get (admit-guard-five-tuple valid-guard) guard-id) 'check-authority-at-use)
      ;; Claiming immutable reuse on an M3 mutable root must fail closed:
      (check-exception
        (admit-guard-five-tuple (.cc valid-guard 'claims-immutable-reuse? #t))
        error?)
      ;; Missing witness-ref fails sealed Record contract:
      (check-exception
        (admit-guard-five-tuple
          (.o guard-id: 'incomplete-guard
              obligation: "Incomplete"
              owner: 'foo
              scoped-failure: "none"
              witness-kind: 'apalache-countermodel
              affected-consumer: 'bar
              mutability: 'M1-immutable
              pathology-prevented: 'P4-bloat
              claims-immutable-reuse?: #t))
        TypeError?)
      ;; G2 hallucination controls cover all 4 LLM defensive pathologies:
      (check-equal? (length AgentDefensiveHallucinationControls) 4))

    (test-case "F1/F2 live ASCENT BoundedRevalidationProgram preserves 6 epistemic states, bounded invalidation, and frozen history"
      (def facts
        (list
          (cons 'subject '(("s-defect") ("s-pending-method") ("s-pending-scope")
                           ("s-proven") ("s-refuted") ("s-conflict")))
          (cons 'expected_body_present '(("s-pending-method") ("s-pending-scope")
                                         ("s-proven") ("s-refuted") ("s-conflict")))
          (cons 'method_completed '(("s-pending-scope") ("s-proven") ("s-refuted") ("s-conflict")))
          (cons 'scope_established '(("s-proven") ("s-refuted") ("s-conflict")))
          (cons 'authentic_allow '(("s-proven") ("s-conflict")))
          (cons 'authentic_deny '(("s-refuted") ("s-conflict")))
          (cons 'conflict_resolved '())
          (cons 'frozen_cut_item '(("kOld" "r2m")))
          (cons 'independent_method_result '(("VOldInvalid" "art-17")))
          (cons 'review_depends_on_neg_domain '(("DOld" "P0-Q-counters") ("DOther" "unrelated-domain")))
          (cons 'neg_domain_member '(("P0-Q-counters" "ENew" "relevant")
                                     ("unrelated-domain" "EOut" "irrelevant")))
          (cons 'replacement_reason_admitted '())
          (cons 'guard_proposal '(("g-valid" "M3-mutable-root" "no" "yes")
                                  ("g-nowitness" "M1-immutable" "yes" "no")
                                  ("g-bad-toctou" "M3-mutable-root" "yes" "yes")))
          (cons 'policy_requires_direct_record '(("s-strict-missing") ("s-strict-ok")))
          (cons 'direct_record_present '(("s-strict-ok")))
          (cons 'method_admission '(("VAdmitted" "admitted")
                                    ("VForbidden" "forbidden")
                                    ("VUnknown" "unknown")))))
      (def res (reason-bounded-revalidation facts))
      (def epi (rows res 'epistemic_state))
      ;; All 6 distinct epistemic states derived without collapsing unknowns or conflicts:
      (check-equal? (and (member '("s-defect" "SetupDefect") epi) #t) #t)
      (check-equal? (and (member '("s-pending-method" "PendingMethod") epi) #t) #t)
      (check-equal? (and (member '("s-pending-scope" "PendingScope") epi) #t) #t)
      (check-equal? (and (member '("s-proven" "Proven") epi) #t) #t)
      (check-equal? (and (member '("s-refuted" "Refuted") epi) #t) #t)
      (check-equal? (and (member '("s-conflict" "Conflict") epi) #t) #t)
      (check-equal? (member '("s-conflict" "Proven") epi) #f)
      (check-equal? (member '("s-pending-scope" "Refuted") epi) #f)
      ;; Bounded negative-dependency invalidation: DOld stale, DOther reusable, frozen history & M1 method preserved:
      (check-equal? (rows res 'review_stale) '(("DOld" "P0-Q-counters" "ENew")))
      (check-equal? (rows res 'review_reusable) '(("DOther")))
      (check-equal? (rows res 'review_reclosable) '())
      (check-equal? (rows res 'history_preserved) '(("kOld" "r2m")))
      (check-equal? (rows res 'method_preserved) '(("VOldInvalid" "art-17")))
      ;; G1 ASCENT admission findings catch missing witness and M3 immutable-reuse claim:
      (def gfind (rows res 'guard_admission_finding))
      (check-equal? (and (member '("g-nowitness" "missing-witness") gfind) #t) #t)
      (check-equal? (and (member '("g-bad-toctou" "immutable-reuse-on-mutable-root") gfind) #t) #t)
      (check-equal? (find (lambda (r) (equal? (car r) "g-valid")) gfind) #f)
      ;; 20.17 / 20.18 policy sufficiency & admission outcomes:
      ;; s-proven qualifies under VAdmitted WITHOUT needing a direct record (sufficiency stops bloat):
      (check-equal? (and (member '("s-proven" "VAdmitted") (rows res 'policy_verdict_qualified)) #t) #t)
      ;; VForbidden refused (AM02), VUnknown stays pending (AM01):
      (check-equal? (and (member '("s-proven" "VForbidden" "forbidden-method-mapping")
                                 (rows res 'policy_binding_refused)) #t) #t)
      (check-equal? (and (member '("s-proven" "unknown-method-admission")
                                 (rows res 'policy_verdict_pending)) #t) #t))

    (test-case "G2 audit-agent-defensive-submission catches all 4 LLM hallucination classes and clears clean submissions"
      (def bad-sub
        (.o silent-fallbacks: '((parse-config missing-body-returns-empty))
            floor-overrides: '((require-countermodels? #t #f)
                               (allow-global-purge? #f #t))
            guard-proposals: '((g-glue #f #t #t))
            evidence-claims: '((claim-safe prose-only))))
      (def bad-res (audit-agent-defensive-submission bad-sub))
      (check-equal? (.get bad-res passed?) #f)
      (def fclasses (map car (.get bad-res findings)))
      (check-equal? (and (memq 'silent-fallback fclasses) #t) #t)
      (check-equal? (and (memq 'floor-weakening fclasses) #t) #t)
      (check-equal? (and (memq 'redundant-defensive-glue fclasses) #t) #t)
      (check-equal? (and (memq 'fabricated-evidence fclasses) #t) #t)
      ;; Clean deterministic submission with complete 5-tuple and genuine backing passes:
      (def clean-sub
        (.o silent-fallbacks: '()
            floor-overrides: '((require-countermodels? #t #t))
            guard-proposals: '((g-essential #t #t #t))
            evidence-claims: '((claim-safe apalache-verified))))
      (def clean-res (audit-agent-defensive-submission clean-sub))
      (check-equal? (.get clean-res passed?) #t)
      (check-equal? (.get clean-res findings) '()))))

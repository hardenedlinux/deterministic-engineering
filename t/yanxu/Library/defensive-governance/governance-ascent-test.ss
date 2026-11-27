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
      (check-equal? (.get clean-res findings) '()))

    (test-case "G5 live ASCENT AgentTranscriptAuditProgram enforces scope, anti-evasion, obligation preservation & bounded human escalation"
      (def t-facts
        (list
          (cons 'patch '(("p-coop-admit") ("p-evasive-escalate") ("p-tamper-scope")
                         ("p-prose-only") ("p-witnessed-replace")))
          (cons 'prose_claim '(("p-coop-admit") ("p-prose-only")))
          (cons 'independent_oracle_passed '(("p-coop-admit") ("p-tamper-scope") ("p-witnessed-replace")))
          (cons 'scope_violation '(("p-tamper-scope" ".github/workflows/defense-audit.yml")))
          (cons 'evasion_finding '(("p-evasive-escalate" "catch-log-and-swallow")))
          (cons 'obligation_deleted '(("p-evasive-escalate" "diff-deleted-assertion")
                                      ("p-witnessed-replace" "diff-deleted-assertion")))
          (cons 'replacement_witness_admitted '(("p-witnessed-replace" "diff-deleted-assertion")))
          (cons 'retry_budget_exhausted '(("p-evasive-escalate") ("p-tamper-scope") ("p-prose-only")))))
      (def tres (reason-agent-transcript t-facts))
      (def admitted (rows tres 'patch_admitted))
      (def blocked (rows tres 'patch_blocked))
      (def escalated (rows tres 'escalation_required))
      ;; Cooperative clean patch & explicitly witnessed replacement admit cleanly:
      (check-equal? (and (member '("p-coop-admit") admitted) #t) #t)
      (check-equal? (and (member '("p-witnessed-replace") admitted) #t) #t)
      ;; Adversarial personas are NEVER admitted and MUST escalate when budget exhausted:
      (check-equal? (member '("p-evasive-escalate") admitted) #f)
      (check-equal? (member '("p-tamper-scope") admitted) #f)
      (check-equal? (member '("p-prose-only") admitted) #f)
      (check-equal? (and (member '("p-tamper-scope" "protected-or-out-of-scope-mutation") blocked) #t) #t)
      (check-equal? (and (member '("p-evasive-escalate" "ast-or-evasion-finding") blocked) #t) #t)
      (check-equal? (and (member '("p-evasive-escalate" "unwitnessed-obligation-deletion") blocked) #t) #t)
      (check-equal? (and (member '("p-prose-only" "self-certified-without-oracle") blocked) #t) #t)
      (check-equal? (and (member '("p-evasive-escalate") escalated) #t) #t)
      (check-equal? (and (member '("p-tamper-scope") escalated) #t) #t)
      (check-equal? (and (member '("p-prose-only") escalated) #t) #t))

    (test-case "R3 assert-m1-persistable! blocks accidental reachability leak of M3 capability and R1 ASCENT co-evolution selectively revalidates"
      (def m3-cap (make-m3-transient-capability 'cap-deploy "src/**" 7))
      ;; Pure M1 data (nested POO + lists + strings) passes:
      (check-equal?
        (assert-m1-persistable! (.o patch-id: "p1" digest: "abc123" tags: '(m1 immutable)))
        #t)
      ;; Accidental reachability leak: M3 capability buried deep inside a POO/list graph MUST be refused!
      (check-exception
        (assert-m1-persistable! (.o handoff: (list "ok" (.o nested-cap: m3-cap))))
        error?)
      ;; R1 live ASCENT hot policy co-evolution:
      (def p-facts
        (list
          (cons 'suspended_verdict '(("v-auth-affected") ("v-parser-unaffected")))
          (cons 'verdict_depends_on_domain '(("v-auth-affected" "auth-policy")
                                             ("v-parser-unaffected" "parser-bounds")))
          (cons 'verdict_policy_digest '(("v-auth-affected" "pol-v1")
                                         ("v-parser-unaffected" "pol-v1")))
          (cons 'active_policy_digest '(("pol-v2")))
          (cons 'domain_changed_in_upgrade '(("auth-policy")))
          (cons 'm1_evidence_leaf '(("llm-step-1" "sha-aaa") ("apalache-proof-1" "sha-bbb")))
          (cons 'frozen_historical_cut '(("cut-v1" "root-111")))))
      (def pres (reason-hot-policy-coevolution p-facts))
      (def reval (rows pres 'verdict_needs_revalidation))
      (def valid (rows pres 'verdict_still_valid))
      ;; Only v-auth-affected requires revalidation; v-parser-unaffected stays valid without replay crash:
      (check-equal? (and (member '("v-auth-affected" "affected-domain-changed") reval) #t) #t)
      (check-equal? (and (member '("v-auth-affected" "stale-policy-digest") reval) #t) #t)
      (check-equal? valid '(("v-parser-unaffected")))
      ;; M1 evidence leaves & frozen historical cut remain 100% preserved:
      (def m1-reuse (rows pres 'm1_evidence_reusable))
      (check-equal? (length m1-reuse) 2)
      (check-equal? (and (member '("llm-step-1" "sha-aaa") m1-reuse) #t) #t)
      (check-equal? (and (member '("apalache-proof-1" "sha-bbb") m1-reuse) #t) #t)
      (check-equal? (rows pres 'historical_cut_preserved) '(("cut-v1" "root-111"))))

    (test-case "Phase 19 (10.167) live ASCENT DurableGovernanceMetaAuditProgram performs transitive cross-pillar B1-B9 Datalog verification"
      (def m-facts
        (list
          ;; B3: 4-hop delegation chain admin -> c1 -> c2 -> c3 -> worker4; sibling admin -> clean-coder
          (cons 'delegation_edge '(("admin" "c1") ("c1" "c2") ("c2" "c3") ("c3" "worker4")
                                   ("admin" "clean-coder")))
          (cons 'revoked_principal '(("c1")))
          ;; B8: worker4 proposed b-root (no oracle) -> b-mid -> b-leaf; clean-coder proposed b-clean (with oracle)
          (cons 'belief_proposer '(("b-root" "worker4") ("b-oracle-safe" "c2") ("b-clean" "clean-coder")))
          (cons 'belief_has_oracle '(("b-oracle-safe") ("b-clean")))
          (cons 'belief_sole_dep '(("b-mid" "b-root") ("b-leaf" "b-mid")))
          (cons 'retracted_belief '())
          ;; B7: Multi-hop DIFC taint v0 (tenant:alpha) -> v1 -> v2 (emitted to public-sink); v3 declassified
          (cons 'base_taint '(("v0" "tenant:alpha")))
          (cons 'derived_from '(("v1" "v0") ("v2" "v1") ("v3" "v1")))
          (cons 'declassified_tag '(("v3" "tenant:alpha")))
          (cons 'sink_emits '(("public-sink" "v2") ("public-sink" "v3") ("alpha-sink" "v2")))
          (cons 'sink_allows '(("alpha-sink" "tenant:alpha")))
          ;; B9: log-honest consistent across witnesses; log-split equivocates at size 4
          (cons 'witness_sth '(("w-reg" "log-honest" "4" "root-h4")
                               ("w-prod" "log-honest" "4" "root-h4")
                               ("w-reg" "log-split" "4" "root-clean")
                               ("w-prod" "log-split" "4" "root-backdoor")))
          ;; B1/B5/B6/B8/B9/B10 release proposals:
          (cons 'release_proposal '(("rel-clean" "clean-coder" "human-approver" "log-honest")
                                    ("rel-sod" "clean-coder" "clean-coder" "log-honest")
                                    ("rel-poison-chain" "clean-coder" "human-approver" "log-honest")
                                    ("rel-revoked-author" "worker4" "human-approver" "log-honest")
                                    ("rel-equivocated" "clean-coder" "human-approver" "log-split")
                                    ("rel-pivot-undo" "clean-coder" "human-approver" "log-honest")
                                    ("rel-subq" "clean-coder" "human-approver" "log-honest")
                                    ("rel-crosslog" "clean-coder" "human-approver" "log-honest")
                                    ("rel-breached" "clean-coder" "human-approver" "log-breached")
                                    ("rel-mcp-rugpull" "clean-coder" "human-approver" "log-honest")
                                    ("rel-amnesia" "clean-coder" "human-approver" "log-honest")
                                    ("rel-deadlock" "clean-coder" "human-approver" "log-honest")
                                    ("rel-slopsquat" "clean-coder" "human-approver" "log-honest")
                                    ("rel-repro-diverge" "clean-coder" "human-approver" "log-honest")
                                    ("rel-tee-bad" "clean-coder" "human-approver" "log-honest")
                                    ("rel-tee-replay-a" "clean-coder" "human-approver" "log-honest")
                                    ("rel-tee-replay-b" "clean-coder" "human-approver" "log-honest")
                                    ("rel-key-stale" "clean-coder" "human-approver" "log-honest")
                                    ("rel-key-shred-read" "clean-coder" "human-approver" "log-honest")))
          (cons 'release_uses_belief '(("rel-clean" "b-clean")
                                       ("rel-clean" "b-oracle-safe")
                                       ("rel-poison-chain" "b-leaf")))
          (cons 'saga_pivot_crossed '(("rel-pivot-undo")))
          (cons 'saga_rollback_attempted '(("rel-pivot-undo")))
          ;; B10: 4-witness committee on log-honest (w1, w2, w3, w4-byz) + split-finality log-breached
          (cons 'witness_roster '(("log-honest" "w1") ("log-honest" "w2")
                                  ("log-honest" "w3") ("log-honest" "w4-byz")
                                  ("log-other" "w1") ("log-other" "w2") ("log-other" "w3")
                                  ("log-breached" "w1") ("log-breached" "w2") ("log-breached" "w3")))
          (cons 'witness_cosign '(;; ckpt-clean achieves 3-of-4 valid quorum {w1, w2, w4-byz}
                                  ("w1" "log-honest" "4" "root-h4" "yes")
                                  ("w2" "log-honest" "4" "root-h4" "yes")
                                  ("w4-byz" "log-honest" "4" "root-h4" "yes")
                                  ;; w4-byz ALSO double-signs a backdoor root at size 4 (exposed, but only 2 votes with w3!)
                                  ("w4-byz" "log-honest" "4" "root-h4-evil" "yes")
                                  ("w3" "log-honest" "4" "root-h4-evil" "yes")
                                  ;; Spoofing attempts on ckpt-subq: rogue witness + unverified consistency
                                  ("w-rogue" "log-honest" "4" "root-h4-evil" "yes")
                                  ("w1" "log-honest" "5" "root-h5-unver" "no")
                                  ;; Unrelated log checkpoint (for cross-log replay test)
                                  ("w1" "log-other" "2" "root-o2" "yes")
                                  ("w2" "log-other" "2" "root-o2" "yes")
                                  ("w3" "log-other" "2" "root-o2" "yes")
                                  ;; Catastrophic > f collusion on log-breached (both roots reach 3-of-3 quorum!)
                                  ("w1" "log-breached" "9" "root-b-clean" "yes")
                                  ("w2" "log-breached" "9" "root-b-clean" "yes")
                                  ("w3" "log-breached" "9" "root-b-clean" "yes")
                                  ("w1" "log-breached" "9" "root-b-evil" "yes")
                                  ("w2" "log-breached" "9" "root-b-evil" "yes")
                                  ("w3" "log-breached" "9" "root-b-evil" "yes")))
          (cons 'claimed_finalized '(("ckpt-clean" "log-honest" "4" "root-h4")
                                     ("ckpt-subq" "log-honest" "4" "root-h4-evil")
                                     ("ckpt-other" "log-other" "2" "root-o2")
                                     ("ckpt-breach-a" "log-breached" "9" "root-b-clean")
                                     ("ckpt-breach-b" "log-breached" "9" "root-b-evil")))
          (cons 'release_requires_finality '(("rel-clean" "ckpt-clean")
                                             ("rel-subq" "ckpt-subq")
                                             ("rel-crosslog" "ckpt-other")))
          (cons 'slashed_witness '(("log-reentry" "w-slashed")))
          (cons 'next_epoch_roster '(("log-honest" "2" "w1")
                                     ("log-honest" "2" "w2")
                                     ("log-reentry" "2" "w-slashed")))
          (cons 'mcp_tool_pinned_schema '(("mcp.db.query" "schema-h1")))
          (cons 'mcp_tool_invoked '(("rel-clean" "mcp.db.query" "schema-h1" "yes")
                                    ("rel-mcp-rugpull" "mcp.db.query" "schema-EVIL" "yes")
                                    ("rel-mcp-rugpull" "mcp.shadow.tool" "schema-x" "yes")
                                    ("rel-mcp-rugpull" "mcp.db.query" "schema-h1" "no")))
          ;; B12: rel-clean retains pinned constraint pin-h1; rel-amnesia drops pin-veto!
          (cons 'context_pinned_constraint '(("rel-clean" "pin-h1") ("rel-amnesia" "pin-veto")))
          (cons 'distillation_retained '(("rel-clean" "pin-h1")))
          ;; B13: sess-clean is acyclic DAG; sess-deadlock has 3-agent cycle a1 -> a2 -> a3 -> a1!
          (cons 'swarm_wait_edge '(("sess-clean" "a1" "a2")
                                   ("sess-deadlock" "a1" "a2")
                                   ("sess-deadlock" "a2" "a3")
                                   ("sess-deadlock" "a3" "a1")))
          (cons 'swarm_session_release '(("rel-clean" "sess-clean")
                                         ("rel-deadlock" "sess-deadlock")))
          ;; B14: rel-clean uses pinned dep-good + matching 2-builder hermetic build;
          ;;      rel-slopsquat pulls unpinned & CVE deps; rel-repro-diverge has diverging builders!
          (cons 'lockfile_pinned_dep '(("dep-good") ("dep-cve")))
          (cons 'cve_tombstone '(("dep-cve")))
          (cons 'release_sbom_dep '(("rel-clean" "dep-good")
                                    ("rel-slopsquat" "dep-hallucinated")
                                    ("rel-slopsquat" "dep-cve")))
          (cons 'build_attestation '(("rel-clean" "b1" "art-v40" "yes")
                                     ("rel-clean" "b2" "art-v40" "yes")
                                     ("rel-repro-diverge" "b1" "art-clean" "yes")
                                     ("rel-repro-diverge" "b2" "art-backdoor" "no")))
          ;; B15: rel-clean matches art-v40 on clean TEE with fresh nonce;
          ;;      rel-tee-bad fails debug/tcb/measurement/revoked; replay-a & replay-b reuse nonce-dup!
          (cons 'expected_enclave_measurement '(("rel-clean" "art-v40")
                                                ("rel-tee-bad" "art-v40")))
          (cons 'enclave_quote '(("rel-clean" "tdx-prod-1" "art-v40" "yes" "yes")
                                 ("rel-tee-bad" "tdx-revoked" "art-trojan" "no" "no")))
          (cons 'revoked_tee_platform '(("tdx-revoked")))
          (cons 'tee_quote_nonce '(("rel-clean" "nonce-clean-42")
                                   ("rel-tee-replay-a" "nonce-dup")
                                   ("rel-tee-replay-b" "nonce-dup")))
          ;; B16: tenant-alpha active=2, shredded=1; rel-clean writes/reads epoch 2;
          ;;      rel-key-stale writes epoch 1; rel-key-shred-read reads shredded epoch 1 & mutates digest!
          (cons 'tenant_active_key_epoch '(("tenant-alpha" "2")))
          (cons 'shredded_key_epoch '(("tenant-alpha" "1")))
          (cons 'release_aead_write '(("rel-clean" "tenant-alpha" "2")
                                      ("rel-key-stale" "tenant-alpha" "1")))
          (cons 'release_aead_read '(("rel-clean" "tenant-alpha" "2" "yes")
                                     ("rel-key-shred-read" "tenant-alpha" "1" "no")))))

      (def mres (reason-durable-governance-meta-audit m-facts))
      (def revoked (rows mres 'effectively_revoked))
      (def poisoned (rows mres 'belief_poisoned))
      (def exfil (rows mres 'exfiltration_violation))
      (def equiv (rows mres 'equivocation_violation))
      (def byz-w (rows mres 'byzantine_witness_equivocation))
      (def inv-c (rows mres 'invalid_witness_cosign))
      (def q3 (rows mres 'quorum_3_verified))
      (def subq (rows mres 'sub_quorum_finality_violation))
      (def splitf (rows mres 'split_world_finality_breach))
      (def reentry (rows mres 'slashed_witness_reentry_violation))
      (def mcp-v (rows mres 'mcp_tool_violation))
      (def amn-v (rows mres 'distillation_amnesia_violation))
      (def ddlk-v (rows mres 'swarm_deadlock_cycle))
      (def sc-dep-v (rows mres 'supply_chain_dep_violation))
      (def repro-v (rows mres 'reproducible_build_violation))
      (def tee-v (rows mres 'enclave_attestation_violation))
      (def tee-replay-v (rows mres 'enclave_nonce_replay_violation))
      (def kr-w-v (rows mres 'key_rotation_write_violation))
      (def kr-r-v (rows mres 'crypto_shred_read_violation))
      (def disq (rows mres 'release_disqualified))
      (def admitted (rows mres 'release_admitted))

      ;; 1. 4-hop B3 transitive revocation catches worker4 while keeping clean-coder untouched:
      (check-equal? (and (member '("worker4") revoked) #t) #t)
      (check-equal? (member '("clean-coder") revoked) #f)
      ;; 2. Cross-pillar B3 -> B8 transitive poisoning catches b-root -> b-mid -> b-leaf, preserves b-oracle-safe:
      (check-equal? (and (member '("b-leaf") poisoned) #t) #t)
      (check-equal? (member '("b-oracle-safe") poisoned) #f)
      (check-equal? (member '("b-clean") poisoned) #f)
      ;; 3. Multi-hop B7 DIFC catches v2 -> public-sink, clears declassified v3 & authorized alpha-sink:
      (check-equal? exfil '(("public-sink" "v2" "tenant:alpha")))
      ;; 4. B9 split-view caught strictly on log-split (never on log-honest):
      (check-equal? (and (member '("log-split" "4" "root-clean" "root-backdoor") equiv) #t) #t)
      (check-equal? (find (lambda (r) (equal? (car r) "log-honest")) equiv) #f)
      ;; 5. B10 declarative witness quorum finality, Byzantine witness exposure & spoofing rejection:
      (check-equal? (and (member '("ckpt-clean" "log-honest" "4" "root-h4") q3) #t) #t)
      (check-equal? (member '("ckpt-subq" "log-honest" "4" "root-h4-evil") q3) #f)
      (check-equal? (and (member '("ckpt-subq" "log-honest" "4" "root-h4-evil") subq) #t) #t)
      (check-equal? (and (member '("w4-byz" "log-honest" "4" "root-h4" "root-h4-evil") byz-w) #t) #t)
      (check-equal? (and (member '("w-rogue" "log-honest" "4" "root-h4-evil" "unregistered-witness") inv-c) #t) #t)
      (check-equal? (and (member '("w1" "log-honest" "5" "root-h5-unver" "missing-consistency-proof") inv-c) #t) #t)
      (check-equal? (and (member '("log-breached" "9" "root-b-clean" "root-b-evil") splitf) #t) #t)
      (check-equal? reentry '(("log-reentry" "2" "w-slashed")))
      ;; 6. Only rel-clean is admitted; all cross-pillar B1-B10 violations are disqualified:
      (check-equal? admitted '(("rel-clean")))
      (check-equal? (and (member '("rel-sod" "sod-self-approval") disq) #t) #t)
      (check-equal? (and (member '("rel-poison-chain" "poisoned-supporting-belief") disq) #t) #t)
      (check-equal? (and (member '("rel-revoked-author" "revoked-delegation-chain") disq) #t) #t)
      (check-equal? (and (member '("rel-equivocated" "coordinator-equivocated") disq) #t) #t)
      (check-equal? (and (member '("rel-pivot-undo" "post-pivot-rollback-violation") disq) #t) #t)
      (check-equal? (and (member '("rel-subq" "unfinalized-quorum-checkpoint") disq) #t) #t)
      (check-equal? (and (member '("rel-crosslog" "unfinalized-quorum-checkpoint") disq) #t) #t)
      (check-equal? (and (member '("rel-breached" "split-world-finality-breach") disq) #t) #t)
      (check-equal? (and (member '("rel-mcp-rugpull" "mcp.db.query" "mcp-schema-rug-pull") mcp-v) #t) #t)
      (check-equal? (and (member '("rel-mcp-rugpull" "mcp.shadow.tool" "unpinned-shadow-tool") mcp-v) #t) #t)
      (check-equal? (and (member '("rel-mcp-rugpull" "mcp.db.query" "sandbox-scope-escalation") mcp-v) #t) #t)
      (check-equal? (and (member '("rel-mcp-rugpull" "mcp-tool-boundary-violation") disq) #t) #t)
      ;; 7. B12 distillation amnesia & B13 3-agent deadlock cycle detection:
      (check-equal? amn-v '(("rel-amnesia" "pin-veto")))
      (check-equal? (and (member '("sess-deadlock" "a1") ddlk-v) #t) #t)
      (check-equal? (and (member '("sess-deadlock" "a2") ddlk-v) #t) #t)
      (check-equal? (and (member '("sess-deadlock" "a3") ddlk-v) #t) #t)
      (check-equal? (find (lambda (r) (equal? (car r) "sess-clean")) ddlk-v) #f)
      (check-equal? (and (member '("rel-amnesia" "distillation-pinned-amnesia") disq) #t) #t)
      (check-equal? (and (member '("rel-deadlock" "swarm-deadlock-cycle") disq) #t) #t)
      ;; 8. B14 supply-chain anti-slopsquatting, CVE tombstones & reproducible-build divergence:
      (check-equal? (and (member '("rel-slopsquat" "dep-hallucinated" "unpinned-slopsquatting-dep") sc-dep-v) #t) #t)
      (check-equal? (and (member '("rel-slopsquat" "dep-cve" "tombstoned-cve-dep") sc-dep-v) #t) #t)
      (check-equal? (and (member '("rel-repro-diverge" "non-hermetic-build") repro-v) #t) #t)
      (check-equal? (and (member '("rel-repro-diverge" "builder-artifact-divergence") repro-v) #t) #t)
      (check-equal? (and (member '("rel-slopsquat" "supply-chain-dep-violation") disq) #t) #t)
      (check-equal? (and (member '("rel-repro-diverge" "reproducible-build-violation") disq) #t) #t)
      ;; 9. B15 confidential compute / hardware TEE attestation & cross-release nonce replay:
      (check-equal? (and (member '("rel-tee-bad" "debug-enclave-forbidden") tee-v) #t) #t)
      (check-equal? (and (member '("rel-tee-bad" "tcb-svn-rollback") tee-v) #t) #t)
      (check-equal? (and (member '("rel-tee-bad" "revoked-tee-platform") tee-v) #t) #t)
      (check-equal? (and (member '("rel-tee-bad" "enclave-measurement-mismatch") tee-v) #t) #t)
      (check-equal? (and (member '("rel-tee-replay-a" "rel-tee-replay-b" "nonce-dup") tee-replay-v) #t) #t)
      (check-equal? (and (member '("rel-tee-bad" "enclave-attestation-violation") disq) #t) #t)
      (check-equal? (and (member '("rel-tee-replay-a" "enclave-nonce-replay") disq) #t) #t)
      (check-equal? (and (member '("rel-tee-replay-b" "enclave-nonce-replay") disq) #t) #t)
      ;; 10. B16 AEAD key rotation stale write, shredded-epoch read & rewrap digest mutation:
      (check-equal? (and (member '("rel-key-stale" "tenant-alpha" "1" "stale-write-epoch") kr-w-v) #t) #t)
      (check-equal? (and (member '("rel-key-stale" "tenant-alpha" "1" "write-to-shredded-epoch") kr-w-v) #t) #t)
      (check-equal? (and (member '("rel-key-shred-read" "tenant-alpha" "1" "read-shredded-key-epoch") kr-r-v) #t) #t)
      (check-equal? (and (member '("rel-key-shred-read" "tenant-alpha" "1" "rewrap-digest-mutated") kr-r-v) #t) #t)
      (check-equal? (and (member '("rel-key-stale" "key-rotation-write-violation") disq) #t) #t)
      (check-equal? (and (member '("rel-key-shred-read" "crypto-shred-or-rewrap-violation") disq) #t) #t))))

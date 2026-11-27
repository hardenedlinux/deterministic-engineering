;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; AI Security & AI-SE Governance Red-Team Qualification Suite (10.154 Phase 4).
;;; Verifies:
;;; 1. Live OpenSysML `api-json` projection of all 10 subjects (5 Engineering + 5 AI-Security)
;;;    passes Phase 4 ASCENT `AR01`–`AR05` with zero findings.
;;; 2. Hostile AI Red-Team Negative Controls across every rule `AR01`–`AR05`:
;;;    - Attack 1 (AR01): LLM-as-a-Judge / AI self-certification without deterministic verifier.
;;;    - Attack 2 (AR01 AI-SE): AI patch mutating security dependency while claiming proof reuse
;;;      (rejected) vs non-security parameter tuning patch (admitted).
;;;    - Attack 3 (AR02): AI tool-executing subject (SM35) missing tool confinement or countermodels.
;;;    - Attack 4 (AR03): Multi-agent authority delegation missing attenuation or revocation currentness.
;;;    - Attack 5 (AR04): Untrusted-context agent (SM34) missing context-integrity-or-ifc.
;;;    - Attack 6 (AR05): Host-mutating agent (SM30) missing human Step-Up/E-Stop, missing human-approver
;;;      binding, or attempting `ai-agent` self-approval for `human-approver` / `policy-admin`.
;;; 3. Cryptographic Human-in-the-Loop Role Separation of Duties (SoD) via live Bun/TS verifier:
;;;    an `ai-agent`-signed DSSE v1 statement CANNOT satisfy `--require-role human-approver`,
;;;    while co-signing with `human-approver` satisfies `--min-signatures 2 --require-role ai-agent --require-role human-approver`.
(import :std/test
        (only-in "../../../support/repo-paths.ss" resolve-repo-root)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case yuanxu-test-checkpoint)
        :std/encoding/json
        :std/misc/ports
        :std/misc/process
        :clan/poo/object
        :deterministic-engineering/library/verification-flow/func
        :deterministic-engineering/library/verification-flow/rules
        :deterministic-engineering/library/verification-flow/attestation
        "../../../support/verification-flow-runner.ss")
(export verification-flow-ai-governance-and-redteam-test)

(def repo-root
  (resolve-repo-root))

(def (run-ts-cli args-str)
  (yuanxu-test-checkpoint 'before-ts-ai-sod-cli)
  (let* ((cmd (string-append
                "cd \"" repo-root "\" && bun t/harness/offline-attestation-verifier.ts "
                args-str))
         (proc (open-process
                 (list path: "/bin/bash"
                       arguments: (list "-euo" "pipefail" "-c" cmd)
                       stdin-redirection: #f
                       stdout-redirection: #t
                       stderr-redirection: #t)))
         (out (read-all-as-string proc))
         (st (process-status proc)))
    (close-port proc)
    (yuanxu-test-checkpoint 'after-ts-ai-sod-cli)
    (values st out)))

(def verification-flow-ai-governance-and-redteam-test
  (test-suite "AI Security & AI-SE Governance (AR01-AR05) and Hostile AI Red-Team Negative Controls"
    (yuanxu-test-case "live SysML v2 projects all 5 AI-Security subjects cleanly through ASCENT AR01-AR05 with zero findings"
      (def sysml-path
        (path-expand
          "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
          repo-root))
      (def json-text (run-process (list "sysml" "-convert" "api-json" sysml-path)))
      (def parsed (call-with-input-string json-text (cut read-json <> object-as-hash: #t)))
      (def projected (sysml-api-json->governance-facts parsed))
      (def ai-sources (.get projected ai-governance-sources))
      (def res (reason-ai-security-governance ai-sources))
      (check-equal? ((.ref res 'rows-of) 'ar_finding) '())
      (def admitted ((.ref res 'rows-of) 'ai_governance_admitted))
      (check-equal? (length admitted) 12)
      (for-each
        (lambda (sid)
          (check (and (member (list sid) admitted) #t) => #t))
        '("threat.identity.delegated-agent-authz"
          "threat.execution.stepup-attestation-and-host-effect-confinement"
          "threat.execution.sandbox-symlink-archive-confinement"
          "threat.execution.runtime-env-activation-and-context-confinement"
          "threat.execution.graph-witness-and-harness-confinement"
          "threat.execution.agent-ifc-capability"
          "threat.execution.agent-tool-circuit-breaker")))

    (yuanxu-test-case "AI-SE Deterministic Change-Admission & Proof-Transport Gate separates safe parameter tuning from security-boundary regressions"
      (def sysml-path
        (path-expand
          "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
          repo-root))
      (def json-text (run-process (list "sysml" "-convert" "api-json" sysml-path)))
      (def parsed (call-with-input-string json-text (cut read-json <> object-as-hash: #t)))
      (def projected (sysml-api-json->governance-facts parsed))

      ;; 1. Safe AI parameter tuning on `agent-ifc-capability` (disjoint from security deps, no Quint edits):
      ;;    admitted = #t, unaffected steps stay reusable, no forced human step-up!
      (let ((v1 (evaluate-ai-patch-admission
                  projected
                  "threat.execution.agent-ifc-capability"
                  '()
                  touched-dep-rows: '(("threat.execution.agent-ifc-capability" "ifcLeanPooTarget" "traceBufferCapacity"))
                  step-security-dep-rows: '(("ifcLeanPooTarget" "controlDataSegregationChecked")
                                            ("ifcLeanPooTarget" "declassificationGateChecked"))
                  claimed-reuse-steps: '("ifcLeanPooTarget"))))
        (check-equal? (.get v1 admitted?) #t)
        (check-equal? (.get v1 ar-findings) '())
        (check-equal? (.get v1 affected-steps) '())
        (check-equal? (length (.get v1 reusable-steps)) 2)
        (check-equal? (.get v1 requires-human-stepup?) #f))

      ;; 2. AI patch edits `AgentIfcCapability.qnt`: exact impact closure forces `ifcQuintTarget` re-verification
      ;;    while preserving `ifcLeanPooTarget` reuse!
      (let ((v2 (evaluate-ai-patch-admission
                  projected
                  "threat.execution.agent-ifc-capability"
                  '("packages/quint-models/threat/execution/agent-ifc-capability/AgentIfcCapability.qnt"))))
        (check-equal? (.get v2 admitted?) #t)
        (check-equal? (.get v2 affected-steps) '("ifcQuintTarget"))
        (check-equal? (.get v2 reusable-steps) '("ifcLeanPooTarget")))

      ;; 3. Hostile AI-SE regression: AI patch mutates `declassificationGateChecked` while claiming reuse ->
      ;;    REFUSED fail-closed (`admitted? = #f`, `reusable-steps = '()`, `requires-human-stepup? = #t`)!
      (let ((v3 (evaluate-ai-patch-admission
                  projected
                  "threat.execution.agent-ifc-capability"
                  '()
                  touched-dep-rows: '(("threat.execution.agent-ifc-capability" "ifcLeanPooTarget" "declassificationGateChecked"))
                  step-security-dep-rows: '(("ifcLeanPooTarget" "controlDataSegregationChecked")
                                            ("ifcLeanPooTarget" "declassificationGateChecked"))
                  claimed-reuse-steps: '("ifcLeanPooTarget"))))
        (check-equal? (.get v3 admitted?) #f)
        (check (pair? (.get v3 ar-findings)) => #t)
        (check-equal? (.get v3 reusable-steps) '())
        (check-equal? (.get v3 requires-human-stepup?) #t))

      ;; 4. Host/governance-mutating subject (`agent-tool-circuit-breaker`):
      ;;    Even clean patches ALWAYS force `requires-human-stepup? = #t`, and injecting
      ;;    `ai-agent -> human-approver` self-approval is rejected fail-closed by AR05!
      (let ((v4-clean (evaluate-ai-patch-admission
                        projected
                        "threat.execution.agent-tool-circuit-breaker"
                        '()))
            (v4-self (evaluate-ai-patch-admission
                       projected
                       "threat.execution.agent-tool-circuit-breaker"
                       '()
                       extra-role-bindings: '(("threat.execution.agent-tool-circuit-breaker" "ai-agent" "human-approver")))))
        (check-equal? (.get v4-clean admitted?) #t)
        (check-equal? (.get v4-clean requires-human-stepup?) #t)
        (check-equal? (.get v4-self admitted?) #f)
        (check-equal? (.get v4-self reusable-steps) '())
        (check-equal? (.get v4-self requires-human-stepup?) #t)))

    (yuanxu-test-case "Red-Team Negative Controls: AR01-AR05 block LLM self-certification, invalid AI-SE proof reuse, unconfined tools, unattenuated delegation, untrusted context, and AI self-approval"
      (def sysml-path
        (path-expand
          "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
          repo-root))
      (def json-text (run-process (list "sysml" "-convert" "api-json" sysml-path)))
      (def parsed (call-with-input-string json-text (cut read-json <> object-as-hash: #t)))
      (def projected (sysml-api-json->governance-facts parsed))
      (def base-ai (.get projected ai-governance-sources))

      ;; Attack 1a (AR01): AI-authored change verified ONLY by `llm-judge` (no deterministic engine).
      (let* ((llm-only-sources
               (list
                 (cons 'subject_factor '(("ai.patch.self-cert" "ai-authored-change")))
                 (cons 'flow_step '(("llm-review-step" "ai.patch.self-cert" "safety-claim" "llm-judge" "bounded-interleaving")))
                 (cons 'step_countermodel '())
                 (cons 'declared_ai_control '())
                 (cons 'declared_role_binding '())
                 (cons 'ai_patch_touches_dep '())
                 (cons 'step_security_dep '())
                 (cons 'ai_claimed_proof_reuse '())))
             (r1a (reason-ai-security-governance llm-only-sources))
             (f1a ((.ref r1a 'rows-of) 'ar01_finding)))
        (check (and (member '("ai.patch.self-cert" "llm-review-step" "untrusted-non-deterministic-verifier") f1a) #t) => #t)
        (check (and (member '("ai.patch.self-cert" "ai.patch.self-cert" "ai-change-missing-deterministic-verifier") f1a) #t) => #t)
        (check-equal? ((.ref r1a 'rows-of) 'ai_governance_admitted) '()))

      ;; Attack 1b (AR01): Adding `ai-self-review` alongside a deterministic engine STILL fails closed!
      (let* ((sm35-src (filter-ai-governance-sources-for-subject base-ai "threat.execution.graph-witness-and-harness-confinement"))
             (mixed-src
               (alist-replace sm35-src 'flow_step
                 (cons '("ai-rubber-stamp" "threat.execution.graph-witness-and-harness-confinement"
                         "rubber-stamp" "ai-self-review" "unbounded-invariant")
                       (alist-ref sm35-src 'flow_step '()))))
             (r1b (reason-ai-security-governance mixed-src)))
        (check (pair? ((.ref r1b 'rows-of) 'ar01_finding)) => #t)
        (check-equal? ((.ref r1b 'rows-of) 'ai_governance_admitted) '()))

      ;; Attack 2 (AR01 AI-SE Proof-Reuse):
      ;; 2a) AI patch mutates security dependency `cedarToolClassification` while claiming reuse -> BLOCKED!
      (let* ((sm35-src (filter-ai-governance-sources-for-subject base-ai "threat.execution.graph-witness-and-harness-confinement"))
             (bad-reuse
               (alist-replace
                 (alist-replace
                   (alist-replace sm35-src 'step_security_dep
                     '(("sm35LeanPooTarget" "cedarToolClassification")
                       ("sm35LeanPooTarget" "witnessSerdeAndReconciliation")))
                   'ai_patch_touches_dep
                   '(("threat.execution.graph-witness-and-harness-confinement" "sm35LeanPooTarget" "cedarToolClassification")))
                 'ai_claimed_proof_reuse
                 '(("threat.execution.graph-witness-and-harness-confinement" "sm35LeanPooTarget"))))
             (r2a (reason-ai-security-governance bad-reuse)))
        (check-equal? ((.ref r2a 'rows-of) 'ar01_finding)
                      '(("threat.execution.graph-witness-and-harness-confinement"
                         "sm35LeanPooTarget"
                         "ai-patch-invalidates-proof-reuse")))
        (check-equal? ((.ref r2a 'rows-of) 'ai_governance_admitted) '()))

      ;; 2b) Positive Control: AI patch mutating ONLY non-security param `maxWeaverTimeoutSecs` preserves safe reuse!
      (let* ((sm35-src (filter-ai-governance-sources-for-subject base-ai "threat.execution.graph-witness-and-harness-confinement"))
             (safe-reuse
               (alist-replace
                 (alist-replace
                   (alist-replace sm35-src 'step_security_dep
                     '(("sm35LeanPooTarget" "cedarToolClassification")
                       ("sm35LeanPooTarget" "witnessSerdeAndReconciliation")))
                   'ai_patch_touches_dep
                   '(("threat.execution.graph-witness-and-harness-confinement" "sm35LeanPooTarget" "maxWeaverTimeoutSecs")))
                 'ai_claimed_proof_reuse
                 '(("threat.execution.graph-witness-and-harness-confinement" "sm35LeanPooTarget"))))
             (r2b (reason-ai-security-governance safe-reuse)))
        (check-equal? ((.ref r2b 'rows-of) 'ar_finding) '())
        (check-equal? ((.ref r2b 'rows-of) 'ai_governance_admitted)
                      '(("threat.execution.graph-witness-and-harness-confinement"))))

      ;; Attack 3 (AR02): Strip `tool-confinement` OR strip countermodels from SM35 -> BLOCKED!
      (let* ((sm35-src (filter-ai-governance-sources-for-subject base-ai "threat.execution.graph-witness-and-harness-confinement"))
             (no-tool-conf
               (alist-replace sm35-src 'declared_ai_control
                 (filter (lambda (r) (not (equal? (cadr r) "tool-confinement")))
                         (alist-ref sm35-src 'declared_ai_control '()))))
             (no-cm (alist-replace sm35-src 'step_countermodel '()))
             (r3a (reason-ai-security-governance no-tool-conf))
             (r3b (reason-ai-security-governance no-cm)))
        (check-equal? ((.ref r3a 'rows-of) 'ar02_finding)
                      '(("threat.execution.graph-witness-and-harness-confinement"
                         "threat.execution.graph-witness-and-harness-confinement"
                         "missing-tool-confinement")))
        (check-equal? ((.ref r3a 'rows-of) 'ai_governance_admitted) '())
        (check-equal? ((.ref r3b 'rows-of) 'ar02_finding)
                      '(("threat.execution.graph-witness-and-harness-confinement"
                         "threat.execution.graph-witness-and-harness-confinement"
                         "missing-tool-attack-countermodel")))
        (check-equal? ((.ref r3b 'rows-of) 'ai_governance_admitted) '()))

      ;; Attack 4 (AR03): Strip `monotonic-attenuation` or `revocation-currentness` from `delegated-agent-authz` -> BLOCKED!
      (let* ((da-src (filter-ai-governance-sources-for-subject base-ai "threat.identity.delegated-agent-authz"))
             (no-att (alist-replace da-src 'declared_ai_control '(("threat.identity.delegated-agent-authz" "revocation-currentness"))))
             (no-cur (alist-replace da-src 'declared_ai_control '(("threat.identity.delegated-agent-authz" "monotonic-attenuation"))))
             (r4a (reason-ai-security-governance no-att))
             (r4b (reason-ai-security-governance no-cur)))
        (check-equal? ((.ref r4a 'rows-of) 'ar03_finding)
                      '(("threat.identity.delegated-agent-authz"
                         "threat.identity.delegated-agent-authz"
                         "missing-monotonic-attenuation")))
        (check-equal? ((.ref r4b 'rows-of) 'ar03_finding)
                      '(("threat.identity.delegated-agent-authz"
                         "threat.identity.delegated-agent-authz"
                         "missing-revocation-currentness")))
        (check-equal? ((.ref r4a 'rows-of) 'ai_governance_admitted) '())
        (check-equal? ((.ref r4b 'rows-of) 'ai_governance_admitted) '()))

      ;; Attack 5 (AR04): Strip `context-integrity-or-ifc` from SM34 -> BLOCKED!
      (let* ((sm34-src (filter-ai-governance-sources-for-subject base-ai "threat.execution.runtime-env-activation-and-context-confinement"))
             (no-ctx
               (alist-replace sm34-src 'declared_ai_control
                 (filter (lambda (r) (not (equal? (cadr r) "context-integrity-or-ifc")))
                         (alist-ref sm34-src 'declared_ai_control '()))))
             (r5 (reason-ai-security-governance no-ctx)))
        (check-equal? ((.ref r5 'rows-of) 'ar04_finding)
                      '(("threat.execution.runtime-env-activation-and-context-confinement"
                         "threat.execution.runtime-env-activation-and-context-confinement"
                         "missing-context-integrity-or-ifc")))
        (check-equal? ((.ref r5 'rows-of) 'ai_governance_admitted) '()))

      ;; Attack 6 (AR05): Host-mutating AI (SM30) without Step-Up/E-Stop, without human-approver,
      ;; OR attempting `ai-agent` self-approval for `human-approver` / `policy-admin` -> BLOCKED!
      (let* ((sm30-src (filter-ai-governance-sources-for-subject base-ai "threat.execution.stepup-attestation-and-host-effect-confinement"))
             (no-estop (alist-replace sm30-src 'declared_ai_control '()))
             (no-human (alist-replace sm30-src 'declared_role_binding '(("threat.execution.stepup-attestation-and-host-effect-confinement" "ai-agent" "ai-proposer"))))
             (ai-self-human
               (alist-replace sm30-src 'declared_role_binding
                 '(("threat.execution.stepup-attestation-and-host-effect-confinement" "human-approver" "human-approver")
                   ("threat.execution.stepup-attestation-and-host-effect-confinement" "ai-agent" "human-approver"))))
             (ai-self-policy
               (alist-replace sm30-src 'declared_role_binding
                 '(("threat.execution.stepup-attestation-and-host-effect-confinement" "human-approver" "human-approver")
                   ("threat.execution.stepup-attestation-and-host-effect-confinement" "ai-agent" "policy-admin"))))
             (r6a (reason-ai-security-governance no-estop))
             (r6b (reason-ai-security-governance no-human))
             (r6c (reason-ai-security-governance ai-self-human))
             (r6d (reason-ai-security-governance ai-self-policy)))
        (check-equal? ((.ref r6a 'rows-of) 'ar05_finding)
                      '(("threat.execution.stepup-attestation-and-host-effect-confinement"
                         "threat.execution.stepup-attestation-and-host-effect-confinement"
                         "missing-human-stepup-and-estop")))
        (check-equal? ((.ref r6b 'rows-of) 'ar05_finding)
                      '(("threat.execution.stepup-attestation-and-host-effect-confinement"
                         "threat.execution.stepup-attestation-and-host-effect-confinement"
                         "missing-human-approver-binding")))
        (check-equal? ((.ref r6c 'rows-of) 'ar05_finding)
                      '(("threat.execution.stepup-attestation-and-host-effect-confinement"
                         "human-approver"
                         "ai-agent-self-approval-forbidden")))
        (check-equal? ((.ref r6d 'rows-of) 'ar05_finding)
                      '(("threat.execution.stepup-attestation-and-host-effect-confinement"
                         "policy-admin"
                         "ai-agent-self-approval-forbidden")))
        (check-equal? ((.ref r6a 'rows-of) 'ai_governance_admitted) '())
        (check-equal? ((.ref r6b 'rows-of) 'ai_governance_admitted) '())
        (check-equal? ((.ref r6c 'rows-of) 'ai_governance_admitted) '())
        (check-equal? ((.ref r6d 'rows-of) 'ai_governance_admitted) '())))

    (yuanxu-test-case "Cryptographic Role-Based SoD defeats ai-agent self-approval for human-approver on live DSSE v1 statements"
      (def work-dir (path-expand ".data/test-runs/ai-gov-sod-drill" repo-root))
      (def ai-key-dir (path-expand "ai-agent-key" work-dir))
      (def human-key-dir (path-expand "human-approver-key" work-dir))
      (run-process (list "rm" "-rf" work-dir))
      (create-directory* ai-key-dir)
      (create-directory* human-key-dir)

      (def ai-kp (ensure-cache-signing-keypair! ai-key-dir))
      (def human-kp (ensure-cache-signing-keypair! human-key-dir))
      (def ai-kid (.get ai-kp key-id))
      (def human-kid (.get human-kp key-id))

      ;; Build Trust Store pinning `ai-agent` and `human-approver` as distinct cryptographic roles.
      (def bundle-ts-path (path-expand "ai-sod-trust-bundle.json" work-dir))
      (let-values (((st _out)
                    (run-ts-cli
                      (string-append
                        "--export-trust-bundle \"" bundle-ts-path "\" "
                        "--role \"" ai-kid "=ai-agent\" "
                        "--role \"" human-kid "=human-approver\" "
                        "\"" (.get ai-kp public-key) "\" "
                        "\"" (.get human-kp public-key) "\""))))
        (check-equal? st 0))

      ;; Construct a valid in-toto v1 verification summary statement and sign it ONLY with `ai-agent`'s key.
      (def stmt-path (path-expand "ai-proposal.intoto.json" work-dir))
      (def dsse-path (path-expand "ai-proposal.intoto.dsse.json" work-dir))
      (def payload-str
        (string-append
          "{\"_type\":\"https://in-toto.io/Statement/v1\","
          "\"subject\":["
          "{\"name\":\"sysml:10.154-multi-method-funflow-runnable-architecture\","
          "\"digest\":{\"sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}},"
          "{\"name\":\"fleet:ai-patch-proposal\","
          "\"digest\":{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}],"
          "\"predicateType\":\"https://deterministic-engineering.hardenedlinux.org/attestation/fleet-verification-summary/v1\","
          "\"predicate\":{\"verifier\":\"de.offline-attestation-verifier.v1\","
          "\"fleetId\":\"ai-patch-proposal\","
          "\"sysmlSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
          "\"fleetPayloadSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
          "\"rootKeyId\":\"" ai-kid "\","
          "\"subjectCount\":1,"
          "\"verifiedSubjects\":[{\"subjectKey\":\"graph-witness-and-harness-confinement\","
          "\"subjectId\":\"threat.execution.graph-witness-and-harness-confinement\","
          "\"keyId\":\"" ai-kid "\",\"evidenceCount\":2}]}}"))
      (call-with-output-file stmt-path (lambda (p) (display payload-str p)))
      (def raw-b64 (run-process (list "openssl" "base64" "-A" "-in" stmt-path)))
      (def payload-b64
        (let loop ((n (string-length raw-b64)))
          (if (and (> n 0) (char-whitespace? (string-ref raw-b64 (- n 1))))
            (loop (- n 1))
            (substring raw-b64 0 n))))
      (def payload-type "application/vnd.in-toto+json")
      (def pae (dsse-v1-pae payload-type payload-str))
      (def ai-sig (ed25519-sign-string (.get ai-kp private-key) pae))
      (def dsse-doc (make-hash-table))
      (hash-put! dsse-doc "payloadType" payload-type)
      (hash-put! dsse-doc "payload" payload-b64)
      (def sig-obj (make-hash-table))
      (hash-put! sig-obj "keyid" ai-kid)
      (hash-put! sig-obj "sig" ai-sig)
      (hash-put! dsse-doc "signatures" (list sig-obj))
      (call-with-output-file dsse-path (lambda (p) (write-json p dsse-doc) (newline p)))

      ;; Attack 7a: `ai-agent`-only DSSE statement MUST BE REJECTED when `--require-role human-approver` is enforced!
      (let-values (((st out)
                    (run-ts-cli
                      (string-append
                        "--json --verify-dsse-statement "
                        "--require-role human-approver "
                        "\"" dsse-path "\" \"" bundle-ts-path "\""))))
        (check (not (= st 0)) => #t)
        (check (and (string-contains out "\"ok\":false") #t) => #t))

      ;; Attack 7b: After genuine `human-approver` offline co-sign, 2-of-2 SoD (`ai-agent` + `human-approver`) PASSES!
      (def cosigned-path (path-expand "ai-proposal-cosigned.intoto.dsse.json" work-dir))
      (let-values (((st _out)
                    (run-ts-cli
                      (string-append
                        "--cosign-dsse-statement \"" dsse-path "\" "
                        "\"" (.get human-kp private-key) "\" "
                        "\"" (.get human-kp public-key) "\" "
                        "\"" bundle-ts-path "\" "
                        "\"" cosigned-path "\""))))
        (check-equal? st 0))
      (let-values (((st out)
                    (run-ts-cli
                      (string-append
                        "--json --verify-dsse-statement "
                        "--min-signatures 2 "
                        "--require-role ai-agent "
                        "--require-role human-approver "
                        "\"" cosigned-path "\" \"" bundle-ts-path "\""))))
        (check-equal? st 0)
        (check (and (string-contains out "\"ok\":true") #t) => #t))
      (run-process (list "rm" "-rf" work-dir)))))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero-Glue SysML v2 -> Fun-Flow DAG Compiler & 3rd Subject (`lease-fencing-token`) Tests.
;;; Verifies:
;;; 1. Pure `sysml-projected->compiled-subjects` compiles ALL 3 engineering subjects
;;;    (`process-tree-reclamation`, `backpressure-memory`, `lease-fencing-token`)
;;;    directly from live OpenSysML `api-json` with ZERO per-subject Scheme glue,
;;;    passes ASCENT MR01-MR06, and emits valid Fun-Flow DAG receipts & manifests.
;;; 2. Live 2-engine Fun-Flow Cold -> Warm SHA-256 cached execution on the 3rd
;;;    subject `lease-fencing-token`:
;;;    - `lfQuintTarget` (Apalache bounded verify + countermodel + 100% MBT + 10 ITF export)
;;;    - `lfLeanPooTarget` (`Core.Order` + `Core.Transport` + `Engineering.LeaseFencing`, 6 theorems, 0 sorryAx)
;;;    - Upstream Fun-Flow Replay Validation (`replayValid = #t`) + ASCENT ER01-ER04 Admission.
(import :std/test
        (only-in "../../../support/repo-paths.ss" resolve-repo-root)
        (only-in :tao3k/yuanxu/testing
                 yuanxu-test-case
                 yuanxu-test-case/with
                 yuanxu-test-checkpoint
                 yuanxu-testing-case-profile-prototype)
        :std/encoding/json
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 flow-dag-receipt-kind
                 replay-report-valid?
                 replay-report-reasons
                 +flow-dag-runtime-manifest-schema+)
        :deterministic-engineering/library/verification-flow/func
        :deterministic-engineering/library/verification-flow/rules
        :deterministic-engineering/library/verification-flow/sysml-compiler
        :deterministic-engineering/library/verification-flow/methods
        "../../../support/verification-flow-runner.ss")
(export verification-flow-sysml-compiler-and-lease-fencing-test)

(def repo-root
  (resolve-repo-root))

(.def (MultiSubjectCompileBudget @ yuanxu-testing-case-profile-prototype)
  max-idle-milliseconds: 180000
  max-duration-milliseconds: 600000
  sample-interval-milliseconds: 500
  collect-before-sample?: #t)

(def verification-flow-sysml-compiler-and-lease-fencing-test
  (test-suite "Zero-glue SysML v2 -> Fun-Flow DAG compiler and 3rd subject lease-fencing-token"
    (yuanxu-test-case/with MultiSubjectCompileBudget "live SysML v2 compiles all 34 subjects (71 engines) into valid Fun-Flow DAGs and manifests with zero Scheme glue"
      (def sysml-path
        (path-expand
          "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
          repo-root))
      (def json-text (run-process (list "sysml" "-convert" "api-json" sysml-path)))
      (def parsed (call-with-input-string json-text (cut read-json <> object-as-hash: #t)))
      (def projected (sysml-api-json->governance-facts parsed))
      (check-equal? (length (.get projected subject-specs)) 34)
      (for-each
        (lambda (spec-expect)
          (def skey (car spec-expect))
          (def expected-steps (cadr spec-expect))
          (let* ((bundle (compile-sysml-subject-by-key projected skey))
                 (subj (.get bundle subject)))
            (check-equal? (length (.get subj steps)) expected-steps)
            (check-equal? (length (.get bundle mutability)) expected-steps)
            (check-equal? (length (.get bundle input-files)) expected-steps)
            (let ((gov-res (reason-multi-method-governance (subject->governance-sources subj))))
              (check-equal? ((.ref gov-res 'rows-of) 'mr_finding) '())
              (check-equal? ((.ref gov-res 'rows-of) 'mr03_open_premise) '()))
            (let ((receipt (subject->dag-receipt subj)))
              (check-equal? (cdr (assoc 'kind receipt)) flow-dag-receipt-kind))
            (let ((manifest (subject->dag-runtime-manifest subj (string-append "req-compile-" (symbol->string skey)))))
              (check-equal? (cdr (assoc 'schema manifest)) +flow-dag-runtime-manifest-schema+)))
          (yuanxu-test-checkpoint skey)
          (##gc))
        '((process-tree-reclamation 4)
          (backpressure-memory 4)
          (lease-fencing-token 2)
          (c-boundary-conservation 2)
          (meta-governance-soundness 1)
          (delegated-agent-authz 2)
          (stepup-attestation-and-host-effect-confinement 2)
          (sandbox-symlink-archive-confinement 2)
          (runtime-env-activation-and-context-confinement 2)
          (graph-witness-and-harness-confinement 2)
          (agent-ifc-capability 2)
          (agent-tool-circuit-breaker 2)
          (shared-context-governance 2)
          (gitops-subprocess-confinement-and-arg-injection 2)
          (control-plane-auth-and-governance-confinement 2)
          (hook-policy-and-protocol-contract-confinement 2)
          (plugin-grant-rollback-and-lease-confinement 2)
          (governance-policy-and-latch-antirollback 2)
          (subprocess-env-scrub-and-auth-timing 2)
          (storage-boundary-integrity-and-sync-confinement 2)
          (single-owner-graph-governance-confinement 2)
          (telemetry-watchdog-and-deck-vm-confinement 2)
          (process-signal-ledger-and-fanout-confinement 2)
          (wasm-sandbox-confinement 2)
          (slsa-hermetic-provenance 2)
          (outbound-http-redirect-ssrf-confinement 2)
          (governance-sod 2)
          (chatroom-ingress-governance 2)
          (data-lineage-disclosure 2)
          (supply-chain-tuf 2)
          (zero-trust-pep-pdp 2)
          (multi-tenant-isolation 2)
          (transparency-log-gossip 2)
          (microsegmentation-egress 2)))
      ;; Verify static change-impact slicing isolates AI-Security subjects cleanly!
      (let* ((impact27
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/supply-chain/transparency-log-gossip/TransparencyLogGossip.qnt")))
             (affected27 (filter (lambda (s) (pair? (.get s affected-steps))) impact27)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected27)
                      '(transparency-log-gossip))
        (check-equal? (.get (car affected27) affected-steps) '("tlogQuintTarget")))
      (let* ((impact28
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/zero-trust/microsegmentation-egress/MicrosegmentationEgress.qnt")))
             (affected28 (filter (lambda (s) (pair? (.get s affected-steps))) impact28)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected28)
                      '(microsegmentation-egress))
        (check-equal? (.get (car affected28) affected-steps) '("egressQuintTarget")))
      (let* ((impact25
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/zero-trust/zero-trust-pep-pdp/ZeroTrustPepPdp.qnt")))
             (affected25 (filter (lambda (s) (pair? (.get s affected-steps))) impact25)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected25)
                      '(zero-trust-pep-pdp))
        (check-equal? (.get (car affected25) affected-steps) '("pepQuintTarget")))
      (let* ((impact26
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/zero-trust/multi-tenant-isolation/MultiTenantIsolation.qnt")))
             (affected26 (filter (lambda (s) (pair? (.get s affected-steps))) impact26)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected26)
                      '(multi-tenant-isolation))
        (check-equal? (.get (car affected26) affected-steps) '("mtiQuintTarget")))
      (let* ((impact23
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/zero-trust/data-lineage-disclosure/DataLineageDisclosure.qnt")))
             (affected23 (filter (lambda (s) (pair? (.get s affected-steps))) impact23)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected23)
                      '(data-lineage-disclosure))
        (check-equal? (.get (car affected23) affected-steps) '("dldQuintTarget")))
      (let* ((impact24
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/supply-chain/supply-chain-tuf/SupplyChainTuf.qnt")))
             (affected24 (filter (lambda (s) (pair? (.get s affected-steps))) impact24)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected24)
                      '(supply-chain-tuf))
        (check-equal? (.get (car affected24) affected-steps) '("tufQuintTarget")))
      (let* ((impact21
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/zero-trust/governance-sod/GovernanceSod.qnt")))
             (affected21 (filter (lambda (s) (pair? (.get s affected-steps))) impact21)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected21)
                      '(governance-sod))
        (check-equal? (.get (car affected21) affected-steps) '("gsodQuintTarget")))
      (let* ((impact22
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/protocol/chatroom-ingress-governance/ChatroomIngressGovernance.qnt")))
             (affected22 (filter (lambda (s) (pair? (.get s affected-steps))) impact22)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected22)
                      '(chatroom-ingress-governance))
        (check-equal? (.get (car affected22) affected-steps) '("chatQuintTarget")))
      (let* ((impact19
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/supply-chain/slsa-hermetic-provenance/SlsaHermeticProvenance.qnt")))
             (affected19 (filter (lambda (s) (pair? (.get s affected-steps))) impact19)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected19)
                      '(slsa-hermetic-provenance))
        (check-equal? (.get (car affected19) affected-steps) '("slsaQuintTarget")))
      (let* ((impact20
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/protocol/outbound-http-redirect-ssrf-confinement/OutboundHttpRedirectSsrfConfinement.qnt")))
             (affected20 (filter (lambda (s) (pair? (.get s affected-steps))) impact20)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected20)
                      '(outbound-http-redirect-ssrf-confinement))
        (check-equal? (.get (car affected20) affected-steps) '("sm23QuintTarget")))
      (let* ((impact17
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/process-signal-ledger-and-fanout-confinement/ProcessSignalLedgerAndFanoutConfinement.qnt")))
             (affected17 (filter (lambda (s) (pair? (.get s affected-steps))) impact17)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected17)
                      '(process-signal-ledger-and-fanout-confinement))
        (check-equal? (.get (car affected17) affected-steps) '("sm37QuintTarget")))
      (let* ((impact18
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/wasm-sandbox-confinement/WasmSandboxConfinement.qnt")))
             (affected18 (filter (lambda (s) (pair? (.get s affected-steps))) impact18)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected18)
                      '(wasm-sandbox-confinement))
        (check-equal? (.get (car affected18) affected-steps) '("wasmQuintTarget")))
      (let* ((impact15
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/single-owner-graph-governance-confinement/SingleOwnerGraphGovernanceConfinement.qnt")))
             (affected15 (filter (lambda (s) (pair? (.get s affected-steps))) impact15)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected15)
                      '(single-owner-graph-governance-confinement))
        (check-equal? (.get (car affected15) affected-steps) '("sm25QuintTarget")))
      (let* ((impact16
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/telemetry-watchdog-and-deck-vm-confinement/TelemetryWatchdogAndDeckVmConfinement.qnt")))
             (affected16 (filter (lambda (s) (pair? (.get s affected-steps))) impact16)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected16)
                      '(telemetry-watchdog-and-deck-vm-confinement))
        (check-equal? (.get (car affected16) affected-steps) '("sm36QuintTarget")))
      (let* ((impact13
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/subprocess-env-scrub-and-auth-timing/SubprocessEnvScrubAndAuthTiming.qnt")))
             (affected13 (filter (lambda (s) (pair? (.get s affected-steps))) impact13)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected13)
                      '(subprocess-env-scrub-and-auth-timing))
        (check-equal? (.get (car affected13) affected-steps) '("sm24QuintTarget")))
      (let* ((impact14
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/storage-boundary-integrity-and-sync-confinement/StorageBoundaryIntegrityAndSyncConfinement.qnt")))
             (affected14 (filter (lambda (s) (pair? (.get s affected-steps))) impact14)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected14)
                      '(storage-boundary-integrity-and-sync-confinement))
        (check-equal? (.get (car affected14) affected-steps) '("sm31QuintTarget")))
      (let* ((impact11
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/plugin-grant-rollback-and-lease-confinement/PluginGrantRollbackAndLeaseConfinement.qnt")))
             (affected11 (filter (lambda (s) (pair? (.get s affected-steps))) impact11)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected11)
                      '(plugin-grant-rollback-and-lease-confinement))
        (check-equal? (.get (car affected11) affected-steps) '("sm28QuintTarget")))
      (let* ((impact12
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/governance-policy-and-latch-antirollback/GovernancePolicyAndLatchAntirollback.qnt")))
             (affected12 (filter (lambda (s) (pair? (.get s affected-steps))) impact12)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected12)
                      '(governance-policy-and-latch-antirollback))
        (check-equal? (.get (car affected12) affected-steps) '("sm29QuintTarget")))
      (let* ((impact9
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/control-plane-auth-and-governance-confinement/ControlPlaneAuthAndGovernanceConfinement.qnt")))
             (affected9 (filter (lambda (s) (pair? (.get s affected-steps))) impact9)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected9)
                      '(control-plane-auth-and-governance-confinement))
        (check-equal? (.get (car affected9) affected-steps) '("sm26QuintTarget")))
      (let* ((impact10
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/hook-policy-and-protocol-contract-confinement/HookPolicyAndProtocolContractConfinement.qnt")))
             (affected10 (filter (lambda (s) (pair? (.get s affected-steps))) impact10)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected10)
                      '(hook-policy-and-protocol-contract-confinement))
        (check-equal? (.get (car affected10) affected-steps) '("sm33QuintTarget")))
      (let* ((impact7
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/zero-trust/shared-context-governance/SharedContextGovernance.qnt")))
             (affected7 (filter (lambda (s) (pair? (.get s affected-steps))) impact7)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected7)
                      '(shared-context-governance))
        (check-equal? (.get (car affected7) affected-steps) '("scgQuintTarget")))
      (let* ((impact8
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/gitops-subprocess-confinement-and-arg-injection/GitopsSubprocessConfinementAndArgInjection.qnt")))
             (affected8 (filter (lambda (s) (pair? (.get s affected-steps))) impact8)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected8)
                      '(gitops-subprocess-confinement-and-arg-injection))
        (check-equal? (.get (car affected8) affected-steps) '("sm32QuintTarget")))
      (let* ((impact5
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/agent-ifc-capability/AgentIfcCapability.qnt")))
             (affected5 (filter (lambda (s) (pair? (.get s affected-steps))) impact5)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected5)
                      '(agent-ifc-capability))
        (check-equal? (.get (car affected5) affected-steps) '("ifcQuintTarget")))
      (let* ((impact6
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/agent-tool-circuit-breaker/AgentToolCircuitBreaker.qnt")))
             (affected6 (filter (lambda (s) (pair? (.get s affected-steps))) impact6)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected6)
                      '(agent-tool-circuit-breaker))
        (check-equal? (.get (car affected6) affected-steps) '("cbBreakerQuintTarget")))
      (let* ((impact4
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/graph-witness-and-harness-confinement/GraphWitnessAndHarnessConfinement.qnt")))
             (affected4 (filter (lambda (s) (pair? (.get s affected-steps))) impact4)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected4)
                      '(graph-witness-and-harness-confinement))
        (check-equal? (.get (car affected4) affected-steps) '("sm35QuintTarget")))
      (let* ((impact3
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/runtime-env-activation-and-context-confinement/RuntimeEnvActivationAndContextConfinement.qnt")))
             (affected3 (filter (lambda (s) (pair? (.get s affected-steps))) impact3)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected3)
                      '(runtime-env-activation-and-context-confinement))
        (check-equal? (.get (car affected3) affected-steps) '("sm34QuintTarget")))
      (let* ((impact
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/stepup-attestation-and-host-effect-confinement/StepUpAttestationAndHostEffectConfinement.qnt")))
             (affected (filter (lambda (s) (pair? (.get s affected-steps))) impact)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected)
                      '(stepup-attestation-and-host-effect-confinement))
        (check-equal? (.get (car affected) affected-steps) '("sm30QuintTarget")))
      (let* ((impact2
              (changed-files->affected-frontier
                projected
                '("packages/quint-models/threat/execution/sandbox-symlink-archive-confinement/SandboxSymlinkArchiveConfinement.qnt")))
             (affected2 (filter (lambda (s) (pair? (.get s affected-steps))) impact2)))
        (check-equal? (map (lambda (s) (.get s subject-key)) affected2)
                      '(sandbox-symlink-archive-confinement))
        (check-equal? (.get (car affected2) affected-steps) '("sm22QuintTarget"))))

    (yuanxu-test-case/with MultiSubjectCompileBudget "live 2-engine Fun-Flow run on SysML-compiled lease-fencing-token passes Apalache+MBT, LeanPoo Core.Order+Transport, Replay, ER01-ER04, and Cold->Warm cache reuse"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def cache-dir (path-expand "m5-lease-fencing-cache-test" tmp-parent))
      (run-process (list "rm" "-rf" cache-dir))
      (create-directory* cache-dir)

      ;; Phase 1 — Cold run: executes lfQuintTarget + lfLeanPooTarget compiled directly from SysML v2.
      (yuanxu-test-checkpoint 'lease-fencing-cold-start)
      (let ((r1 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'lease-fencing-token
                  cache-dir: cache-dir
                  request-id: "req-lf-1-cold")))
        (yuanxu-test-checkpoint 'lease-fencing-cold-done)
        (def mr-admitted ((.ref (.get r1 mr-result) 'rows-of) 'runnable_admitted))
        (check (and (member '("engineering.lifecycle.process-tree-reclamation") mr-admitted) #t) => #t)
        (check (and (member '("engineering.concurrency.backpressure-memory") mr-admitted) #t) => #t)
        (check (and (member '("engineering.concurrency.lease-fencing-token") mr-admitted) #t) => #t)
        (check-equal? (cdr (assoc 'schema (.get r1 dag-manifest)))
                      +flow-dag-runtime-manifest-schema+)
        (check-equal? (replay-report-valid? (.get r1 replay-report)) #t)
        (check-equal? (replay-report-reasons (.get r1 replay-report)) '())
        (check-equal? (length (.get r1 evidence-records)) 2)
        (for-each (lambda (ev) (check-equal? (.get ev outcome) 'pass)) (.get r1 evidence-records))
        (def er1 (.get r1 er-result))
        (check-equal? ((.ref er1 'rows-of) 'er_finding) '())
        (check-equal? (length ((.ref er1 'rows-of) 'obligation_passed)) 2)
        (check-equal? ((.ref er1 'rows-of) 'verification_admitted)
                      '(("engineering.concurrency.lease-fencing-token")))
        (check-equal? (length (.get (.get r1 cache-summary) executed)) 2)
        (check-equal? (.get (.get r1 cache-summary) reused) '()))
      (##gc)

      ;; Phase 2 — Warm run: 0 engines spawned, 2/2 reused from SHA-256 cache!
      (let ((r2 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'lease-fencing-token
                  cache-dir: cache-dir
                  request-id: "req-lf-2-warm")))
        (check-equal? (replay-report-valid? (.get r2 replay-report)) #t)
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'er_finding) '())
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'verification_admitted)
                      '(("engineering.concurrency.lease-fencing-token")))
        (check-equal? (.get (.get r2 cache-summary) executed) '())
        (check-equal? (length (.get (.get r2 cache-summary) reused)) 2)))))

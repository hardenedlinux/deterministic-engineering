;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-Role Agent Chat Room Ingress, External Connector Provenance & Human-Only One-Shot Gate Governance.
;;; Co-located Yuanxu unit: single source of truth alongside ChatroomIngressGovernance.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ChatroomIngressGovernanceModel
        ForgedExternalIngressCountermodel
        CrossChannelThreadInjectCountermodel
        GateReplayOrAgentApproveCountermodel
        AgentSelfUnblockMatterCountermodel
        TaintedExternalToolBypassCountermodel)

(.def (ChatroomIngressGovernanceModel @ ThreatModel.)
  identity: 'threat.protocol.chatroom-ingress-governance
  family: 'threat.protocol.chatroom-ingress-governance
  title: "Multi-Role Chat Room External Ingress, Channel Isolation & Human-Only Gate Governance"
  subdomain: 'quint.threat.protocol
  papers:
  '(("E. Debenedetti et al. (2025)"
     "Defeating Prompt Injections by Design (CaMeL): untrusted external ingress taint containment and human-gated tool execution.")
    ("R. S. Sandhu, E. J. Coyne, H. L. Feinstein & C. E. Youman (IEEE Computer, 1996)"
     "Role-Based Access Control Models: separation of duty and non-delegable human approval authority in collaborative rooms."))
  quint-module: "chatroom_ingress_governance"
  quint-file: "ChatroomIngressGovernance.qnt"
  domain-dir: "threat/protocol/chatroom-ingress-governance"
  quint-imports: '()
  rules:
  '((ingress-origin-provenance ROOM-INGRESS-ORIGIN quint)
    (channel-thread-affinity ROOM-CHANNEL-AFFINITY quint)
    (gate-oneshot-pending ROOM-GATE-ONESHOT quint)
    (matter-gate-lock ROOM-MATTER-LOCK quint)
    (tainted-tool-human-gate ROOM-TAINT-GATE quint))
  dependencies:
  '((ROOM-INGRESS-ORIGIN source)
    (ROOM-INGRESS-ORIGIN profile)
    (ROOM-INGRESS-ORIGIN method)
    (ROOM-CHANNEL-AFFINITY source)
    (ROOM-CHANNEL-AFFINITY profile)
    (ROOM-CHANNEL-AFFINITY method)
    (ROOM-GATE-ONESHOT source)
    (ROOM-GATE-ONESHOT profile)
    (ROOM-GATE-ONESHOT method)
    (ROOM-MATTER-LOCK source)
    (ROOM-MATTER-LOCK profile)
    (ROOM-MATTER-LOCK method)
    (ROOM-TAINT-GATE source)
    (ROOM-TAINT-GATE profile)
    (ROOM-TAINT-GATE method))
  invariant: "External room ingress never forges origin or gate receipts and never injects across channels; approval gates resolve strictly once by a human operator; gate-blocked matters cannot be unblocked by AI agents; and untrusted external messages never trigger privileged tools without human gate approval."
  parameters: '()
  state:
  '((gateId "int" "0")
    (gateStatus "int" "0")
    (matterBlockedByGate "bool" "false")
    (taintedExternalMsg "bool" "false")
    (toolExecuted "bool" "false")
    (forgedGateReceipt "bool" "false")
    (crossChannelInjected "bool" "false")
    (gateReplayed "bool" "false")
    (agentSelfUnblocked "bool" "false")
    (taintedToolBypass "bool" "false"))
  guards:
  '((ingress-origin-provenance (and originVerified (not claimsGate)))
    (channel-thread-affinity (= targetCh rootCh))
    (gate-oneshot-pending (and (= (. h gateStatus) 1) (not isAgent)))
    (matter-gate-lock (or (not (. h matterBlockedByGate)) (not isAgent)))
    (tainted-tool-human-gate (or (not (. h taintedExternalMsg)) (= (. h gateStatus) 2))))
  transitions:
  '((ingestExternalAs
      (action ingestExternalAs ((originVerified "bool") (claimsGate "bool") (targetCh "int") (rootCh "int")) "bool"
        (if (and (guard ingress-origin-provenance (and originVerified (not claimsGate)))
                 (guard channel-thread-affinity (= targetCh rootCh)))
          (set-h (taintedExternalMsg #t)
                 (forgedGateReceipt (or (. h forgedGateReceipt) (not originVerified) claimsGate))
                 (crossChannelInjected (or (. h crossChannelInjected) (!= targetCh rootCh))))
          (keep-h))))
    (ingestExternal
      (action ingestExternal ()
        (nondet ((originVerified (set #t #f))
                 (claimsGate (set #f #t))
                 (targetCh (set 1 2))
                 (rootCh (set 1 2)))
          (call ingestExternalAs originVerified claimsGate targetCh rootCh))))
    (agentRequestGate
      (action agentRequestGate ()
        (if (and (!= (. h gateStatus) 1) (< (. h gateId) 3))
          (set-h (gateId (+ (. h gateId) 1))
                 (gateStatus 1)
                 (matterBlockedByGate #t))
          (keep-h))))
    (resolveGateAs
      (action resolveGateAs ((isAgent "bool") (approve "bool")) "bool"
        (if (and (> (. h gateId) 0)
                 (guard gate-oneshot-pending (and (= (. h gateStatus) 1) (not isAgent))))
          (set-h (gateReplayed (or (. h gateReplayed) (!= (. h gateStatus) 1) isAgent))
                 (gateStatus (if approve 2 3))
                 (matterBlockedByGate (if approve #f (. h matterBlockedByGate))))
          (keep-h))))
    (resolveGate
      (action resolveGate ()
        (nondet ((isAgent (set #f #t))
                 (approve (set #t #f)))
          (call resolveGateAs isAgent approve))))
    (unblockMatterAs
      (action unblockMatterAs ((isAgent "bool")) "bool"
        (if (and (. h matterBlockedByGate)
                 (guard matter-gate-lock (or (not (. h matterBlockedByGate)) (not isAgent))))
          (set-h (matterBlockedByGate #f)
                 (agentSelfUnblocked (or (. h agentSelfUnblocked) isAgent)))
          (keep-h))))
    (unblockMatter
      (action unblockMatter ()
        (nondet ((isAgent (set #f #t)))
          (call unblockMatterAs isAgent))))
    (agentInvokeTool
      (action agentInvokeTool ()
        (if (guard tainted-tool-human-gate
                   (or (not (. h taintedExternalMsg)) (= (. h gateStatus) 2)))
          (set-h (toolExecuted #t)
                 (taintedToolBypass
                   (or (. h taintedToolBypass)
                       (and (. h taintedExternalMsg) (!= (. h gateStatus) 2)))))
          (keep-h))))
    (step
      (action step ()
        (any ingestExternal agentRequestGate resolveGate unblockMatter agentInvokeTool))))
  safety:
  '(and (not (. h forgedGateReceipt))
        (not (. h crossChannelInjected))
        (not (. h gateReplayed))
        (not (. h agentSelfUnblocked))
        (not (. h taintedToolBypass)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (verifiedExternalThenHumanGateAllowsToolTest
      (run verifiedExternalThenHumanGateAllowsToolTest
        (then init
              (call ingestExternalAs #t #f 1 1)
              agentInvokeTool
              agentRequestGate
              (call resolveGateAs #t #t)
              (call unblockMatterAs #t)
              (call resolveGateAs #f #t)
              agentInvokeTool
              (all (assert (. h toolExecuted))
                   (assert (not (. h matterBlockedByGate)))
                   (assert (= (. h gateStatus) 2))
                   (assert safety)
                   (keep-h)))))
    (rejectedGateBlocksReplayAndUnblockTest
      (run rejectedGateBlocksReplayAndUnblockTest
        (then init
              (call ingestExternalAs #t #f 1 1)
              agentRequestGate
              (call resolveGateAs #f #f)
              (call resolveGateAs #f #t)
              (call unblockMatterAs #t)
              agentInvokeTool
              (all (assert (= (. h gateStatus) 3))
                   (assert (. h matterBlockedByGate))
                   (assert (not (. h toolExecuted)))
                   (assert safety)
                   (keep-h)))))
    (forgedExternalIngressCountermodelTest
      (run forgedExternalIngressCountermodelTest
        (then init (call ingestExternalNoOrigin #f #t 1 1) checkUnsafe)))
    (crossChannelInjectCountermodelTest
      (run crossChannelInjectCountermodelTest
        (then init (call ingestExternalNoChannelCheck #t #f 1 2) checkUnsafe)))
    (gateReplayCountermodelTest
      (run gateReplayCountermodelTest
        (then init agentRequestGate (call resolveGateAs #f #f) (call resolveGateNoOneShot #f #t) checkUnsafe)))
    (agentSelfUnblockCountermodelTest
      (run agentSelfUnblockCountermodelTest
        (then init agentRequestGate (call unblockMatterNoGateLock #t) checkUnsafe)))
    (taintedToolBypassCountermodelTest
      (run taintedToolBypassCountermodelTest
        (then init (call ingestExternalAs #t #f 1 1) agentInvokeToolNoTaintGate checkUnsafe))))
  countermodels:
  (list ForgedExternalIngressCountermodel
        CrossChannelThreadInjectCountermodel
        GateReplayOrAgentApproveCountermodel
        AgentSelfUnblockMatterCountermodel
        TaintedExternalToolBypassCountermodel)
  limits: "Finite multi-role agent chatroom ingress, channel affinity, and one-shot human gate governance abstraction; does not model cryptographic webhook HMAC algorithms, semantic LLM prompt classification, or federated transport encryption.")

(.def (ForgedExternalIngressCountermodel @ ChatroomIngressGovernanceModel)
  identity: 'threat.protocol.chatroom-ingress-governance.forged-external-ingress
  dropped-guard: 'ingress-origin-provenance
  step-action: "stepForgedExternalIngress"
  derive-from-transition: 'ingestExternalAs
  derive-action-name: 'ingestExternalNoOrigin
  derive-step-call: '(nondet ((originVerified (set #t #f))
                              (claimsGate (set #f #t))
                              (targetCh (set 1 2))
                              (rootCh (set 1 2)))
                       (call ingestExternalNoOrigin originVerified claimsGate targetCh rootCh))
  expected-itf-predicate: "h.forgedGateReceipt == true")

(.def (CrossChannelThreadInjectCountermodel @ ChatroomIngressGovernanceModel)
  identity: 'threat.protocol.chatroom-ingress-governance.cross-channel-inject
  dropped-guard: 'channel-thread-affinity
  step-action: "stepCrossChannelInject"
  derive-from-transition: 'ingestExternalAs
  derive-action-name: 'ingestExternalNoChannelCheck
  derive-step-call: '(nondet ((originVerified (set #t #f))
                              (claimsGate (set #f #t))
                              (targetCh (set 1 2))
                              (rootCh (set 1 2)))
                       (call ingestExternalNoChannelCheck originVerified claimsGate targetCh rootCh))
  expected-itf-predicate: "h.crossChannelInjected == true")

(.def (GateReplayOrAgentApproveCountermodel @ ChatroomIngressGovernanceModel)
  identity: 'threat.protocol.chatroom-ingress-governance.gate-replay-or-agent-approve
  dropped-guard: 'gate-oneshot-pending
  step-action: "stepGateReplayOrAgentApprove"
  derive-from-transition: 'resolveGateAs
  derive-action-name: 'resolveGateNoOneShot
  derive-step-call: '(nondet ((isAgent (set #f #t))
                              (approve (set #t #f)))
                       (call resolveGateNoOneShot isAgent approve))
  expected-itf-predicate: "h.gateReplayed == true")

(.def (AgentSelfUnblockMatterCountermodel @ ChatroomIngressGovernanceModel)
  identity: 'threat.protocol.chatroom-ingress-governance.agent-self-unblock-matter
  dropped-guard: 'matter-gate-lock
  step-action: "stepAgentSelfUnblock"
  derive-from-transition: 'unblockMatterAs
  derive-action-name: 'unblockMatterNoGateLock
  derive-step-call: '(nondet ((isAgent (set #f #t)))
                       (call unblockMatterNoGateLock isAgent))
  expected-itf-predicate: "h.agentSelfUnblocked == true")

(.def (TaintedExternalToolBypassCountermodel @ ChatroomIngressGovernanceModel)
  identity: 'threat.protocol.chatroom-ingress-governance.tainted-tool-bypass
  dropped-guard: 'tainted-tool-human-gate
  step-action: "stepTaintedToolBypass"
  derive-from-transition: 'agentInvokeTool
  derive-action-name: 'agentInvokeToolNoTaintGate
  expected-itf-predicate: "h.taintedToolBypass == true")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-Party Shared Context Governance, Scope Lattice & Taint Isolation threat model.
;;; Co-located Yuanxu unit: single source of truth alongside SharedContextGovernance.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export SharedContextGovernanceModel
        PrivateContextLeakCountermodel
        UnauthorizedPromotionCountermodel
        RevokedMemberReadCountermodel
        MultiPartyTaintHijackCountermodel)

(.def (SharedContextGovernanceModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust.shared-context-governance
  family: 'threat.zero-trust.shared-context-governance
  title: "Multi-Party Shared Context Governance, Scope Lattice, and Taint Isolation"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("D. E. Denning (CACM 1976)"
     "A Lattice Model of Secure Information Flow: scoped confidentiality boundaries and explicit declassification.")
    ("E. Debenedetti et al. (2025)"
     "Defeating Prompt Injections by Design (CaMeL): preventing untrusted shared-context taint from hijacking privileged tools."))
  quint-module: "shared_context_governance"
  quint-file: "SharedContextGovernance.qnt"
  domain-dir: "threat/zero-trust/shared-context-governance"
  quint-imports:
  '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules:
  '((owner-only-scope-promotion SCG-OWNER-PROMOTE quint)
    (private-scope-isolation SCG-PRIVATE-SCOPE quint)
    (share-membership-current SCG-ACL-CURRENT quint)
    (multi-party-taint-gate SCG-TAINT-GATE quint))
  dependencies:
  '((SCG-OWNER-PROMOTE source)
    (SCG-OWNER-PROMOTE profile)
    (SCG-OWNER-PROMOTE method)
    (SCG-PRIVATE-SCOPE source)
    (SCG-PRIVATE-SCOPE profile)
    (SCG-PRIVATE-SCOPE method)
    (SCG-ACL-CURRENT source)
    (SCG-ACL-CURRENT profile)
    (SCG-ACL-CURRENT method)
    (SCG-TAINT-GATE source)
    (SCG-TAINT-GATE profile)
    (SCG-TAINT-GATE method))
  invariant: "Private context never leaks to peer principals, only owners with explicit declassification may widen private scope, revoked members never read via stale handles, and tainted multi-party shared context never drives tool execution without human gate approval."
  parameters: '()
  state:
  '((entryScope "int" "0")
    (entryConfidential "bool" "true")
    (entryDeclassified "bool" "false")
    (peerInChannel "bool" "true")
    (aclEpoch "int" "1")
    (peerHandleIssued "bool" "false")
    (peerHandleEpoch "int" "0")
    (channelTainted "bool" "false")
    (peerReads "int" "0")
    (agentToolCalls "int" "0")
    (privateLeak "bool" "false")
    (unauthorizedPromote "bool" "false")
    (revokedReadLeak "bool" "false")
    (taintedToolHijack "bool" "false"))
  guards:
  '((owner-only-scope-promotion (and actorIsOwner (or (not (. h entryConfidential)) explicitDeclassify)))
    (private-scope-isolation (>= (. h entryScope) 1))
    (share-membership-current (and (. h peerInChannel) (call epochCurrent (. h aclEpoch) (. h peerHandleEpoch))))
    (multi-party-taint-gate (or (not (. h channelTainted)) humanGateApproved)))
  transitions:
  '((promoteScopeAs
      (action promoteScopeAs ((actorIsOwner "bool") (explicitDeclassify "bool")) "bool"
        (if (and (= (. h entryScope) 0)
                 (guard owner-only-scope-promotion
                        (and actorIsOwner (or (not (. h entryConfidential)) explicitDeclassify))))
          (set-h (entryScope 1)
                 (entryDeclassified (or (. h entryDeclassified) explicitDeclassify))
                 (unauthorizedPromote
                   (or (. h unauthorizedPromote)
                       (not actorIsOwner)
                       (and (. h entryConfidential) (not explicitDeclassify)))))
          (keep-h))))
    (promoteScope
      (action promoteScope ()
        (nondet ((actorIsOwner (set #f #t))
                 (explicitDeclassify (set #f #t)))
          (call promoteScopeAs actorIsOwner explicitDeclassify))))
    (mintPeerHandle
      (action mintPeerHandle ()
        (if (and (. h peerInChannel) (not (. h peerHandleIssued)))
          (set-h (peerHandleIssued #t)
                 (peerHandleEpoch (. h aclEpoch)))
          (keep-h))))
    (peerReadContext
      (action peerReadContext ()
        (if (and (. h peerHandleIssued)
                 (< (. h peerReads) 3)
                 (guard private-scope-isolation (>= (. h entryScope) 1))
                 (guard share-membership-current
                        (and (. h peerInChannel)
                             (call epochCurrent (. h aclEpoch) (. h peerHandleEpoch)))))
          (set-h (peerReads (+ (. h peerReads) 1))
                 (privateLeak (or (. h privateLeak) (= (. h entryScope) 0)))
                 (revokedReadLeak
                   (or (. h revokedReadLeak)
                       (not (. h peerInChannel))
                       (!= (. h aclEpoch) (. h peerHandleEpoch)))))
          (keep-h))))
    (revokePeerAccess
      (action revokePeerAccess ()
        (if (and (. h peerInChannel) (< (. h aclEpoch) 4))
          (set-h (peerInChannel #f)
                 (aclEpoch (+ (. h aclEpoch) 1)))
          (keep-h))))
    (rejoinPeer
      (action rejoinPeer ()
        (if (and (not (. h peerInChannel)) (< (. h aclEpoch) 4))
          (set-h (peerInChannel #t)
                 (peerHandleIssued #f)
                 (peerHandleEpoch 0))
          (keep-h))))
    (poisonSharedContext
      (action poisonSharedContext ()
        (set-h (channelTainted #t))))
    (agentExecToolAs
      (action agentExecToolAs ((humanGateApproved "bool")) "bool"
        (if (and (< (. h agentToolCalls) 3)
                 (guard multi-party-taint-gate (or (not (. h channelTainted)) humanGateApproved)))
          (set-h (agentToolCalls (+ (. h agentToolCalls) 1))
                 (taintedToolHijack
                   (or (. h taintedToolHijack)
                       (and (. h channelTainted) (not humanGateApproved)))))
          (keep-h))))
    (agentExecTool
      (action agentExecTool ()
        (nondet ((humanGateApproved (set #f #t)))
          (call agentExecToolAs humanGateApproved))))
    (step
      (action step ()
        (any promoteScope mintPeerHandle peerReadContext revokePeerAccess rejoinPeer
             poisonSharedContext agentExecTool))))
  safety:
  '(and (not (. h privateLeak))
        (not (. h unauthorizedPromote))
        (not (. h revokedReadLeak))
        (not (. h taintedToolHijack)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (validOwnerPromoteAndPeerReadTest
      (run validOwnerPromoteAndPeerReadTest
        (then init
              (call promoteScopeAs #t #t)
              mintPeerHandle
              peerReadContext
              (all (assert (= (. h entryScope) 1))
                   (assert (= (. h peerReads) 1))
                   (assert safety)
                   (keep-h)))))
    (privateAndRevokedReadsBlockedTest
      (run privateAndRevokedReadsBlockedTest
        (then init
              mintPeerHandle
              peerReadContext
              (call promoteScopeAs #f #t)
              (call promoteScopeAs #t #t)
              revokePeerAccess
              peerReadContext
              (all (assert (= (. h peerReads) 0))
                   (assert (not (. h privateLeak)))
                   (assert (not (. h unauthorizedPromote)))
                   (assert (not (. h revokedReadLeak)))
                   (assert safety)
                   (keep-h)))))
    (taintedSharedContextRequiresGateTest
      (run taintedSharedContextRequiresGateTest
        (then init
              poisonSharedContext
              (call agentExecToolAs #f)
              (call agentExecToolAs #t)
              (all (assert (= (. h agentToolCalls) 1))
                   (assert (not (. h taintedToolHijack)))
                   (assert safety)
                   (keep-h)))))
    (privateLeakCountermodelTest
      (run privateLeakCountermodelTest
        (then init
              mintPeerHandle
              peerReadNoScopeCheck
              checkUnsafe)))
    (unauthorizedPromoteCountermodelTest
      (run unauthorizedPromoteCountermodelTest
        (then init
              (call promoteScopeUnchecked #f #f)
              checkUnsafe)))
    (revokedReadCountermodelTest
      (run revokedReadCountermodelTest
        (then init
              (call promoteScopeAs #t #t)
              mintPeerHandle
              revokePeerAccess
              peerReadNoAclCheck
              checkUnsafe)))
    (multiPartyTaintCountermodelTest
      (run multiPartyTaintCountermodelTest
        (then init
              poisonSharedContext
              (call agentExecToolNoTaintGate #f)
              checkUnsafe))))
  countermodels:
  (list PrivateContextLeakCountermodel
        UnauthorizedPromotionCountermodel
        RevokedMemberReadCountermodel
        MultiPartyTaintHijackCountermodel)
  limits: "Finite two-principal scope-promotion, ACL-epoch revocation, and multi-party taint abstraction; does not model vector-embedding semantic leakage, encrypted group key agreement, or side-channel cache timing.")

(.def (PrivateContextLeakCountermodel @ SharedContextGovernanceModel)
  identity: 'threat.zero-trust.shared-context-governance.private-context-leak
  dropped-guard: 'private-scope-isolation
  step-action: "stepPrivateContextLeak"
  derive-from-transition: 'peerReadContext
  derive-action-name: 'peerReadNoScopeCheck
  expected-itf-predicate: "h.privateLeak == true")

(.def (UnauthorizedPromotionCountermodel @ SharedContextGovernanceModel)
  identity: 'threat.zero-trust.shared-context-governance.unauthorized-promotion
  dropped-guard: 'owner-only-scope-promotion
  step-action: "stepUnauthorizedPromotion"
  derive-from-transition: 'promoteScopeAs
  derive-action-name: 'promoteScopeUnchecked
  derive-step-call: '(nondet ((actorIsOwner (set #f #t)) (explicitDeclassify (set #f #t)))
                       (call promoteScopeUnchecked actorIsOwner explicitDeclassify))
  expected-itf-predicate: "h.unauthorizedPromote == true")

(.def (RevokedMemberReadCountermodel @ SharedContextGovernanceModel)
  identity: 'threat.zero-trust.shared-context-governance.revoked-member-read
  dropped-guard: 'share-membership-current
  step-action: "stepRevokedMemberRead"
  derive-from-transition: 'peerReadContext
  derive-action-name: 'peerReadNoAclCheck
  expected-itf-predicate: "h.revokedReadLeak == true")

(.def (MultiPartyTaintHijackCountermodel @ SharedContextGovernanceModel)
  identity: 'threat.zero-trust.shared-context-governance.multi-party-taint-hijack
  dropped-guard: 'multi-party-taint-gate
  step-action: "stepMultiPartyTaintHijack"
  derive-from-transition: 'agentExecToolAs
  derive-action-name: 'agentExecToolNoTaintGate
  derive-step-call: '(nondet ((humanGateApproved (set #f #t)))
                       (call agentExecToolNoTaintGate humanGateApproved))
  expected-itf-predicate: "h.taintedToolHijack == true")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B3 (10.160): Cross-Trust-Boundary Multi-Agent Delegation,
;;; Macaroon-Style Monotonic Capability Attenuation, and Cascading Ancestor Revocation.
;;; Proves three capability-security invariants across multi-hop agent supply chains:
;;;   1. Monotonic attenuation: no delegated child can widen scope beyond parent/root
;;;      (escalationViolations == 0).
;;;   2. Cascading revocation: revoking any ancestor in live M3 immediately invalidates
;;;      all downstream delegates (revokedSubtreeExecutions == 0).
;;;   3. Chain MAC integrity, non-delegable flag, and finite hop depth are strictly
;;;      enforced at consumption time (forgedOrDepthViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export CapabilityAttenuationModel
        ScopeEscalationCountermodel
        RevokedSubtreeCountermodel
        ForgedOrDepthBypassCountermodel)

(.def (CapabilityAttenuationModel @ ThreatModel.)
  identity: 'engineering.defense.capability-attenuation
  family: 'engineering.defense.capability-attenuation
  title: "Cross-Trust-Boundary Delegation: Monotonic Capability Attenuation & Cascading Revocation"
  subdomain: 'quint.engineering.defense
  papers:
  '(("N. Hardy (ACM OSR 1988) / M. S. Miller, K.-P. Yee & J. Shapiro (2003)"
     "The Confused Deputy & Capability Myths Demolished: strict confinement, attenuation, and revocable caretakers.")
    ("A. Birgisson et al. (NDSS 2014)"
     "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud.")
    ("Deterministic Engineering (10.156 / 10.160)"
     "Immutable M1 Merkle delegation certificates chained with live M3 root signing keys and cascading revocation."))
  quint-module: "capability_attenuation"
  quint-file: "CapabilityAttenuation.qnt"
  domain-dir: "engineering/defense/capability-attenuation"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((capability-attenuation-safe DE-CAP-SAFE quint)
    (capability-attenuation-countermodel DE-CAP-COUNTER quint))
  dependencies:
  '((DE-CAP-SAFE source)
    (DE-CAP-SAFE profile)
    (DE-CAP-SAFE method)
    (DE-CAP-COUNTER source)
    (DE-CAP-COUNTER profile)
    (DE-CAP-COUNTER method))
  invariant: "No delegated agent executes with an escalated scope exceeding parent/root (escalationViolations == 0), no downstream delegate executes after any ancestor is revoked in M3 (revokedSubtreeExecutions == 0), and no forged chain MAC, non-delegable hop, or hop-depth overflow executes (forgedOrDepthViolations == 0)."
  parameters: '()
  state:
  '((rootScope "int" "3")
    (parentScope "int" "0")
    (childScope "int" "0")
    (delegationDepth "int" "0")
    (maxDepth "int" "2")
    (parentDelegatable "bool" "true")
    (chainMacValid "bool" "false")
    (ancestorRevoked "bool" "false")
    (escalationViolations "int" "0")
    (revokedSubtreeExecutions "int" "0")
    (forgedOrDepthViolations "int" "0")
    (validExecutions "int" "0"))
  guards:
  '((enforce-monotonic-attenuation
      (and (> (. h childScope) 0)
           (<= (. h childScope) (. h parentScope))
           (<= (. h parentScope) (. h rootScope))))
    (forbid-revoked-ancestor-subtree
      (not (. h ancestorRevoked)))
    (require-valid-mac-and-depth
      (and (. h chainMacValid)
           (. h parentDelegatable)
           (<= (. h delegationDepth) (. h maxDepth)))))
  transitions:
  '((mintParentDelegation
      (action mintParentDelegation ()
        (if (= (. h parentScope) 0)
          (set-h (parentScope 2) (delegationDepth 1) (chainMacValid #t))
          (keep-h))))
    (attenuateChildSafe
      (action attenuateChildSafe ()
        (if (and (> (. h parentScope) 0) (= (. h childScope) 0))
          (set-h (childScope 1) (delegationDepth 2) (chainMacValid #t))
          (keep-h))))
    (attemptScopeEscalation
      (action attemptScopeEscalation ()
        (if (and (> (. h parentScope) 0) (= (. h childScope) 0))
          (set-h (childScope 3) (delegationDepth 2) (chainMacValid #t))
          (keep-h))))
    (attemptTamperMacOrDepth
      (action attemptTamperMacOrDepth ()
        (if (and (> (. h parentScope) 0) (. h chainMacValid))
          (set-h (chainMacValid #f) (delegationDepth 3))
          (keep-h))))
    (freezeParentDelegation
      (action freezeParentDelegation ()
        (if (. h parentDelegatable)
          (set-h (parentDelegatable #f))
          (keep-h))))
    (revokeAncestorInM3
      (action revokeAncestorInM3 ()
        (if (not (. h ancestorRevoked))
          (set-h (ancestorRevoked #t))
          (keep-h))))
    (executeDelegatedAction
      (action executeDelegatedAction ()
        (if (and (guard enforce-monotonic-attenuation
                   (and (> (. h childScope) 0)
                        (<= (. h childScope) (. h parentScope))
                        (<= (. h parentScope) (. h rootScope))))
                 (guard forbid-revoked-ancestor-subtree
                   (not (. h ancestorRevoked)))
                 (guard require-valid-mac-and-depth
                   (and (. h chainMacValid)
                        (. h parentDelegatable)
                        (<= (. h delegationDepth) (. h maxDepth)))))
          (set-h (validExecutions (+ (. h validExecutions) 1))
                 (escalationViolations
                   (if (and (> (. h childScope) 0)
                            (<= (. h childScope) (. h parentScope))
                            (<= (. h parentScope) (. h rootScope)))
                     (. h escalationViolations)
                     (+ (. h escalationViolations) 1)))
                 (revokedSubtreeExecutions
                   (if (not (. h ancestorRevoked))
                     (. h revokedSubtreeExecutions)
                     (+ (. h revokedSubtreeExecutions) 1)))
                 (forgedOrDepthViolations
                   (if (and (. h chainMacValid)
                            (. h parentDelegatable)
                            (<= (. h delegationDepth) (. h maxDepth)))
                     (. h forgedOrDepthViolations)
                     (+ (. h forgedOrDepthViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any mintParentDelegation attenuateChildSafe attemptScopeEscalation
             attemptTamperMacOrDepth freezeParentDelegation revokeAncestorInM3
             executeDelegatedAction))))
  safety:
  '(and (= (. h escalationViolations) 0)
        (= (. h revokedSubtreeExecutions) 0)
        (= (. h forgedOrDepthViolations) 0))
  traces:
  '((monotonicAttenuationAndSafeExecutionTest
      (run monotonicAttenuationAndSafeExecutionTest
        (then init mintParentDelegation attenuateChildSafe executeDelegatedAction
              (all (assert safety)
                   (assert (= (. h validExecutions) 1))
                   (assert (<= (. h childScope) (. h parentScope)))
                   (keep-h)))))
    (scopeEscalationViolatesSafetyTest
      (run scopeEscalationViolatesSafetyTest
        (then init mintParentDelegation attemptScopeEscalation executeEscalated
              (all (assert (not safety))
                   (assert (> (. h escalationViolations) 0))
                   (keep-h)))))
    (revokedSubtreeViolatesSafetyTest
      (run revokedSubtreeViolatesSafetyTest
        (then init mintParentDelegation attenuateChildSafe revokeAncestorInM3 executeRevokedSubtree
              (all (assert (not safety))
                   (assert (> (. h revokedSubtreeExecutions) 0))
                   (keep-h)))))
    (forgedOrOverDepthViolatesSafetyTest
      (run forgedOrOverDepthViolatesSafetyTest
        (then init mintParentDelegation attenuateChildSafe attemptTamperMacOrDepth executeForgedOrOverDepth
              (all (assert (not safety))
                   (assert (> (. h forgedOrDepthViolations) 0))
                   (keep-h))))))
  countermodels:
  (list ScopeEscalationCountermodel
        RevokedSubtreeCountermodel
        ForgedOrDepthBypassCountermodel)
  limits: "Finite two-hop monotonic scope attenuation, chain MAC integrity, hop-depth bound, and M3 cascading revocation abstraction; does not model side-channel exfiltration by an authorized delegate or out-of-band network collusion.")

(.def (ScopeEscalationCountermodel @ CapabilityAttenuationModel)
  identity: 'engineering.defense.capability-attenuation.scope-escalation
  dropped-guard: 'enforce-monotonic-attenuation
  step-action: "stepScopeEscalation"
  derive-from-transition: 'executeDelegatedAction
  derive-action-name: 'executeEscalated
  expected-itf-predicate: "h.escalationViolations > 0")

(.def (RevokedSubtreeCountermodel @ CapabilityAttenuationModel)
  identity: 'engineering.defense.capability-attenuation.revoked-subtree
  dropped-guard: 'forbid-revoked-ancestor-subtree
  step-action: "stepRevokedSubtree"
  derive-from-transition: 'executeDelegatedAction
  derive-action-name: 'executeRevokedSubtree
  expected-itf-predicate: "h.revokedSubtreeExecutions > 0")

(.def (ForgedOrDepthBypassCountermodel @ CapabilityAttenuationModel)
  identity: 'engineering.defense.capability-attenuation.forged-or-depth
  dropped-guard: 'require-valid-mac-and-depth
  step-action: "stepForgedOrDepth"
  derive-from-transition: 'executeDelegatedAction
  derive-action-name: 'executeForgedOrOverDepth
  expected-itf-predicate: "h.forgedOrDepthViolations > 0")

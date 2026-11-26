;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Transparency Log Consistency & Split-View Gossip threat model.
;;; Grounded in RFC 9162 (Certificate Transparency v2 §2.1.4 Consistency Proofs),
;;; Sigstore Rekor / Omniwitness (Newman et al., ACM CCS 2022), and Chuat et al.
;;; (NDSS 2015, Efficient Gossip Protocols for Verifying the Consistency of CT Logs).
;;; Emergent safety (zero synthetic unsafe flag); both countermodels auto-derived via (guard ...).
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export TransparencyLogGossipModel
        UnloggedArtifactCountermodel
        SplitViewEquivocationCountermodel)

(.def (TransparencyLogGossipModel @ AuthorityCurrentnessModel)
  identity: 'threat.transparency-log-gossip
  family: 'threat.transparency-log-gossip
  quint-module: "transparency_log_gossip"
  quint-file: "TransparencyLogGossip.qnt"
  domain-dir: "threat/transparency-log-gossip"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((log-inclusion-proof TLOG-INCL-PROOF quint)
           (sth-consistency-gossip TLOG-GOSSIP-CONSIST quint))
  dependencies: '((TLOG-INCL-PROOF source) (TLOG-INCL-PROOF profile) (TLOG-INCL-PROOF method)
                  (TLOG-GOSSIP-CONSIST source) (TLOG-GOSSIP-CONSIST profile) (TLOG-GOSSIP-CONSIST method))
  invariant: "Every artifact accepted by a client appears in the publicly audited append-only log, preventing both unlogged binaries and split-view equivocation."
  parameters: '()
  state: '((publicLog "Set[int]" "Set(1)")
           (victimViewLog "Set[int]" "Set(1)")
           (logForked "bool" "false")
           (gossipChecked "bool" "true")
           (acceptedArtifacts "Set[int]" "Set()"))
  guards: '((log-inclusion-proof (contains (. h victimViewLog) art))
            (sth-consistency-gossip (and (. h gossipChecked) (subseteq (. h victimViewLog) (. h publicLog)))))
  transitions:
  '((appendHonestRelease
      (action appendHonestRelease ()
        (if (not (contains (. h publicLog) 2))
          (set-h (publicLog (union (. h publicLog) (set 2)))
                 (victimViewLog (if (. h logForked) (. h victimViewLog) (union (. h victimViewLog) (set 2)))))
          (keep-h))))
    (logEquivocateSplitView
      (action logEquivocateSplitView ()
        (if (not (. h logForked))
          (set-h (victimViewLog (union (. h victimViewLog) (set 99)))
                 (logForked #t)
                 (gossipChecked #f))
          (keep-h))))
    (gossipVerifyConsistency
      (action gossipVerifyConsistency ()
        (set-h (gossipChecked (subseteq (. h victimViewLog) (. h publicLog))))))
    (clientAcceptArtifactAs
      (action clientAcceptArtifactAs ((art "int")) "bool"
        (if (and (guard log-inclusion-proof (contains (. h victimViewLog) art))
                 (guard sth-consistency-gossip (and (. h gossipChecked) (subseteq (. h victimViewLog) (. h publicLog)))))
          (set-h (acceptedArtifacts (union (. h acceptedArtifacts) (set art))))
          (keep-h))))
    (clientAcceptArtifact
      (action clientAcceptArtifact ()
        (nondet ((art (set 1 2 99)))
          (call clientAcceptArtifactAs art))))
    (step
      (action step ()
        (any appendHonestRelease logEquivocateSplitView gossipVerifyConsistency clientAcceptArtifact))))
  safety: '(subseteq (. h acceptedArtifacts) (. h publicLog))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (honestLoggedArtifactAcceptedTest
      (run honestLoggedArtifactAcceptedTest
        (then init appendHonestRelease gossipVerifyConsistency (call clientAcceptArtifactAs 2)
              (all (assert (contains (. h acceptedArtifacts) 2)) (assert safety) (keep-h)))))
    (splitViewBackdoorRejectedByGossipTest
      (run splitViewBackdoorRejectedByGossipTest
        (then init logEquivocateSplitView gossipVerifyConsistency (call clientAcceptArtifactAs 99)
              (all (assert (not (contains (. h acceptedArtifacts) 99))) (assert safety) (keep-h)))))
    (unloggedArtifactCountermodelTest
      (run unloggedArtifactCountermodelTest
        (then init (call clientAcceptNoInclusion 99) checkUnsafe)))
    (splitViewCountermodelTest
      (run splitViewCountermodelTest
        (then init logEquivocateSplitView (call clientAcceptNoGossip 99) checkUnsafe))))
  countermodels: (list UnloggedArtifactCountermodel SplitViewEquivocationCountermodel)
  limits: "Finite set-prefix abstraction of Merkle consistency proofs and witness gossip; does not model SHA-256 second-preimage resistance, witness threshold collusion, or network eclipsing.")

(.def (UnloggedArtifactCountermodel @ TransparencyLogGossipModel)
  identity: 'threat.transparency-log-gossip.unlogged-artifact
  dropped-guard: 'log-inclusion-proof
  step-action: "stepUnloggedArtifact"
  derive-from-transition: 'clientAcceptArtifactAs
  derive-action-name: 'clientAcceptNoInclusion
  derive-step-call: '(nondet ((art (set 1 2 99))) (call clientAcceptNoInclusion art))
  expected-itf-predicate: "not(subseteq(h.acceptedArtifacts, h.publicLog))")

(.def (SplitViewEquivocationCountermodel @ TransparencyLogGossipModel)
  identity: 'threat.transparency-log-gossip.split-view-equivocation
  dropped-guard: 'sth-consistency-gossip
  step-action: "stepSplitViewEquivocation"
  derive-from-transition: 'clientAcceptArtifactAs
  derive-action-name: 'clientAcceptNoGossip
  derive-step-call: '(nondet ((art (set 1 2 99))) (call clientAcceptNoGossip art))
  expected-itf-predicate: "h.logForked == true and contains(h.acceptedArtifacts, 99) and not(contains(h.publicLog, 99))")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; TLS 1.3 & Noise Protocol 0-RTT Anti-Replay and Forward Secrecy threat model.
;;; Grounded in RFC 8446 (Rescorla, IETF 2018, §2.3 & §8), RFC 8470 (Early-Data),
;;; Cremers et al. (ACM CCS 2017, Tamarin Symbolic Analysis of TLS 1.3),
;;; Bhargavan, Blanchet & Kobeissi (IEEE S&P 2017, Verified TLS 1.3),
;;; Fischlin & Gunther (IEEE EuroS&P 2017, 0-RTT Replay Attacks), and Noise IK/XX.
;;; Emergent replay-conservation + post-compromise forward-secrecy safety (zero synthetic
;;; unsafe flag); all 3 protocol counterexamples are auto-derived via (guard ...).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export Tls13ZeroRttForwardSecrecyModel
        NonIdempotentZeroRttCountermodel
        CrossEdgeReplayCountermodel
        PskOnlyNoForwardSecrecyCountermodel)

(.def (Tls13ZeroRttForwardSecrecyModel @ ThreatModel.)
  identity: 'threat.tls13-0rtt-forward-secrecy
  family: 'threat.tls13-0rtt-forward-secrecy
  quint-module: "tls13_0rtt_forward_secrecy"
  quint-file: "Tls13ZeroRttForwardSecrecy.qnt"
  domain-dir: "threat/tls13-0rtt-forward-secrecy"
  quint-imports: '()
  verify-depth: 10
  countermodel-depth: 6
  rules: '((reject-non-idempotent-0rtt TLS13-0RTT-IDEMPOTENT quint)
           (cross-edge-strike-sync TLS13-0RTT-STRIKE-SYNC quint)
           (require-ecdhe-pfs TLS13-PFS-ECDHE quint))
  dependencies: '((TLS13-0RTT-IDEMPOTENT source) (TLS13-0RTT-IDEMPOTENT profile) (TLS13-0RTT-IDEMPOTENT method)
                  (TLS13-0RTT-STRIKE-SYNC source) (TLS13-0RTT-STRIKE-SYNC profile) (TLS13-0RTT-STRIKE-SYNC method)
                  (TLS13-PFS-ECDHE source) (TLS13-PFS-ECDHE profile) (TLS13-PFS-ECDHE method))
  invariant: "Non-idempotent operations never execute in 0-RTT, total 0-RTT executions never exceed genuine client transmissions across edge nodes, and later long-term PSK/STEK compromise never recovers previously exchanged confidential secrets."
  parameters: '()
  state: '((pskIssued "bool" "false")
           (pskCompromised "bool" "false")
           (ecdheDone "bool" "false")
           (clientSentZeroRtt "int" "0")
           (zeroRttNonIdempotent "bool" "false")
           (capturedZeroRtt "bool" "false")
           (capturedNonPfsSecret "bool" "false")
           (capturedPfsSecret "bool" "false")
           (nodeAStrikeUsed "bool" "false")
           (nodeBStrikeUsed "bool" "false")
           (zeroRttExecutions "int" "0")
           (nonIdempotentZeroRttExecutions "int" "0")
           (secretRecovered "bool" "false"))
  guards: '((reject-non-idempotent-0rtt (not (. h zeroRttNonIdempotent)))
            (cross-edge-strike-sync (and (not (. h nodeAStrikeUsed)) (not (. h nodeBStrikeUsed))))
            (require-ecdhe-pfs (. h ecdheDone)))
  transitions:
  '((issueResumptionPsk
      (action issueResumptionPsk ()
        (if (not (. h pskIssued))
          (set-h (pskIssued #t))
          (keep-h))))
    (clientSendZeroRttAs
      (action clientSendZeroRttAs ((isNonIdempotent "bool")) "bool"
        (if (and (. h pskIssued) (= (. h clientSentZeroRtt) 0))
          (set-h
            (clientSentZeroRtt 1)
            (zeroRttNonIdempotent isNonIdempotent)
            (capturedZeroRtt #t))
          (keep-h))))
    (clientSendZeroRtt
      (action clientSendZeroRtt ()
        (nondet ((isNonIdempotent (set #t #f)))
          (call clientSendZeroRttAs isNonIdempotent))))
    (edgeProcessZeroRttAs
      (action edgeProcessZeroRttAs ((node "int")) "bool"
        (if (and (. h capturedZeroRtt)
                 (guard reject-non-idempotent-0rtt (not (. h zeroRttNonIdempotent)))
                 (if (= node 1)
                   (and (not (. h nodeAStrikeUsed))
                        (guard cross-edge-strike-sync (not (. h nodeBStrikeUsed))))
                   (and (not (. h nodeBStrikeUsed))
                        (guard cross-edge-strike-sync (not (. h nodeAStrikeUsed))))))
          (set-h
            (nodeAStrikeUsed (if (= node 1) #t (. h nodeAStrikeUsed)))
            (nodeBStrikeUsed (if (= node 2) #t (. h nodeBStrikeUsed)))
            (zeroRttExecutions (+ (. h zeroRttExecutions) 1))
            (nonIdempotentZeroRttExecutions
              (if (. h zeroRttNonIdempotent)
                (+ (. h nonIdempotentZeroRttExecutions) 1)
                (. h nonIdempotentZeroRttExecutions))))
          (keep-h))))
    (edgeProcessZeroRtt
      (action edgeProcessZeroRtt ()
        (nondet ((node (set 1 2)))
          (call edgeProcessZeroRttAs node))))
    (completeEcdheHandshake
      (action completeEcdheHandshake ()
        (if (and (. h pskIssued) (not (. h ecdheDone)))
          (set-h (ecdheDone #t))
          (keep-h))))
    (clientSendConfidentialSecret
      (action clientSendConfidentialSecret ()
        (if (and (. h pskIssued)
                 (not (. h capturedPfsSecret))
                 (not (. h capturedNonPfsSecret))
                 (guard require-ecdhe-pfs (. h ecdheDone)))
          (if (. h ecdheDone)
            (set-h (capturedPfsSecret #t))
            (set-h (capturedNonPfsSecret #t)))
          (keep-h))))
    (compromiseLongTermPsk
      (action compromiseLongTermPsk ()
        (if (and (. h pskIssued) (not (. h pskCompromised)))
          (set-h (pskCompromised #t))
          (keep-h))))
    (attackerDecryptTranscript
      (action attackerDecryptTranscript ()
        (if (and (. h pskCompromised) (. h capturedNonPfsSecret))
          (set-h (secretRecovered #t))
          (keep-h))))
    (step
      (action step ()
        (any issueResumptionPsk clientSendZeroRtt edgeProcessZeroRtt
             completeEcdheHandshake clientSendConfidentialSecret
             compromiseLongTermPsk attackerDecryptTranscript))))
  safety:
  '(and (= (. h nonIdempotentZeroRttExecutions) 0)
        (<= (. h zeroRttExecutions) (. h clientSentZeroRtt))
        (not (. h secretRecovered)))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (pfsSurvivesPostCompromiseTest
      (run pfsSurvivesPostCompromiseTest
        (then init issueResumptionPsk
              (call clientSendZeroRttAs #f)
              (call edgeProcessZeroRttAs 1)
              (call edgeProcessZeroRttAs 2)
              completeEcdheHandshake
              clientSendConfidentialSecret
              compromiseLongTermPsk
              attackerDecryptTranscript
              (all (assert (= (. h zeroRttExecutions) 1))
                   (assert (. h capturedPfsSecret))
                   (assert (not (. h secretRecovered)))
                   (assert safety)
                   (keep-h)))))
    (nonIdempotentZeroRttCountermodelTest
      (run nonIdempotentZeroRttCountermodelTest
        (then init issueResumptionPsk
              (call clientSendZeroRttAs #t)
              (call edgeProcessNonIdempotent 1)
              checkUnsafe)))
    (crossEdgeReplayCountermodelTest
      (run crossEdgeReplayCountermodelTest
        (then init issueResumptionPsk
              (call clientSendZeroRttAs #f)
              (call edgeProcessZeroRttAs 1)
              (call edgeProcessUnsyncedStrike 2)
              checkUnsafe)))
    (noForwardSecrecyCountermodelTest
      (run noForwardSecrecyCountermodelTest
        (then init issueResumptionPsk
              clientSendSecretNoPfs
              compromiseLongTermPsk
              attackerDecryptTranscript
              checkUnsafe))))
  countermodels:
  (list NonIdempotentZeroRttCountermodel
        CrossEdgeReplayCountermodel
        PskOnlyNoForwardSecrecyCountermodel)
  limits: "Symbolic Dolev-Yao abstraction of TLS 1.3 / Noise 0-RTT anti-replay across 2 edge nodes and post-compromise forward secrecy; does not model cryptographic key schedule collision bounds, ticket age skew windows, or active MitM downgrade cipher suites.")

(.def (NonIdempotentZeroRttCountermodel @ Tls13ZeroRttForwardSecrecyModel)
  identity: 'threat.tls13-0rtt-forward-secrecy.non-idempotent-0rtt
  dropped-guard: 'reject-non-idempotent-0rtt
  step-action: "stepNonIdempotentZeroRtt"
  derive-from-transition: 'edgeProcessZeroRttAs
  derive-action-name: 'edgeProcessNonIdempotent
  derive-step-call: '(nondet ((node (set 1 2))) (call edgeProcessNonIdempotent node))
  expected-itf-predicate: "h.nonIdempotentZeroRttExecutions > 0")

(.def (CrossEdgeReplayCountermodel @ Tls13ZeroRttForwardSecrecyModel)
  identity: 'threat.tls13-0rtt-forward-secrecy.cross-edge-replay
  dropped-guard: 'cross-edge-strike-sync
  step-action: "stepCrossEdgeReplay"
  derive-from-transition: 'edgeProcessZeroRttAs
  derive-action-name: 'edgeProcessUnsyncedStrike
  derive-step-call: '(nondet ((node (set 1 2))) (call edgeProcessUnsyncedStrike node))
  expected-itf-predicate: "h.zeroRttExecutions > h.clientSentZeroRtt")

(.def (PskOnlyNoForwardSecrecyCountermodel @ Tls13ZeroRttForwardSecrecyModel)
  identity: 'threat.tls13-0rtt-forward-secrecy.psk-only-no-pfs
  dropped-guard: 'require-ecdhe-pfs
  step-action: "stepPskOnlyNoPfs"
  derive-from-transition: 'clientSendConfidentialSecret
  derive-action-name: 'clientSendSecretNoPfs
  expected-itf-predicate: "h.secretRecovered == true and h.pskCompromised == true and h.capturedNonPfsSecret == true")

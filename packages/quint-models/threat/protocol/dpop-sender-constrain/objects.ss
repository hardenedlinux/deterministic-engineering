;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OAuth 2.0 DPoP Sender-Constrained Tokens (RFC 9449 / FAPI 2.0) threat model.
;;; Co-located Yuanxu unit: single source of truth alongside DpopSenderConstrain.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export DpopSenderConstrainModel
        StolenTokenMisuseCountermodel
        DpopProofReplayCountermodel)

(.def (DpopSenderConstrainModel @ AuthorityCurrentnessModel)
  identity: 'threat.protocol.dpop-sender-constrain
  family: 'threat.protocol.dpop-sender-constrain
  title: "OAuth 2.0 DPoP Sender-Constrained Tokens & jti Replay Prevention"
  subdomain: 'quint.threat.protocol
  papers:
  '(("D. Fett, B. Campbell, J. Bradley, T. Lodderstedt, M. Jones & D. Waite (IETF RFC 9449, 2023)"
     "OAuth 2.0 Demonstrating Proof of Possession (DPoP): cnf.jkt sender binding and jti replay caches.")
    ("D. Fett, P. Hosseyni & R. Küsters (ACM CCS 2019 / OpenID FAPI 2.0)"
     "An Extensive Formal Security Analysis of the OpenID Financial-grade API (FAPI)."))
  quint-module: "dpop_sender_constrain"
  quint-file: "DpopSenderConstrain.qnt"
  domain-dir: "threat/protocol/dpop-sender-constrain"
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
  rules:
  '((cnf-jkt-binding DPOP-CNF-BIND quint)
    (jti-replay-cache DPOP-JTI-ONCE quint))
  dependencies:
  '((DPOP-CNF-BIND source)
    (DPOP-CNF-BIND profile)
    (DPOP-CNF-BIND method)
    (DPOP-JTI-ONCE source)
    (DPOP-JTI-ONCE profile)
    (DPOP-JTI-ONCE method))
  invariant: "An attacker who steals a sender-constrained access token never gets accepted at the resource server, and no DPoP proof jti is accepted twice."
  parameters: '()
  state:
  '((tokenIssued "bool" "false")
    (tokenBoundKey "int" "1")
    (attackerStoleToken "bool" "false")
    (nextJti "int" "1")
    (usedJtis "Set[int]" "Set()")
    (lastProofJti "int" "0")
    (acceptedActors "Set[int]" "Set()")
    (totalAccepted "int" "0"))
  guards:
  '((cnf-jkt-binding (= proofKey (. h tokenBoundKey)))
    (jti-replay-cache (not (contains (. h usedJtis) jti))))
  transitions:
  '((issueBoundToken
      (action issueBoundToken ()
        (if (not (. h tokenIssued))
          (set-h (tokenIssued #t)
                 (tokenBoundKey 1))
          (keep-h))))
    (stealAccessToken
      (action stealAccessToken ()
        (if (and (. h tokenIssued) (not (. h attackerStoleToken)))
          (set-h (attackerStoleToken #t))
          (keep-h))))
    (rsVerifyAndAccept
      (action rsVerifyAndAccept ((actor "int") (proofKey "int") (jti "int")) "bool"
        (if (and (. h tokenIssued)
                 (guard cnf-jkt-binding (= proofKey (. h tokenBoundKey)))
                 (guard jti-replay-cache (not (contains (. h usedJtis) jti))))
          (set-h (usedJtis (union (. h usedJtis) (set jti)))
                 (lastProofJti jti)
                 (acceptedActors (union (. h acceptedActors) (set actor)))
                 (totalAccepted (+ (. h totalAccepted) 1)))
          (keep-h))))
    (honestSendFresh
      (action honestSendFresh ()
        (if (and (. h tokenIssued) (<= (. h nextJti) 3))
          (set-h (nextJti (+ (. h nextJti) 1))
                 (usedJtis (union (. h usedJtis) (set (. h nextJti))))
                 (lastProofJti (. h nextJti))
                 (acceptedActors (union (. h acceptedActors) (set 1)))
                 (totalAccepted (+ (. h totalAccepted) 1)))
          (keep-h))))
    (attackerTryOwnKey
      (action attackerTryOwnKey ()
        (if (and (. h attackerStoleToken) (<= (. h nextJti) 3))
          (call rsVerifyAndAccept 2 2 (. h nextJti))
          (keep-h))))
    (attackerReplayProof
      (action attackerReplayProof ()
        (if (> (. h lastProofJti) 0)
          (call rsVerifyAndAccept 1 1 (. h lastProofJti))
          (keep-h))))
    (step
      (action step ()
        (any issueBoundToken stealAccessToken honestSendFresh
             attackerTryOwnKey attackerReplayProof))))
  safety:
  '(and (not (contains (. h acceptedActors) 2))
        (= (. h totalAccepted) (size (. h usedJtis))))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (stolenTokenBlockedTest
      (run stolenTokenBlockedTest
        (then init issueBoundToken stealAccessToken attackerTryOwnKey
              (all (assert (not (contains (. h acceptedActors) 2)))
                   (assert safety)
                   (keep-h)))))
    (replayProofBlockedTest
      (run replayProofBlockedTest
        (then init issueBoundToken honestSendFresh attackerReplayProof
              (all (assert (= (. h totalAccepted) 1))
                   (assert safety)
                   (keep-h)))))
    (stolenTokenCountermodelTest
      (run stolenTokenCountermodelTest
        (then init issueBoundToken stealAccessToken (call rsVerifyNoCnf 2 2 1) checkUnsafe)))
    (replayCountermodelTest
      (run replayCountermodelTest
        (then init issueBoundToken honestSendFresh (call rsVerifyNoJtiCache 1 1 1) checkUnsafe))))
  countermodels:
  (list StolenTokenMisuseCountermodel
        DpopProofReplayCountermodel)
  limits: "Finite RFC 9449 / FAPI 2.0 sender-constrain abstraction; does not model asymmetric JWS signature verification mathematics or TLS transport interception.")

(.def (StolenTokenMisuseCountermodel @ DpopSenderConstrainModel)
  identity: 'threat.protocol.dpop-sender-constrain.stolen-token-misuse
  dropped-guard: 'cnf-jkt-binding
  step-action: "stepStolenTokenMisuse"
  derive-from-transition: 'rsVerifyAndAccept
  derive-action-name: 'rsVerifyNoCnf
  derive-step-call: '(if (and (. h attackerStoleToken) (<= (. h nextJti) 3))
                       (call rsVerifyNoCnf 2 2 (. h nextJti))
                       (keep-h))
  expected-itf-predicate: "contains(h.acceptedActors, 2)")

(.def (DpopProofReplayCountermodel @ DpopSenderConstrainModel)
  identity: 'threat.protocol.dpop-sender-constrain.dpop-proof-replay
  dropped-guard: 'jti-replay-cache
  step-action: "stepDpopProofReplay"
  derive-from-transition: 'rsVerifyAndAccept
  derive-action-name: 'rsVerifyNoJtiCache
  derive-step-call: '(if (> (. h lastProofJti) 0)
                       (call rsVerifyNoJtiCache 1 1 (. h lastProofJti))
                       (keep-h))
  expected-itf-predicate: "h.totalAccepted > size(h.usedJtis)")

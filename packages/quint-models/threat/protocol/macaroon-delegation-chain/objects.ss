;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Macaroons Multi-Hop Caveat Attenuation threat model (Birgisson et al., NDSS 2014).
;;; Co-located Yuanxu unit: single source of truth alongside MacaroonDelegationChain.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export MacaroonDelegationModel
        CaveatStrippingCountermodel)

(.def (MacaroonDelegationModel @ AuthorityCurrentnessModel)
  identity: 'threat.protocol.macaroon-delegation-chain
  family: 'threat.protocol.macaroon-delegation-chain
  title: "Macaroons Multi-Hop Caveat Attenuation & HMAC Chain Verification"
  subdomain: 'quint.threat.protocol
  papers:
  '(("A. Birgisson, J. G. Politz, Ú. Erlingsson, A. Taly, M. Vrable & M. Lentczner (NDSS 2014)"
     "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud.")
    ("M. S. Miller (Johns Hopkins PhD Thesis 2006)"
     "Robust Composition: monotonic capability attenuation across untrusted delegation hops."))
  quint-module: "macaroon_delegation_chain"
  quint-file: "MacaroonDelegationChain.qnt"
  domain-dir: "threat/protocol/macaroon-delegation-chain"
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
  rules:
  '((hmac-caveat-chain-verify MACAROON-HMAC-CHAIN quint))
  dependencies:
  '((MACAROON-HMAC-CHAIN source)
    (MACAROON-HMAC-CHAIN profile)
    (MACAROON-HMAC-CHAIN method))
  invariant: "Every tool permission executed under a delegated macaroon is a subset of the monotonically attenuated caveat chain."
  parameters: '()
  state:
  '((rootPerms "Set[int]" "Set(1, 2, 3)")
    (attenuatedPerms "Set[int]" "Set(1, 2, 3)")
    (presentedPerms "Set[int]" "Set(1, 2, 3)")
    (hmacValid "bool" "true")
    (delegationHops "int" "0")
    (executedPerms "Set[int]" "Set()"))
  guards:
  '((hmac-caveat-chain-verify (and (. h hmacValid) (contains (. h presentedPerms) p))))
  transitions:
  '((delegateDropAdmin
      (action delegateDropAdmin ()
        (if (and (< (. h delegationHops) 2)
                 (= (. h executedPerms) (set))
                 (contains (. h attenuatedPerms) 3))
          (set-h (attenuatedPerms (exclude (. h attenuatedPerms) (set 3)))
                 (presentedPerms (exclude (. h attenuatedPerms) (set 3)))
                 (hmacValid #t)
                 (delegationHops (+ (. h delegationHops) 1)))
          (keep-h))))
    (delegateDropWrite
      (action delegateDropWrite ()
        (if (and (< (. h delegationHops) 2)
                 (= (. h executedPerms) (set))
                 (contains (. h attenuatedPerms) 2))
          (set-h (attenuatedPerms (exclude (. h attenuatedPerms) (set 2)))
                 (presentedPerms (exclude (. h attenuatedPerms) (set 2)))
                 (hmacValid #t)
                 (delegationHops (+ (. h delegationHops) 1)))
          (keep-h))))
    (subagentStripCaveats
      (action subagentStripCaveats ()
        (if (!= (. h attenuatedPerms) (. h rootPerms))
          (set-h (presentedPerms (. h rootPerms))
                 (hmacValid #f))
          (keep-h))))
    (invokeToolAs
      (action invokeToolAs ((p "int")) "bool"
        (if (and (guard hmac-caveat-chain-verify (. h hmacValid))
                 (contains (. h presentedPerms) p))
          (set-h (executedPerms (union (. h executedPerms) (set p))))
          (keep-h))))
    (invokeTool
      (action invokeTool ()
        (nondet ((p (set 1 2 3)))
          (call invokeToolAs p))))
    (step
      (action step ()
        (any delegateDropAdmin delegateDropWrite subagentStripCaveats invokeTool))))
  safety: '(subseteq (. h executedPerms) (. h attenuatedPerms))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (attenuatedSubagentSafeTest
      (run attenuatedSubagentSafeTest
        (then init delegateDropAdmin (call invokeToolAs 1) (call invokeToolAs 3)
              (all (assert (= (. h executedPerms) (set 1)))
                   (assert safety)
                   (keep-h)))))
    (strippedCaveatRejectedTest
      (run strippedCaveatRejectedTest
        (then init delegateDropAdmin subagentStripCaveats (call invokeToolAs 3)
              (all (assert (= (. h executedPerms) (set)))
                   (assert safety)
                   (keep-h)))))
    (caveatStrippingCountermodelTest
      (run caveatStrippingCountermodelTest
        (then init delegateDropAdmin subagentStripCaveats
              (call invokeToolNoHmac 3) checkUnsafe))))
  countermodels: (list CaveatStrippingCountermodel)
  limits: "Finite three-permission delegation chain abstraction; does not model HMAC-SHA256 collision resistance or third-party discharge macaroon distribution.")

(.def (CaveatStrippingCountermodel @ MacaroonDelegationModel)
  identity: 'threat.protocol.macaroon-delegation-chain.caveat-stripping
  dropped-guard: 'hmac-caveat-chain-verify
  step-action: "stepCaveatStripping"
  derive-from-transition: 'invokeToolAs
  derive-action-name: 'invokeToolNoHmac
  derive-step-call: '(nondet ((p (set 1 2 3)))
                       (call invokeToolNoHmac p))
  expected-itf-predicate: "not(subseteq(h.executedPerms, h.attenuatedPerms))")

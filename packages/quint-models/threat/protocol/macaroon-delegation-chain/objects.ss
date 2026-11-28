;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Macaroons Multi-Hop Caveat Attenuation threat model (Birgisson et al., NDSS 2014).
;;; Co-located Yuanxu unit: single source of truth alongside MacaroonDelegationChain.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export MacaroonDelegationModel)

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
  rules:
  '((hmac-caveat-chain-verify MACAROON-HMAC-CHAIN quint))
  dependencies:
  '((MACAROON-HMAC-CHAIN source)
    (MACAROON-HMAC-CHAIN profile)
    (MACAROON-HMAC-CHAIN method))
  invariant: "Every tool permission executed under a delegated macaroon is a subset of the monotonically attenuated caveat chain."
  limits: "Finite three-permission delegation chain abstraction; does not model HMAC-SHA256 collision resistance or third-party discharge macaroon distribution.")

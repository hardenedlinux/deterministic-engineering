;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OAuth 2.0 DPoP Sender-Constrained Tokens (RFC 9449 / FAPI 2.0) threat model.
;;; Co-located Yuanxu unit: single source of truth alongside DpopSenderConstrain.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export DpopSenderConstrainModel)

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
  limits: "Finite RFC 9449 / FAPI 2.0 sender-constrain abstraction; does not model asymmetric JWS signature verification mathematics or TLS transport interception.")

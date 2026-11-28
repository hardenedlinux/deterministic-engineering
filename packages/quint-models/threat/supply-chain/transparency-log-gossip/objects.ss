;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Transparency Log Consistency & Split-View Gossip threat model.
;;; Co-located Yuanxu unit: single source of truth alongside TransparencyLogGossip.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export TransparencyLogGossipModel)

(.def (TransparencyLogGossipModel @ AuthorityCurrentnessModel)
  identity: 'threat.supply-chain.transparency-log-gossip
  family: 'threat.supply-chain.transparency-log-gossip
  title: "Transparency Log Inclusion & Split-View Consistency Gossip"
  subdomain: 'quint.threat.supply-chain
  papers:
  '(("B. Laurie, E. Messeri & R. Stradling (IETF RFC 9162, 2021)"
     "Certificate Transparency Version 2.0: §2.1.4 Merkle Consistency Proofs and Signed Tree Heads.")
    ("L. Chuat, P. Szalachowski, A. Perrig, B. Laurie & E. Messeri (NDSS 2015)"
     "Efficient Gossip Protocols for Verifying the Consistency of Certificate Logs.")
    ("Z. Newman, J. S. Meyers & S. Torres-Arias (ACM CCS 2022)"
     "Sigstore: Software Signing for Everybody (Rekor transparency log & witness cosigning)."))
  quint-module: "transparency_log_gossip"
  quint-file: "TransparencyLogGossip.qnt"
  domain-dir: "threat/supply-chain/transparency-log-gossip"
  rules:
  '((log-inclusion-proof TLOG-INCL-PROOF quint)
    (sth-consistency-gossip TLOG-GOSSIP-CONSIST quint))
  dependencies:
  '((TLOG-INCL-PROOF source)
    (TLOG-INCL-PROOF profile)
    (TLOG-INCL-PROOF method)
    (TLOG-GOSSIP-CONSIST source)
    (TLOG-GOSSIP-CONSIST profile)
    (TLOG-GOSSIP-CONSIST method))
  invariant: "Every artifact accepted by a client appears in the publicly audited append-only log, preventing both unlogged binaries and split-view equivocation."
  limits: "Finite set-prefix abstraction of Merkle consistency proofs and witness gossip; does not model SHA-256 second-preimage resistance, witness threshold collusion, or network eclipsing.")

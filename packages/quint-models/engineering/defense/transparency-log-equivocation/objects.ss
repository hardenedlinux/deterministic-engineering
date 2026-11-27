;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B9 (10.166): Verifiable Append-Only Transparency Log,
;;; RFC 6962 Consistency Proofs, Ed25519 Signed Tree Heads, and Split-View
;;; Equivocation Fraud Proofs against a Compromised Coordinator.
;;; Proves three cryptographic transparency invariants:
;;;   1. No audit entry is accepted without a verified RFC 6962 inclusion proof
;;;      (unverifiedEntryAccepts == 0).
;;;   2. No updated Signed Tree Head is accepted if it fails RFC 6962 append-only
;;;      consistency (historyRewriteAccepts == 0).
;;;   3. No audit snapshot is accepted when witness gossip detects split-view
;;;      equivocation by the coordinator (equivocationAccepts == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export TransparencyLogEquivocationModel)

(.def (TransparencyLogEquivocationModel @ ThreatModel.)
  identity: 'engineering.defense.transparency-log-equivocation
  family: 'engineering.defense.transparency-log-equivocation
  title: "Verifiable Transparency Log: RFC 6962 Consistency & Split-View Equivocation Defense"
  subdomain: 'quint.engineering.defense
  papers:
  '(("B. Laurie, A. Langley & E. Kasper (RFC 6962 / ACM Queue 2014)"
     "Certificate Transparency: O(log N) Merkle inclusion & append-only consistency proofs.")
    ("M. Syta et al. (IEEE S&P 2016)"
     "Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning & Split-View Fraud Proofs.")
    ("Deterministic Engineering (10.156 / 10.166)"
     "Asymmetric Ed25519 Signed Tree Heads eliminating the trusted-coordinator assumption."))
  quint-module: "transparency_log_equivocation"
  quint-file: "TransparencyLogEquivocation.qnt"
  domain-dir: "engineering/defense/transparency-log-equivocation"
  rules:
  '((transparency-log-safe DE-TLOG-SAFE quint)
    (transparency-log-countermodel DE-TLOG-COUNTER quint))
  dependencies:
  '((DE-TLOG-SAFE source)
    (DE-TLOG-SAFE profile)
    (DE-TLOG-SAFE method)
    (DE-TLOG-COUNTER source)
    (DE-TLOG-COUNTER profile)
    (DE-TLOG-COUNTER method))
  invariant: "No governance audit accepts an unverified entry (unverifiedEntryAccepts == 0), a retroactively rewritten or rolled-back history (historyRewriteAccepts == 0), or a split-view equivocating coordinator (equivocationAccepts == 0)."
  limits: "Finite two-STH inclusion, consistency, and witness-gossip equivocation abstraction; does not model network eclipse attacks that completely isolate all external witnesses from gossiping with one another.")

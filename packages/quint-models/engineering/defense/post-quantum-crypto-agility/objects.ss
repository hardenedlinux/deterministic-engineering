;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B17 (10.193 / 10.194): Post-Quantum Hybrid Cryptographic Agility,
;;; Anti-Algorithm-Downgrade & Stateful Hash-Based OTS Leaf Anti-Reuse.
;;; Proves three post-quantum transition safety invariants:
;;;   1. Anti-Algorithm-Downgrade Floor: hybrid suite level >= 2 is required for
;;;      envelope admission (downgradeViolations == 0).
;;;   2. Dual-AND Hybrid Combiner: BOTH classical (Ed25519) AND post-quantum
;;;      (Lamport-Diffie OTS Merkle) legs must verify (singleLegBypassViolations == 0).
;;;   3. Stateful OTS Leaf Anti-Reuse: each accepted hybrid envelope requires a fresh
;;;      unspent OTS leaf and immediately consumes it (otsReuseViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PostQuantumCryptoAgilityModel)

(.def (PostQuantumCryptoAgilityModel @ ThreatModel.)
  identity: 'engineering.defense.post-quantum-crypto-agility
  family: 'engineering.defense.post-quantum-crypto-agility
  title: "Post-Quantum Hybrid Cryptographic Agility & Anti-Downgrade"
  subdomain: 'quint.engineering.defense
  papers:
  '(("L. Lamport (SRI Technical Report, 1979) & R. Merkle (CRYPTO 1989)"
     "Hash-based one-time signatures and stateful Merkle signature trees.")
    ("N. Bindel, U. Herath, M. McKague & D. Stebila (PQCrypto 2017)"
     "Transitioning to a Quantum-Resistant Public Key Infrastructure — Dual-AND hybrid combiners.")
    ("Deterministic Engineering (10.193 / 10.194)"
     "Hybrid Ed25519 + Lamport-Diffie OTS Merkle agility with anti-downgrade and OTS leaf anti-reuse."))
  quint-module: "post_quantum_crypto_agility"
  quint-file: "PostQuantumCryptoAgility.qnt"
  domain-dir: "engineering/defense/post-quantum-crypto-agility"
  rules:
  '((pq-agility-safe DE-PQCA-SAFE quint)
    (pq-agility-countermodel DE-PQCA-COUNTER quint))
  dependencies:
  '((DE-PQCA-SAFE source)
    (DE-PQCA-SAFE profile)
    (DE-PQCA-SAFE method)
    (DE-PQCA-COUNTER source)
    (DE-PQCA-COUNTER profile)
    (DE-PQCA-COUNTER method))
  invariant: "Hybrid certificate admission enforces hybrid PQ suite floor (downgradeViolations == 0), Dual-AND classical+PQ leg verification (singleLegBypassViolations == 0), and single-use stateful OTS leaf freshness (otsReuseViolations == 0)."
  limits: "Bounded 2-suite agility and single-slot OTS leaf freshness abstraction; arbitrary deprecated suites, domain separation tags, and unbounded Merkle OTS indices are proved in PostQuantumCryptoAgility.lean.")

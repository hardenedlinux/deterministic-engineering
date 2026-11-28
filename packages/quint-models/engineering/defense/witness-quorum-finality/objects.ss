;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B10 (10.169): Proactive Threshold Witness Cosigning
;;; (t = 2f + 1 of N = 3f + 1), Quorum Intersection Safety, and Eclipse-Resistant
;;; Checkpoint Finality.
;;; Proves three BFT transparency finality invariants under N = 4, f = 1, t = 3:
;;;   1. Quorum Intersection Safety: even with 1 Byzantine witness freely double-signing
;;;      BOTH branches, conflicting Clean and Backdoor checkpoints can NEVER both finalize
;;;      (not (and cleanFinalized backdoorFinalized)).
;;;   2. Consistency-Before-Cosign: honest witnesses never cosign without verified RFC 6962
;;;      append-only consistency (unverifiedCosignViolations == 0).
;;;   3. Threshold Quorum & Non-Equivocation: no checkpoint finalizes below 2f + 1 = 3
;;;      distinct witness cosignatures and no honest witness double-signs
;;;      (subQuorumViolations == 0 and honestEquivocationViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export WitnessQuorumFinalityModel)

(.def (WitnessQuorumFinalityModel @ ThreatModel.)
  identity: 'engineering.defense.witness-quorum-finality
  family: 'engineering.defense.witness-quorum-finality
  title: "Proactive Threshold Witness Cosigning (2f+1 of 3f+1) & Quorum Intersection Finality"
  subdomain: 'quint.engineering.defense
  papers:
  '(("M. Castro & B. Liskov (USENIX OSDI 1999) / M. Yin et al. (ACM PODC 2019)"
     "PBFT & HotStuff: 2f+1 Quorum Certificates guaranteeing intersection of at least one honest replica.")
    ("E. Syta et al. (IEEE S&P 2016)"
     "Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning (CoSi).")
    ("Deterministic Engineering (10.166 / 10.169)"
     "Proactive offline-verifiable Ed25519 witness cosigning blocking split-view even under total network eclipse."))
  quint-module: "witness_quorum_finality"
  quint-file: "WitnessQuorumFinality.qnt"
  domain-dir: "engineering/defense/witness-quorum-finality"
  rules:
  '((witness-quorum-safe DE-WQC-SAFE quint)
    (witness-quorum-countermodel DE-WQC-COUNTER quint))
  dependencies:
  '((DE-WQC-SAFE source)
    (DE-WQC-SAFE profile)
    (DE-WQC-SAFE method)
    (DE-WQC-COUNTER source)
    (DE-WQC-COUNTER profile)
    (DE-WQC-COUNTER method))
  invariant: "With N=4 witnesses (3 honest + 1 Byzantine double-signer) and threshold t=3 (2f+1), conflicting clean and backdoor branches can never both finalize (not(cleanFinalized and backdoorFinalized)), no honest witness cosigns without RFC 6962 consistency (unverifiedCosignViolations == 0) or double-signs (honestEquivocationViolations == 0), and no checkpoint finalizes below quorum (subQuorumViolations == 0)."
  limits: "Finite N=4 (f=1, t=3) Byzantine witness cosigning quorum-intersection abstraction; assumes static witness roster and <= f compromised witnesses (safety breaks if > f witnesses collude).")

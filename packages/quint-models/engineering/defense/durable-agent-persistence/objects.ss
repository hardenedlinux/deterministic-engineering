;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F4 / G5 / M1+M3: Orthogonal Persistence (gerbil-persist) x Durable Multi-Agent Governance (10.156).
;;; Proves three safety invariants when concurrent AI agents persist Merkleized state across crashes:
;;;   1. Atomic M3 root swaps require pre-commit stability across concurrent agents.
;;;   2. Post-crash/post-pause resumption MUST re-attest live M3 authority (forbids zombie permits).
;;;   3. Unresolved persisted side-effect intents block blind replay after crash recovery.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DurableAgentPersistenceModel)

(.def (DurableAgentPersistenceModel @ ThreatModel.)
  identity: 'engineering.defense.durable-agent-persistence
  family: 'engineering.defense.durable-agent-persistence
  title: "Orthogonal Persistence & Durable Multi-Agent Crash-Resume Governance"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Mighty Gerbils (gerbil-persist)"
     "Orthogonal persistence for concurrent activities via content-addressed Merkle DAG, pre-commit hook stability, and single atomic mutable root cell.")
    ("M. Atkinson & R. Morrison (VLDB J. 1995)"
     "Orthogonally Persistent Object Systems.")
    ("Deterministic Engineering (10.153 / 10.155 / 10.156)"
     "Separating persisted M1 Merkleized evidence from live M3 resume-time authority re-attestation and PendingUnknownEffect intent fencing."))
  quint-module: "durable_agent_persistence"
  quint-file: "DurableAgentPersistence.qnt"
  domain-dir: "engineering/defense/durable-agent-persistence"
  rules:
  '((durable-agent-safe DE-DUR-SAFE quint)
    (durable-agent-countermodel DE-DUR-COUNTER quint))
  dependencies:
  '((DE-DUR-SAFE source)
    (DE-DUR-SAFE profile)
    (DE-DUR-SAFE method)
    (DE-DUR-COUNTER source)
    (DE-DUR-COUNTER profile)
    (DE-DUR-COUNTER method))
  invariant: "Frozen M1 Merkle history stays intact, no M3 root commit occurs without pre-commit stability (unsafeUnstableCommits == 0), no resumed effect runs under stale/revoked authority (unsafeZombieEffects == 0), and no crash replay duplicates an unresolved in-flight intent (duplicateCrashEffects == 0)."
  limits: "Finite single-root orthogonal persistence and crash-resume governance abstraction; does not model Byzantine storage corruption, multi-region consensus latency, or hardware NVRAM tearing.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F4 / G5 / M1+M3: Orthogonal Persistence (gerbil-persist) x Durable Multi-Agent Governance (10.156).
;;; Proves three safety invariants when concurrent AI agents persist Merkleized state across crashes:
;;;   1. Atomic M3 root swaps require pre-commit stability across concurrent agents.
;;;   2. Post-crash/post-pause resumption MUST re-attest live M3 authority (forbids zombie permits).
;;;   3. Unresolved persisted side-effect intents block blind replay after crash recovery.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DurableAgentPersistenceModel
        UnstableRootCommitCountermodel
        ZombieAuthorityResumeCountermodel
        CrashReplayDuplicateEffectCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((rootVersion "int" "0")
    (merkleHistoryIntact "bool" "true")
    (preCommitStable "bool" "false")
    (agentCrashed "bool" "false")
    (authorityRevoked "bool" "false")
    (resumeReattested "bool" "false")
    (inFlightIntent "bool" "false")
    (unsafeUnstableCommits "int" "0")
    (unsafeZombieEffects "int" "0")
    (duplicateCrashEffects "int" "0"))
  guards:
  '((require-precommit-stable (. h preCommitStable))
    (require-resume-reattestation (and (. h resumeReattested) (not (. h authorityRevoked))))
    (forbid-blind-crash-replay-intent (not (. h inFlightIntent))))
  transitions:
  '((settlePreCommitHook
      (action settlePreCommitHook ()
        (if (and (not (. h agentCrashed)) (not (. h preCommitStable)))
          (set-h (preCommitStable #t))
          (keep-h))))
    (commitMerkleRoot
      (action commitMerkleRoot ()
        (if (and (not (. h agentCrashed))
                 (< (. h rootVersion) 3)
                 (guard require-precommit-stable (. h preCommitStable)))
          (set-h (rootVersion (+ (. h rootVersion) 1))
                 (preCommitStable #f)
                 (unsafeUnstableCommits
                   (if (. h preCommitStable)
                     (. h unsafeUnstableCommits)
                     (+ (. h unsafeUnstableCommits) 1))))
          (keep-h))))
    (recordInFlightIntent
      (action recordInFlightIntent ()
        (if (and (not (. h agentCrashed)) (not (. h inFlightIntent)))
          (set-h (inFlightIntent #t))
          (keep-h))))
    (crashOrSuspendAgent
      (action crashOrSuspendAgent ()
        (if (not (. h agentCrashed))
          (set-h (agentCrashed #t)
                 (preCommitStable #f)
                 (resumeReattested #f))
          (keep-h))))
    (revokeLiveAuthority
      (action revokeLiveAuthority ()
        (if (not (. h authorityRevoked))
          (set-h (authorityRevoked #t)
                 (resumeReattested #f))
          (keep-h))))
    (resumeFromMerkleRoot
      (action resumeFromMerkleRoot ()
        (if (. h agentCrashed)
          (set-h (agentCrashed #f)
                 (resumeReattested #f))
          (keep-h))))
    (reattestLiveAuthority
      (action reattestLiveAuthority ()
        (if (and (not (. h agentCrashed)) (not (. h authorityRevoked)) (not (. h resumeReattested)))
          (set-h (resumeReattested #t))
          (keep-h))))
    (reconcilePendingIntent
      (action reconcilePendingIntent ()
        (if (and (not (. h agentCrashed)) (. h inFlightIntent))
          (set-h (inFlightIntent #f))
          (keep-h))))
    (dispatchResumedEffect
      (action dispatchResumedEffect ()
        (if (and (not (. h agentCrashed))
                 (guard require-resume-reattestation
                   (and (. h resumeReattested) (not (. h authorityRevoked))))
                 (guard forbid-blind-crash-replay-intent (not (. h inFlightIntent))))
          (set-h (inFlightIntent #t)
                 (unsafeZombieEffects
                   (if (and (. h resumeReattested) (not (. h authorityRevoked)))
                     (. h unsafeZombieEffects)
                     (+ (. h unsafeZombieEffects) 1)))
                 (duplicateCrashEffects
                   (if (. h inFlightIntent)
                     (+ (. h duplicateCrashEffects) 1)
                     (. h duplicateCrashEffects))))
          (keep-h))))
    (step
      (action step ()
        (any settlePreCommitHook commitMerkleRoot recordInFlightIntent
             crashOrSuspendAgent revokeLiveAuthority resumeFromMerkleRoot
             reattestLiveAuthority reconcilePendingIntent dispatchResumedEffect))))
  safety:
  '(and (. h merkleHistoryIntact)
        (= (. h unsafeUnstableCommits) 0)
        (= (. h unsafeZombieEffects) 0)
        (= (. h duplicateCrashEffects) 0))
  traces:
  '((stableCommitAndSafeResumeTest
      (run stableCommitAndSafeResumeTest
        (then init settlePreCommitHook commitMerkleRoot recordInFlightIntent
              crashOrSuspendAgent resumeFromMerkleRoot reconcilePendingIntent
              reattestLiveAuthority dispatchResumedEffect
              (all (assert safety)
                   (assert (= (. h rootVersion) 1))
                   (assert (. h merkleHistoryIntact))
                   (keep-h)))))
    (unstableCommitViolatesSafetyTest
      (run unstableCommitViolatesSafetyTest
        (then init commitMerkleRootUnstable
              (all (assert (not safety))
                   (assert (> (. h unsafeUnstableCommits) 0))
                   (keep-h)))))
    (zombieResumeViolatesSafetyTest
      (run zombieResumeViolatesSafetyTest
        (then init crashOrSuspendAgent revokeLiveAuthority resumeFromMerkleRoot dispatchZombieEffect
              (all (assert (not safety))
                   (assert (> (. h unsafeZombieEffects) 0))
                   (keep-h)))))
    (crashReplayDuplicateViolatesSafetyTest
      (run crashReplayDuplicateViolatesSafetyTest
        (then init recordInFlightIntent crashOrSuspendAgent resumeFromMerkleRoot reattestLiveAuthority dispatchBlindCrashReplay
              (all (assert (not safety))
                   (assert (> (. h duplicateCrashEffects) 0))
                   (keep-h))))))
  countermodels:
  (list UnstableRootCommitCountermodel
        ZombieAuthorityResumeCountermodel
        CrashReplayDuplicateEffectCountermodel)
  limits: "Finite single-root orthogonal persistence and crash-resume governance abstraction; does not model Byzantine storage corruption, multi-region consensus latency, or hardware NVRAM tearing.")

(.def (UnstableRootCommitCountermodel @ DurableAgentPersistenceModel)
  identity: 'engineering.defense.durable-agent-persistence.unstable-commit
  dropped-guard: 'require-precommit-stable
  step-action: "stepUnstableCommit"
  derive-from-transition: 'commitMerkleRoot
  derive-action-name: 'commitMerkleRootUnstable
  expected-itf-predicate: "h.unsafeUnstableCommits > 0")

(.def (ZombieAuthorityResumeCountermodel @ DurableAgentPersistenceModel)
  identity: 'engineering.defense.durable-agent-persistence.zombie-resume
  dropped-guard: 'require-resume-reattestation
  step-action: "stepZombieResume"
  derive-from-transition: 'dispatchResumedEffect
  derive-action-name: 'dispatchZombieEffect
  expected-itf-predicate: "h.unsafeZombieEffects > 0")

(.def (CrashReplayDuplicateEffectCountermodel @ DurableAgentPersistenceModel)
  identity: 'engineering.defense.durable-agent-persistence.crash-replay-duplicate
  dropped-guard: 'forbid-blind-crash-replay-intent
  step-action: "stepBlindCrashReplay"
  derive-from-transition: 'dispatchResumedEffect
  derive-action-name: 'dispatchBlindCrashReplay
  expected-itf-predicate: "h.duplicateCrashEffects > 0")

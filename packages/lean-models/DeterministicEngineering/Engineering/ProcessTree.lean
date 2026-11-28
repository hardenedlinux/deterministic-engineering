/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Containment

/-!
# DeterministicEngineering.Engineering.ProcessTree

Domain refinement of `Core.Containment` using native `LeanPoo`:
1. `ObjectContract.refine` platform specializations (`LinuxCgroupV2` and `DarwinPgidPipe`)
   with monotonic rejection preservation (`refine_preserves_rejection`).
2. `LeanPoo.Proof.Patch` + `LeanPoo.Proof.reuse` dependency-certified proof transport:
   tuning grace-period timeouts transports the containment certificate automatically,
   whereas regressing `containerClosed` invalidates transport.
-/

namespace DeterministicEngineering.Engineering.ProcessTree

open LeanPoo.Functional.ObjectContract
open LeanPoo.Functional.ObjectDiagnostics
open DeterministicEngineering.Core.Containment

/-- Configuration carrier for a process-tree supervisor contract. -/
structure SupervisorConfig where
  spawnPreservesContainer : Bool
  gracePeriodMs : Nat
  cgroupKillEnabled : Bool
  pgidIsolated : Bool
  noSetsidEscape : Bool
  pipeEofWatchdogActive : Bool
  deriving DecidableEq, Repr

inductive ConfigKey where
  | spawnPreservesContainer
  | gracePeriodMs
  | cgroupKillEnabled
  | pgidIsolated
  | pipeEofWatchdogActive
  deriving DecidableEq, Repr

inductive SupervisorIssue where
  | missingContainmentClosure
  | zeroGracePeriod
  | missingLinuxCgroupKill
  | missingDarwinFateSharing
  deriving DecidableEq, Repr

private def configView : View SupervisorConfig ConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base process-tree supervisor contract: requires containment closure and positive grace window. -/
def baseSupervisorContract : Contract SupervisorConfig ConfigKey Unit SupervisorIssue where
  view := configView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.spawnPreservesContainer then [] else [.rejected path .missingContainmentClosure]) ++
    (if cfg.gracePeriodMs > 0 then [] else [.rejected path .zeroGracePeriod])
  validInventory := Or.inl rfl

/-- Linux cgroup v2 refinement via `LeanPoo.Functional.ObjectContract.refine`. -/
def linuxCgroupV2Contract : Contract SupervisorConfig ConfigKey Unit SupervisorIssue :=
  refine baseSupervisorContract fun cfg path =>
    if cfg.cgroupKillEnabled then [] else [.rejected path .missingLinuxCgroupKill]

/-- macOS (Darwin) refinement via `LeanPoo.Functional.ObjectContract.refine`:
requires process-group isolation plus either no `setsid()` escape or an active Pipe-EOF watchdog. -/
def darwinPgidPipeContract : Contract SupervisorConfig ConfigKey Unit SupervisorIssue :=
  refine baseSupervisorContract fun cfg path =>
    if cfg.pgidIsolated && (cfg.noSetsidEscape || cfg.pipeEofWatchdogActive) then []
    else [.rejected path .missingDarwinFateSharing]

/-- Monotonic strengthening: `linuxCgroupV2Contract` never admits a config rejected by base. -/
theorem linuxCgroupV2_preserves_rejection (cfg : SupervisorConfig) (path : List ConfigKey)
    (hRej : diagnose baseSupervisorContract cfg path ≠ []) :
    diagnose linuxCgroupV2Contract cfg path ≠ [] :=
  refine_preserves_rejection baseSupervisorContract _ cfg path hRej

/-- Monotonic strengthening: `darwinPgidPipeContract` never admits a config rejected by base. -/
theorem darwinPgidPipe_preserves_rejection (cfg : SupervisorConfig) (path : List ConfigKey)
    (hRej : diagnose baseSupervisorContract cfg path ≠ []) :
    diagnose darwinPgidPipeContract cfg path ≠ [] :=
  refine_preserves_rejection baseSupervisorContract _ cfg path hRej

/-- Acceptance characterization for `darwinPgidPipeContract`. -/
theorem darwinPgidPipe_accepts_iff (cfg : SupervisorConfig) (path : List ConfigKey) :
    diagnose darwinPgidPipeContract cfg path = [] ↔
      diagnose baseSupervisorContract cfg path = [] ∧
      (if cfg.pgidIsolated && (cfg.noSetsidEscape || cfg.pipeEofWatchdogActive) then []
       else [Issue.rejected path SupervisorIssue.missingDarwinFateSharing]) = [] :=
  refine_accepts_iff baseSupervisorContract _ cfg path

/-! ## Dependency-Certified Proof Transport (`LeanPoo.Proof.Reuse`) -/

inductive ProofKey where
  | containerClosed
  | gracePeriodMs
  | retryBackoffMs
  deriving DecidableEq

abbrev ProofValue : ProofKey → Type
  | .containerClosed => Bool
  | .gracePeriodMs => Nat
  | .retryBackoffMs => Nat

/-- Containment obligation depends ONLY on `.containerClosed`, not timeout/backoff constants. -/
def containmentObligation : LeanPoo.Proof.Obligation ProofKey ProofValue where
  dependencies := [.containerClosed]
  holds := fun state => state .containerClosed = true
  stable := by
    intro before after same holds
    exact (same .containerClosed (by simp)).symm.trans holds

def baselineSupervisor : LeanPoo.Proof.ProofObject ProofKey ProofValue where
  state := fun
    | .containerClosed => true
    | .gracePeriodMs => 3000
    | .retryBackoffMs => 100
  obligations := [containmentObligation]

theorem baselineCertified : LeanPoo.Proof.Certificate baselineSupervisor := by
  intro obligation member
  have hEq : obligation = containmentObligation := by simpa [baselineSupervisor] using member
  subst obligation
  rfl

/-- Patch tuning grace period from 3000ms to 5000ms (untouched: `.containerClosed`). -/
def graceTuningPatch : LeanPoo.Proof.Patch ProofKey ProofValue :=
  LeanPoo.Proof.Patch.set .gracePeriodMs 5000

theorem containmentUntouchedByGraceTuning :
    LeanPoo.Proof.unaffected containmentObligation graceTuningPatch := by
  intro key dep touched
  have hKey : key = .containerClosed := by simpa [containmentObligation] using dep
  subst key
  simp [graceTuningPatch, LeanPoo.Proof.Patch.set] at touched

/-- Automatic proof transport via `LeanPoo.Proof.reuse` across grace-period tuning. -/
theorem containment_transported_across_grace_tuning :
    containmentObligation.holds (LeanPoo.Proof.append baselineSupervisor graceTuningPatch).state :=
  LeanPoo.Proof.reuse baselineSupervisor graceTuningPatch baselineCertified
    containmentObligation (by simp [baselineSupervisor]) containmentUntouchedByGraceTuning

/-- Full certificate closure after grace-period tuning without re-proving containment. -/
theorem graceTunedCertified :
    LeanPoo.Proof.Certificate (LeanPoo.Proof.append baselineSupervisor graceTuningPatch) := by
  apply LeanPoo.Proof.close baselineSupervisor graceTuningPatch baselineCertified
  · intro obligation member affected
    have hEq : obligation = containmentObligation := by simpa [baselineSupervisor] using member
    subst obligation
    exact False.elim (affected containmentUntouchedByGraceTuning)
  · intro obligation member
    simp [graceTuningPatch, LeanPoo.Proof.Patch.set] at member

/-- Negative control: regressing `.containerClosed := false` (single-PID kill) IS affected
and cannot reuse the containment proof via `LeanPoo.Proof.reuse`. -/
def singlePidRegressionPatch : LeanPoo.Proof.Patch ProofKey ProofValue :=
  LeanPoo.Proof.Patch.set .containerClosed false

theorem singlePidRegression_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected containmentObligation singlePidRegressionPatch := by
  intro hUnaffected
  exact hUnaffected .containerClosed (by simp [containmentObligation])
    (by simp [singlePidRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.ProcessTree

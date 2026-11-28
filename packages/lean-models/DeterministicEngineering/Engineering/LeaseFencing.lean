/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Order
import DeterministicEngineering.Core.Transport

/-!
# Lease Fencing Token LeanPoo Refinement & Proof Reuse (`Engineering.LeaseFencing`)

Refines `Core.Order` (unbounded monotonic fencing epochs) and `Core.Transport`
(1-line certificate transport & 2-step contract refinement) for the 3rd engineering
subject `engineering.concurrency.lease-fencing-token` (10.154).

Orthogonal to Quint (`LeaseFencingToken.qnt` checks finite 2-client GC-pause races
and the `stale-lease-zombie-write` countermodel): this module proves unbounded
epoch rejection for arbitrary `Nat` token numbers and cross-patch proof transport.
-/

namespace DeterministicEngineering.Engineering.LeaseFencing

open DeterministicEngineering.Core.Order
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-- Unbounded zombie-write rejection across any arbitrary sequence of higher epochs. -/
theorem zombieWrite_always_rejected (storageMax newerEpoch zombieEpoch : Nat)
    (hZombieOlder : zombieEpoch < storageMax) :
    admitEpoch (advanceEpoch storageMax newerEpoch) zombieEpoch = false :=
  advanceEpoch_rejects_strictly_older storageMax newerEpoch zombieEpoch hZombieOlder

/-! ## Two-Step LeanPoo `ObjectContract.refine` (via `Core.Transport`) -/

structure LeaseStorageConfig where
  monotonicTokenIssuer : Bool
  storageChecksFencingToken : Bool
  durableMaxTokenPersisted : Bool
  deriving DecidableEq, Repr

inductive LeaseConfigKey where
  | monotonicTokenIssuer
  | storageChecksFencingToken
  | durableMaxTokenPersisted
  deriving DecidableEq, Repr

inductive LeaseIssue where
  | nonMonotonicIssuer
  | missingStorageFencingCheck
  | volatileMaxToken
  deriving DecidableEq, Repr

private def leaseView : View LeaseStorageConfig LeaseConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseLeaseContract : Contract LeaseStorageConfig LeaseConfigKey Unit LeaseIssue where
  view := leaseView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.monotonicTokenIssuer then [] else [.rejected path .nonMonotonicIssuer]
  validInventory := Or.inl rfl

def fencedStorageExt (cfg : LeaseStorageConfig) (path : List LeaseConfigKey) :
    List (Issue LeaseConfigKey LeaseIssue) :=
  if cfg.storageChecksFencingToken then [] else [.rejected path .missingStorageFencingCheck]

def durableFencingExt (cfg : LeaseStorageConfig) (path : List LeaseConfigKey) :
    List (Issue LeaseConfigKey LeaseIssue) :=
  if cfg.durableMaxTokenPersisted then [] else [.rejected path .volatileMaxToken]

def durableFencedStorageContract : Contract LeaseStorageConfig LeaseConfigKey Unit LeaseIssue :=
  refine (refine baseLeaseContract fencedStorageExt) durableFencingExt

/-- One-line two-step monotonic refinement proof reusing `Core.Transport`. -/
theorem durableFencedStorage_preserves_rejection
    (cfg : LeaseStorageConfig) (path : List LeaseConfigKey)
    (hRej : diagnose baseLeaseContract cfg path ≠ []) :
    diagnose durableFencedStorageContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseLeaseContract fencedStorageExt durableFencingExt cfg path hRej

/-! ## One-Line Proof Transport via `Core.Transport` -/

inductive LeaseProofKey where
  | fencingEnforced
  | heartbeatIntervalMs
  | metricsFlushMs
  deriving DecidableEq

abbrev LeaseProofValue : LeaseProofKey → Type
  | .fencingEnforced => Bool
  | .heartbeatIntervalMs => Nat
  | .metricsFlushMs => Nat

def fencingObligation : LeanPoo.Proof.Obligation LeaseProofKey LeaseProofValue where
  dependencies := [.fencingEnforced]
  holds := fun s => s .fencingEnforced = true
  stable := by
    intro before after same holds
    exact (same .fencingEnforced (by simp)).symm.trans holds

def baselineLeaseStorage : LeanPoo.Proof.ProofObject LeaseProofKey LeaseProofValue where
  state := fun
    | .fencingEnforced => true
    | .heartbeatIntervalMs => 500
    | .metricsFlushMs => 1000
  obligations := [fencingObligation]

theorem baselineLeaseCertified : LeanPoo.Proof.Certificate baselineLeaseStorage := by
  intro ob hMem
  have hEq : ob = fencingObligation := by simpa [baselineLeaseStorage] using hMem
  subst ob
  rfl

/-- One-line proof transport across heartbeat tuning via `Core.Transport.close_single_set_untouched`. -/
theorem heartbeatTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineLeaseStorage
        (LeanPoo.Proof.Patch.set .heartbeatIntervalMs 1500)) :=
  close_single_set_untouched baselineLeaseStorage fencingObligation
    .heartbeatIntervalMs 1500 rfl baselineLeaseCertified (by simp [fencingObligation])

/-- Negative control: disabling `.fencingEnforced` invalidates proof reuse (1-line via `Core.Transport`). -/
theorem disableFencing_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected fencingObligation
        (LeanPoo.Proof.Patch.set .fencingEnforced false) :=
  set_dependency_invalidates_unaffected fencingObligation
    .fencingEnforced false (by simp [fencingObligation])

end DeterministicEngineering.Engineering.LeaseFencing

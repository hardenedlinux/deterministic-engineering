/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Budget
import DeterministicEngineering.Core.Order
import DeterministicEngineering.Core.Transport

/-!
# AI Agent Wasm Linear-Memory, WASI Capability & Preopen Path Confinement (`Threat.WasmSandboxConfinement`)

LeanPoo AI-Security refinement sharing `Core.Budget` (guest linear-memory page ceiling),
`Core.Order` (monotonic sandbox revocation epoch fencing), and `Core.Transport`
(`ObjectContract.refine` + `Patch.frame` + `Proof.reuse`) with zero duplicated base
mathematics.

Orthogonal to Quint (`packages/quint-models/threat/execution/wasm-sandbox-confinement/WasmSandboxConfinement.qnt`,
which bounds `guestMemSize = 64` and checks 3 finite guard-pruned countermodels):
this module proves:
1. **Unbounded linear-memory bounds enforcement**: for any guest linear memory size
   `memSize : Nat`, every access at `addr ≥ memSize` is unconditionally rejected.
2. **WASI capability & preopen root confinement**: missing capability handles or any
   preopen path escape unconditionally blocks the hostcall.
3. **Unbounded guest linear-memory page budget ceiling (`Core.Budget`)**: conserving
   `activePages + reservedPages ≤ maxPages` bounds total retained sandbox bytes for
   any page size and runtime overhead.
4. **Monotonic sandbox revocation epoch fencing (`Core.Order`)**: advancing the sandbox
   epoch rejects every stale pre-revocation guest instance handle at any `e < currentEpoch`.
5. **Two-step LeanPoo `ObjectContract.refine` & one-line `Proof.reuse` (`Core.Transport`)**:
   AI-safe fuel-check interval tuning transports the certificate cleanly, while disabling
   linear-memory bounds checking invalidates proof reuse.
-/

namespace DeterministicEngineering.Threat.WasmSandboxConfinement

open DeterministicEngineering.Core.Budget
open DeterministicEngineering.Core.Order
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## 1. Unbounded Linear-Memory Bounds, WASI Handle & Epoch Confinement Laws -/

/-- Whether a Wasm guest linear-memory access is admitted within `[0, memSize)`. -/
def wasmMemAccessAdmitted (memSize addr : Nat) : Bool :=
  decide (addr < memSize)

/-- Whether a WASI hostcall is admitted (requires granted capability handle,
    preopen root confinement, and current sandbox revocation epoch). -/
def wasmHostcallAdmitted
    (handleGranted escapesPreopenRoot : Bool)
    (currentSandboxEpoch instanceEpoch : Nat) : Bool :=
  match handleGranted with
  | false => false
  | true =>
    match escapesPreopenRoot with
    | true => false
    | false => admitEpoch currentSandboxEpoch instanceEpoch

/-- Theorem 1: Any out-of-bounds Wasm linear memory access (`addr ≥ memSize`) is
    unconditionally rejected for arbitrary memory sizes. -/
theorem wasmMemAccess_oob_rejected (memSize addr : Nat) (hOob : memSize ≤ addr) :
    wasmMemAccessAdmitted memSize addr = false := by
  unfold wasmMemAccessAdmitted
  exact decide_eq_false (Nat.not_lt.mpr hOob)

/-- Theorem 2: Ungranted WASI capability handles and preopen host-root escapes are
    unconditionally rejected regardless of sandbox epoch. -/
theorem wasmHostcall_ungranted_or_escape_rejected
    (handleGranted escapesRoot : Bool) (curEpoch instEpoch : Nat) :
    wasmHostcallAdmitted false escapesRoot curEpoch instEpoch = false ∧
    wasmHostcallAdmitted handleGranted true curEpoch instEpoch = false := by
  constructor
  · rfl
  · cases handleGranted <;> rfl

/-- Theorem 3: Unbounded Wasm linear-memory page ceiling (reusing `Core.Budget.conservation_bounds_peak`). -/
theorem wasmSandbox_linearMemory_bounded
    (activePages reservedPages maxPages pageBytes stackOverhead runtimeOverhead : Nat)
    (hConserved : activePages + reservedPages ≤ maxPages) :
    retainedBytes activePages reservedPages pageBytes stackOverhead runtimeOverhead ≤
      maxPages * pageBytes + stackOverhead + runtimeOverhead :=
  conservation_bounds_peak activePages reservedPages maxPages pageBytes stackOverhead runtimeOverhead hConserved

/-- Theorem 4: Advancing the sandbox revocation epoch unconditionally rejects every
    stale pre-revocation Wasm instance hostcall (reusing `Core.Order.advanceEpoch_rejects_strictly_older`). -/
theorem wasmSandbox_revokedEpoch_blocks_staleInstance
    (sandboxEpoch nextEpoch staleInstEpoch : Nat)
    (hStale : staleInstEpoch < sandboxEpoch) :
    wasmHostcallAdmitted true false (advanceEpoch sandboxEpoch nextEpoch) staleInstEpoch = false := by
  unfold wasmHostcallAdmitted
  exact advanceEpoch_rejects_strictly_older sandboxEpoch nextEpoch staleInstEpoch hStale

/-! ## 2. Two-Step LeanPoo `ObjectContract.refine` (reusing `Core.Transport`) -/

structure WasmSandboxConfig where
  enforcesLinearMemBounds : Bool
  enforcesWasiCapabilityHandles : Bool
  enforcesPreopenPathConfinement : Bool
  deriving DecidableEq, Repr

inductive WasmSandboxConfigKey where
  | enforcesLinearMemBounds
  | enforcesWasiCapabilityHandles
  | enforcesPreopenPathConfinement
  deriving DecidableEq, Repr

inductive WasmSandboxIssue where
  | missingLinearMemBounds
  | missingWasiCapabilityHandles
  | missingPreopenPathConfinement
  deriving DecidableEq, Repr

private def wasmSandboxView : View WasmSandboxConfig WasmSandboxConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseWasmSandboxContract :
    Contract WasmSandboxConfig WasmSandboxConfigKey Unit WasmSandboxIssue where
  view := wasmSandboxView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.enforcesLinearMemBounds then [] else [.rejected path .missingLinearMemBounds]
  validInventory := Or.inl rfl

def wasiCapabilityExt (cfg : WasmSandboxConfig) (path : List WasmSandboxConfigKey) :
    List (Issue WasmSandboxConfigKey WasmSandboxIssue) :=
  if cfg.enforcesWasiCapabilityHandles then [] else [.rejected path .missingWasiCapabilityHandles]

def preopenPathExt (cfg : WasmSandboxConfig) (path : List WasmSandboxConfigKey) :
    List (Issue WasmSandboxConfigKey WasmSandboxIssue) :=
  if cfg.enforcesPreopenPathConfinement then [] else [.rejected path .missingPreopenPathConfinement]

def wasmSandboxContract :
    Contract WasmSandboxConfig WasmSandboxConfigKey Unit WasmSandboxIssue :=
  refine (refine baseWasmSandboxContract wasiCapabilityExt) preopenPathExt

/-- Theorem 5: Two-step Wasm sandbox refinement monotonically preserves all base bounds rejections. -/
theorem wasmSandboxContract_preserves_rejection
    (cfg : WasmSandboxConfig) (path : List WasmSandboxConfigKey)
    (hRej : diagnose baseWasmSandboxContract cfg path ≠ []) :
    diagnose wasmSandboxContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseWasmSandboxContract wasiCapabilityExt preopenPathExt cfg path hRej

/-! ## 3. AI-SE Proof Transport via `Core.Transport` -/

inductive WasmSandboxProofKey where
  | boundsCheckEnforced
  | wasiCapHandlesEnforced
  | preopenConfinementEnforced
  | fuelCheckIntervalOps
  deriving DecidableEq

abbrev WasmSandboxProofValue : WasmSandboxProofKey → Type
  | .boundsCheckEnforced => Bool
  | .wasiCapHandlesEnforced => Bool
  | .preopenConfinementEnforced => Bool
  | .fuelCheckIntervalOps => Nat

def wasmSandboxObligation :
    LeanPoo.Proof.Obligation WasmSandboxProofKey WasmSandboxProofValue where
  dependencies := [.boundsCheckEnforced, .wasiCapHandlesEnforced, .preopenConfinementEnforced]
  holds := fun s =>
    s .boundsCheckEnforced = true ∧
    s .wasiCapHandlesEnforced = true ∧
    s .preopenConfinementEnforced = true
  stable := by
    intro before after same holds
    exact ⟨(same .boundsCheckEnforced (by simp)).symm.trans holds.1,
           (same .wasiCapHandlesEnforced (by simp)).symm.trans holds.2.1,
           (same .preopenConfinementEnforced (by simp)).symm.trans holds.2.2⟩

def baselineWasmSandbox :
    LeanPoo.Proof.ProofObject WasmSandboxProofKey WasmSandboxProofValue where
  state := fun
    | .boundsCheckEnforced => true
    | .wasiCapHandlesEnforced => true
    | .preopenConfinementEnforced => true
    | .fuelCheckIntervalOps => 1024
  obligations := [wasmSandboxObligation]

theorem baselineWasmSandboxCertified : LeanPoo.Proof.Certificate baselineWasmSandbox := by
  intro ob hMem
  have hEq : ob = wasmSandboxObligation := by simpa [baselineWasmSandbox] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl⟩

/-- Theorem 6: AI-safe fuel-metering interval tuning transports the Wasm sandbox certificate in 1 line. -/
theorem wasmFuelBudgetTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineWasmSandbox
        (LeanPoo.Proof.Patch.set .fuelCheckIntervalOps 2048)) :=
  close_single_set_untouched baselineWasmSandbox wasmSandboxObligation
    .fuelCheckIntervalOps 2048 rfl baselineWasmSandboxCertified (by simp [wasmSandboxObligation])

/-- Theorem 7: Negative control — AI regression disabling linear-memory bounds checking invalidates reuse. -/
theorem disableBoundsCheck_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected wasmSandboxObligation
        (LeanPoo.Proof.Patch.set .boundsCheckEnforced false) :=
  set_dependency_invalidates_unaffected wasmSandboxObligation
    .boundsCheckEnforced false (by simp [wasmSandboxObligation])

end DeterministicEngineering.Threat.WasmSandboxConfinement

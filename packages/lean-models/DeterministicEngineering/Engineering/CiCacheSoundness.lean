/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Order
import DeterministicEngineering.Core.Budget

/-!
# CI/CD Scientific Caching & Subdomain Sharding LeanPoo Refinement (`Engineering.CiCacheSoundness`, SM18)

Objectified `LeanPoo` domain module proving:
1. Hermetic cryptographic `ActionKey` soundness (`sm18_cas_soundness_no_false_hit`),
   parallel subdomain shard namespace conflict freedom (`sm18_disjoint_shard_conflict_freedom`),
   and active-set cache quota watermark bounding (`sm18_active_set_gc_bounds_cache_watermark`).
2. `LeanPoo.Functional.ObjectContract.refine` specialization from generic CAS soundness to
   GitHub Actions two-layer sharded caching (`githubActionsShardedCasContract`).
3. `LeanPoo.Proof.Patch` + `LeanPoo.Proof.reuse` / `LeanPoo.Proof.close` certificate
   transport across worker concurrency tuning, plus negative control proving that dropping
   engine digest binding invalidates certificate reuse.
-/

namespace DeterministicEngineering.Engineering.CiCacheSoundness

open LeanPoo.Functional.ObjectContract
open LeanPoo.Functional.ObjectDiagnostics

/-! ## 1. Unbounded Algebraic CAS Soundness, Shard Disjointness & Quota GC Laws -/

structure CiActionKey where
  engineDigest : Nat
  flagsDigest : Nat
  sourceDigest : Nat
  deriving DecidableEq

def CiActionKey.matches (stored current : CiActionKey) : Bool :=
  decide (stored = current)

/-- Exact cryptographic ActionKey matching guarantees zero stale cache hits:
whenever ANY component (engine/toolchain fingerprint, CLI flags, or transitive
source closure) diverges, `CiActionKey.matches` returns `false`. -/
theorem sm18_cas_soundness_no_false_hit
    (stored current : CiActionKey)
    (hDiff :
      stored.engineDigest ≠ current.engineDigest ∨
      stored.flagsDigest ≠ current.flagsDigest ∨
      stored.sourceDigest ≠ current.sourceDigest) :
    CiActionKey.matches stored current = false := by
  unfold CiActionKey.matches
  have hNeq : stored ≠ current := by
    intro hEq
    subst hEq
    rcases hDiff with h1 | h2 | h3
    · exact h1 rfl
    · exact h2 rfl
    · exact h3 rfl
  simp [hNeq]

/-- Partitioning CI cache keys by subdomain shard (`shardId × actionHash`)
guarantees strict namespace disjointness across arbitrary parallel shards:
two jobs belonging to distinct shards can never collide on a cache key. -/
theorem sm18_disjoint_shard_conflict_freedom
    (shardA shardB hashA hashB : Nat)
    (hDistinct : shardA ≠ shardB) :
    (shardA, hashA) ≠ (shardB, hashB) := by
  intro hEq
  injection hEq with hShard _
  exact hDistinct hShard

structure CiCacheWatermark where
  maxEntries : Nat
  retainedEntries : Nat

def CiCacheWatermark.saveWithActiveSetGc
    (c : CiCacheWatermark) (activeUnits : Nat) : CiCacheWatermark :=
  { c with retainedEntries := min c.maxEntries activeUnits }

def CiCacheWatermark.runCycles
    (c : CiCacheWatermark) : List Nat → CiCacheWatermark
  | [] => c
  | activeUnits :: rest => (c.saveWithActiveSetGc activeUnits).runCycles rest

/-- Active-set garbage collection on cache save bounds retained cache entries to
`≤ maxEntries` across arbitrary sequences of CI commits and PR rebuild cycles,
preventing unbounded 10 GiB quota ratchet eviction thrashing. -/
theorem sm18_active_set_gc_bounds_cache_watermark
    (c : CiCacheWatermark)
    (hInit : c.retainedEntries ≤ c.maxEntries)
    (cycles : List Nat) :
    let out := c.runCycles cycles
    out.retainedEntries ≤ out.maxEntries ∧ out.maxEntries = c.maxEntries := by
  induction cycles generalizing c with
  | nil => exact ⟨hInit, rfl⟩
  | cons hd tl ih =>
    dsimp [CiCacheWatermark.runCycles, CiCacheWatermark.saveWithActiveSetGc]
    exact ih _ (Nat.min_le_left _ _)

/-! ## 2. LeanPoo `ObjectContract.refine` for GitHub Actions Sharded Two-Layer Caching -/

structure CiCacheConfig where
  hermeticActionKey : Bool
  disjointShardNamespaces : Bool
  activeSetGcBounded : Bool
  failNeverCached : Bool
  shaPinnedActions : Bool
  shardInTransportKey : Bool
  engineHashInRestorePrefix : Bool
  deriving DecidableEq, Repr

inductive CiCacheConfigKey where
  | hermeticActionKey
  | disjointShardNamespaces
  | activeSetGcBounded
  | failNeverCached
  | shaPinnedActions
  | shardInTransportKey
  | engineHashInRestorePrefix
  deriving DecidableEq, Repr

inductive CiCacheIssue where
  | underSpecifiedActionKey
  | crossShardWriteConflict
  | unboundedCacheRatchet
  | cachedFailureVerdict
  | unsafeGithubActionsCacheWiring
  deriving DecidableEq, Repr

private def ciCacheView : View CiCacheConfig CiCacheConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base CI/CD CAS contract: requires hermetic ActionKey, disjoint shard namespaces,
active-set GC ceiling, and non-caching of failures. -/
def baseCiCasContract : Contract CiCacheConfig CiCacheConfigKey Unit CiCacheIssue where
  view := ciCacheView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.hermeticActionKey then [] else [.rejected path .underSpecifiedActionKey]) ++
    (if cfg.disjointShardNamespaces then [] else [.rejected path .crossShardWriteConflict]) ++
    (if cfg.activeSetGcBounded then [] else [.rejected path .unboundedCacheRatchet]) ++
    (if cfg.failNeverCached then [] else [.rejected path .cachedFailureVerdict])
  validInventory := Or.inl rfl

/-- GitHub Actions specialization refined via `LeanPoo.Functional.ObjectContract.refine`:
adds full SHA-pinned actions, shard-qualified transport keys, and engine-hash restore prefixes. -/
def githubActionsShardedCasContract :
    Contract CiCacheConfig CiCacheConfigKey Unit CiCacheIssue :=
  refine baseCiCasContract fun cfg path =>
    if cfg.shaPinnedActions && cfg.shardInTransportKey && cfg.engineHashInRestorePrefix then []
    else [.rejected path .unsafeGithubActionsCacheWiring]

/-- Monotonic strengthening: GitHub Actions refinement preserves every base rejection. -/
theorem githubActionsShardedCas_preserves_rejection
    (cfg : CiCacheConfig) (path : List CiCacheConfigKey)
    (hRej : diagnose baseCiCasContract cfg path ≠ []) :
    diagnose githubActionsShardedCasContract cfg path ≠ [] :=
  refine_preserves_rejection baseCiCasContract _ cfg path hRej

/-- Exact acceptance characterization for `githubActionsShardedCasContract`. -/
theorem githubActionsShardedCas_accepts_iff
    (cfg : CiCacheConfig) (path : List CiCacheConfigKey) :
    diagnose githubActionsShardedCasContract cfg path = [] ↔
      diagnose baseCiCasContract cfg path = [] ∧
      (if cfg.shaPinnedActions && cfg.shardInTransportKey && cfg.engineHashInRestorePrefix then []
       else [Issue.rejected path CiCacheIssue.unsafeGithubActionsCacheWiring]) = [] :=
  refine_accepts_iff baseCiCasContract _ cfg path

/-! ## 3. Dependency-Certified Proof Transport (`LeanPoo.Proof.Reuse`) -/

inductive CiCasProofKey where
  | engineDigestBound
  | flagsDigestBound
  | sourceDigestBound
  | shardDisjoint
  | activeSetGc
  | workerConcurrency
  deriving DecidableEq

abbrev CiCasProofValue : CiCasProofKey → Type
  | .engineDigestBound => Bool
  | .flagsDigestBound => Bool
  | .sourceDigestBound => Bool
  | .shardDisjoint => Bool
  | .activeSetGc => Bool
  | .workerConcurrency => Nat

/-- CAS soundness depends ONLY on cryptographic key completeness, shard disjointness, and GC,
never on runner worker concurrency. -/
def casSoundnessObligation : LeanPoo.Proof.Obligation CiCasProofKey CiCasProofValue where
  dependencies :=
    [.engineDigestBound, .flagsDigestBound, .sourceDigestBound, .shardDisjoint, .activeSetGc]
  holds := fun s =>
    s .engineDigestBound = true ∧
    s .flagsDigestBound = true ∧
    s .sourceDigestBound = true ∧
    s .shardDisjoint = true ∧
    s .activeSetGc = true
  stable := by
    intro before after same holds
    have h1 : before .engineDigestBound = after .engineDigestBound := same .engineDigestBound (by simp)
    have h2 : before .flagsDigestBound = after .flagsDigestBound := same .flagsDigestBound (by simp)
    have h3 : before .sourceDigestBound = after .sourceDigestBound := same .sourceDigestBound (by simp)
    have h4 : before .shardDisjoint = after .shardDisjoint := same .shardDisjoint (by simp)
    have h5 : before .activeSetGc = after .activeSetGc := same .activeSetGc (by simp)
    simpa [h1, h2, h3, h4, h5] using holds

def baselineCiPipeline : LeanPoo.Proof.ProofObject CiCasProofKey CiCasProofValue where
  state := fun
    | .engineDigestBound => true
    | .flagsDigestBound => true
    | .sourceDigestBound => true
    | .shardDisjoint => true
    | .activeSetGc => true
    | .workerConcurrency => 4
  obligations := [casSoundnessObligation]

theorem baselineCiPipelineCertified : LeanPoo.Proof.Certificate baselineCiPipeline := by
  intro obligation member
  have hEq : obligation = casSoundnessObligation := by simpa [baselineCiPipeline] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- Scaling runner concurrency from 4 to 8 workers does not touch any CAS soundness dependency. -/
def workerScalingPatch : LeanPoo.Proof.Patch CiCasProofKey CiCasProofValue :=
  LeanPoo.Proof.Patch.set .workerConcurrency 8

theorem casSoundnessUntouchedByWorkerScaling :
    LeanPoo.Proof.unaffected casSoundnessObligation workerScalingPatch := by
  intro key dep touched
  have hKey : key = .workerConcurrency := by
    simpa [workerScalingPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [casSoundnessObligation] at dep

theorem casSoundness_transported_across_worker_scaling :
    casSoundnessObligation.holds
      (LeanPoo.Proof.append baselineCiPipeline workerScalingPatch).state :=
  LeanPoo.Proof.reuse baselineCiPipeline workerScalingPatch baselineCiPipelineCertified
    casSoundnessObligation (by simp [baselineCiPipeline]) casSoundnessUntouchedByWorkerScaling

theorem workerScaledPipelineCertified :
    LeanPoo.Proof.Certificate (LeanPoo.Proof.append baselineCiPipeline workerScalingPatch) := by
  apply LeanPoo.Proof.close baselineCiPipeline workerScalingPatch baselineCiPipelineCertified
  · intro obligation member affected
    have hEq : obligation = casSoundnessObligation := by simpa [baselineCiPipeline] using member
    subst obligation
    exact False.elim (affected casSoundnessUntouchedByWorkerScaling)
  · intro obligation member
    simp [workerScalingPatch, LeanPoo.Proof.Patch.set] at member

/-- Negative control: omitting engine/toolchain digest from the ActionKey invalidates reuse. -/
def omitEngineDigestPatch : LeanPoo.Proof.Patch CiCasProofKey CiCasProofValue :=
  LeanPoo.Proof.Patch.set .engineDigestBound false

theorem omitEngineDigest_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected casSoundnessObligation omitEngineDigestPatch := by
  intro hUnaffected
  exact hUnaffected .engineDigestBound (by simp [casSoundnessObligation])
    (by simp [omitEngineDigestPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.CiCacheSoundness

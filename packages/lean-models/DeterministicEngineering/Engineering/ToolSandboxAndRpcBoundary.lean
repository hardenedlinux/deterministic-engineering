/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.MerkleConsistencyAndAsyncCut

/-!
# LeanPoo Unbounded MCP / Tool-Sandbox & RPC Schema-Boundary Safety (`B11`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `MerkleConsistencyAndAsyncCut` (all 9 prior modules, 106 theorems)
and adds 10 machine-checked theorems defending AI Agent MCP / RPC tool boundaries,
bringing the pure `LeanPoo` library to **116 theorems across 10 modules**.

Machine-checked theorems (10 total -> **116 theorems across 10 modules**, zero `sorry`, zero custom axioms):
1. `unpinned_shadow_tool_always_refused` — unregistered / shadow tool invocation always blocked
2. `mcp_schema_rug_pull_always_refused` — mutated MCP tool schema hash always blocked
3. `sandbox_scope_escalation_always_refused` — requesting egress/fs scope outside allowed list blocked
4. `side_effecting_tool_without_idempotency_key_refused` — non-idempotent side-effecting call blocked
5. `ambiguous_rpc_timeout_blocks_blind_retry` — unreconciled RPC timeout or invalid sandbox cap blocks retry
6. `oversized_or_untagged_tool_output_refused` — response exceeding byte cap or lacking untrusted taint blocked
7. `tool_response_admit_iff_bounded_and_tainted` — exact iff characterization of tool response firewall
8. `toolSandboxContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` tool host)
9. `rpcLogSampleRateTuning_preserves_toolSandbox_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingSchemaPinning_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Unbounded MCP Tool Manifest Pinning, Sandbox Confinement & Response Firewall (`B11`) -/

section ToolSandboxRpc

structure PinnedToolManifest (ToolId SchemaHash Scope : Type) where
  toolId : ToolId
  pinnedSchemaHash : SchemaHash
  allowedScopes : List Scope
  maxOutputBytes : Nat
  isSideEffecting : Bool
  deriving DecidableEq, Repr

structure ToolInvocation (ToolId SchemaHash Scope : Type) where
  toolId : ToolId
  observedSchemaHash : SchemaHash
  requestedScopes : List Scope
  idempotencyKeyPresent : Bool
  hasUnreconciledTimeout : Bool
  sandboxCapValid : Bool
  deriving DecidableEq, Repr

structure ToolResponse where
  outputBytes : Nat
  taintTaggedAsUntrusted : Bool
  deriving DecidableEq, Repr

def entryMatchesInvocation [DecidableEq ToolId] [DecidableEq SchemaHash] [DecidableEq Scope]
    (entry : PinnedToolManifest ToolId SchemaHash Scope)
    (inv : ToolInvocation ToolId SchemaHash Scope) : Bool :=
  decide (entry.toolId = inv.toolId) &&
  decide (entry.pinnedSchemaHash = inv.observedSchemaHash) &&
  inv.requestedScopes.all (fun s => decide (s ∈ entry.allowedScopes)) &&
  (!entry.isSideEffecting || inv.idempotencyKeyPresent)

/-- Complete MCP / RPC tool invocation admissibility gate matching
    `DeterministicToolSandboxEngine.invokeTool`. -/
def toolCallAdmitted [DecidableEq ToolId] [DecidableEq SchemaHash] [DecidableEq Scope]
    (manifest : List (PinnedToolManifest ToolId SchemaHash Scope))
    (inv : ToolInvocation ToolId SchemaHash Scope) : Bool :=
  inv.sandboxCapValid &&
  !inv.hasUnreconciledTimeout &&
  manifest.any (fun e => entryMatchesInvocation e inv)

/-- Tool response firewall matching `B7` DIFC taint confinement + output-size ceiling. -/
def toolResponseAdmitted (maxOutputBytes : Nat) (resp : ToolResponse) : Bool :=
  decide (resp.outputBytes ≤ maxOutputBytes) && resp.taintTaggedAsUntrusted

/-- **Theorem 1 (Unpinned / Shadow Tool Refusal)**: If `inv.toolId` is absent from the
    pinned `M1` manifest, `toolCallAdmitted` unconditionally returns `false`. -/
theorem unpinned_shadow_tool_always_refused [DecidableEq ToolId] [DecidableEq SchemaHash] [DecidableEq Scope]
    (manifest : List (PinnedToolManifest ToolId SchemaHash Scope))
    (inv : ToolInvocation ToolId SchemaHash Scope)
    (hUnpinned : ∀ e ∈ manifest, e.toolId ≠ inv.toolId) :
    toolCallAdmitted manifest inv = false := by
  have hany : manifest.any (fun e => entryMatchesInvocation e inv) = false := by
    cases h : manifest.any (fun e => entryMatchesInvocation e inv) with
    | false => rfl
    | true =>
      obtain ⟨e, heMem, heMatch⟩ := List.any_eq_true.mp h
      have hne := hUnpinned e heMem
      simp [entryMatchesInvocation, hne] at heMatch
  simp [toolCallAdmitted, hany]

/-- **Theorem 2 (MCP Rug-Pull Schema Mutation Refusal)**: If every pinned manifest entry
    for `inv.toolId` has a different `pinnedSchemaHash ≠ inv.observedSchemaHash`,
    `toolCallAdmitted` unconditionally returns `false`. -/
theorem mcp_schema_rug_pull_always_refused [DecidableEq ToolId] [DecidableEq SchemaHash] [DecidableEq Scope]
    (manifest : List (PinnedToolManifest ToolId SchemaHash Scope))
    (inv : ToolInvocation ToolId SchemaHash Scope)
    (hRugPull : ∀ e ∈ manifest, e.toolId = inv.toolId → e.pinnedSchemaHash ≠ inv.observedSchemaHash) :
    toolCallAdmitted manifest inv = false := by
  have hany : manifest.any (fun e => entryMatchesInvocation e inv) = false := by
    cases h : manifest.any (fun e => entryMatchesInvocation e inv) with
    | false => rfl
    | true =>
      obtain ⟨e, heMem, heMatch⟩ := List.any_eq_true.mp h
      by_cases hId : e.toolId = inv.toolId
      · have hDiff := hRugPull e heMem hId
        simp [entryMatchesInvocation, hDiff] at heMatch
      · simp [entryMatchesInvocation, hId] at heMatch
  simp [toolCallAdmitted, hany]

/-- **Theorem 3 (Sandbox Scope Escalation Refusal)**: If for every matching manifest entry
    there exists a requested scope `s ∉ e.allowedScopes`, `toolCallAdmitted` returns `false`. -/
theorem sandbox_scope_escalation_always_refused [DecidableEq ToolId] [DecidableEq SchemaHash] [DecidableEq Scope]
    (manifest : List (PinnedToolManifest ToolId SchemaHash Scope))
    (inv : ToolInvocation ToolId SchemaHash Scope)
    (hEsc : ∀ e ∈ manifest, e.toolId = inv.toolId → ∃ s ∈ inv.requestedScopes, s ∉ e.allowedScopes) :
    toolCallAdmitted manifest inv = false := by
  have hany : manifest.any (fun e => entryMatchesInvocation e inv) = false := by
    cases h : manifest.any (fun e => entryMatchesInvocation e inv) with
    | false => rfl
    | true =>
      obtain ⟨e, heMem, heMatch⟩ := List.any_eq_true.mp h
      by_cases hId : e.toolId = inv.toolId
      · obtain ⟨s, hsReq, hsNotAllow⟩ := hEsc e heMem hId
        have hallFalse : inv.requestedScopes.all (fun x => decide (x ∈ e.allowedScopes)) = false := by
          cases ha : inv.requestedScopes.all (fun x => decide (x ∈ e.allowedScopes)) with
          | false => rfl
          | true =>
            have hsIn := of_decide_eq_true (List.all_eq_true.mp ha s hsReq)
            exact False.elim (hsNotAllow hsIn)
        simp [entryMatchesInvocation, hallFalse] at heMatch
      · simp [entryMatchesInvocation, hId] at heMatch
  simp [toolCallAdmitted, hany]

/-- **Theorem 4 (Side-Effecting Idempotency Key Enforcement)**: Any side-effecting tool
    invoked without `idempotencyKeyPresent = true` is unconditionally refused. -/
theorem side_effecting_tool_without_idempotency_key_refused
    [DecidableEq ToolId] [DecidableEq SchemaHash] [DecidableEq Scope]
    (manifest : List (PinnedToolManifest ToolId SchemaHash Scope))
    (inv : ToolInvocation ToolId SchemaHash Scope)
    (hNoKey : inv.idempotencyKeyPresent = false)
    (hSideEff : ∀ e ∈ manifest, e.toolId = inv.toolId → e.isSideEffecting = true) :
    toolCallAdmitted manifest inv = false := by
  have hany : manifest.any (fun e => entryMatchesInvocation e inv) = false := by
    cases h : manifest.any (fun e => entryMatchesInvocation e inv) with
    | false => rfl
    | true =>
      obtain ⟨e, heMem, heMatch⟩ := List.any_eq_true.mp h
      by_cases hId : e.toolId = inv.toolId
      · have hEff := hSideEff e heMem hId
        simp [entryMatchesInvocation, hEff, hNoKey] at heMatch
      · simp [entryMatchesInvocation, hId] at heMatch
  simp [toolCallAdmitted, hany]

/-- **Theorem 5 (`PendingUnknownEffect` RPC Timeout & Sandbox Capability Fence)**:
    An unreconciled RPC timeout OR an invalid/revoked `M3` sandbox capability unconditionally
    blocks blind retry (`false`). -/
theorem ambiguous_rpc_timeout_blocks_blind_retry
    [DecidableEq ToolId] [DecidableEq SchemaHash] [DecidableEq Scope]
    (manifest : List (PinnedToolManifest ToolId SchemaHash Scope))
    (inv : ToolInvocation ToolId SchemaHash Scope)
    (hBlocked : inv.hasUnreconciledTimeout = true ∨ inv.sandboxCapValid = false) :
    toolCallAdmitted manifest inv = false := by
  rcases hBlocked with h | h <;> simp [toolCallAdmitted, h]

/-- **Theorem 6 (Response Overflow & Untrusted-Output Laundering Firewall)**:
    Any tool response exceeding `maxOutputBytes` OR missing mandatory `B7` untrusted-taint
    tagging is unconditionally refused. -/
theorem oversized_or_untagged_tool_output_refused
    (maxOutputBytes : Nat) (resp : ToolResponse)
    (hBad : resp.outputBytes > maxOutputBytes ∨ resp.taintTaggedAsUntrusted = false) :
    toolResponseAdmitted maxOutputBytes resp = false := by
  rcases hBad with hOver | hUntagged
  · have hNotLe : ¬ (resp.outputBytes ≤ maxOutputBytes) := by omega
    simp [toolResponseAdmitted, hNotLe]
  · simp [toolResponseAdmitted, hUntagged]

/-- **Theorem 7 (Exact Sound & Complete Tool Response Firewall Characterization)**:
    `toolResponseAdmitted maxOutputBytes resp = true` iff bounded size and untrusted-taint tagged. -/
theorem tool_response_admit_iff_bounded_and_tainted
    (maxOutputBytes : Nat) (resp : ToolResponse) :
    toolResponseAdmitted maxOutputBytes resp = true ↔
      resp.outputBytes ≤ maxOutputBytes ∧ resp.taintTaggedAsUntrusted = true := by
  simp [toolResponseAdmitted]

end ToolSandboxRpc

/-! ## Section 2: LeanPoo Two-Step Refinement (`Tool Sandbox -> Response Firewall -> cedar-poo-spec Tool Host`) & `Core.Transport` -/

section LeanPooToolSandboxContract

structure ToolSandboxConfig where
  mcpSchemaPinningEnforced : Bool
  sandboxScopeConfinementEnforced : Bool
  rpcTimeoutFenceEnforced : Bool
  responseSizeAndTaintEnforced : Bool
  deriving DecidableEq, Repr

inductive ToolSandboxKey where
  | mcpSchemaPinningEnforced
  | sandboxScopeConfinementEnforced
  | rpcTimeoutFenceEnforced
  | responseSizeAndTaintEnforced
  deriving DecidableEq, Repr

inductive ToolSandboxIssue where
  | mcpRugPullUnchecked
  | sandboxEscapeAllowed
  | blindRpcRetryAllowed
  | untrustedResponseLaundered
  deriving DecidableEq, Repr

private def toolSandboxView : View ToolSandboxConfig ToolSandboxKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseToolSandboxContract :
    Contract ToolSandboxConfig ToolSandboxKey Unit ToolSandboxIssue where
  view := toolSandboxView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.mcpSchemaPinningEnforced then [] else [.rejected path .mcpRugPullUnchecked]) ++
    (if cfg.sandboxScopeConfinementEnforced then [] else [.rejected path .sandboxEscapeAllowed]) ++
    (if cfg.rpcTimeoutFenceEnforced then [] else [.rejected path .blindRpcRetryAllowed])
  validInventory := Or.inl rfl

def toolResponseFirewallExt (cfg : ToolSandboxConfig) (path : List ToolSandboxKey) :
    List (Issue ToolSandboxKey ToolSandboxIssue) :=
  if cfg.responseSizeAndTaintEnforced then [] else [.rejected path .untrustedResponseLaundered]

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Tool Authorization Host)**:
    Layering response-size/taint firewalling AND ANY downstream `cedar-poo-spec` tool policy
    extension `hostToolExt` onto `baseToolSandboxContract` monotonically preserves every
    MCP/RPC sandbox rejection. -/
theorem toolSandboxContract_preserves_rejection
    (hostToolExt : ToolSandboxConfig → List ToolSandboxKey →
      List (Issue ToolSandboxKey ToolSandboxIssue))
    (cfg : ToolSandboxConfig) (path : List ToolSandboxKey)
    (hRej : diagnose baseToolSandboxContract cfg path ≠ []) :
    diagnose (refine (refine baseToolSandboxContract toolResponseFirewallExt) hostToolExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseToolSandboxContract toolResponseFirewallExt hostToolExt cfg path hRej

inductive ToolSandboxProofKey where
  | mcpSchemaPinningEnforced
  | sandboxScopeConfinementEnforced
  | rpcTimeoutFenceEnforced
  | responseSizeAndTaintEnforced
  | rpcTraceSampleRatePct
  deriving DecidableEq

abbrev ToolSandboxProofValue : ToolSandboxProofKey → Type
  | .mcpSchemaPinningEnforced => Bool
  | .sandboxScopeConfinementEnforced => Bool
  | .rpcTimeoutFenceEnforced => Bool
  | .responseSizeAndTaintEnforced => Bool
  | .rpcTraceSampleRatePct => Nat

def toolSandboxObligation :
    LeanPoo.Proof.Obligation ToolSandboxProofKey ToolSandboxProofValue where
  dependencies :=
    [ .mcpSchemaPinningEnforced
    , .sandboxScopeConfinementEnforced
    , .rpcTimeoutFenceEnforced
    , .responseSizeAndTaintEnforced
    ]
  holds := fun s =>
    s .mcpSchemaPinningEnforced = true ∧
    s .sandboxScopeConfinementEnforced = true ∧
    s .rpcTimeoutFenceEnforced = true ∧
    s .responseSizeAndTaintEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .mcpSchemaPinningEnforced (by simp)).symm.trans h1,
           (same .sandboxScopeConfinementEnforced (by simp)).symm.trans h2,
           (same .rpcTimeoutFenceEnforced (by simp)).symm.trans h3,
           (same .responseSizeAndTaintEnforced (by simp)).symm.trans h4⟩

def baselineToolSandboxSystem :
    LeanPoo.Proof.ProofObject ToolSandboxProofKey ToolSandboxProofValue where
  state := fun
    | .mcpSchemaPinningEnforced => true
    | .sandboxScopeConfinementEnforced => true
    | .rpcTimeoutFenceEnforced => true
    | .responseSizeAndTaintEnforced => true
    | .rpcTraceSampleRatePct => 10
  obligations := [toolSandboxObligation]

theorem baselineToolSandboxCertified :
    LeanPoo.Proof.Certificate baselineToolSandboxSystem := by
  intro ob hMem
  have hEq : ob = toolSandboxObligation := by simpa [baselineToolSandboxSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.rpcTraceSampleRatePct` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem rpcLogSampleRateTuning_preserves_toolSandbox_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineToolSandboxSystem
        (LeanPoo.Proof.Patch.set .rpcTraceSampleRatePct 25)) :=
  close_single_set_untouched baselineToolSandboxSystem toolSandboxObligation
    .rpcTraceSampleRatePct 25 rfl baselineToolSandboxCertified
    (by simp [toolSandboxObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.mcpSchemaPinningEnforced` ALWAYS invalidates reuse. -/
theorem disablingSchemaPinning_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected toolSandboxObligation
        (LeanPoo.Proof.Patch.set .mcpSchemaPinningEnforced false) :=
  set_dependency_invalidates_unaffected toolSandboxObligation
    .mcpSchemaPinningEnforced false (by simp [toolSandboxObligation])

end LeanPooToolSandboxContract

end DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary

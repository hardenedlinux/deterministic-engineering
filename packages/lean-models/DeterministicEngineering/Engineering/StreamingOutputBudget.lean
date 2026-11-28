/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Budget

/-!
# Streaming LLM & HTTP Output Budget LeanPoo Refinement (`Engineering.StreamingOutputBudget`, SM17)

Objectified `LeanPoo` domain module proving:
1. Unbounded pre-allocation budget conservation across arbitrary interleaved visible-text
   and hidden-thinking stream traces (`sm17_precheck_stream_budget_invariant`), zero-allocation
   oversized `Content-Length` rejection (`sm17_declared_header_oversize_zero_allocation`),
   and fail-closed buffer release (`sm17_overflow_chunk_terminates_and_releases`).
2. `LeanPoo.Functional.ObjectContract.refine` specialization from generic streaming budget
   enforcement to Marlin Weaver SSE + OpenAI HTTP chunked-stream gateway symmetry.
3. `LeanPoo.Proof.Patch` + `LeanPoo.Proof.reuse` / `LeanPoo.Proof.close` certificate
   transport across chunk-size tuning, plus negative control showing thinking-accounting
   regression invalidates reuse.
-/

namespace DeterministicEngineering.Engineering.StreamingOutputBudget

open LeanPoo.Functional.ObjectContract
open LeanPoo.Functional.ObjectDiagnostics

/-! ## 1. Unbounded Algebraic Stream Budget Invariants -/

structure StreamBudgetState where
  budgetLimit : Nat
  streamOpen : Bool
  textBytes : Nat
  thinkingBytes : Nat
  peakRetained : Nat
  overflowRefusals : Nat

def StreamBudgetState.consumeBounded (s : StreamBudgetState) (isThinking : Bool) (delta : Nat) :
    StreamBudgetState :=
  if !s.streamOpen then
    s
  else if s.textBytes + s.thinkingBytes + delta ≤ s.budgetLimit then
    let nextTotal := s.textBytes + s.thinkingBytes + delta
    { s with
      textBytes := if isThinking then s.textBytes else s.textBytes + delta
      thinkingBytes := if isThinking then s.thinkingBytes + delta else s.thinkingBytes
      peakRetained := max s.peakRetained nextTotal }
  else
    { s with
      streamOpen := false
      textBytes := 0
      thinkingBytes := 0
      overflowRefusals := s.overflowRefusals + 1 }

def StreamBudgetState.consumeTrace (s : StreamBudgetState) :
    List (Bool × Nat) → StreamBudgetState
  | [] => s
  | (isThinking, delta) :: rest =>
      (s.consumeBounded isThinking delta).consumeTrace rest

def StreamBudgetState.rejectDeclaredOversize (s : StreamBudgetState) (declaredLen : Nat) :
    StreamBudgetState :=
  if declaredLen > s.budgetLimit then
    { s with
      streamOpen := false
      textBytes := 0
      thinkingBytes := 0
      overflowRefusals := s.overflowRefusals + 1 }
  else
    { s with
      streamOpen := true
      textBytes := 0
      thinkingBytes := 0 }

/-- Across arbitrary interleaved visible-text and hidden-thinking stream deltas of
arbitrary byte sizes, pre-allocation budget checks keep `textBytes + thinkingBytes ≤ budgetLimit`,
prevent check-after-buffering peak overshoot (`peakRetained ≤ budgetLimit`), and release all
retained bytes upon closure or overflow refusal. -/
theorem sm17_precheck_stream_budget_invariant
    (s : StreamBudgetState)
    (hUsed : s.textBytes + s.thinkingBytes ≤ s.budgetLimit)
    (hPeak : s.peakRetained ≤ s.budgetLimit)
    (hClosed : s.streamOpen = false → s.textBytes = 0 ∧ s.thinkingBytes = 0)
    (chunks : List (Bool × Nat)) :
    let out := s.consumeTrace chunks
    out.textBytes + out.thinkingBytes ≤ out.budgetLimit ∧
      out.peakRetained ≤ out.budgetLimit ∧
      (out.streamOpen = false → out.textBytes = 0 ∧ out.thinkingBytes = 0) ∧
      out.budgetLimit = s.budgetLimit := by
  induction chunks generalizing s with
  | nil =>
    exact ⟨hUsed, hPeak, hClosed, rfl⟩
  | cons hd tl ih =>
    rcases hd with ⟨isThinking, delta⟩
    dsimp [StreamBudgetState.consumeTrace, StreamBudgetState.consumeBounded]
    cases hOpen : s.streamOpen
    · simp only [Bool.not_false, ↓reduceIte]
      exact ih s hUsed hPeak hClosed
    · simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      by_cases hFit : s.textBytes + s.thinkingBytes + delta ≤ s.budgetLimit
      · simp only [hFit, ↓reduceIte]
        have hNextUsed :
            (if isThinking then s.textBytes else s.textBytes + delta) +
            (if isThinking then s.thinkingBytes + delta else s.thinkingBytes) ≤ s.budgetLimit := by
          cases isThinking <;> simp <;> omega
        have hNextPeak :
            max s.peakRetained (s.textBytes + s.thinkingBytes + delta) ≤ s.budgetLimit :=
          Nat.max_le.mpr ⟨hPeak, hFit⟩
        have hNextClosed :
            true = false →
              (if isThinking then s.textBytes else s.textBytes + delta) = 0 ∧
              (if isThinking then s.thinkingBytes + delta else s.thinkingBytes) = 0 := by
          intro hAbsurd
          cases hAbsurd
        exact ih _ hNextUsed hNextPeak hNextClosed
      · simp only [hFit, ↓reduceIte]
        have hZeroUsed : 0 + 0 ≤ s.budgetLimit := Nat.zero_le _
        have hZeroClosed : false = false → 0 = 0 ∧ 0 = 0 := fun _ => ⟨rfl, rfl⟩
        exact ih _ hZeroUsed hPeak hZeroClosed

/-- Oversized `Content-Length` header rejection opens no stream and allocates zero payload bytes. -/
theorem sm17_declared_header_oversize_zero_allocation
    (s : StreamBudgetState)
    (hPeakZero : s.peakRetained = 0)
    (declaredLen : Nat)
    (hOver : declaredLen > s.budgetLimit) :
    let out := s.rejectDeclaredOversize declaredLen
    out.streamOpen = false ∧
      out.textBytes = 0 ∧
      out.thinkingBytes = 0 ∧
      out.peakRetained = 0 ∧
      out.overflowRefusals = s.overflowRefusals + 1 := by
  simp [StreamBudgetState.rejectDeclaredOversize, hOver, hPeakZero]

/-- Overflow chunk refusal immediately closes the stream, releases all buffered bytes,
and turns every subsequent trailing chunk into a no-op. -/
theorem sm17_overflow_chunk_terminates_and_releases
    (s : StreamBudgetState)
    (hOpen : s.streamOpen = true)
    (isThinking : Bool)
    (delta : Nat)
    (hOver : s.textBytes + s.thinkingBytes + delta > s.budgetLimit)
    (trailing : List (Bool × Nat)) :
    let afterRefusal := s.consumeBounded isThinking delta
    let finalState := afterRefusal.consumeTrace trailing
    finalState.streamOpen = false ∧
      finalState.textBytes = 0 ∧
      finalState.thinkingBytes = 0 ∧
      finalState.peakRetained = s.peakRetained ∧
      finalState.overflowRefusals = s.overflowRefusals + 1 := by
  have hNotLe : ¬ (s.textBytes + s.thinkingBytes + delta ≤ s.budgetLimit) := by omega
  have hStep :
      s.consumeBounded isThinking delta =
        { s with
          streamOpen := false
          textBytes := 0
          thinkingBytes := 0
          overflowRefusals := s.overflowRefusals + 1 } := by
    dsimp [StreamBudgetState.consumeBounded]
    simp only [hOpen, Bool.not_true, Bool.false_eq_true, ↓reduceIte, hNotLe]
  dsimp only
  rw [hStep]
  generalize hInit :
    ({ s with
        streamOpen := false
        textBytes := 0
        thinkingBytes := 0
        overflowRefusals := s.overflowRefusals + 1 } : StreamBudgetState) = closedState
  have hFields :
      closedState.streamOpen = false ∧
        closedState.textBytes = 0 ∧
        closedState.thinkingBytes = 0 ∧
        closedState.peakRetained = s.peakRetained ∧
        closedState.overflowRefusals = s.overflowRefusals + 1 := by
    rw [← hInit]
    exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  clear hInit hStep hNotLe hOver hOpen
  induction trailing with
  | nil => exact hFields
  | cons hd tl ih =>
    rcases hd with ⟨b, d⟩
    dsimp [StreamBudgetState.consumeTrace, StreamBudgetState.consumeBounded]
    simp only [hFields.1, Bool.not_false, ↓reduceIte]
    exact ih

/-! ## 2. LeanPoo `ObjectContract.refine` for Marlin Weaver SSE + HTTP Budget Symmetry -/

structure StreamGatewayConfig where
  precheckBeforeBuffer : Bool
  accountThinkingBytes : Bool
  sseCompleteParity : Bool
  httpHeaderFailFast : Bool
  incrementalChunkReader : Bool
  deriving DecidableEq, Repr

inductive StreamConfigKey where
  | precheckBeforeBuffer
  | accountThinkingBytes
  | sseCompleteParity
  | httpHeaderFailFast
  | incrementalChunkReader
  deriving DecidableEq, Repr

inductive StreamBudgetIssue where
  | checkAfterBuffering
  | unaccountedThinkingFlood
  | sseCompleteBudgetBypass
  | missingHttpStreamingGuard
  deriving DecidableEq, Repr

private def streamConfigView : View StreamGatewayConfig StreamConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base streaming output budget contract: requires pre-allocation cap check,
thinking-channel accounting, and SSE completion parity. -/
def baseStreamBudgetContract : Contract StreamGatewayConfig StreamConfigKey Unit StreamBudgetIssue where
  view := streamConfigView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.precheckBeforeBuffer then [] else [.rejected path .checkAfterBuffering]) ++
    (if cfg.accountThinkingBytes then [] else [.rejected path .unaccountedThinkingFlood]) ++
    (if cfg.sseCompleteParity then [] else [.rejected path .sseCompleteBudgetBypass])
  validInventory := Or.inl rfl

/-- Marlin Weaver SSE + OpenAI HTTP refinement via `LeanPoo.Functional.ObjectContract.refine`. -/
def marlinHttpSseBudgetContract :
    Contract StreamGatewayConfig StreamConfigKey Unit StreamBudgetIssue :=
  refine baseStreamBudgetContract fun cfg path =>
    if cfg.httpHeaderFailFast && cfg.incrementalChunkReader then []
    else [.rejected path .missingHttpStreamingGuard]

/-- Monotonic strengthening: Marlin HTTP/SSE refinement preserves every base rejection. -/
theorem marlinHttpSse_preserves_rejection (cfg : StreamGatewayConfig) (path : List StreamConfigKey)
    (hRej : diagnose baseStreamBudgetContract cfg path ≠ []) :
    diagnose marlinHttpSseBudgetContract cfg path ≠ [] :=
  refine_preserves_rejection baseStreamBudgetContract _ cfg path hRej

/-- Exact acceptance characterization for `marlinHttpSseBudgetContract`. -/
theorem marlinHttpSse_accepts_iff (cfg : StreamGatewayConfig) (path : List StreamConfigKey) :
    diagnose marlinHttpSseBudgetContract cfg path = [] ↔
      diagnose baseStreamBudgetContract cfg path = [] ∧
      (if cfg.httpHeaderFailFast && cfg.incrementalChunkReader then []
       else [Issue.rejected path StreamBudgetIssue.missingHttpStreamingGuard]) = [] :=
  refine_accepts_iff baseStreamBudgetContract _ cfg path

/-! ## 3. Dependency-Certified Proof Transport (`LeanPoo.Proof.Reuse`) -/

inductive StreamProofKey where
  | precheckBeforeBuffer
  | accountThinkingBytes
  | sseCompleteParity
  | maxChunkBytes
  deriving DecidableEq

abbrev StreamProofValue : StreamProofKey → Type
  | .precheckBeforeBuffer => Bool
  | .accountThinkingBytes => Bool
  | .sseCompleteParity => Bool
  | .maxChunkBytes => Nat

def streamBudgetObligation : LeanPoo.Proof.Obligation StreamProofKey StreamProofValue where
  dependencies := [.precheckBeforeBuffer, .accountThinkingBytes, .sseCompleteParity]
  holds := fun s =>
    s .precheckBeforeBuffer = true ∧ s .accountThinkingBytes = true ∧ s .sseCompleteParity = true
  stable := by
    intro before after same holds
    have h1 : before .precheckBeforeBuffer = after .precheckBeforeBuffer :=
      same .precheckBeforeBuffer (by simp)
    have h2 : before .accountThinkingBytes = after .accountThinkingBytes :=
      same .accountThinkingBytes (by simp)
    have h3 : before .sseCompleteParity = after .sseCompleteParity :=
      same .sseCompleteParity (by simp)
    simpa [h1, h2, h3] using holds

def baselineStreamGateway : LeanPoo.Proof.ProofObject StreamProofKey StreamProofValue where
  state := fun
    | .precheckBeforeBuffer => true
    | .accountThinkingBytes => true
    | .sseCompleteParity => true
    | .maxChunkBytes => 65536
  obligations := [streamBudgetObligation]

theorem baselineStreamGatewayCertified : LeanPoo.Proof.Certificate baselineStreamGateway := by
  intro obligation member
  have hEq : obligation = streamBudgetObligation := by simpa [baselineStreamGateway] using member
  subst obligation
  exact ⟨rfl, rfl, rfl⟩

/-- Tuning chunk framing size (`64 KiB` -> `16 KiB`) leaves safety obligations unaffected. -/
def chunkSizeTuningPatch : LeanPoo.Proof.Patch StreamProofKey StreamProofValue :=
  LeanPoo.Proof.Patch.set .maxChunkBytes 16384

theorem streamBudgetUntouchedByChunkTuning :
    LeanPoo.Proof.unaffected streamBudgetObligation chunkSizeTuningPatch := by
  intro key dep touched
  have hKey : key = .maxChunkBytes := by
    simpa [chunkSizeTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [streamBudgetObligation] at dep

theorem streamBudget_transported_across_chunk_tuning :
    streamBudgetObligation.holds
      (LeanPoo.Proof.append baselineStreamGateway chunkSizeTuningPatch).state :=
  LeanPoo.Proof.reuse baselineStreamGateway chunkSizeTuningPatch baselineStreamGatewayCertified
    streamBudgetObligation (by simp [baselineStreamGateway]) streamBudgetUntouchedByChunkTuning

theorem chunkTunedStreamGatewayCertified :
    LeanPoo.Proof.Certificate (LeanPoo.Proof.append baselineStreamGateway chunkSizeTuningPatch) := by
  apply LeanPoo.Proof.close baselineStreamGateway chunkSizeTuningPatch baselineStreamGatewayCertified
  · intro obligation member affected
    have hEq : obligation = streamBudgetObligation := by simpa [baselineStreamGateway] using member
    subst obligation
    exact False.elim (affected streamBudgetUntouchedByChunkTuning)
  · intro obligation member
    simp [chunkSizeTuningPatch, LeanPoo.Proof.Patch.set] at member

/-- Negative control: disabling thinking-channel byte accounting invalidates certificate reuse. -/
def dropThinkingAccountingPatch : LeanPoo.Proof.Patch StreamProofKey StreamProofValue :=
  LeanPoo.Proof.Patch.set .accountThinkingBytes false

theorem dropThinkingAccounting_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected streamBudgetObligation dropThinkingAccountingPatch := by
  intro hUnaffected
  exact hUnaffected .accountThinkingBytes (by simp [streamBudgetObligation])
    (by simp [dropThinkingAccountingPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.StreamingOutputBudget

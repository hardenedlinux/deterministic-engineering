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
# AI Agent Control/Data Segregation & Capability-Based IFC (`Threat.AgentIfcConfinement`)

LeanPoo AI-Security refinement (CaMeL + FIDES dual-LLM control/data segregation and
information-flow control) sharing `Core.Order` (monotonic lattice floors) and
`Core.Transport` (`ObjectContract.refine` + `Patch.frame` + `Proof.reuse`) with zero
duplicated base mathematics.

Orthogonal to Quint (`packages/quint-models/threat/execution/agent-ifc-capability/AgentIfcCapability.qnt`,
which explores finite prompt-injection hijack and confidential-egress countermodels):
this module proves:
1. **Unbounded integrity/confidentiality lattice non-elevation**: combining tainted
   data-plane content with control-plane actions never elevates integrity to trusted
   control authority.
2. **Fail-closed confidential egress**: confidential data never exits to an untrusted
   sink without explicit high-integrity declassification.
3. **Monotonic IFC floor lattice (`Core.Order`)**: joining a child policy onto an
   IFC governance floor never weakens integrity/declassification enforcement.
4. **Two-step LeanPoo `ObjectContract.refine` & one-line `Proof.reuse` (`Core.Transport`)**:
   AI-safe telemetry tuning transports the certificate cleanly, while disabling the
   declassification gate invalidates proof reuse.
-/

namespace DeterministicEngineering.Threat.AgentIfcConfinement

open DeterministicEngineering.Core.Order
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## 1. Unbounded Integrity & Confidentiality Lattice Laws -/

inductive IntegrityLabel where
  | untrustedData
  | trustedControl
  deriving DecidableEq, Repr

inductive ConfidentialityLabel where
  | publicData
  | confidentialSecret
  deriving DecidableEq, Repr

/-- Lattice meet on integrity: any untrusted data input taints the combined label. -/
def IntegrityLabel.meet (a b : IntegrityLabel) : IntegrityLabel :=
  match a with
  | .untrustedData => .untrustedData
  | .trustedControl => b

/-- Whether a tool invocation is permitted under CaMeL/FIDES IFC rules:
    1. Control-plane instruction must be `trustedControl` (not steered by tainted data).
    2. Confidential data may only exit to an untrusted sink if explicitly declassified
       under `trustedControl`. -/
def ifcToolInvokeAdmitted
    (controlIntegrity : IntegrityLabel)
    (payloadConfidentiality : ConfidentialityLabel)
    (explicitDeclassification : Bool) : Bool :=
  match controlIntegrity with
  | .untrustedData => false
  | .trustedControl =>
    match payloadConfidentiality with
    | .publicData => true
    | .confidentialSecret => explicitDeclassification

/-- Theorem 1: Mixing untrusted data-plane content into control flow never yields
    `trustedControl`, unconditionally blocking prompt-injection tool hijacks. -/
theorem taintedData_never_elevates_controlIntegrity (other : IntegrityLabel)
    (payload : ConfidentialityLabel) (declass : Bool) :
    IntegrityLabel.meet .untrustedData other = .untrustedData ∧
    IntegrityLabel.meet other .untrustedData = .untrustedData ∧
    ifcToolInvokeAdmitted (IntegrityLabel.meet .untrustedData other) payload declass = false := by
  refine ⟨rfl, ?_, rfl⟩
  cases other <;> rfl

/-- Theorem 2: Confidential data without explicit high-integrity declassification is
    unconditionally blocked from exiting to any untrusted tool sink. -/
theorem confidentialEgress_blocked_without_declassification (ctrl : IntegrityLabel) :
    ifcToolInvokeAdmitted ctrl .confidentialSecret false = false := by
  cases ctrl <;> rfl

/-- Theorem 3: Joining any child profile onto an IFC governance floor never weakens
    the required Band-5 floor (reusing `Core.Order`). -/
theorem ifcLatticeFloor_join_never_weakens (parent child : GovernanceFloor) :
    parent.le (parent.join child) ∧ child.le (parent.join child) :=
  ⟨join_never_weakens_left parent child, join_never_weakens_right parent child⟩

/-! ## 2. Two-Step LeanPoo `ObjectContract.refine` (reusing `Core.Transport`) -/

structure AgentIfcConfig where
  enforcesControlDataSegregation : Bool
  enforcesDeclassificationGate : Bool
  enforcesQuarantinedDataPlane : Bool
  deriving DecidableEq, Repr

inductive AgentIfcConfigKey where
  | enforcesControlDataSegregation
  | enforcesDeclassificationGate
  | enforcesQuarantinedDataPlane
  deriving DecidableEq, Repr

inductive AgentIfcIssue where
  | missingControlDataSegregation
  | missingDeclassificationGate
  | missingQuarantinedDataPlane
  deriving DecidableEq, Repr

private def agentIfcView : View AgentIfcConfig AgentIfcConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseAgentIfcContract : Contract AgentIfcConfig AgentIfcConfigKey Unit AgentIfcIssue where
  view := agentIfcView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.enforcesControlDataSegregation then [] else [.rejected path .missingControlDataSegregation]
  validInventory := Or.inl rfl

def declassGateExt (cfg : AgentIfcConfig) (path : List AgentIfcConfigKey) :
    List (Issue AgentIfcConfigKey AgentIfcIssue) :=
  if cfg.enforcesDeclassificationGate then [] else [.rejected path .missingDeclassificationGate]

def quarantinedPlaneExt (cfg : AgentIfcConfig) (path : List AgentIfcConfigKey) :
    List (Issue AgentIfcConfigKey AgentIfcIssue) :=
  if cfg.enforcesQuarantinedDataPlane then [] else [.rejected path .missingQuarantinedDataPlane]

def camelFidesContract : Contract AgentIfcConfig AgentIfcConfigKey Unit AgentIfcIssue :=
  refine (refine baseAgentIfcContract declassGateExt) quarantinedPlaneExt

/-- Theorem 4: Two-step CaMeL/FIDES contract refinement monotonically preserves all base rejections. -/
theorem camelFidesContract_preserves_rejection
    (cfg : AgentIfcConfig) (path : List AgentIfcConfigKey)
    (hRej : diagnose baseAgentIfcContract cfg path ≠ []) :
    diagnose camelFidesContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseAgentIfcContract declassGateExt quarantinedPlaneExt cfg path hRej

/-! ## 3. AI-SE Proof Transport via `Core.Transport` -/

inductive AgentIfcProofKey where
  | controlDataSegregationChecked
  | declassificationGateChecked
  | traceBufferCapacity
  deriving DecidableEq

abbrev AgentIfcProofValue : AgentIfcProofKey → Type
  | .controlDataSegregationChecked => Bool
  | .declassificationGateChecked => Bool
  | .traceBufferCapacity => Nat

def ifcSafetyObligation : LeanPoo.Proof.Obligation AgentIfcProofKey AgentIfcProofValue where
  dependencies := [.controlDataSegregationChecked, .declassificationGateChecked]
  holds := fun s => s .controlDataSegregationChecked = true ∧ s .declassificationGateChecked = true
  stable := by
    intro before after same holds
    exact ⟨(same .controlDataSegregationChecked (by simp)).symm.trans holds.1,
           (same .declassificationGateChecked (by simp)).symm.trans holds.2⟩

def baselineAgentIfc : LeanPoo.Proof.ProofObject AgentIfcProofKey AgentIfcProofValue where
  state := fun
    | .controlDataSegregationChecked => true
    | .declassificationGateChecked => true
    | .traceBufferCapacity => 64
  obligations := [ifcSafetyObligation]

theorem baselineAgentIfcCertified : LeanPoo.Proof.Certificate baselineAgentIfc := by
  intro ob hMem
  have hEq : ob = ifcSafetyObligation := by simpa [baselineAgentIfc] using hMem
  subst ob
  exact ⟨rfl, rfl⟩

/-- Theorem 5: AI-safe telemetry buffer tuning transports the IFC safety certificate in 1 line. -/
theorem ifcTelemetryTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineAgentIfc
        (LeanPoo.Proof.Patch.set .traceBufferCapacity 256)) :=
  close_single_set_untouched baselineAgentIfc ifcSafetyObligation
    .traceBufferCapacity 256 rfl baselineAgentIfcCertified (by simp [ifcSafetyObligation])

/-- Theorem 6: Negative control — AI regression disabling the declassification gate invalidates reuse. -/
theorem disableDeclassGate_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected ifcSafetyObligation
        (LeanPoo.Proof.Patch.set .declassificationGateChecked false) :=
  set_dependency_invalidates_unaffected ifcSafetyObligation
    .declassificationGateChecked false (by simp [ifcSafetyObligation])

end DeterministicEngineering.Threat.AgentIfcConfinement

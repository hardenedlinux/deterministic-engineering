// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

// Companion SysML v2 architecture specification for 10.154:
// Multi-Method Fun-Flow Runnable Interface, LeanPoo Package Family,
// ASCENT MR01-MR06 Governance, Requirements/Verification Traceability,
// Fun-Flow Action Workflow, and ProcessTreeReclamation Pilot Slice.
// Design specification only; establishes no build, proof, or runtime acceptance.

package MultiMethodFunFlowArchitecture {
    public import ScalarValues::*;

    doc /* Scope: 10.154 multi-method architecture design draft aligned with 10.150 (organization), 10.151 (Quint library), and 10.153 (defensive-engineering taxonomy & seven-window Yuanxu layering). No execution, proof, or acceptance verdict is claimed. */

    // ── 1. Typed Boundary Payloads (Items) & Ports ──

    item def InputEnvelope {
        attribute subjectId : String;
        attribute profileSelection : String;
        attribute inputDigestClosure : String;
    }

    item def DagRuntimeManifest {
        attribute schema : String = "yuanxu.core.flow-dag-runtime-manifest.v1";
        attribute receiptKind : String = "yuanxu.core.flow-dag-receipt.v1";
        attribute frontierNodes : String;
    }

    item def ItfTraceArtifact {
        attribute producerModel : String;
        attribute seed : String;
        attribute maxSteps : String;
    }

    item def LeanCertificateArtifact {
        attribute leanModule : String;
        attribute zeroSorry : Boolean;
        attribute transportFrameChecked : Boolean;
    }

    item def RawReceipt {
        attribute stepId : String;
        attribute exitCode : Integer;
        attribute artifactDigests : String;
    }

    item def EvidenceRecord {
        attribute obligationId : String;
        attribute methodFamily : String;
        attribute claimKind : String;
        attribute outcome : String;
    }

    item def PremiseWitness {
        attribute premiseId : String;
        attribute supporterStep : String;
        attribute consumerStep : String;
    }

    port def GovernanceGatePort {
        in item envelope : InputEnvelope;
        out item manifest : DagRuntimeManifest;
    }

    port def ManifestExecutionPort {
        in item manifest : DagRuntimeManifest;
        out item receipt : RawReceipt;
    }

    port def EvidenceAdmissionPort {
        in item receipt : RawReceipt;
        out item record : EvidenceRecord;
    }

    port def ArtifactHandoffPort {
        out item itfTrace : ItfTraceArtifact;
    }

    port def ArtifactConsumerPort {
        in item itfTrace : ItfTraceArtifact;
    }

    port def PremiseHandoffPort {
        out item premise : PremiseWitness;
    }

    port def PremiseConsumerPort {
        in item premise : PremiseWitness;
    }

    // ── 2. Extended Physical Package Taxonomy (extends 10.150) ──

    abstract part def VerificationPackagePlacement {
        attribute pathPattern : String;
        attribute ecosystem : String;
        attribute family : String;
        attribute mirror : String;
        attribute allows : String;
        attribute rejects : String;
    }

    part def QuintModelPackage :> VerificationPackagePlacement;
    part def LeanPooModelPackage :> VerificationPackagePlacement;
    part def LanguageSubjectPlacement {
        attribute pathPattern : String;
        attribute ecosystem : String;
        attribute roles : String;
    }

    // ── 3. Orthogonal Method Task Families (Fun-Flow TaskFamilyRegistry) ──

    abstract part def MethodTaskFamily {
        attribute familyName : String;
        attribute capability : String;
        attribute route : String;
        attribute runtimeOwner : String;
        attribute authorizedClaimKinds : String;
        attribute forbiddenClaimKinds : String;
    }

    part def QuintTaskFamily :> MethodTaskFamily;
    part def LeanPooTaskFamily :> MethodTaskFamily;
    part def SourceContractTaskFamily :> MethodTaskFamily;
    part def NativeFaultOracleTaskFamily :> MethodTaskFamily;

    // ── 4. Pure Scheme Control Plane (Zero I/O, library/ boundary) ──

    part def FunFlowControlPlane {
        attribute upstreamModule : String = ":tao3k/agentic-ai-lab/modules/funflow/control-plane/api";
        attribute dagReceiptKind : String = "yuanxu.core.flow-dag-receipt.v1";
        attribute manifestSchema : String = "yuanxu.core.flow-dag-runtime-manifest.v1";
        attribute purityInvariant : String = "zero-io-zero-subprocess-in-library";
        attribute yuanxuLayer : String = "de.layer.method";

        port gatePort : GovernanceGatePort;
        port manifestOut : ManifestExecutionPort;
        port admitPort : EvidenceAdmissionPort;

        part quintFamily : QuintTaskFamily {
            attribute redefines familyName = "de-quint";
            attribute redefines capability = "quint-apalache-mbt";
            attribute redefines route = "adapter";
            attribute redefines runtimeOwner = "quint-modules-resolver";
            attribute redefines authorizedClaimKinds = "bounded-interleaving,fault-race,guard-countermodel,mbt-trace";
            attribute redefines forbiddenClaimKinds = "unbounded-invariant,algebraic-bound,contract-refinement,proof-transport";
        }

        part leanPooFamily : LeanPooTaskFamily {
            attribute redefines familyName = "de-lean-poo";
            attribute redefines capability = "lean4-lake-kernel";
            attribute redefines route = "adapter";
            attribute redefines runtimeOwner = "lake-lean";
            attribute redefines authorizedClaimKinds = "unbounded-invariant,algebraic-bound,contract-refinement,proof-transport";
            attribute redefines forbiddenClaimKinds = "bounded-interleaving,fault-race,guard-countermodel,mbt-trace";
        }

        part sourceContractFamily : SourceContractTaskFamily {
            attribute redefines familyName = "de-source-contract";
            attribute redefines capability = "cbmc-kani-clippy";
            attribute redefines route = "adapter";
            attribute redefines runtimeOwner = "native-toolchain";
            attribute redefines authorizedClaimKinds = "source-memory-ub,drop-unwind-safety,api-ban-lint";
            attribute redefines forbiddenClaimKinds = "bounded-interleaving,unbounded-invariant";
        }

        part nativeOracleFamily : NativeFaultOracleTaskFamily {
            attribute redefines familyName = "de-native-oracle";
            attribute redefines capability = "mbt-fault-oracle";
            attribute redefines route = "adapter";
            attribute redefines runtimeOwner = "ops-contained-runner";
            attribute redefines authorizedClaimKinds = "empirical-mbt-replay,os-sigkill-oracle,zero-leak-assertion";
            attribute redefines forbiddenClaimKinds = "unbounded-invariant,exhaustive-schedule-proof";
        }

        part hygienicMacros {
            attribute mechanism : String = "gerbil-defrules";
            attribute forms : String = "defde-method-family,defde-verification-step,defde-verification-dag";
            attribute invariant : String = "expands-to-funflow-combinators-no-alist-dsl";
        }

        part runnableClosProtocol {
            attribute generics : String = "runnable-inputs,runnable-flow,runnable-admit";
            attribute adapters : String = "quint-methods,lean-methods,source-contracts,native-oracle-methods";
        }
    }

    // ── 5. ASCENT Multi-Method Governance Program (MR01-MR06) ──

    part def AscentGovernanceProgram {
        attribute dslModule : String = ":gerbil-ascent/rules/func";
        attribute yuanxuLayer : String = "de.layer.governance";
        attribute rules : String = "MR01-claim-routing,MR02-anti-duplication,MR03-premise-handoff,MR04-artifact-dag-closure,MR05-mandatory-countermodels,MR06-subprocess-containment";
        attribute evidenceSession : String = "library/evidence/func.ss::make-resource-evidence";

        port gatePort : GovernanceGatePort;
        port admissionIn : EvidenceAdmissionPort;
    }

    // ── 6. Contained Runtime Adapter Boundary (outside library/) ──

    part def ContainedRuntimeAdapter {
        attribute placement : String = "host-core-ops-or-t-support";
        attribute consumesSchema : String = "yuanxu.core.flow-dag-runtime-manifest.v1";
        attribute containmentContract : String = "process-tree-fate-sharing-bounded-grace-escalation";

        port execPort : ManifestExecutionPort;
    }

    // ── 7. LeanPoo Reusable Mathematical Core & Domain Refinements ──

    part def LeanPooCoreLibrary {
        attribute rootNamespace : String = "DeterministicEngineering.Core";
        part conservation { attribute role : String = "single-ownership-conservation-idempotent-release"; }
        part budget       { attribute role : String = "additive-monotonic-capacity-memory-bounds"; }
        part containment  { attribute role : String = "arbitrary-depth-tree-closure-fate-sharing"; }
        part order        { attribute role : String = "fencing-token-version-governance-floor-lattice"; }
        part transport    { attribute role : String = "ObjectContract.refine-Patch.frame-Proof.reuse"; }
    }

    // ── 8. Formal Architecture & Anti-Leak Requirements ──

    package requirements {
        requirement <'MM-R01'> claimKindOrthogonality {
            doc /* MR01: Each verification method family may discharge only its authorized claim-kind set (Quint: finite races/MBT; LeanPoo: unbounded laws/refinement/transport; Source: UB/lints; Oracle: OS fault grounding). */
        }
        requirement <'MM-R02'> zeroModelDuplication {
            doc /* MR02: Two distinct formal methods must not re-encode the same obligation and claim-kind unless bound by an explicit correspondence_bridge obligation. */
        }
        requirement <'MM-R03'> explicitPremiseHandoff {
            doc /* MR03: Every abstract premise required by a LeanPoo theorem (e.g., SpawnPreservesContainer) must be visibly linked to a supporting Quint/source/OS step or remain open_premise. */
        }
        requirement <'MM-R04'> dagArtifactClosure {
            doc /* MR04: Every Fun-Flow step declaring consumes_artifact (e.g., itf-trace) must have a matching upstream produces_artifact edge in the composed DAG. */
        }
        requirement <'MM-R05'> mandatoryCountermodelFloor {
            doc /* MR05: Stateful Quint targets inherit Band-5 governance.mandatory-countermodels and cannot be admitted with zero guard-pruned countermodels. */
        }
        requirement <'MM-R06'> subprocessContainmentObligation {
            doc /* MR06: Any engineering subject or runtime runner carrying factor owns-subprocess-tree requires both a declared OS containment strategy and an os-sigkill-oracle negative control. */
        }
        requirement <'MM-R07'> ecosystemPackageIsolation {
            doc /* Extends 10.150 OR02/OR03: packages/lean-models/ (lean-model-content) remains physically isolated from packages/quint-models/ (quint-model-content) and pure Scheme library/. */
        }
        requirement <'MM-R08'> pureControlPlaneBoundary {
            doc /* Preserves 10.148 & Fun-Flow 10.07: library/verification-flow/ emits inert DAG receipts and runtime manifests with zero I/O or subprocess execution. */
        }
        requirement <'PT-R01'> zeroOrphanAfterDrop {
            doc /* ProcessTreeReclamation safety: once Guardian/GatewayGuard reaches Reaped/Dropped, zero descendant processes remain live or orphaned. */
        }
        requirement <'PT-R02'> noPrematureSigkill {
            doc /* ProcessTreeReclamation escalation discipline: cooperative shutdown (POST /shutdown or SIGTERM) must not be preempted by SIGKILL before grace expiry or observed supervisor hang/exit. */
        }
        requirement <'PT-R03'> arbitraryDepthContainmentClosure {
            doc /* LeanPoo unbounded law: for all tree depths d and branching factors k, if spawn preserves container membership, atomic container termination reaps the entire subtree regardless of intermediate SIGKILL crashes. */
        }
        requirement <'PT-R04'> crashSafeOsFateSharing {
            doc /* OS boundary law: external SIGKILL to supervisor (exit 137) or test-body panic must still terminate all grandchildren within bounded time via cgroup.kill/PID-ns (Linux) or killpg+Pipe-EOF/kqueue (Darwin). */
        }
    }

    // ── 9. Planned Verification Obligations (Design Traceability Only) ──

    package obligations {
        verification <'MM-V01'> ascentMultiMethodGate {
            doc /* Planned ASCENT MR01-MR06 unit & negative-control verification suite; unexecuted design obligation. */
            objective {
                verify requirements::claimKindOrthogonality;
                verify requirements::zeroModelDuplication;
                verify requirements::explicitPremiseHandoff;
                verify requirements::dagArtifactClosure;
                verify requirements::mandatoryCountermodelFloor;
                verify requirements::subprocessContainmentObligation;
            }
        }
        verification <'MM-V02'> repositoryPlacementGate {
            doc /* Planned OR01-OR06 + lean-model-content organization verification gate; unexecuted design obligation. */
            objective {
                verify requirements::ecosystemPackageIsolation;
                verify requirements::pureControlPlaneBoundary;
            }
        }
        verification <'MM-V03'> quintProcessTreeCheck {
            doc /* Planned Apalache bounded safety + 5 guard-pruned countermodels + mbt-audit on ProcessTreeReclamation.qnt; unexecuted design obligation. */
            objective {
                verify requirements::zeroOrphanAfterDrop;
                verify requirements::noPrematureSigkill;
                verify requirements::mandatoryCountermodelFloor;
            }
        }
        verification <'MM-V04'> leanPooContainmentProof {
            doc /* Planned Lake kernel check (zero sorry, standard axioms) + ObjectContract.refine + Patch.frame transport on Core.Containment and Engineering.ProcessTree; unexecuted design obligation. */
            objective {
                verify requirements::arbitraryDepthContainmentClosure;
                verify requirements::explicitPremiseHandoff;
            }
        }
        verification <'MM-V05'> rustSigkillLeakOracle {
            doc /* Planned 4-control native OS fault injection (normal shutdown, panic drop, external SIGKILL 137, hung child ignoring SIGTERM) + Clippy API ban + Quint ITF replay; unexecuted design obligation. */
            objective {
                verify requirements::zeroOrphanAfterDrop;
                verify requirements::noPrematureSigkill;
                verify requirements::crashSafeOsFateSharing;
                verify requirements::subprocessContainmentObligation;
            }
        }
    }

    // ── 10. Declarative Fun-Flow + ASCENT Closed-Loop Workflow ──

    package workflow {
        doc /* Conceptual Fun-Flow + ASCENT verification lifecycle. Scheme constructs pure DAG manifests; external runtime adapter executes steps inside containment guards. */

        action def MultiMethodVerificationFlow {
            action captureInputClosure;
            action evaluateAscentMrGate;
            action selectPendingFrontier;
            action projectFunFlowManifest;
            action runQuintBoundedAndMbt;
            action runRustMbtAndSigkillOracle;
            action runLeanPooKernelAndReuse;
            action admitReceiptsToAscent;

            first captureInputClosure then evaluateAscentMrGate;
            first evaluateAscentMrGate then selectPendingFrontier;
            first selectPendingFrontier then projectFunFlowManifest;

            // Parallel Fun-Flow fanout (Quint >>> RustOracle || LeanPoo)
            first projectFunFlowManifest then runQuintBoundedAndMbt;
            first runQuintBoundedAndMbt then runRustMbtAndSigkillOracle;
            first projectFunFlowManifest then runLeanPooKernelAndReuse;

            // Converge into pure ASCENT evidence admission
            first runRustMbtAndSigkillOracle then admitReceiptsToAscent;
            first runLeanPooKernelAndReuse then admitReceiptsToAscent;
        }
    }

    // ── 11. System Composition & Pilot Slice: ProcessTreeReclamation ──

    part system {
        part quintModels : QuintModelPackage {
            attribute redefines pathPattern = "packages/quint-models/<domain>/<subdomain>/<model>/";
            attribute redefines ecosystem = "bun,gerbil-yuanxu";
            attribute redefines family = "quint-model-content";
            attribute redefines mirror = "hardenedlinux/deterministic-engineering-quint-models";
            attribute redefines allows = "scheme-poo-ast,pure-qnt,model-readmes";
            attribute redefines rejects = "lean-files,tool-code,json-sidecars,orphan-qnt";
        }

        part leanModels : LeanPooModelPackage {
            attribute redefines pathPattern = "packages/lean-models/DeterministicEngineering/";
            attribute redefines ecosystem = "lake,lean4,lean-poo";
            attribute redefines family = "lean-model-content";
            attribute redefines mirror = "hardenedlinux/deterministic-engineering-lean-models";
            attribute redefines allows = "lakefile,lake-manifest,lean-toolchain,leanpoo-objects,proofs,readme";
            attribute redefines rejects = "qnt-files,ts-js,scheme-files,sorry-proofs,json-sidecars";
            part core : LeanPooCoreLibrary;
        }

        part rustSubjects : LanguageSubjectPlacement {
            attribute redefines pathPattern = "languages-engineering/rust/<domain>/<subject>/";
            attribute redefines ecosystem = "cargo,rustc,clippy,kani";
            attribute redefines roles = "checked-rust-subjects,os-containment-guards";
        }

        part controlPlane : FunFlowControlPlane;
        part governance : AscentGovernanceProgram;
        part runtimeAdapter : ContainedRuntimeAdapter;

        // Concrete Pilot Engineering Subject (Anti-Leak Vertical Slice)
        part processTreeReclamation {
            attribute identity : String = "engineering.lifecycle.process-tree-reclamation";
            attribute tags : String = "engineering,lifecycle,concurrency,defense.mutability.mutable-root,hazard.process-orphan";
            attribute factors : String = "owns-subprocess-tree";

            part quintTarget {
                attribute modelId : String = "engineering.concurrency.process-tree-reclamation";
                attribute countermodels : String = "premature-sigkill,http-ack-not-quiescence,single-pid-kill-no-containment,pgid-spawn-toctou,pid-reuse-double-kill";
                attribute producesArtifact : String = "itf-trace";
                port traceOut : ArtifactHandoffPort;
            }

            part leanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.ProcessTree";
                attribute refinesCore : String = "DeterministicEngineering.Core.Containment";
                attribute platformSpecializations : String = "LinuxCgroupV2Supervisor,DarwinPgidPipeSupervisor";
                attribute requiresPremise : String = "SpawnPreservesContainer";
                attribute transportContract : String = "Patch.frame+Proof.reuse";
                port premiseIn : PremiseConsumerPort;
            }

            part sourceContractTarget {
                attribute subjectDir : String = "languages-engineering/rust/lifecycle/process-tree-guard";
                attribute staticTool : String = "clippy";
                attribute staticBans : String = "raw-Command::spawn,tokio-kill_on_drop";
            }

            part rustOracleTarget {
                attribute cratePath : String = "languages-engineering/rust/lifecycle/process-tree-guard";
                attribute staticBans : String = "raw-Command::spawn,tokio-kill_on_drop";
                attribute consumesArtifact : String = "itf-trace";
                attribute supportsPremise : String = "SpawnPreservesContainer";
                attribute faultControls : String = "normal-shutdown,panic-drop-grace,external-sigkill-137,hung-child-sigterm-ignore";
                port traceIn : ArtifactConsumerPort;
                port premiseOut : PremiseHandoffPort;
            }
        }

        // Second Engineering Subject proving horizontal reuse across domains with zero framework duplication
        part backpressureMemory {
            attribute identity : String = "engineering.concurrency.backpressure-memory";
            attribute tags : String = "engineering,concurrency,memory,defense.mutability.mutable-root,hazard.memory-exhaustion";
            attribute factors : String = "bounded-memory-backpressure";

            part bpQuintTarget {
                attribute modelId : String = "engineering.concurrency.backpressure-memory";
                attribute countermodels : String = "early-release,over-admit,queue-overflow,duplicate-admit";
                attribute producesArtifact : String = "itf-trace";
                port traceOut : ArtifactHandoffPort;
            }

            part bpLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.Backpressure";
                attribute refinesCore : String = "DeterministicEngineering.Core.Budget";
                attribute platformSpecializations : String = "TokioRayonBoundedBackpressure";
                attribute requiresPremise : String = "PayloadDropPrecedesPermitRelease";
                attribute transportContract : String = "Patch.frame+Proof.reuse";
                port premiseIn : PremiseConsumerPort;
            }

            part bpSourceContractTarget {
                attribute subjectDir : String = "languages-engineering/rust/concurrency/resource-control/backpressure-memory";
                attribute staticTool : String = "clippy";
            }

            part bpRustOracleTarget {
                attribute cratePath : String = "languages-engineering/rust/concurrency/resource-control/backpressure-memory";
                attribute oracleClaimKind : String = "zero-leak-assertion";
                attribute oracleObligation : String = "rust-zero-leak-oracle";
                attribute consumesArtifact : String = "itf-trace";
                attribute supportsPremise : String = "PayloadDropPrecedesPermitRelease";
                port traceIn : ArtifactConsumerPort;
                port premiseOut : PremiseHandoffPort;
            }
        }
    }

    // ── 12. Architectural, Cross-Method, and Requirement Dependencies ──

    dependency 'governance-gates-flow' from system::controlPlane to system::governance;
    dependency 'manifest-handoff' from system::runtimeAdapter to system::controlPlane;
    dependency 'evidence-admission' from system::governance to system::runtimeAdapter;

    dependency 'quint-step-source' from system::processTreeReclamation::quintTarget to system::quintModels;
    dependency 'lean-step-source' from system::processTreeReclamation::leanPooTarget to system::leanModels;
    dependency 'lean-refines-core' from system::processTreeReclamation::leanPooTarget to system::leanModels::core::containment;
    dependency 'rust-contract-source' from system::processTreeReclamation::sourceContractTarget to system::rustSubjects;
    dependency 'rust-step-source' from system::processTreeReclamation::rustOracleTarget to system::rustSubjects;

    dependency 'bp-quint-source' from system::backpressureMemory::bpQuintTarget to system::quintModels;
    dependency 'bp-lean-source' from system::backpressureMemory::bpLeanPooTarget to system::leanModels;
    dependency 'bp-lean-refines-core' from system::backpressureMemory::bpLeanPooTarget to system::leanModels::core::budget;
    dependency 'bp-rust-contract-source' from system::backpressureMemory::bpSourceContractTarget to system::rustSubjects;
    dependency 'bp-rust-oracle-source' from system::backpressureMemory::bpRustOracleTarget to system::rustSubjects;

    // Cross-method edges enforced by MR03 & MR04 (zero model duplication)
    dependency 'pt-mbt-itf-edge' from system::processTreeReclamation::rustOracleTarget::traceIn to system::processTreeReclamation::quintTarget::traceOut;
    dependency 'pt-premise-handoff-edge' from system::processTreeReclamation::leanPooTarget::premiseIn to system::processTreeReclamation::rustOracleTarget::premiseOut;
    dependency 'bp-mbt-itf-edge' from system::backpressureMemory::bpRustOracleTarget::traceIn to system::backpressureMemory::bpQuintTarget::traceOut;
    dependency 'bp-premise-handoff-edge' from system::backpressureMemory::bpLeanPooTarget::premiseIn to system::backpressureMemory::bpRustOracleTarget::premiseOut;

    // Verification obligation allocations (planned checks, no execution verdict)
    dependency 'alloc-mr-gate' from obligations::ascentMultiMethodGate to system::governance;
    dependency 'alloc-placement-gate' from obligations::repositoryPlacementGate to system::leanModels;
    dependency 'alloc-quint-check' from obligations::quintProcessTreeCheck to system::processTreeReclamation::quintTarget;
    dependency 'alloc-lean-proof' from obligations::leanPooContainmentProof to system::processTreeReclamation::leanPooTarget;
    dependency 'alloc-rust-oracle' from obligations::rustSigkillLeakOracle to system::processTreeReclamation::rustOracleTarget;

    // Design specification only. Does not modify live project.sysml or claim qualification.
}

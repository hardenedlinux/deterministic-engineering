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

    // ── 5. ASCENT Multi-Method & AI Security Governance Program (MR01-MR08, ER01-ER04, IR01-IR08, AR01-AR05) ──

    part def AscentGovernanceProgram {
        attribute dslModule : String = ":gerbil-ascent/rules/func";
        attribute yuanxuLayer : String = "de.layer.governance";
        attribute rules : String = "MR01-claim-routing,MR02-anti-duplication,MR03-premise-handoff,MR04-artifact-dag-closure,MR05-mandatory-countermodels,MR06-subprocess-containment,MR07-cyclic-premise-dependency,MR08-cyclic-flow-dag,ER01-ER04-evidence-admission,IR01-IR04-incremental-reuse,IR05-toolchain-drift,IR06-attestation-invalid,IR07-premise-supporter-invalidated,IR08-witness-ttl-expired,AR01-no-ai-self-certification,AR02-ai-tool-confinement,AR03-ai-delegation-attenuation-currentness,AR04-ai-context-integrity-ifc,AR05-ai-human-stepup-sod";
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
        part conservation   { attribute role : String = "single-ownership-conservation-idempotent-release"; }
        part budget         { attribute role : String = "additive-monotonic-capacity-memory-bounds"; }
        part containment    { attribute role : String = "arbitrary-depth-tree-closure-fate-sharing"; }
        part order          { attribute role : String = "fencing-token-version-governance-floor-lattice"; }
        part transport      { attribute role : String = "ObjectContract.refine-Patch.frame-Proof.reuse"; }
        part metaGovernance { attribute role : String = "mechanized-ascent-MR-ER-IR-meta-soundness"; }
        part aiGovernance   { attribute role : String = "strict-zero-axiom-AR01-AR05-ai-security-and-aise-soundness"; }
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
        requirement <'AI-R01'> noAiSelfCertification {
            doc /* AR01: AI-authored changes cannot be certified by LLM-as-a-Judge or ai-self-review; they require deterministic formal/source/oracle verifiers and invalidate silent proof reuse whenever an AI patch touches a security dependency. */
        }
        requirement <'AI-R02'> aiToolExecutionConfinement {
            doc /* AR02: Any AI subject with factor ai-executes-tools must declare tool-confinement and at least one executable attack countermodel. */
        }
        requirement <'AI-R03'> aiDelegationAttenuationAndCurrentness {
            doc /* AR03: Any AI subject with factor ai-delegates-authority must declare both monotonic-attenuation and revocation-currentness. */
        }
        requirement <'AI-R04'> aiUntrustedContextIsolation {
            doc /* AR04: Any AI subject with factor ai-ingests-untrusted-context must declare context-integrity-or-ifc confinement. */
        }
        requirement <'AI-R05'> aiHumanInTheLoopSeparation {
            doc /* AR05: Any AI subject with factor ai-mutates-host-or-governance must declare human-stepup-and-estop plus a genuine human-approver role binding; ai-agent identities are strictly forbidden from satisfying human-approver or policy-admin authority. */
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
        verification <'MM-V06'> aiSecurityGovernanceAndRedTeamGate {
            doc /* Planned ASCENT AR01-AR05 + Lean Core.AiGovernance + Role-SoD AI Red-Team verification suite; unexecuted design obligation. */
            objective {
                verify requirements::noAiSelfCertification;
                verify requirements::aiToolExecutionConfinement;
                verify requirements::aiDelegationAttenuationAndCurrentness;
                verify requirements::aiUntrustedContextIsolation;
                verify requirements::aiHumanInTheLoopSeparation;
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

        part cSubjects : LanguageSubjectPlacement {
            attribute redefines pathPattern = "languages-engineering/c/<domain>/<subject>/";
            attribute redefines ecosystem = "clang,cbmc";
            attribute redefines roles = "checked-c-trust-boundaries,cbmc-ub-proofs";
        }

        part controlPlane : FunFlowControlPlane;
        part governance : AscentGovernanceProgram;
        part runtimeAdapter : ContainedRuntimeAdapter;

        // Concrete Pilot Engineering Subject (Anti-Leak Vertical Slice)
        part processTreeReclamation {
            attribute subjectKey : String = "process-tree-reclamation";
            attribute identity : String = "engineering.lifecycle.process-tree-reclamation";
            attribute tags : String = "engineering,lifecycle,concurrency,defense.mutability.mutable-root,hazard.process-orphan";
            attribute factors : String = "owns-subprocess-tree";

            part quintTarget {
                attribute modelId : String = "engineering.concurrency.process-tree-reclamation";
                attribute quintFile : String = "packages/quint-models/engineering/concurrency/process-tree-reclamation/ProcessTreeReclamation.qnt";
                attribute quintMain : String = "concurrency_process_tree_reclamation";
                attribute itfSubdir : String = "process-tree-reclamation";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "20";
                attribute maxSamples : String = "60";
                attribute maxSteps : String = "24";
                attribute countermodels : String = "premature-sigkill,http-ack-not-quiescence,single-pid-kill-no-containment,pgid-spawn-toctou,pid-reuse-double-kill";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/engineering/concurrency/process-tree-reclamation/ProcessTreeReclamation.qnt,packages/quint-models/engineering/concurrency/process-tree-reclamation/objects.ss,packages/quint-models/engineering/concurrency/process-tree-reclamation/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part leanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.ProcessTree";
                attribute refinesCore : String = "DeterministicEngineering.Core.Containment";
                attribute platformSpecializations : String = "LinuxCgroupV2Supervisor,DarwinPgidPipeSupervisor";
                attribute requiresPremise : String = "SpawnPreservesContainer";
                attribute transportContract : String = "Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Core.Conservation.admit_preserves_withinCap,DeterministicEngineering.Core.Conservation.release_idempotent,DeterministicEngineering.Core.Order.staleEpoch_rejected,DeterministicEngineering.Core.Order.join_never_weakens_left,DeterministicEngineering.Core.Transport.close_single_set_untouched,DeterministicEngineering.Core.Containment.killContainer_allDead_of_closed,DeterministicEngineering.Core.Containment.crashSafe_killContainer_after_root_sigkill,DeterministicEngineering.Core.Containment.singlePidKill_strands_live_child,DeterministicEngineering.Engineering.ProcessTree.linuxCgroupV2_preserves_rejection,DeterministicEngineering.Engineering.ProcessTree.darwinPgidPipe_preserves_rejection,DeterministicEngineering.Engineering.ProcessTree.containment_transported_across_grace_tuning,DeterministicEngineering.Engineering.ProcessTree.graceTunedCertified,DeterministicEngineering.Engineering.ProcessTree.singlePidRegression_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Conservation.lean,packages/lean-models/DeterministicEngineering/Core/Order.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Core/Containment.lean,packages/lean-models/DeterministicEngineering/Engineering/ProcessTree.lean";
                port premiseIn : PremiseConsumerPort;
            }

            part sourceContractTarget {
                attribute subjectDir : String = "languages-engineering/rust/lifecycle/process-tree-guard";
                attribute staticTool : String = "clippy";
                attribute offlineMode : String = "false";
                attribute staticBans : String = "raw-Command::spawn,tokio-kill_on_drop";
                attribute inputFiles : String = "languages-engineering/rust/lifecycle/process-tree-guard/Cargo.toml,languages-engineering/rust/lifecycle/process-tree-guard/clippy.toml,languages-engineering/rust/lifecycle/process-tree-guard/src/lib.rs,languages-engineering/rust/lifecycle/process-tree-guard/src/cgroup_v2.rs,languages-engineering/rust/lifecycle/process-tree-guard/src/bin/mock_tree.rs";
            }

            part rustOracleTarget {
                attribute cratePath : String = "languages-engineering/rust/lifecycle/process-tree-guard";
                attribute itfSubdir : String = "process-tree-reclamation";
                attribute oracleMode : String = "cargo-test-itf";
                attribute staticBans : String = "raw-Command::spawn,tokio-kill_on_drop";
                attribute consumesArtifact : String = "itf-trace";
                attribute supportsPremise : String = "SpawnPreservesContainer";
                attribute faultControls : String = "normal-shutdown,panic-drop-grace,external-sigkill-137,hung-child-sigterm-ignore,online-os-itf-driver,darwin-setsid-pipe-eof-catch,darwin-setsid-rogue-escape-negative-control,linux-cgroup-v2-atomic-kill";
                attribute inputFiles : String = "languages-engineering/rust/lifecycle/process-tree-guard/Cargo.toml,languages-engineering/rust/lifecycle/process-tree-guard/clippy.toml,languages-engineering/rust/lifecycle/process-tree-guard/src/lib.rs,languages-engineering/rust/lifecycle/process-tree-guard/src/cgroup_v2.rs,languages-engineering/rust/lifecycle/process-tree-guard/src/bin/mock_tree.rs,languages-engineering/rust/lifecycle/process-tree-guard/tests/sigkill_leak_oracle.rs,languages-engineering/rust/lifecycle/process-tree-guard/tests/itf_mbt_replay.rs,languages-engineering/rust/lifecycle/process-tree-guard/tests/http_shutdown_e2e.rs";
                port traceIn : ArtifactConsumerPort;
                port premiseOut : PremiseHandoffPort;
            }
        }

        // Second Engineering Subject proving horizontal reuse across domains with zero framework duplication
        part backpressureMemory {
            attribute subjectKey : String = "backpressure-memory";
            attribute identity : String = "engineering.concurrency.backpressure-memory";
            attribute tags : String = "engineering,concurrency,memory,defense.mutability.mutable-root,hazard.memory-exhaustion";
            attribute factors : String = "bounded-memory-backpressure";

            part bpQuintTarget {
                attribute modelId : String = "engineering.concurrency.backpressure-memory";
                attribute quintFile : String = "packages/quint-models/engineering/concurrency/backpressure-memory/BackpressureOwners.qnt";
                attribute quintMain : String = "BackpressureOwners";
                attribute itfSubdir : String = "backpressure-memory";
                attribute verifyMode : String = "plan";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "early-release,over-admit,queue-overflow,duplicate-admit";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/engineering/concurrency/backpressure-memory/BackpressureOwners.qnt,packages/quint-models/engineering/concurrency/backpressure-memory/objects.ss,packages/quint-models/engineering/concurrency/backpressure-memory/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part bpLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.Backpressure";
                attribute refinesCore : String = "DeterministicEngineering.Core.Budget";
                attribute platformSpecializations : String = "TokioRayonBoundedBackpressure";
                attribute requiresPremise : String = "PayloadDropPrecedesPermitRelease";
                attribute transportContract : String = "Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Core.Budget.conservation_bounds_peak,DeterministicEngineering.Core.Budget.budget_preserved_under_shrink,DeterministicEngineering.Core.Budget.earlyPermitRelease_can_exceed_budget,DeterministicEngineering.Engineering.Backpressure.backpressure_within_budget,DeterministicEngineering.Engineering.Backpressure.tokioRayon_preserves_rejection,DeterministicEngineering.Engineering.Backpressure.budget_transported_across_poll_tuning,DeterministicEngineering.Engineering.Backpressure.pollTunedCertified,DeterministicEngineering.Engineering.Backpressure.limitDoubling_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Budget.lean,packages/lean-models/DeterministicEngineering/Engineering/Backpressure.lean";
                port premiseIn : PremiseConsumerPort;
            }

            part bpSourceContractTarget {
                attribute subjectDir : String = "languages-engineering/rust/concurrency/resource-control/backpressure-memory";
                attribute staticTool : String = "clippy";
                attribute offlineMode : String = "true";
                attribute inputFiles : String = "languages-engineering/rust/concurrency/resource-control/backpressure-memory/Cargo.toml,languages-engineering/rust/concurrency/resource-control/backpressure-memory/src/main.rs";
            }

            part bpRustOracleTarget {
                attribute cratePath : String = "languages-engineering/rust/concurrency/resource-control/backpressure-memory";
                attribute itfSubdir : String = "backpressure-memory";
                attribute oracleMode : String = "cargo-run-lifecycle-json";
                attribute oracleClaimKind : String = "zero-leak-assertion";
                attribute oracleObligation : String = "rust-zero-leak-oracle";
                attribute consumesArtifact : String = "itf-trace";
                attribute supportsPremise : String = "PayloadDropPrecedesPermitRelease";
                attribute inputFiles : String = "languages-engineering/rust/concurrency/resource-control/backpressure-memory/Cargo.toml,languages-engineering/rust/concurrency/resource-control/backpressure-memory/src/main.rs";
                port traceIn : ArtifactConsumerPort;
                port premiseOut : PremiseHandoffPort;
            }
        }

        // Third Engineering Subject compiled with ZERO per-subject Scheme glue (refines Core.Order + Core.Transport)
        part leaseFencingToken {
            attribute subjectKey : String = "lease-fencing-token";
            attribute identity : String = "engineering.concurrency.lease-fencing-token";
            attribute tags : String = "engineering,concurrency,distributed,defense.mutability.immutable-proof,hazard.stale-zombie-write";
            attribute factors : String = "monotonic-fencing-token";

            part lfQuintTarget {
                attribute modelId : String = "engineering.concurrency.lease-fencing-token";
                attribute quintFile : String = "packages/quint-models/engineering/concurrency/lease-fencing-token/LeaseFencingToken.qnt";
                attribute quintMain : String = "lease_fencing_token";
                attribute itfSubdir : String = "lease-fencing-token";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "monotonic-fencing-token";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/engineering/concurrency/lease-fencing-token/LeaseFencingToken.qnt,packages/quint-models/engineering/concurrency/lease-fencing-token/objects.ss,packages/quint-models/engineering/concurrency/lease-fencing-token/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part lfLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.LeaseFencing";
                attribute refinesCore : String = "DeterministicEngineering.Core.Order,DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Core.Order.staleEpoch_rejected,DeterministicEngineering.Core.Order.advanceEpoch_rejects_strictly_older,DeterministicEngineering.Engineering.LeaseFencing.zombieWrite_always_rejected,DeterministicEngineering.Engineering.LeaseFencing.durableFencedStorage_preserves_rejection,DeterministicEngineering.Engineering.LeaseFencing.heartbeatTunedCertified,DeterministicEngineering.Engineering.LeaseFencing.disableFencing_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Order.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/LeaseFencing.lean";
            }
        }

        // Fourth Engineering Subject uniting CBMC (source-memory-ub) + LeanPoo (Core.Conservation + Core.Transport) with ZERO Scheme glue
        part cBoundaryConservation {
            attribute subjectKey : String = "c-boundary-conservation";
            attribute identity : String = "engineering.defense.c-boundary-conservation";
            attribute tags : String = "engineering,defense,c-boundary,defense.mutability.immutable-proof,hazard.silent-fallback-ub";
            attribute factors : String = "c-trust-boundary-conservation";

            part cbCbmcTarget {
                attribute subjectDir : String = "languages-engineering/c/defense/silent-fallback-contrast";
                attribute staticTool : String = "cbmc";
                attribute sourceObligation : String = "c-cbmc-memory-ub";
                attribute sourceClaimKind : String = "source-memory-ub";
                attribute cbmcFiles : String = "deterministic_boundary.c,proof.c";
                attribute supportsPremise : String = "NoCSourceOverflowOrPointerUB";
                attribute inputFiles : String = "languages-engineering/c/defense/silent-fallback-contrast/boundary.h,languages-engineering/c/defense/silent-fallback-contrast/deterministic_boundary.c,languages-engineering/c/defense/silent-fallback-contrast/proof.c";
                port premiseOut : PremiseHandoffPort;
            }

            part cbLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.BoundaryConservation";
                attribute refinesCore : String = "DeterministicEngineering.Core.Conservation,DeterministicEngineering.Core.Transport";
                attribute requiresPremise : String = "NoCSourceOverflowOrPointerUB";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Core.Conservation.admit_preserves_withinCap,DeterministicEngineering.Core.Conservation.release_idempotent,DeterministicEngineering.Core.Conservation.uncheckedAdmit_violates_withinCap,DeterministicEngineering.Engineering.BoundaryConservation.boundaryAdmit_preserves_cap,DeterministicEngineering.Engineering.BoundaryConservation.boundaryRelease_idempotent,DeterministicEngineering.Engineering.BoundaryConservation.strictBoundaryContract_preserves_rejection,DeterministicEngineering.Engineering.BoundaryConservation.telemetryTunedCertified,DeterministicEngineering.Engineering.BoundaryConservation.disableOverflowGuard_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Conservation.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/BoundaryConservation.lean";
                port premiseIn : PremiseConsumerPort;
            }
        }

        // Fifth Engineering Subject (Self-Verifying Meta-Governance Soundness: proves ASCENT MR/ER/IR soundness in Lean 4)
        part metaGovernanceSoundness {
            attribute subjectKey : String = "meta-governance-soundness";
            attribute identity : String = "engineering.governance.meta-governance-soundness";
            attribute tags : String = "engineering,governance,meta-verification,defense.mutability.immutable-proof";
            attribute factors : String = "ascent-meta-soundness";

            part mgLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.MetaGovernanceSoundness";
                attribute refinesCore : String = "DeterministicEngineering.Core.MetaGovernance,DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Core.MetaGovernance.ir_partition_exclusive,DeterministicEngineering.Core.MetaGovernance.ir03_transitive_path_invalidation,DeterministicEngineering.Core.MetaGovernance.reusable_implies_all_ancestors_reusable,DeterministicEngineering.Core.MetaGovernance.reusable_sound,DeterministicEngineering.Core.MetaGovernance.ir07_mixed_dag_and_premise_invalidation,DeterministicEngineering.Core.MetaGovernance.ir07_reusable_implies_premise_supporters_reusable,DeterministicEngineering.Core.MetaGovernance.ir08_expired_m3_prevents_reuse,DeterministicEngineering.Core.MetaGovernance.ir08_expired_m3_cascades_under_strict_premise,DeterministicEngineering.Core.MetaGovernance.er_admitted_sound,DeterministicEngineering.Core.MetaGovernance.mr_admitted_sound,DeterministicEngineering.Core.MetaGovernance.mr03_06_full_sound,DeterministicEngineering.Core.MetaGovernance.mr07_acyclic_premise_sound,DeterministicEngineering.Core.MetaGovernance.mr08_acyclic_dag_sound,DeterministicEngineering.Core.MetaGovernance.same_wave_implies_independent,DeterministicEngineering.Core.MetaGovernance.fleet_merkle_pinned_key_tamper_resistant,DeterministicEngineering.Core.MetaGovernance.revoked_key_never_admitted,DeterministicEngineering.Core.MetaGovernance.rotation_preserves_unrevoked_trust,DeterministicEngineering.Core.MetaGovernance.revoked_key_blocks_reuse_and_downstream,DeterministicEngineering.Core.MetaGovernance.mixedKeyFleet_rotation_preserves_verification,DeterministicEngineering.Core.MetaGovernance.mixedKeyFleet_rejects_revoked_child_even_with_valid_root_key,DeterministicEngineering.Core.MetaGovernance.mixedKeyFleet_rejects_tampered_child_digest,DeterministicEngineering.Core.MetaGovernance.absolute_path_never_safe,DeterministicEngineering.Core.MetaGovernance.dotdot_segment_never_safe,DeterministicEngineering.Core.MetaGovernance.exportBundle_rejects_privateKey_pem,DeterministicEngineering.Core.MetaGovernance.exportBundle_rejects_symlink_or_nonRegular,DeterministicEngineering.Core.MetaGovernance.exportBundle_rejects_zeroActiveLockout,DeterministicEngineering.Core.MetaGovernance.bundle_rejects_missing_child_entry,DeterministicEngineering.Core.MetaGovernance.bundle_rejects_smuggled_extra_child,DeterministicEngineering.Core.MetaGovernance.bundle_rejects_revoked_or_tampered_embedded_child,DeterministicEngineering.Core.MetaGovernance.freshnessWindow_rejects_expired_replay,DeterministicEngineering.Core.MetaGovernance.freshnessWindow_rejects_future_clock_forgery,DeterministicEngineering.Core.MetaGovernance.sysmlPinnedBundle_rejects_spec_downgrade,DeterministicEngineering.Core.MetaGovernance.fleetCoverage_rejects_omitted_subject_count,DeterministicEngineering.Core.MetaGovernance.fleetCoverage_rejects_missing_required_subject,DeterministicEngineering.Engineering.MetaGovernanceSoundness.fleetSignedCache_reusable_is_authentic,DeterministicEngineering.Engineering.MetaGovernanceSoundness.parallelWave_concurrent_execution_race_free,DeterministicEngineering.Engineering.MetaGovernanceSoundness.fleetAttestation_rejects_tamper_and_rogue_key,DeterministicEngineering.Engineering.MetaGovernanceSoundness.strictPremisePolicy_blocks_stale_downstream_proofs,DeterministicEngineering.Engineering.MetaGovernanceSoundness.expiredM3Oracle_blocks_reuse_and_strict_dependents,DeterministicEngineering.Engineering.MetaGovernanceSoundness.keyRevocation_invalidates_witness_and_downstream,DeterministicEngineering.Engineering.MetaGovernanceSoundness.mixedKeyFleet_rotation_and_childRevocation_sound,DeterministicEngineering.Engineering.MetaGovernanceSoundness.fleetChildPathContainment_rejects_traversal_and_absolute,DeterministicEngineering.Engineering.MetaGovernanceSoundness.trustBundleExport_prevents_privateKeyLeak_symlink_and_lockout,DeterministicEngineering.Engineering.MetaGovernanceSoundness.fleetEvidenceBundle_rejects_missing_smuggled_and_tampered_children,DeterministicEngineering.Engineering.MetaGovernanceSoundness.cacheFreshnessWindow_defeats_staleReplay_and_futureForgery,DeterministicEngineering.Engineering.MetaGovernanceSoundness.fleetSpecPinning_defeats_sysml_downgrade_replay,DeterministicEngineering.Engineering.MetaGovernanceSoundness.fleetCoverageCompleteness_prevents_silent_subject_omission,DeterministicEngineering.Engineering.MetaGovernanceSoundness.fullMetaGovContract_preserves_rejection,DeterministicEngineering.Engineering.MetaGovernanceSoundness.reportFormatTunedCertified,DeterministicEngineering.Engineering.MetaGovernanceSoundness.disableSignedCache_invalidates_reuse";
                attribute inputFiles : String = "library/verification-flow/ascent-rules.ss,library/verification-flow/attestation.ss,packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/MetaGovernance.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/MetaGovernanceSoundness.lean";
            }
        }

        // Sixth Zero-Glue Subject (First AI-Security Threat Subject: cross-domain reuse of Core.Containment + Core.Order + Core.Transport)
        part delegatedAgentAuthz {
            attribute subjectKey : String = "delegated-agent-authz";
            attribute identity : String = "threat.identity.delegated-agent-authz";
            attribute tags : String = "threat,identity,delegation,ai-security,defense.mutability.immutable-proof,hazard.scope-amplification";
            attribute factors : String = "delegated-capability-containment,ai-delegates-authority";
            attribute aiControls : String = "monotonic-attenuation,revocation-currentness";

            part daQuintTarget {
                attribute modelId : String = "threat.identity.delegated-agent-authz";
                attribute quintFile : String = "packages/quint-models/threat/identity/delegated-agent-authz/DelegatedAgentAuthz.qnt";
                attribute quintMain : String = "delegated_agent_authz";
                attribute itfSubdir : String = "delegated-agent-authz";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "obo-scope-attenuation,obo-actor-provenance,obo-revocation-currency,step-up-verified-floor";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/identity/delegated-agent-authz/DelegatedAgentAuthz.qnt,packages/quint-models/threat/identity/delegated-agent-authz/objects.ss,packages/quint-models/threat/identity/delegated-agent-authz/interface.ss,packages/quint-models/threat/zero-trust/authority-currentness/AuthorityCurrentness.qnt";
                port traceOut : ArtifactHandoffPort;
            }

            part daLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Threat.CapabilityContainment";
                attribute refinesCore : String = "DeterministicEngineering.Core.Containment,DeterministicEngineering.Core.Order,DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Threat.CapabilityContainment.revokeRootSession_kills_all_delegated_hops,DeterministicEngineering.Threat.CapabilityContainment.crashSafe_sessionRevocation_zero_zombie_tokens,DeterministicEngineering.Threat.CapabilityContainment.multiHop_attenuation_prevents_amplification,DeterministicEngineering.Threat.CapabilityContainment.revokedEpoch_rejects_zombie_delegation,DeterministicEngineering.Threat.CapabilityContainment.oboDelegationContract_preserves_rejection,DeterministicEngineering.Threat.CapabilityContainment.auditBatchTunedCertified,DeterministicEngineering.Threat.CapabilityContainment.disableRevocationEpoch_invalidates_reuse,DeterministicEngineering.Threat.AuthorityCurrentness.isCurrent_eq_true_iff,DeterministicEngineering.Threat.AuthorityCurrentness.paused_never_current,DeterministicEngineering.Threat.AuthorityCurrentness.epochAdvance_invalidates_all_prior_plans,DeterministicEngineering.Threat.AuthorityCurrentness.authorityFloor_join_never_weakens,DeterministicEngineering.Threat.AuthorityCurrentness.strictZeroTrustContract_preserves_rejection,DeterministicEngineering.Threat.AuthorityCurrentness.telemetryTunedCertified,DeterministicEngineering.Threat.AuthorityCurrentness.disableFreshnessCheck_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Containment.lean,packages/lean-models/DeterministicEngineering/Core/Order.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Threat/CapabilityContainment.lean,packages/lean-models/DeterministicEngineering/Threat/AuthorityCurrentness.lean";
            }
        }

        // Seventh Zero-Glue Subject (Second AI-Security Threat Subject: SM30 Step-Up MFA Attestation & Host Effect Confinement)
        part stepupAttestationHostConfinement {
            attribute subjectKey : String = "stepup-attestation-and-host-effect-confinement";
            attribute identity : String = "threat.execution.stepup-attestation-and-host-effect-confinement";
            attribute tags : String = "threat,execution,stepup-mfa,ai-security,defense.mutability.immutable-proof,hazard.host-effect-escape";
            attribute factors : String = "stepup-mfa-and-host-effect-confinement,ai-mutates-host-or-governance";
            attribute aiControls : String = "human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part sm30QuintTarget {
                attribute modelId : String = "threat.execution.stepup-attestation-and-host-effect-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/stepup-attestation-and-host-effect-confinement/StepUpAttestationAndHostEffectConfinement.qnt";
                attribute quintMain : String = "execution_stepup_attestation_and_host_effect_confinement";
                attribute itfSubdir : String = "stepup-attestation-and-host-effect-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-stepup-spoof-or-weak-acr-rearm,forbid-estop-llm-or-reserved-cas-overwrite,forbid-watcher-suicide-on-broadcast-lag,forbid-fact-store-deser-bomb-or-persist-desync";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/stepup-attestation-and-host-effect-confinement/StepUpAttestationAndHostEffectConfinement.qnt,packages/quint-models/threat/execution/stepup-attestation-and-host-effect-confinement/objects.ss,packages/quint-models/threat/execution/stepup-attestation-and-host-effect-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm30LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_stepup_spoof_weak_acr_and_duplicate_params_refused,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_estop_blocks_llm_complete,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_reserved_governance_cas_overwrite_refused,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_fact_insert_at_cap_refused,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_gentle_pressure_rejected,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_baseline_certified,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_obligation_untouched_by_concurrency_tuning,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_concurrency_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement.sm30_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/StepUpAttestationAndHostEffectConfinement.lean";
            }
        }

        // Eighth Zero-Glue Subject (Third AI-Security Threat Subject: SM22 ADV-L4 Sandbox Symlink & Archive Confinement)
        part sandboxSymlinkArchiveConfinement {
            attribute subjectKey : String = "sandbox-symlink-archive-confinement";
            attribute identity : String = "threat.execution.sandbox-symlink-archive-confinement";
            attribute tags : String = "threat,execution,sandbox-confinement,ai-security,defense.mutability.immutable-proof,hazard.symlink-archive-escape";
            attribute factors : String = "sandbox-symlink-and-archive-confinement,ai-executes-tools";
            attribute aiControls : String = "tool-confinement";

            part sm22QuintTarget {
                attribute modelId : String = "threat.execution.sandbox-symlink-archive-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/sandbox-symlink-archive-confinement/SandboxSymlinkArchiveConfinement.qnt";
                attribute quintMain : String = "execution_sandbox_symlink_archive_confinement";
                attribute itfSubdir : String = "sandbox-symlink-archive-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "reject-symlink-escape,confine-entry-path-to-root,reject-duplicate-and-alias-entries,enforce-cumulative-decompressed-cap";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/sandbox-symlink-archive-confinement/SandboxSymlinkArchiveConfinement.qnt,packages/quint-models/threat/execution/sandbox-symlink-archive-confinement/objects.ss,packages/quint-models/threat/execution/sandbox-symlink-archive-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm22LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Core.Conservation,DeterministicEngineering.Core.Containment";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.sm22_gentle_pressure_rejected,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.sm22_medium_high_and_hostile_admitted,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.sm22_hostile_confinement_safety,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.sm22_cumulative_decompressed_budget,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.sm22_per_entry_check_defeated_by_two_entry_bomb,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.marlinAdversarialConfinement_preserves_rejection,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.marlinAdversarialConfinement_accepts_iff,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.baselineAdversarialConfinementCertified,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.confinementUntouchedByBundleCapTuning,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.confinement_transported_across_bundle_cap_tuning,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.bundleCapTunedConfinementCertified,DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement.downgradeToGentle_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Conservation.lean,packages/lean-models/DeterministicEngineering/Core/Containment.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean";
            }
        }

        // Ninth Zero-Glue Subject (Fourth AI-Security Threat Subject: SM34 ADV-L4 Runtime Environment Activation & Governed Context Confinement)
        part runtimeEnvActivationContextConfinement {
            attribute subjectKey : String = "runtime-env-activation-and-context-confinement";
            attribute identity : String = "threat.execution.runtime-env-activation-and-context-confinement";
            attribute tags : String = "threat,execution,runtime-env-context,ai-security,defense.mutability.immutable-proof,hazard.direnv-symlink-rollback-prompt-spoof";
            attribute factors : String = "runtime-env-activation-and-context-confinement,ai-ingests-untrusted-context,ai-executes-tools";
            attribute aiControls : String = "context-integrity-or-ifc,tool-confinement";

            part sm34QuintTarget {
                attribute modelId : String = "threat.execution.runtime-env-activation-and-context-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/runtime-env-activation-and-context-confinement/RuntimeEnvActivationAndContextConfinement.qnt";
                attribute quintMain : String = "execution_runtime_env_activation_and_context_confinement";
                attribute itfSubdir : String = "runtime-env-activation-and-context-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-direnv-loader-hijack,forbid-envrc-org-symlink-escape,forbid-org-channel-rollback,forbid-two-zone-prefix-or-task-spoof";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/runtime-env-activation-and-context-confinement/RuntimeEnvActivationAndContextConfinement.qnt,packages/quint-models/threat/execution/runtime-env-activation-and-context-confinement/objects.ss,packages/quint-models/threat/execution/runtime-env-activation-and-context-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm34LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_direnv_export_fail_closed,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_confined_path_refuses_traversal_escape_and_symlink,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_snapshot_rollback_and_active_lease_swap_refused,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_two_zone_recomputed_digest_and_task_binding,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_gentle_pressure_rejected,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_baseline_certified,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_obligation_untouched_by_byte_cap_tuning,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_byte_cap_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement.sm34_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/RuntimeEnvActivationAndContextConfinement.lean";
            }
        }

        // Tenth Zero-Glue Subject (Fifth AI-Security Threat Subject: SM35 ADV-L4 AgentGraph Witness/Routing & Harness Governance/Artifact Confinement)
        part graphWitnessHarnessConfinement {
            attribute subjectKey : String = "graph-witness-and-harness-confinement";
            attribute identity : String = "threat.execution.graph-witness-and-harness-confinement";
            attribute tags : String = "threat,execution,agent-graph-harness,ai-security,defense.mutability.immutable-proof,hazard.witness-serde-cedar-spoof-artifact-escape";
            attribute factors : String = "graph-witness-and-harness-confinement,ai-executes-tools,ai-ingests-untrusted-context";
            attribute aiControls : String = "tool-confinement,context-integrity-or-ifc";

            part sm35QuintTarget {
                attribute modelId : String = "threat.execution.graph-witness-and-harness-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/graph-witness-and-harness-confinement/GraphWitnessAndHarnessConfinement.qnt";
                attribute quintMain : String = "execution_graph_witness_and_harness_confinement";
                attribute itfSubdir : String = "graph-witness-and-harness-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-sealed-witness-or-epoch-serde-forgery,forbid-policy-decision-routing-or-dup-edge-bypass,forbid-harness-cedar-capability-spoof-or-case-bypass,forbid-artifact-symlink-escape-or-config-env-exfil";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/graph-witness-and-harness-confinement/GraphWitnessAndHarnessConfinement.qnt,packages/quint-models/threat/execution/graph-witness-and-harness-confinement/objects.ss,packages/quint-models/threat/execution/graph-witness-and-harness-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm35LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_sealed_witness_and_epoch_fail_closed,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_policy_scoped_routing_fail_closed,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_cedar_harness_tool_classification_fail_closed,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_artifact_symlink_and_config_bounds_fail_closed,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_gentle_pressure_rejected,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_baseline_certified,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_obligation_untouched_by_timeout_tuning,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_timeout_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement.sm35_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/GraphWitnessAndHarnessConfinement.lean";
            }
        }

        // Eleventh Zero-Glue Subject (Sixth AI-Security Threat Subject: CaMeL/FIDES AI Agent Control/Data Segregation & Capability-Based IFC)
        part agentIfcCapability {
            attribute subjectKey : String = "agent-ifc-capability";
            attribute identity : String = "threat.execution.agent-ifc-capability";
            attribute tags : String = "threat,execution,ai-security,prompt-injection,ifc,camel-fides,defense.mutability.immutable-proof,hazard.prompt-injection-exfiltration";
            attribute factors : String = "agent-ifc-capability-confinement,ai-ingests-untrusted-context,ai-executes-tools";
            attribute aiControls : String = "context-integrity-or-ifc,tool-confinement";

            part ifcQuintTarget {
                attribute modelId : String = "threat.execution.agent-ifc-capability";
                attribute quintFile : String = "packages/quint-models/threat/execution/agent-ifc-capability/AgentIfcCapability.qnt";
                attribute quintMain : String = "agent_ifc_capability";
                attribute itfSubdir : String = "agent-ifc-capability";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "control-data-segregation,capability-ifc-egress";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/agent-ifc-capability/AgentIfcCapability.qnt,packages/quint-models/threat/execution/agent-ifc-capability/objects.ss,packages/quint-models/threat/execution/agent-ifc-capability/interface.ss,packages/quint-models/threat/zero-trust/authority-currentness/AuthorityCurrentness.qnt";
                port traceOut : ArtifactHandoffPort;
            }

            part ifcLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Threat.AgentIfcConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Core.Order,DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Threat.AgentIfcConfinement.taintedData_never_elevates_controlIntegrity,DeterministicEngineering.Threat.AgentIfcConfinement.confidentialEgress_blocked_without_declassification,DeterministicEngineering.Threat.AgentIfcConfinement.ifcLatticeFloor_join_never_weakens,DeterministicEngineering.Threat.AgentIfcConfinement.camelFidesContract_preserves_rejection,DeterministicEngineering.Threat.AgentIfcConfinement.ifcTelemetryTunedCertified,DeterministicEngineering.Threat.AgentIfcConfinement.disableDeclassGate_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Order.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Threat/AgentIfcConfinement.lean";
            }
        }

        // Twelfth Zero-Glue Subject (Seventh AI-Security Threat Subject: AI Tool Execution Circuit Breaker / E-Stop / Lease-Epoch Fencing)
        part agentToolCircuitBreaker {
            attribute subjectKey : String = "agent-tool-circuit-breaker";
            attribute identity : String = "threat.execution.agent-tool-circuit-breaker";
            attribute tags : String = "threat,execution,ai-security,circuit-breaker,estop,defense.mutability.immutable-proof,hazard.runaway-tool-self-rearm";
            attribute factors : String = "agent-tool-circuit-breaker-estop,ai-executes-tools,ai-mutates-host-or-governance";
            attribute aiControls : String = "tool-confinement,human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part cbBreakerQuintTarget {
                attribute modelId : String = "threat.execution.agent-tool-circuit-breaker";
                attribute quintFile : String = "packages/quint-models/threat/execution/agent-tool-circuit-breaker/AgentToolCircuitBreaker.qnt";
                attribute quintMain : String = "agent_tool_circuit_breaker";
                attribute itfSubdir : String = "agent-tool-circuit-breaker";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "breaker-closed-at-commit,lease-epoch-current,human-only-rearm,tool-budget-bounded";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/agent-tool-circuit-breaker/AgentToolCircuitBreaker.qnt,packages/quint-models/threat/execution/agent-tool-circuit-breaker/objects.ss,packages/quint-models/threat/execution/agent-tool-circuit-breaker/interface.ss,packages/quint-models/threat/zero-trust/authority-currentness/AuthorityCurrentness.qnt";
                port traceOut : ArtifactHandoffPort;
            }

            part cbBreakerLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Threat.AgentCircuitBreaker";
                attribute refinesCore : String = "DeterministicEngineering.Core.Budget,DeterministicEngineering.Core.Order,DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Threat.AgentCircuitBreaker.trippedBreaker_blocks_all_toolCommits,DeterministicEngineering.Threat.AgentCircuitBreaker.rearmTripEpoch_rejects_all_preTrip_staleLeases,DeterministicEngineering.Threat.AgentCircuitBreaker.aiAgent_never_selfRearms_trippedBreaker,DeterministicEngineering.Threat.AgentCircuitBreaker.toolCallBudget_bounded_within_armedWindow,DeterministicEngineering.Threat.AgentCircuitBreaker.circuitBreakerContract_preserves_rejection,DeterministicEngineering.Threat.AgentCircuitBreaker.breakerTelemetryTunedCertified,DeterministicEngineering.Threat.AgentCircuitBreaker.allowAgentSelfRearm_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Budget.lean,packages/lean-models/DeterministicEngineering/Core/Order.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Threat/AgentCircuitBreaker.lean";
            }
        }

        // Thirteenth Zero-Glue Subject (Eighth AI-Security Threat Subject: Multi-Party Shared Context Governance, Scope Lattice & Taint Isolation)
        part sharedContextGovernance {
            attribute subjectKey : String = "shared-context-governance";
            attribute identity : String = "threat.zero-trust.shared-context-governance";
            attribute tags : String = "threat,zero-trust,ai-security,shared-context,taint-isolation,defense.mutability.immutable-proof,hazard.cross-principal-context-leak";
            attribute factors : String = "shared-context-scope-and-taint-isolation,ai-ingests-untrusted-context,ai-delegates-authority,ai-mutates-host-or-governance";
            attribute aiControls : String = "context-integrity-or-ifc,monotonic-attenuation,revocation-currentness,human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part scgQuintTarget {
                attribute modelId : String = "threat.zero-trust.shared-context-governance";
                attribute quintFile : String = "packages/quint-models/threat/zero-trust/shared-context-governance/SharedContextGovernance.qnt";
                attribute quintMain : String = "shared_context_governance";
                attribute itfSubdir : String = "shared-context-governance";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "private-scope-isolation,owner-only-scope-promotion,share-membership-current,multi-party-taint-gate";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/zero-trust/shared-context-governance/SharedContextGovernance.qnt,packages/quint-models/threat/zero-trust/shared-context-governance/objects.ss,packages/quint-models/threat/zero-trust/shared-context-governance/interface.ss,packages/quint-models/threat/zero-trust/authority-currentness/AuthorityCurrentness.qnt";
                port traceOut : ArtifactHandoffPort;
            }

            part scgLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Threat.SharedContextConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Core.Order,DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Threat.SharedContextConfinement.privateScope_never_readable_by_peer,DeterministicEngineering.Threat.SharedContextConfinement.confidentialScopePromotion_requires_owner_and_declass,DeterministicEngineering.Threat.SharedContextConfinement.revokedAclEpoch_rejects_all_staleHandles,DeterministicEngineering.Threat.SharedContextConfinement.taintedSharedChannel_blocks_toolExec_without_humanGate,DeterministicEngineering.Threat.SharedContextConfinement.sharedContextContract_preserves_rejection,DeterministicEngineering.Threat.SharedContextConfinement.sharedContextAuditTunedCertified,DeterministicEngineering.Threat.SharedContextConfinement.disableTaintGate_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Order.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Threat/SharedContextConfinement.lean";
            }
        }

        // Fourteenth Zero-Glue Subject (Ninth AI-Security Threat Subject: SM32 ADV-L4 GitOps Subprocess Environment Neutralization, Fsmonitor Lockdown & Arg-Injection Confinement)
        part gitopsSubprocessConfinement {
            attribute subjectKey : String = "gitops-subprocess-confinement-and-arg-injection";
            attribute identity : String = "threat.execution.gitops-subprocess-confinement-and-arg-injection";
            attribute tags : String = "threat,execution,ai-security,gitops-confinement,arg-injection,defense.mutability.immutable-proof,hazard.git-env-fsmonitor-arg-injection";
            attribute factors : String = "gitops-subprocess-and-arg-confinement,ai-executes-tools";
            attribute aiControls : String = "tool-confinement";

            part sm32QuintTarget {
                attribute modelId : String = "threat.execution.gitops-subprocess-confinement-and-arg-injection";
                attribute quintFile : String = "packages/quint-models/threat/execution/gitops-subprocess-confinement-and-arg-injection/GitopsSubprocessConfinementAndArgInjection.qnt";
                attribute quintMain : String = "execution_gitops_subprocess_confinement_and_arg_injection";
                attribute itfSubdir : String = "gitops-subprocess-confinement-and-arg-injection";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-git-env-config-or-exec-path-hijack,forbid-repo-fsmonitor-or-hook-execution,forbid-option-injection-or-snapshot-path-escape,forbid-unbounded-subprocess-or-parallel-worker-panic-crash";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/gitops-subprocess-confinement-and-arg-injection/GitopsSubprocessConfinementAndArgInjection.qnt,packages/quint-models/threat/execution/gitops-subprocess-confinement-and-arg-injection/objects.ss,packages/quint-models/threat/execution/gitops-subprocess-confinement-and-arg-injection/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm32LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_git_env_confinement_requires_all_guards,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_hooks_and_fsmonitor_lockdown_complete,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_arg_injection_and_snapshot_escape_refused,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_bounded_capture_refuses_overflow_timeout_or_orphan,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_parallel_panic_isolation_conserves_receipts,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_gentle_pressure_rejected,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_baseline_certified,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_obligation_untouched_by_timeout_tuning,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_timeout_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection.sm32_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/GitopsSubprocessConfinementAndArgInjection.lean";
            }
        }

        // Fifteenth Zero-Glue Subject (Tenth AI-Security Threat Subject: SM26 ADV-L4 Control-Plane Auth, RPC E-Stop & Release-Gate Shell Scrubbing)
        part controlPlaneAuthGovernanceConfinement {
            attribute subjectKey : String = "control-plane-auth-and-governance-confinement";
            attribute identity : String = "threat.execution.control-plane-auth-and-governance-confinement";
            attribute tags : String = "threat,execution,ai-security,control-plane-auth,estop,defense.mutability.immutable-proof,hazard.shadow-auth-estop-bypass";
            attribute factors : String = "control-plane-auth-and-governance-confinement,ai-mutates-host-or-governance,ai-executes-tools";
            attribute aiControls : String = "human-stepup-and-estop,tool-confinement";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part sm26QuintTarget {
                attribute modelId : String = "threat.execution.control-plane-auth-and-governance-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/control-plane-auth-and-governance-confinement/ControlPlaneAuthAndGovernanceConfinement.qnt";
                attribute quintMain : String = "execution_control_plane_auth_and_governance_confinement";
                attribute itfSubdir : String = "control-plane-auth-and-governance-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "enforce-canonical-ct-auth-entrypoint,enforce-control-plane-rpc-estop,scrub-and-bound-release-gate-shell,reject-empty-bearer-credential";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/control-plane-auth-and-governance-confinement/ControlPlaneAuthAndGovernanceConfinement.qnt,packages/quint-models/threat/execution/control-plane-auth-and-governance-confinement/objects.ss,packages/quint-models/threat/execution/control-plane-auth-and-governance-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm26LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_empty_bearer_payload_rejected_fail_closed,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_non_loopback_default_token_rejected,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_estop_blocks_all_mutating_control_plane_surfaces,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_release_shell_scrubs_host_secrets,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_step_preserves_safety,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_compound_adv_l4_zero_bypass_invariant,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_marlin_control_plane_refinement_laws,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_baseline_certified,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_obligation_untouched_by_output_cap_tuning,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_output_cap_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement.sm26_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/ControlPlaneAuthAndGovernanceConfinement.lean";
            }
        }

        // Sixteenth Zero-Glue Subject (Eleventh AI-Security Threat Subject: SM33 ADV-L4 Hook Policy Dispatch, Trust-Floor Immutability & SubAgent Protocol Confinement)
        part hookPolicyProtocolConfinement {
            attribute subjectKey : String = "hook-policy-and-protocol-contract-confinement";
            attribute identity : String = "threat.execution.hook-policy-and-protocol-contract-confinement";
            attribute tags : String = "threat,execution,ai-security,hook-policy,subagent-protocol,defense.mutability.immutable-proof,hazard.hook-shadow-trust-masking";
            attribute factors : String = "hook-policy-and-protocol-contract-confinement,ai-executes-tools,ai-delegates-authority";
            attribute aiControls : String = "tool-confinement,monotonic-attenuation,revocation-currentness";

            part sm33QuintTarget {
                attribute modelId : String = "threat.execution.hook-policy-and-protocol-contract-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/hook-policy-and-protocol-contract-confinement/HookPolicyAndProtocolContractConfinement.qnt";
                attribute quintMain : String = "execution_hook_policy_and_protocol_contract_confinement";
                attribute itfSubdir : String = "hook-policy-and-protocol-contract-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-toml-unknown-field-failopen-or-unbounded-config,forbid-duplicate-hook-shadow-or-unbounded-async-fanout,forbid-trust-rejection-masking-or-dynamic-action-flood,forbid-subagent-contradiction-serde-bypass-or-endpoint-injection";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/hook-policy-and-protocol-contract-confinement/HookPolicyAndProtocolContractConfinement.qnt,packages/quint-models/threat/execution/hook-policy-and-protocol-contract-confinement/objects.ss,packages/quint-models/threat/execution/hook-policy-and-protocol-contract-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm33LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_hook_toml_config_fail_closed,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_rust_trust_rejection_immutable_under_extension,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_subagent_policy_refuses_contradiction_zero_budget_and_runaway,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_protocol_identifier_refuses_blank_control_and_meta,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_gentle_pressure_rejected,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_baseline_certified,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_obligation_untouched_by_concurrency_tuning,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_concurrency_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement.sm33_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/HookPolicyAndProtocolContractConfinement.lean";
            }
        }

        // Seventeenth Zero-Glue Subject (Twelfth AI-Security Threat Subject: SM28 ADV-L4 Plugin Capability Grant, Release Anti-Rollback & Device-Lease Confinement)
        part pluginGrantRollbackLeaseConfinement {
            attribute subjectKey : String = "plugin-grant-rollback-and-lease-confinement";
            attribute identity : String = "threat.execution.plugin-grant-rollback-and-lease-confinement";
            attribute tags : String = "threat,execution,ai-security,plugin-grant,anti-rollback,defense.mutability.immutable-proof,hazard.plugin-grant-rollback-hijack";
            attribute factors : String = "plugin-grant-rollback-and-lease-confinement,ai-delegates-authority,ai-executes-tools";
            attribute aiControls : String = "monotonic-attenuation,revocation-currentness,tool-confinement";

            part sm28QuintTarget {
                attribute modelId : String = "threat.execution.plugin-grant-rollback-and-lease-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/plugin-grant-rollback-and-lease-confinement/PluginGrantRollbackAndLeaseConfinement.qnt";
                attribute quintMain : String = "execution_plugin_grant_rollback_and_lease_confinement";
                attribute itfSubdir : String = "plugin-grant-rollback-and-lease-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-ungranted-panel-activation,forbid-release-rollback-or-publisher-hijack,forbid-forged-device-lease-mutation,forbid-conflicting-idempotency-replay";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/plugin-grant-rollback-and-lease-confinement/PluginGrantRollbackAndLeaseConfinement.qnt,packages/quint-models/threat/execution/plugin-grant-rollback-and-lease-confinement/objects.ss,packages/quint-models/threat/execution/plugin-grant-rollback-and-lease-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm28LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_version_downgrade_rejected,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_cross_publisher_hijack_rejected,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_unconfined_entry_path_rejected,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_conflicting_idempotency_refused,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_matching_idempotency_replays,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_gentle_pressure_rejected,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_baseline_certified,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_obligation_untouched_by_retention_tuning,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_retention_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement.sm28_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/PluginGrantRollbackAndLeaseConfinement.lean";
            }
        }

        // Eighteenth Zero-Glue Subject (Thirteenth AI-Security Threat Subject: SM29 ADV-L4 Governance Policy Cedar Fail-Closed & Durable E-Stop Latch Anti-Rollback)
        part governancePolicyLatchAntirollback {
            attribute subjectKey : String = "governance-policy-and-latch-antirollback";
            attribute identity : String = "threat.execution.governance-policy-and-latch-antirollback";
            attribute tags : String = "threat,execution,ai-security,governance-latch,anti-rollback,defense.mutability.immutable-proof,hazard.policy-latch-rollback-resurrection";
            attribute factors : String = "governance-policy-and-latch-antirollback,ai-mutates-host-or-governance";
            attribute aiControls : String = "human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part sm29QuintTarget {
                attribute modelId : String = "threat.execution.governance-policy-and-latch-antirollback";
                attribute quintFile : String = "packages/quint-models/threat/execution/governance-policy-and-latch-antirollback/GovernancePolicyAndLatchAntirollback.qnt";
                attribute quintMain : String = "execution_governance_policy_and_latch_antirollback";
                attribute itfSubdir : String = "governance-policy-and-latch-antirollback";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-unless-missing-context-failopen,forbid-same-epoch-policy-revision-rollback,forbid-same-epoch-estop-checkpoint-replay,forbid-rearm-resurrecting-retracted-derivation";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/governance-policy-and-latch-antirollback/GovernancePolicyAndLatchAntirollback.qnt,packages/quint-models/threat/execution/governance-policy-and-latch-antirollback/objects.ss,packages/quint-models/threat/execution/governance-policy-and-latch-antirollback/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm29LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_unless_missing_context_fails_closed_for_both_effects,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_same_epoch_revision_rollback_rejected,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_same_epoch_tripped_undeny_rejected,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_same_epoch_checkpoint_cannot_untrip_estop,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_stale_epoch_checkpoint_rejected,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_rearm_preserves_retracted_derivations,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_gentle_pressure_rejected,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_baseline_certified,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_obligation_untouched_by_lease_bound_tuning,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_lease_bound_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback.sm29_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/GovernancePolicyAndLatchAntirollback.lean";
            }
        }

        // Nineteenth Zero-Glue Subject (Fourteenth AI-Security Threat Subject: SM24 ADV-L4 Subprocess Environment Allowlist Scrubbing & Constant-Time Bearer Auth)
        part subprocessEnvScrubAuthTiming {
            attribute subjectKey : String = "subprocess-env-scrub-and-auth-timing";
            attribute identity : String = "threat.execution.subprocess-env-scrub-and-auth-timing";
            attribute tags : String = "threat,execution,ai-security,env-scrub,constant-time-auth,defense.mutability.immutable-proof,hazard.ambient-secret-leak-timing-oracle";
            attribute factors : String = "subprocess-env-scrub-and-auth-timing,ai-executes-tools";
            attribute aiControls : String = "tool-confinement";

            part sm24QuintTarget {
                attribute modelId : String = "threat.execution.subprocess-env-scrub-and-auth-timing";
                attribute quintFile : String = "packages/quint-models/threat/execution/subprocess-env-scrub-and-auth-timing/SubprocessEnvScrubAndAuthTiming.qnt";
                attribute quintMain : String = "execution_subprocess_env_scrub_and_auth_timing";
                attribute itfSubdir : String = "subprocess-env-scrub-and-auth-timing";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "scrub-sandbox-env-allowlist,scrub-plugin-build-env-allowlist,constant-time-bearer-verify,reject-blank-auth-and-stdin-inherit";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/subprocess-env-scrub-and-auth-timing/SubprocessEnvScrubAndAuthTiming.qnt,packages/quint-models/threat/execution/subprocess-env-scrub-and-auth-timing/objects.ss,packages/quint-models/threat/execution/subprocess-env-scrub-and-auth-timing/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm24LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_scrubbed_env_subset_of_allowlist,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_allowlist_scrub_drops_all_secrets,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_blank_expected_bearer_rejected,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_nonblank_bearer_exact_match,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_compound_adv_l4_zero_leak_invariant,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_gentle_pressure_rejected,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_marlin_mygo_preserves_rejection,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_marlin_mygo_accepts_iff,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_baseline_certified,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_obligation_untouched_by_output_tuning,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_output_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming.sm24_security_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/SubprocessEnvScrubAndAuthTiming.lean";
            }
        }

        // Twentieth Zero-Glue Subject (Fifteenth AI-Security Threat Subject: SM31 ADV-L4 Storage Boundary Integrity, CAS Digest Binding & Sync TLS Confinement)
        part storageBoundaryIntegritySyncConfinement {
            attribute subjectKey : String = "storage-boundary-integrity-and-sync-confinement";
            attribute identity : String = "threat.execution.storage-boundary-integrity-and-sync-confinement";
            attribute tags : String = "threat,execution,ai-security,storage-cas-integrity,sync-tls,defense.mutability.immutable-proof,hazard.cas-poisoning-cleartext-sync";
            attribute factors : String = "storage-boundary-integrity-and-sync-confinement,ai-ingests-untrusted-context,ai-executes-tools";
            attribute aiControls : String = "context-integrity-or-ifc,tool-confinement";

            part sm31QuintTarget {
                attribute modelId : String = "threat.execution.storage-boundary-integrity-and-sync-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/storage-boundary-integrity-and-sync-confinement/StorageBoundaryIntegrityAndSyncConfinement.qnt";
                attribute quintMain : String = "execution_storage_boundary_integrity_and_sync_confinement";
                attribute itfSubdir : String = "storage-boundary-integrity-and-sync-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-serde-bypass-empty-id-or-unbounded-page,forbid-artifact-size-lie-or-sha256-cas-poisoning,forbid-cleartext-remote-sync-or-userinfo-smuggle,forbid-context-index-same-rev-overwrite-or-cas-receipt-crash";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/storage-boundary-integrity-and-sync-confinement/StorageBoundaryIntegrityAndSyncConfinement.qnt,packages/quint-models/threat/execution/storage-boundary-integrity-and-sync-confinement/objects.ss,packages/quint-models/threat/execution/storage-boundary-integrity-and-sync-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm31LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_deserialized_page_limit_bounds,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_artifact_integrity_refuses_size_lie_and_digest_poison,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_sync_url_refuses_remote_cleartext_and_smuggling,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_finalized_rebuild_divergent_cuts_returns_conflict,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_gentle_pressure_rejected,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_baseline_certified,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_obligation_untouched_by_page_tuning,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_page_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement.sm31_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/StorageBoundaryIntegrityAndSyncConfinement.lean";
            }
        }

        // Twenty-First Zero-Glue Subject (Sixteenth AI-Security Threat Subject: SM25 ADV-L4 Single-Owner Graph Execution Convergence & Production Governance Confinement)
        part singleOwnerGraphGovernanceConfinement {
            attribute subjectKey : String = "single-owner-graph-governance-confinement";
            attribute identity : String = "threat.execution.single-owner-graph-governance-confinement";
            attribute tags : String = "threat,execution,ai-security,single-owner-graph,complete-mediation,defense.mutability.immutable-proof,hazard.disconnected-governance-shadow-engine";
            attribute factors : String = "single-owner-graph-governance-confinement,ai-executes-tools,ai-mutates-host-or-governance";
            attribute aiControls : String = "tool-confinement,human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part sm25QuintTarget {
                attribute modelId : String = "threat.execution.single-owner-graph-governance-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/single-owner-graph-governance-confinement/SingleOwnerGraphGovernanceConfinement.qnt";
                attribute quintMain : String = "execution_single_owner_graph_governance_confinement";
                attribute itfSubdir : String = "single-owner-graph-governance-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "wire-prod-executor-governance-gate,retire-shadow-legacy-engine,fail-closed-tripped-breaker,bind-fencing-and-governance-epoch";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/single-owner-graph-governance-confinement/SingleOwnerGraphGovernanceConfinement.qnt,packages/quint-models/threat/execution/single-owner-graph-governance-confinement/objects.ss,packages/quint-models/threat/execution/single-owner-graph-governance-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm25LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_tripped_breaker_blocks_all_effects,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_cedar_ascent_epoch_and_shadow_blocked,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_disconnected_governance_allows_bypass,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_shadow_legacy_breaks_single_owner,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_compound_adv_l4_zero_bypass_invariant,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_gentle_pressure_rejected,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_marlin_graph_gov_preserves_rejection,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_marlin_graph_gov_accepts_iff,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_baseline_certified,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_obligation_untouched_by_budget_tuning,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_budget_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement.sm25_architecture_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/SingleOwnerGraphGovernanceConfinement.lean";
            }
        }

        // Twenty-Second Zero-Glue Subject (Seventeenth AI-Security Threat Subject: SM36 ADV-L4 Telemetry/Watchdog & Deck Single-VM Confinement)
        part telemetryWatchdogDeckVmConfinement {
            attribute subjectKey : String = "telemetry-watchdog-and-deck-vm-confinement";
            attribute identity : String = "threat.execution.telemetry-watchdog-and-deck-vm-confinement";
            attribute tags : String = "threat,execution,ai-security,telemetry-tls,watchdog-clock,deck-vm-bounds,defense.mutability.immutable-proof,hazard.otlp-exfil-watchdog-blinding";
            attribute factors : String = "telemetry-watchdog-and-deck-vm-confinement,ai-executes-tools,ai-ingests-untrusted-context";
            attribute aiControls : String = "tool-confinement,context-integrity-or-ifc";

            part sm36QuintTarget {
                attribute modelId : String = "threat.execution.telemetry-watchdog-and-deck-vm-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/telemetry-watchdog-and-deck-vm-confinement/TelemetryWatchdogAndDeckVmConfinement.qnt";
                attribute quintMain : String = "execution_telemetry_watchdog_and_deck_vm_confinement";
                attribute itfSubdir : String = "telemetry-watchdog-and-deck-vm-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-cleartext-remote-otlp-endpoint,forbid-unscrubbed-host-observer-env-leak,forbid-watchdog-future-timestamp-blinding,forbid-deck-vm-unbounded-controls-or-timer-pinning";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/telemetry-watchdog-and-deck-vm-confinement/TelemetryWatchdogAndDeckVmConfinement.qnt,packages/quint-models/threat/execution/telemetry-watchdog-and-deck-vm-confinement/objects.ss,packages/quint-models/threat/execution/telemetry-watchdog-and-deck-vm-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm36LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_otlp_export_fail_closed,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_host_observer_spawn_fail_closed,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_watchdog_future_timestamp_and_zero_attach_fail_closed,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_deck_vm_bounds_fail_closed,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_gentle_pressure_rejected,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_baseline_certified,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_obligation_untouched_by_timer_budget_tuning,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_timer_budget_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement.sm36_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/TelemetryWatchdogAndDeckVmConfinement.lean";
            }
        }

        // Twenty-Third Zero-Glue Subject (Eighteenth AI-Security Threat Subject: SM37 ADV-L4 Process Signal, Ledger & Sub-Agent Fanout Confinement)
        part processSignalLedgerFanoutConfinement {
            attribute subjectKey : String = "process-signal-ledger-and-fanout-confinement";
            attribute identity : String = "threat.execution.process-signal-ledger-and-fanout-confinement";
            attribute tags : String = "threat,execution,ai-security,process-signal-guard,subagent-fanout,defense.mutability.immutable-proof,hazard.pid-reuse-fanout-exhaustion";
            attribute factors : String = "process-signal-ledger-and-fanout-confinement,ai-executes-tools,ai-mutates-host-or-governance";
            attribute aiControls : String = "tool-confinement,human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part sm37QuintTarget {
                attribute modelId : String = "threat.execution.process-signal-ledger-and-fanout-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/process-signal-ledger-and-fanout-confinement/ProcessSignalLedgerAndFanoutConfinement.qnt";
                attribute quintMain : String = "execution_process_signal_ledger_and_fanout_confinement";
                attribute itfSubdir : String = "process-signal-ledger-and-fanout-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "forbid-protected-pid-or-pgid-kill,forbid-unfingerprinted-pid-reuse-reap,forbid-symlink-or-unbounded-process-ledger,forbid-unbounded-fanout-or-undrained-abort";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/process-signal-ledger-and-fanout-confinement/ProcessSignalLedgerAndFanoutConfinement.qnt,packages/quint-models/threat/execution/process-signal-ledger-and-fanout-confinement/objects.ss,packages/quint-models/threat/execution/process-signal-ledger-and-fanout-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm37LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_protected_pid_pgid_fail_closed,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_orphan_identity_fail_closed,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_process_ledger_bounds_fail_closed,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_fanout_cap_and_drain_fail_closed,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_strict_admission_eliminates_all_exploits,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_gentle_pressure_rejected,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_defective_configs_expose_live_exploits,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_marlin_contract_refinement_laws,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_baseline_certified,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_obligation_untouched_by_terminal_retention_tuning,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_terminal_retention_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement.sm37_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/ProcessSignalLedgerAndFanoutConfinement.lean";
            }
        }

        // Twenty-Fourth Zero-Glue Subject (Nineteenth AI-Security Threat Subject: Wasm Linear-Memory, WASI Capability & Preopen Path Confinement)
        part wasmSandboxConfinement {
            attribute subjectKey : String = "wasm-sandbox-confinement";
            attribute identity : String = "threat.execution.wasm-sandbox-confinement";
            attribute tags : String = "threat,execution,ai-security,wasm-sandbox,wasi-capability,defense.mutability.immutable-proof,hazard.sandbox-escape-ambient-fd";
            attribute factors : String = "wasm-sandbox-confinement,ai-executes-tools";
            attribute aiControls : String = "tool-confinement";

            part wasmQuintTarget {
                attribute modelId : String = "threat.execution.wasm-sandbox-confinement";
                attribute quintFile : String = "packages/quint-models/threat/execution/wasm-sandbox-confinement/WasmSandboxConfinement.qnt";
                attribute quintMain : String = "wasm_sandbox_confinement";
                attribute itfSubdir : String = "wasm-sandbox-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "wasm-bounds-check,wasi-capability-handle,preopen-path-confinement";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/execution/wasm-sandbox-confinement/WasmSandboxConfinement.qnt,packages/quint-models/threat/execution/wasm-sandbox-confinement/objects.ss,packages/quint-models/threat/execution/wasm-sandbox-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part wasmLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Threat.WasmSandboxConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Core.Budget,DeterministicEngineering.Core.Order,DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Threat.WasmSandboxConfinement.wasmMemAccess_oob_rejected,DeterministicEngineering.Threat.WasmSandboxConfinement.wasmHostcall_ungranted_or_escape_rejected,DeterministicEngineering.Threat.WasmSandboxConfinement.wasmSandbox_linearMemory_bounded,DeterministicEngineering.Threat.WasmSandboxConfinement.wasmSandbox_revokedEpoch_blocks_staleInstance,DeterministicEngineering.Threat.WasmSandboxConfinement.wasmSandboxContract_preserves_rejection,DeterministicEngineering.Threat.WasmSandboxConfinement.wasmFuelBudgetTunedCertified,DeterministicEngineering.Threat.WasmSandboxConfinement.disableBoundsCheck_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Budget.lean,packages/lean-models/DeterministicEngineering/Core/Order.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Threat/WasmSandboxConfinement.lean";
            }
        }

        // Twenty-Fifth Zero-Glue Subject (Twentieth AI-Security Threat Subject — Supply-Chain Domain: SLSA L3/L4 Hermetic Provenance & Reproducible Build)
        part slsaHermeticProvenance {
            attribute subjectKey : String = "slsa-hermetic-provenance";
            attribute identity : String = "threat.supply-chain.slsa-hermetic-provenance";
            attribute tags : String = "threat,supply-chain,ai-security,slsa-provenance,anti-slopsquatting,defense.mutability.immutable-proof,hazard.compromised-builder-injection";
            attribute factors : String = "slsa-hermetic-provenance,ai-ingests-untrusted-context,ai-executes-tools";
            attribute aiControls : String = "context-integrity-or-ifc,tool-confinement";

            part slsaQuintTarget {
                attribute modelId : String = "threat.supply-chain.slsa-hermetic-provenance";
                attribute quintFile : String = "packages/quint-models/threat/supply-chain/slsa-hermetic-provenance/SlsaHermeticProvenance.qnt";
                attribute quintMain : String = "slsa_hermetic_provenance";
                attribute itfSubdir : String = "slsa-hermetic-provenance";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "slsa-provenance-signed,slsa-source-digest-match,slsa-reproducible-match";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/supply-chain/slsa-hermetic-provenance/SlsaHermeticProvenance.qnt,packages/quint-models/threat/supply-chain/slsa-hermetic-provenance/objects.ss,packages/quint-models/threat/supply-chain/slsa-hermetic-provenance/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part slsaLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.SupplyChainProvenance";
                attribute refinesCore : String = "DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.SupplyChainProvenance.unpinned_dependency_always_refused,DeterministicEngineering.Engineering.SupplyChainProvenance.tombstoned_cve_dependency_always_refused,DeterministicEngineering.Engineering.SupplyChainProvenance.non_hermetic_network_build_always_refused,DeterministicEngineering.Engineering.SupplyChainProvenance.reproducible_build_mismatch_always_refused,DeterministicEngineering.Engineering.SupplyChainProvenance.forged_or_revoked_builder_signature_refused,DeterministicEngineering.Engineering.SupplyChainProvenance.mismatched_source_or_toolchain_digest_refused,DeterministicEngineering.Engineering.SupplyChainProvenance.hermetic_provenance_admit_sound_and_complete,DeterministicEngineering.Engineering.SupplyChainProvenance.supplyChainContract_preserves_rejection,DeterministicEngineering.Engineering.SupplyChainProvenance.baselineSupplyChainCertified,DeterministicEngineering.Engineering.SupplyChainProvenance.buildLogVerbosityTuning_preserves_certificate,DeterministicEngineering.Engineering.SupplyChainProvenance.disablingLockfilePinning_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/SupplyChainProvenance.lean";
            }
        }

        // Twenty-Sixth Zero-Glue Subject (Twenty-First AI-Security Threat Subject — Protocol Domain: SM23 ADV-L4 Outbound HTTP Redirect, SSRF & Credential Confinement)
        part outboundHttpRedirectSsrfConfinement {
            attribute subjectKey : String = "outbound-http-redirect-ssrf-confinement";
            attribute identity : String = "threat.protocol.outbound-http-redirect-ssrf-confinement";
            attribute tags : String = "threat,protocol,ai-security,ssrf-confinement,http-redirect-ban,defense.mutability.immutable-proof,hazard.ssrf-credential-exfil";
            attribute factors : String = "outbound-http-redirect-ssrf-confinement,ai-executes-tools,ai-ingests-untrusted-context";
            attribute aiControls : String = "tool-confinement,context-integrity-or-ifc";

            part sm23QuintTarget {
                attribute modelId : String = "threat.protocol.outbound-http-redirect-ssrf-confinement";
                attribute quintFile : String = "packages/quint-models/threat/protocol/outbound-http-redirect-ssrf-confinement/OutboundHttpRedirectSsrfConfinement.qnt";
                attribute quintMain : String = "protocol_outbound_http_redirect_ssrf_confinement";
                attribute itfSubdir : String = "outbound-http-redirect-ssrf-confinement";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "disable-http-redirects,enforce-https-for-remote-credentials,confine-download-url-origin,reject-userinfo-and-symlink-serve";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/protocol/outbound-http-redirect-ssrf-confinement/OutboundHttpRedirectSsrfConfinement.qnt,packages/quint-models/threat/protocol/outbound-http-redirect-ssrf-confinement/objects.ss,packages/quint-models/threat/protocol/outbound-http-redirect-ssrf-confinement/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm23LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_no_redirect_blocks_all_3xx_ssrf,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_remote_cleartext_credential_leak_impossible,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_download_url_origin_confinement_blocks_ssrf_and_downgrade,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_userinfo_and_control_char_rejection_prevents_authority_spoof,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_lstat_serve_policy_blocks_symlink_file_disclosure,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_compound_adv_l4_zero_escape_invariant,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_compound_adv_l4_blocks_every_hostile_probe,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_gentle_tier_rejected_by_outbound_http_gate,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_weaver_mygo_preserves_rejection,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_weaver_mygo_accepts_iff,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.baselineWeaverHttpCertified,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.httpObligationUntouchedByTimeoutTuning,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_timeout_tuning_certified,DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement.sm23_security_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/OutboundHttpRedirectSsrfConfinement.lean";
            }
        }

        // Twenty-Seventh Zero-Glue Subject (Twenty-Second AI-Security Threat Subject — Zero-Trust Domain: Governance SoD & Durable BFT Quorum)
        part governanceSod {
            attribute subjectKey : String = "governance-sod";
            attribute identity : String = "threat.zero-trust.governance-sod";
            attribute tags : String = "threat,zero-trust,ai-security,governance-sod,bft-quorum,defense.mutability.immutable-proof,hazard.ai-self-approval-veto-override";
            attribute factors : String = "governance-sod,ai-mutates-host-or-governance";
            attribute aiControls : String = "human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part gsodQuintTarget {
                attribute modelId : String = "threat.zero-trust.governance-sod";
                attribute quintFile : String = "packages/quint-models/threat/zero-trust/governance-sod/GovernanceSod.qnt";
                attribute quintMain : String = "governance_sod";
                attribute itfSubdir : String = "governance-sod";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "sod-distinct-actor,veto-precedence";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/zero-trust/governance-sod/GovernanceSod.qnt,packages/quint-models/threat/zero-trust/governance-sod/objects.ss,packages/quint-models/threat/zero-trust/governance-sod/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part gsodLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.DurableGovernanceQuorum";
                attribute refinesCore : String = "DeterministicEngineering.Core.Order,DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Patch.frame+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.DurableGovernanceQuorum.bft_quorum_intersection_honest_witness,DeterministicEngineering.Engineering.DurableGovernanceQuorum.bft_no_conflicting_finality,DeterministicEngineering.Engineering.DurableGovernanceQuorum.handover_chain_rejects_all_retired_epochs,DeterministicEngineering.Engineering.DurableGovernanceQuorum.m3_leak_always_refused,DeterministicEngineering.Engineering.DurableGovernanceQuorum.ancestor_revocation_invalidates_chain,DeterministicEngineering.Engineering.DurableGovernanceQuorum.durableQuorumContract_preserves_rejection,DeterministicEngineering.Engineering.DurableGovernanceQuorum.baselineQuorumCertified,DeterministicEngineering.Engineering.DurableGovernanceQuorum.gossipTuning_preserves_quorum_certificate,DeterministicEngineering.Engineering.DurableGovernanceQuorum.droppingExternalPolicyHost_invalidates_reuse,DeterministicEngineering.Engineering.DurableGovernanceQuorum.slashed_witness_never_reenters_future_epochs";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Order.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/DurableGovernanceQuorum.lean";
            }
        }

        // Twenty-Eighth Zero-Glue Subject (Twenty-Third AI-Security Threat Subject — Protocol Domain: Multi-Role AI Chatroom Ingress & Context Distillation Provenance)
        part chatroomIngressGovernance {
            attribute subjectKey : String = "chatroom-ingress-governance";
            attribute identity : String = "threat.protocol.chatroom-ingress-governance";
            attribute tags : String = "threat,protocol,ai-security,chatroom-ingress,context-distillation,defense.mutability.immutable-proof,hazard.tainted-tool-bypass-context-laundering";
            attribute factors : String = "chatroom-ingress-governance,ai-ingests-untrusted-context,ai-executes-tools,ai-mutates-host-or-governance";
            attribute aiControls : String = "context-integrity-or-ifc,tool-confinement,human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part chatQuintTarget {
                attribute modelId : String = "threat.protocol.chatroom-ingress-governance";
                attribute quintFile : String = "packages/quint-models/threat/protocol/chatroom-ingress-governance/ChatroomIngressGovernance.qnt";
                attribute quintMain : String = "chatroom_ingress_governance";
                attribute itfSubdir : String = "chatroom-ingress-governance";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "ingress-origin-provenance,channel-thread-affinity,gate-oneshot-pending,matter-gate-lock,tainted-tool-human-gate";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/protocol/chatroom-ingress-governance/ChatroomIngressGovernance.qnt,packages/quint-models/threat/protocol/chatroom-ingress-governance/objects.ss,packages/quint-models/threat/protocol/chatroom-ingress-governance/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part chatLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.ContextDistillationAndProvenance";
                attribute refinesCore : String = "DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.ContextDistillationAndProvenance.dropping_pinned_m1_constraint_always_refused,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.hallucinated_citation_always_refused,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.secrecy_tag_stripping_by_summarizer_refused,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.integrity_laundering_untrusted_to_trusted_refused,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.distilled_context_exceeding_token_budget_refused,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.empty_sources_with_zero_citations_and_budget_admitted,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.retained_pinned_subset_monotonic_under_append,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.distillationContract_preserves_rejection,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.baselineDistillationCertified,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.summaryPromptVersionTuning_preserves_distillation_certificate,DeterministicEngineering.Engineering.ContextDistillationAndProvenance.disablingPinnedRetention_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/ContextDistillationAndProvenance.lean";
            }
        }

        // Twenty-Ninth Zero-Glue Subject (Twenty-Fourth AI-Security Threat Subject — Zero-Trust Domain: Data Lineage Disclosure, DIFC Non-Interference & ATMS Retraction)
        part dataLineageDisclosure {
            attribute subjectKey : String = "data-lineage-disclosure";
            attribute identity : String = "threat.zero-trust.data-lineage-disclosure";
            attribute tags : String = "threat,zero-trust,ai-security,data-lineage,difc-atms,defense.mutability.immutable-proof,hazard.singling-out-exfiltration";
            attribute factors : String = "data-lineage-disclosure,ai-ingests-untrusted-context";
            attribute aiControls : String = "context-integrity-or-ifc";

            part dldQuintTarget {
                attribute modelId : String = "threat.zero-trust.data-lineage-disclosure";
                attribute quintFile : String = "packages/quint-models/threat/zero-trust/data-lineage-disclosure/DataLineageDisclosure.qnt";
                attribute quintMain : String = "data_lineage_disclosure";
                attribute itfSubdir : String = "data-lineage-disclosure";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "k-anonymity-narrowing,disclosure-budget";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/zero-trust/data-lineage-disclosure/DataLineageDisclosure.qnt,packages/quint-models/threat/zero-trust/data-lineage-disclosure/objects.ss,packages/quint-models/threat/zero-trust/data-lineage-disclosure/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part dldLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.InformationFlowAndTms";
                attribute refinesCore : String = "DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.InformationFlowAndTms.difc_secrecy_monotonic_without_declass,DeterministicEngineering.Engineering.InformationFlowAndTms.difc_no_write_down_blocks_exfiltration,DeterministicEngineering.Engineering.InformationFlowAndTms.difc_failed_declass_preserves_taint,DeterministicEngineering.Engineering.InformationFlowAndTms.camel_integrity_meet_never_elevates,DeterministicEngineering.Engineering.InformationFlowAndTms.camel_control_slot_blocks_untrusted,DeterministicEngineering.Engineering.InformationFlowAndTms.doyle_single_justification_retraction_cascades,DeterministicEngineering.Engineering.InformationFlowAndTms.atms_clean_alternative_justification_survives,DeterministicEngineering.Engineering.InformationFlowAndTms.poison_immunization_tombstone_blocks_reproposal,DeterministicEngineering.Engineering.InformationFlowAndTms.difcAtmsContract_preserves_rejection,DeterministicEngineering.Engineering.InformationFlowAndTms.baselineInfoFlowCertified,DeterministicEngineering.Engineering.InformationFlowAndTms.retentionTuning_preserves_difc_atms_certificate,DeterministicEngineering.Engineering.InformationFlowAndTms.disablingCamelIntegrity_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/InformationFlowAndTms.lean";
            }
        }

        // Thirtieth Zero-Glue Subject (Twenty-Fifth AI-Security Threat Subject — Supply-Chain Domain: TUF Anti-Rollback & Deterministic Model-Weight/Inference Attestation)
        part supplyChainTuf {
            attribute subjectKey : String = "supply-chain-tuf";
            attribute identity : String = "threat.supply-chain.supply-chain-tuf";
            attribute tags : String = "threat,supply-chain,ai-security,tuf-antirollback,model-weight-attestation,defense.mutability.immutable-proof,hazard.model-weight-rollback-lora-poisoning";
            attribute factors : String = "supply-chain-tuf,ai-ingests-untrusted-context,ai-executes-tools";
            attribute aiControls : String = "context-integrity-or-ifc,tool-confinement";

            part tufQuintTarget {
                attribute modelId : String = "threat.supply-chain.supply-chain-tuf";
                attribute quintFile : String = "packages/quint-models/threat/supply-chain/supply-chain-tuf/SupplyChainTuf.qnt";
                attribute quintMain : String = "supply_chain_tuf";
                attribute itfSubdir : String = "supply-chain-tuf";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "monotonic-version-check,timestamp-expiry-check,snapshot-atomic-binding";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/supply-chain/supply-chain-tuf/SupplyChainTuf.qnt,packages/quint-models/threat/supply-chain/supply-chain-tuf/objects.ss,packages/quint-models/threat/supply-chain/supply-chain-tuf/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part tufLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation";
                attribute refinesCore : String = "DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.unpinned_base_weight_refused,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.unauthorized_lora_adapter_refused,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.non_deterministic_sampling_temperature_refused,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.missing_seed_or_kernel_pin_refused,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.forged_or_revoked_model_attestation_refused,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.clean_zero_adapter_base_model_admitted,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.model_inference_attestation_sound_and_complete,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.modelAttestationContract_preserves_rejection,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.baselineModelAttestationCertified,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.kvCacheEvictionTuning_preserves_certificate,DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.disablingWeightRootPinning_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/ModelWeightAndInferenceAttestation.lean";
            }
        }

        // Thirty-First Zero-Glue Subject (Twenty-Sixth AI-Security Threat Subject — Zero-Trust Domain: PEP/PDP Policy-Epoch Currency & SM27 Policy-Gate Blind-Spot/Cycle Confinement)
        part zeroTrustPepPdp {
            attribute subjectKey : String = "zero-trust-pep-pdp";
            attribute identity : String = "threat.zero-trust.zero-trust-pep-pdp";
            attribute tags : String = "threat,zero-trust,ai-security,pep-pdp-currency,policy-gate-blindspot,defense.mutability.immutable-proof,hazard.stale-policy-cycle-blindspot";
            attribute factors : String = "zero-trust-pep-pdp,ai-mutates-host-or-governance";
            attribute aiControls : String = "human-stepup-and-estop";
            attribute aiRoleBindings : String = "human-approver:human-approver,ai-agent:ai-proposer";

            part pepQuintTarget {
                attribute modelId : String = "threat.zero-trust.zero-trust-pep-pdp";
                attribute quintFile : String = "packages/quint-models/threat/zero-trust/zero-trust-pep-pdp/ZeroTrustPepPdp.qnt";
                attribute quintMain : String = "zero_trust_pep_pdp";
                attribute itfSubdir : String = "zero-trust-pep-pdp";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "policy-epoch-currency,policy-active";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/zero-trust/zero-trust-pep-pdp/ZeroTrustPepPdp.qnt,packages/quint-models/threat/zero-trust/zero-trust-pep-pdp/objects.ss,packages/quint-models/threat/zero-trust/zero-trust-pep-pdp/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part sm27LeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement";
                attribute refinesCore : String = "DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_strict_admission_eliminates_all_blindspots,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_cycle_blinded_workspace_fails_admission,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_ungated_or_downgraded_fails_admission,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_fat_entrypoint_fails_admission,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_ci_omission_fails_admission,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_gentle_pressure_tiers_rejected,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_breaking_cycles_restores_gate_visibility,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_defective_postures_expose_live_exploits,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_marlin_policy_contract_refinement_laws,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_baseline_certified,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_obligation_untouched_by_report_tuning,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_report_tuning_reuses_and_closes_certificate,DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement.sm27_regressions_invalidate_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Engineering/SandboxSymlinkArchiveConfinement.lean,packages/lean-models/DeterministicEngineering/Engineering/PolicyGateBlindspotAndCycleConfinement.lean";
            }
        }

        // Thirty-Second Zero-Glue Subject (Twenty-Seventh AI-Security Threat Subject — Zero-Trust Domain: Multi-Tenant Isolation & MCP/RPC Tool-Sandbox Boundary)
        part multiTenantIsolation {
            attribute subjectKey : String = "multi-tenant-isolation";
            attribute identity : String = "threat.zero-trust.multi-tenant-isolation";
            attribute tags : String = "threat,zero-trust,ai-security,multi-tenant-isolation,mcp-tool-sandbox,defense.mutability.immutable-proof,hazard.cross-tenant-deputy-mcp-rugpull";
            attribute factors : String = "multi-tenant-isolation,ai-executes-tools,ai-ingests-untrusted-context";
            attribute aiControls : String = "tool-confinement,context-integrity-or-ifc";

            part mtiQuintTarget {
                attribute modelId : String = "threat.zero-trust.multi-tenant-isolation";
                attribute quintFile : String = "packages/quint-models/threat/zero-trust/multi-tenant-isolation/MultiTenantIsolation.qnt";
                attribute quintMain : String = "multi_tenant_isolation";
                attribute itfSubdir : String = "multi-tenant-isolation";
                attribute verifyMode : String = "apalache";
                attribute nTraces : String = "10";
                attribute maxSamples : String = "30";
                attribute maxSteps : String = "12";
                attribute countermodels : String = "tenant-resource-match,tenant-membership-current,outbox-tenant-binding";
                attribute producesArtifact : String = "itf-trace";
                attribute inputFiles : String = "packages/quint-models/threat/zero-trust/multi-tenant-isolation/MultiTenantIsolation.qnt,packages/quint-models/threat/zero-trust/multi-tenant-isolation/objects.ss,packages/quint-models/threat/zero-trust/multi-tenant-isolation/interface.ss";
                port traceOut : ArtifactHandoffPort;
            }

            part mtiLeanPooTarget {
                attribute module : String = "DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary";
                attribute refinesCore : String = "DeterministicEngineering.Core.Transport";
                attribute transportContract : String = "ObjectContract.refine+Proof.reuse";
                attribute theorems : String = "DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.unpinned_shadow_tool_always_refused,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.mcp_schema_rug_pull_always_refused,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.sandbox_scope_escalation_always_refused,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.side_effecting_tool_without_idempotency_key_refused,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.ambiguous_rpc_timeout_blocks_blind_retry,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.oversized_or_untagged_tool_output_refused,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.tool_response_admit_iff_bounded_and_tainted,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.toolSandboxContract_preserves_rejection,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.baselineToolSandboxCertified,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.rpcLogSampleRateTuning_preserves_toolSandbox_certificate,DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary.disablingSchemaPinning_invalidates_reuse";
                attribute inputFiles : String = "packages/lean-models/lean-toolchain,packages/lean-models/lakefile.toml,packages/lean-models/DeterministicEngineering.lean,packages/lean-models/DeterministicEngineering/Core/Transport.lean,packages/lean-models/DeterministicEngineering/Engineering/ToolSandboxAndRpcBoundary.lean";
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

    dependency 'lf-quint-source' from system::leaseFencingToken::lfQuintTarget to system::quintModels;
    dependency 'lf-lean-source' from system::leaseFencingToken::lfLeanPooTarget to system::leanModels;
    dependency 'lf-lean-refines-order' from system::leaseFencingToken::lfLeanPooTarget to system::leanModels::core::order;
    dependency 'lf-lean-refines-transport' from system::leaseFencingToken::lfLeanPooTarget to system::leanModels::core::transport;

    dependency 'cb-cbmc-source' from system::cBoundaryConservation::cbCbmcTarget to system::cSubjects;
    dependency 'cb-lean-source' from system::cBoundaryConservation::cbLeanPooTarget to system::leanModels;
    dependency 'cb-lean-refines-conservation' from system::cBoundaryConservation::cbLeanPooTarget to system::leanModels::core::conservation;
    dependency 'cb-lean-refines-transport' from system::cBoundaryConservation::cbLeanPooTarget to system::leanModels::core::transport;

    dependency 'mg-lean-source' from system::metaGovernanceSoundness::mgLeanPooTarget to system::leanModels;
    dependency 'mg-lean-refines-meta' from system::metaGovernanceSoundness::mgLeanPooTarget to system::leanModels::core::metaGovernance;
    dependency 'mg-lean-refines-transport' from system::metaGovernanceSoundness::mgLeanPooTarget to system::leanModels::core::transport;
    dependency 'mg-verifies-governance' from system::metaGovernanceSoundness::mgLeanPooTarget to system::governance;

    dependency 'da-quint-source' from system::delegatedAgentAuthz::daQuintTarget to system::quintModels;
    dependency 'da-lean-source' from system::delegatedAgentAuthz::daLeanPooTarget to system::leanModels;
    dependency 'da-lean-refines-containment' from system::delegatedAgentAuthz::daLeanPooTarget to system::leanModels::core::containment;
    dependency 'da-lean-refines-order' from system::delegatedAgentAuthz::daLeanPooTarget to system::leanModels::core::order;
    dependency 'da-lean-refines-transport' from system::delegatedAgentAuthz::daLeanPooTarget to system::leanModels::core::transport;

    dependency 'sm30-quint-source' from system::stepupAttestationHostConfinement::sm30QuintTarget to system::quintModels;
    dependency 'sm30-lean-source' from system::stepupAttestationHostConfinement::sm30LeanPooTarget to system::leanModels;

    dependency 'sm22-quint-source' from system::sandboxSymlinkArchiveConfinement::sm22QuintTarget to system::quintModels;
    dependency 'sm22-lean-source' from system::sandboxSymlinkArchiveConfinement::sm22LeanPooTarget to system::leanModels;
    dependency 'sm22-lean-refines-conservation' from system::sandboxSymlinkArchiveConfinement::sm22LeanPooTarget to system::leanModels::core::conservation;
    dependency 'sm22-lean-refines-containment' from system::sandboxSymlinkArchiveConfinement::sm22LeanPooTarget to system::leanModels::core::containment;

    dependency 'sm34-quint-source' from system::runtimeEnvActivationContextConfinement::sm34QuintTarget to system::quintModels;
    dependency 'sm34-lean-source' from system::runtimeEnvActivationContextConfinement::sm34LeanPooTarget to system::leanModels;

    dependency 'sm35-quint-source' from system::graphWitnessHarnessConfinement::sm35QuintTarget to system::quintModels;
    dependency 'sm35-lean-source' from system::graphWitnessHarnessConfinement::sm35LeanPooTarget to system::leanModels;

    dependency 'ifc-quint-source' from system::agentIfcCapability::ifcQuintTarget to system::quintModels;
    dependency 'ifc-lean-source' from system::agentIfcCapability::ifcLeanPooTarget to system::leanModels;
    dependency 'ifc-lean-refines-order' from system::agentIfcCapability::ifcLeanPooTarget to system::leanModels::core::order;
    dependency 'ifc-lean-refines-transport' from system::agentIfcCapability::ifcLeanPooTarget to system::leanModels::core::transport;

    dependency 'cb-breaker-quint-source' from system::agentToolCircuitBreaker::cbBreakerQuintTarget to system::quintModels;
    dependency 'cb-breaker-lean-source' from system::agentToolCircuitBreaker::cbBreakerLeanPooTarget to system::leanModels;
    dependency 'cb-breaker-lean-refines-budget' from system::agentToolCircuitBreaker::cbBreakerLeanPooTarget to system::leanModels::core::budget;
    dependency 'cb-breaker-lean-refines-order' from system::agentToolCircuitBreaker::cbBreakerLeanPooTarget to system::leanModels::core::order;
    dependency 'cb-breaker-lean-refines-transport' from system::agentToolCircuitBreaker::cbBreakerLeanPooTarget to system::leanModels::core::transport;

    dependency 'scg-quint-source' from system::sharedContextGovernance::scgQuintTarget to system::quintModels;
    dependency 'scg-lean-source' from system::sharedContextGovernance::scgLeanPooTarget to system::leanModels;
    dependency 'scg-lean-refines-order' from system::sharedContextGovernance::scgLeanPooTarget to system::leanModels::core::order;
    dependency 'scg-lean-refines-transport' from system::sharedContextGovernance::scgLeanPooTarget to system::leanModels::core::transport;

    dependency 'sm32-quint-source' from system::gitopsSubprocessConfinement::sm32QuintTarget to system::quintModels;
    dependency 'sm32-lean-source' from system::gitopsSubprocessConfinement::sm32LeanPooTarget to system::leanModels;

    dependency 'sm26-quint-source' from system::controlPlaneAuthGovernanceConfinement::sm26QuintTarget to system::quintModels;
    dependency 'sm26-lean-source' from system::controlPlaneAuthGovernanceConfinement::sm26LeanPooTarget to system::leanModels;

    dependency 'sm33-quint-source' from system::hookPolicyProtocolConfinement::sm33QuintTarget to system::quintModels;
    dependency 'sm33-lean-source' from system::hookPolicyProtocolConfinement::sm33LeanPooTarget to system::leanModels;

    dependency 'sm28-quint-source' from system::pluginGrantRollbackLeaseConfinement::sm28QuintTarget to system::quintModels;
    dependency 'sm28-lean-source' from system::pluginGrantRollbackLeaseConfinement::sm28LeanPooTarget to system::leanModels;

    dependency 'sm29-quint-source' from system::governancePolicyLatchAntirollback::sm29QuintTarget to system::quintModels;
    dependency 'sm29-lean-source' from system::governancePolicyLatchAntirollback::sm29LeanPooTarget to system::leanModels;

    dependency 'sm24-quint-source' from system::subprocessEnvScrubAuthTiming::sm24QuintTarget to system::quintModels;
    dependency 'sm24-lean-source' from system::subprocessEnvScrubAuthTiming::sm24LeanPooTarget to system::leanModels;

    dependency 'sm31-quint-source' from system::storageBoundaryIntegritySyncConfinement::sm31QuintTarget to system::quintModels;
    dependency 'sm31-lean-source' from system::storageBoundaryIntegritySyncConfinement::sm31LeanPooTarget to system::leanModels;

    dependency 'sm25-quint-source' from system::singleOwnerGraphGovernanceConfinement::sm25QuintTarget to system::quintModels;
    dependency 'sm25-lean-source' from system::singleOwnerGraphGovernanceConfinement::sm25LeanPooTarget to system::leanModels;

    dependency 'sm36-quint-source' from system::telemetryWatchdogDeckVmConfinement::sm36QuintTarget to system::quintModels;
    dependency 'sm36-lean-source' from system::telemetryWatchdogDeckVmConfinement::sm36LeanPooTarget to system::leanModels;

    dependency 'sm37-quint-source' from system::processSignalLedgerFanoutConfinement::sm37QuintTarget to system::quintModels;
    dependency 'sm37-lean-source' from system::processSignalLedgerFanoutConfinement::sm37LeanPooTarget to system::leanModels;

    dependency 'wasm-quint-source' from system::wasmSandboxConfinement::wasmQuintTarget to system::quintModels;
    dependency 'wasm-lean-source' from system::wasmSandboxConfinement::wasmLeanPooTarget to system::leanModels;
    dependency 'wasm-lean-refines-budget' from system::wasmSandboxConfinement::wasmLeanPooTarget to system::leanModels::core::budget;
    dependency 'wasm-lean-refines-order' from system::wasmSandboxConfinement::wasmLeanPooTarget to system::leanModels::core::order;
    dependency 'wasm-lean-refines-transport' from system::wasmSandboxConfinement::wasmLeanPooTarget to system::leanModels::core::transport;

    dependency 'slsa-quint-source' from system::slsaHermeticProvenance::slsaQuintTarget to system::quintModels;
    dependency 'slsa-lean-source' from system::slsaHermeticProvenance::slsaLeanPooTarget to system::leanModels;
    dependency 'slsa-lean-refines-transport' from system::slsaHermeticProvenance::slsaLeanPooTarget to system::leanModels::core::transport;

    dependency 'sm23-quint-source' from system::outboundHttpRedirectSsrfConfinement::sm23QuintTarget to system::quintModels;
    dependency 'sm23-lean-source' from system::outboundHttpRedirectSsrfConfinement::sm23LeanPooTarget to system::leanModels;

    dependency 'gsod-quint-source' from system::governanceSod::gsodQuintTarget to system::quintModels;
    dependency 'gsod-lean-source' from system::governanceSod::gsodLeanPooTarget to system::leanModels;
    dependency 'gsod-lean-refines-order' from system::governanceSod::gsodLeanPooTarget to system::leanModels::core::order;
    dependency 'gsod-lean-refines-transport' from system::governanceSod::gsodLeanPooTarget to system::leanModels::core::transport;

    dependency 'chat-quint-source' from system::chatroomIngressGovernance::chatQuintTarget to system::quintModels;
    dependency 'chat-lean-source' from system::chatroomIngressGovernance::chatLeanPooTarget to system::leanModels;
    dependency 'chat-lean-refines-transport' from system::chatroomIngressGovernance::chatLeanPooTarget to system::leanModels::core::transport;

    dependency 'dld-quint-source' from system::dataLineageDisclosure::dldQuintTarget to system::quintModels;
    dependency 'dld-lean-source' from system::dataLineageDisclosure::dldLeanPooTarget to system::leanModels;
    dependency 'dld-lean-refines-transport' from system::dataLineageDisclosure::dldLeanPooTarget to system::leanModels::core::transport;

    dependency 'tuf-quint-source' from system::supplyChainTuf::tufQuintTarget to system::quintModels;
    dependency 'tuf-lean-source' from system::supplyChainTuf::tufLeanPooTarget to system::leanModels;
    dependency 'tuf-lean-refines-transport' from system::supplyChainTuf::tufLeanPooTarget to system::leanModels::core::transport;

    dependency 'pep-quint-source' from system::zeroTrustPepPdp::pepQuintTarget to system::quintModels;
    dependency 'sm27-lean-source' from system::zeroTrustPepPdp::sm27LeanPooTarget to system::leanModels;

    dependency 'mti-quint-source' from system::multiTenantIsolation::mtiQuintTarget to system::quintModels;
    dependency 'mti-lean-source' from system::multiTenantIsolation::mtiLeanPooTarget to system::leanModels;
    dependency 'mti-lean-refines-transport' from system::multiTenantIsolation::mtiLeanPooTarget to system::leanModels::core::transport;

    // Cross-method edges enforced by MR03 & MR04 (zero model duplication)
    dependency 'pt-mbt-itf-edge' from system::processTreeReclamation::rustOracleTarget::traceIn to system::processTreeReclamation::quintTarget::traceOut;
    dependency 'pt-premise-handoff-edge' from system::processTreeReclamation::leanPooTarget::premiseIn to system::processTreeReclamation::rustOracleTarget::premiseOut;
    dependency 'bp-mbt-itf-edge' from system::backpressureMemory::bpRustOracleTarget::traceIn to system::backpressureMemory::bpQuintTarget::traceOut;
    dependency 'bp-premise-handoff-edge' from system::backpressureMemory::bpLeanPooTarget::premiseIn to system::backpressureMemory::bpRustOracleTarget::premiseOut;
    dependency 'cb-premise-handoff-edge' from system::cBoundaryConservation::cbLeanPooTarget::premiseIn to system::cBoundaryConservation::cbCbmcTarget::premiseOut;

    // Verification obligation allocations (planned checks, no execution verdict)
    dependency 'alloc-mr-gate' from obligations::ascentMultiMethodGate to system::governance;
    dependency 'alloc-placement-gate' from obligations::repositoryPlacementGate to system::leanModels;
    dependency 'alloc-quint-check' from obligations::quintProcessTreeCheck to system::processTreeReclamation::quintTarget;
    dependency 'alloc-lean-proof' from obligations::leanPooContainmentProof to system::processTreeReclamation::leanPooTarget;
    dependency 'alloc-rust-oracle' from obligations::rustSigkillLeakOracle to system::processTreeReclamation::rustOracleTarget;
    dependency 'alloc-ai-gov-gate' from obligations::aiSecurityGovernanceAndRedTeamGate to system::governance;

    // Design specification only. Does not modify live project.sysml or claim qualification.
}

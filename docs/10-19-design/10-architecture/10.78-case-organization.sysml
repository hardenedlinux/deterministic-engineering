// DE-CASE-01 organization model. Bounded formation runs are recorded in 10.80; no satisfaction or approval verdict.
// Stable identities are existing project IDs; locations are not Contract versions.
// Structural organization source: this file. Rationale/status: linked Org. Runtime truth: actual owners.
package DECaseOrganization {
    doc /* Scope: DE-CASE-01; source-inspected baseline and proposed organization, not a qualified live architecture. */
    package actual {
        part <'DE-E01'> selection {
            doc /* selection/build entry. Content/source: init.ss (../../../init.ss) selects three Modules and two Scenarios; callers explicitly request build/currentness. Allocation: R01,R03 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E02'> genericLibrary {
            doc /* generic backpressure publication. Content/source: abstract/interface.ss (../../../library/concurrency/resource-control/backpressure-memory/abstract/interface.ss) exports Config entry under BackpressureScopeContract. Allocation: R01,R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E03'> rustLibrary {
            doc /* Rust specialization/public methods. Content/source: rust/interface.ss (../../../library/concurrency/resource-control/backpressure-memory/rust/interface.ss), objects.ss (../../../library/concurrency/resource-control/backpressure-memory/rust/objects.ss), types.ss (../../../library/concurrency/resource-control/backpressure-memory/rust/types.ss), func.ss (../../../library/concurrency/resource-control/backpressure-memory/rust/func.ss) require parent, specialize duties and expose Contracts/methods. Allocation: R01,R03,R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E04'> evidence {
            doc /* resource evidence publication. Content/source: Evidence interface (../../../modules/resource-evidence/interface.ss) and rules/session adapter (../../../modules/resource-evidence/func.ss) expose open-review and finite applicability/query rules. Allocation: R01,R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E05'> gateway {
            doc /* gateway fixture Scenario. Content/source: GatewayReview requirements (../../../scenarios/gateway-review/interface.ss) and operations (../../../scenarios/gateway-review/func.ss) provide fixture cases and scope rows; no cryptographic host capture claimed. Allocation: R01,R03 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E06'> lifecycle {
            doc /* native lifecycle Scenario. Content/source: ResourceLifecycle requirements (../../../scenarios/resource-lifecycle/interface.ss) and operations (../../../scenarios/resource-lifecycle/func.ss) delegate capture/currentness and open review. Allocation: R01,R03 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E07'> profiles {
            doc /* independent Profile values. Content/source: Gateway Profiles (../../../profiles/gateway.ss) contain fixture premises; Lifecycle Profiles (../../../profiles/resource-lifecycle.ss) contain controlled native premises; imported independently. Allocation: R01,R03 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E08'> methods {
            doc /* method observers/private result boundary. Content/source: methods.ss (../../../library/concurrency/resource-control/backpressure-memory/rust/methods.ss) executes, validates, issues, checks currentness and registers results. Allocation: R03,R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E09'> oracles {
            doc /* independent oracles and mapping. Content/source: oracle.ss (../../../library/concurrency/resource-control/backpressure-memory/rust/oracle.ss) checks observations; correspondence.ss (../../../library/concurrency/resource-control/backpressure-memory/rust/correspondence.ss) maps cuts and generates facets; currently also extends entry semantics. Allocation: R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E10'> integrationDriver {
            doc /* integration driver. Content/source: integration example (../../../examples/resource-integration-evidence.ss) selects, extends entry, joins scopes/snapshot, invokes methods, registers and renders results. Allocation: R03,R04,R06 / ARCH,DOC,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E11'> review {
            doc /* local Aitia consumer. Content/source: review exports (../../../scenarios/resource-lifecycle/review/interface.ss), content verification (../../../scenarios/resource-lifecycle/review/func.ss), review driver (../../../examples/backpressure-aitia-review.ss); separate native subpackage, not an init-selected Module. Allocation: R05 / ARCH,REVIEW. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E12'> formalInputs {
            doc /* implementation/formal inputs. Content/source: Rust mechanism (../../../library/concurrency/resource-control/backpressure-memory/rust/native/src/main.rs), QNT model (../../../library/concurrency/resource-control/backpressure-memory/model.qnt), Lean budget (../../../library/concurrency/resource-control/backpressure-memory/budget.lean) and method-generated SysML/QNT facets. Allocation: R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E13'> documents {
            doc /* authored architecture/products/views. Content/source: 10.26-10.33, existing 10.19-10.25 evidence/review explanations and their selected paired views. Allocation: R02,R06 / ARCH,DOC,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-elements. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-E14'> projectFormation {
            doc /* Actual bounded formation slice, 10.80-declarative-project-formation.org. Observed Core Scope + ASCENT + model rendering passed; full package build, cold/recovery parity and authenticated C/Q/R remain open. Existing E01-E13 retain their historical baseline meanings. */
            part <'DE-E15'> organizationLibrary {
                doc /* library/project-organization/{types,objects,config,interface}.ss publishes independent role/owner/product/duty/capability demand. No project package name or selected layout is owned here. Allocation: R01,R02,R06 / ARCH,DOC,TRACE. */
            }
            part <'DE-E16'> profile {
                doc /* profiles/library-formation.ss selects confirmed reusable-library intent, LIB-C01-C03 alternatives, SysML catalog, package/instance, layout references and dependencies. Proposed data is not authenticated evidence. Allocation: R02,R03,R06 / ARCH,DOC,TRACE. */
            }
            part <'DE-E17'> reasoning {
                doc /* modules/project-formation/{types,objects,config,interface,func}.ss owns application LR01-LR08 and pure result-to-SysML materialization. Generic define-program and native Session remain ASCENT's responsibility. Allocation: R01,R02,R04,R06 / ARCH,TRACE. */
            }
            part <'DE-E18'> scenario {
                doc /* scenarios/project-formation/{types,objects,config,interface,func}.ss requires Library and Engine Scopes, binds Profile data to typed inputs and exposes inputs/run/render. No full authenticated capture or review receipt is issued. Allocation: R01,R03,R06 / ARCH,TRACE. */
            }
            part <'DE-E19'> projectEntry {
                doc /* projects/library-formation/init.ss uses poo-flow! to declare the three selected owners and source locations. Core owns source linking, dependency Contracts and Scope admission. examples/library-formation.ss observes actual source stages and runs this Scope; it is not a second Project declaration. Allocation: R01,R02,R03,R06 / ARCH,DOC,TRACE. */
            }
        }
    }
    package boundaries {
        part <'DE-I01'> selectionBoundary {
            doc /* E01 -> E02-E06. Content/source: Explicit native selection in init.ss; DE-X02 supplies selection/build machinery. Allocation: Selection is not method execution or approval; R01,R03 / ARCH. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I02'> parentBoundary {
            doc /* E03 -> E02. Content/source: Core Parent requirement/BackpressureScopeContract; specialize-backpressure derives entry and preserves rows. Allocation: Structural inheritance alone does not prove semantic refinement; R01,R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I03'> gatewayBoundary {
            doc /* E05 -> E03,E04; E07 -> E05. Content/source: Gateway open-review takes profile/usage/snapshot/source and optional scope rows, then opens selected Evidence session. Allocation: scope-key is finite fixture serialization, not actual toolchain/source identity; R03,R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I04'> captureBoundary {
            doc /* E06 -> E08,E04; E07 -> E06. Content/source: capture takes root/Profile/crate/Cargo/rustc/usage/mode; open-review checks context entry/currentness then projects entry/Profile/usage/snapshot/scopes. Allocation: Current seven-role context, ignored validation return and narrow methods recognized in audit remain debt; R03 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I05'> methodBoundary {
            doc /* E03 -> E08. Content/source: ResourceMethods publishes native/formal/integration/capture/register helpers and result projections. Allocation: Domain and utility surface are currently mixed; no second executor; R01,R03 / ARCH. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I06'> executionBoundary {
            doc /* E08 -> X02,X05,X06. Content/source: command derives Core ProcessScript command with argv/directory/log/deadline; observers interpret raw output and issue private results. Allocation: Process exit alone is insufficient; timeout/currentness and oracle checks retain meaning; R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I07'> mappingBoundary {
            doc /* E08 -> E09,E12. Content/source: Native observations and formal inputs feed independent checks and explicit cut/state mapping. Allocation: Synthesized intermediate states are not observed events; M02 extension and finite bounds explicit; R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I08'> temporalBoundary {
            doc /* E08 -> E04,X03. Content/source: register takes existing session/issued results/trajectory/rules path; uses clue-exchange and checks expected content before/through registration. Allocation: JSON cannot reconstruct issuer; ASCENT applicability does not issue activation; R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I09'> queryBoundary {
            doc /* E10 -> E03,E08,E04; E07 -> E10. Content/source: Example builds current selection, derives integration entry, captures seven roles, appends three extra roles, recomputes snapshot and directly opens Evidence. Allocation: This currently bypasses Scenario open-review for the complete integration path; R03,R04,R06 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I10'> reviewBoundary {
            doc /* E11 -> X04,X02; evidence files -> E11. Content/source: Local review consumer validates source/content and uses existing Aitia context/content/stage and Core verification owners. Allocation: Bounded backpressure review is not whole-case review; not automatically connected to DE-E04 query output; R05 / ARCH,REVIEW. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I11'> documentBoundary {
            doc /* E13 -> authored D2 -> SVG. Content/source: Org semantic owner, editable graph and render convention; source links describe actual nodes and target changes. Allocation: Documentation projection, not runtime call or proof; R02,R06 / DOC,ARCH. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-I12'> currentUseBoundary {
            doc /* E08,E10,E11 -> X06. Content/source: Actual source/config/tool/artifact paths and content digests; evidence saved locally and read under declared custody/currentness. Allocation: File checks are local consistency, not atomic check-to-use or portable delivery; R03,R05 / TRACE,REVIEW. Org: 10.33-case-actual-and-target-architecture.org::#case-actual-interfaces. State: documented baseline allocation, not a new execution claim. */
        }
    }
    package target {
        part <'DE-T01'> effectiveContracts {
            doc /* native value/invocation contracts. Content/source: E03/E05/E06; local types and operations; reuse X01/X02. Allocation: R01,R03 / ARCH,TRACE; A01/A02; use normalized returns, preserve supported domains and required parent meaning. Org: 10.33-case-actual-and-target-architecture.org::#case-target-architecture. State: proposed target, not implemented. */
        }
        part <'DE-T02'> publishedIntegration {
            doc /* published integration semantics. Content/source: E03/E09; specialize-backpressure and resource-slice-entry seams. Allocation: R01,R04 / ARCH,TRACE; A07/A08; publish SI/TM links, mapping/M02 semantics and duties under Library; retain independent oracle. Org: 10.33-case-actual-and-target-architecture.org::#case-target-architecture. State: proposed target, not implemented. */
        }
        part <'DE-T03'> oneCapture {
            doc /* one complete project/selected-method use. Content/source: E06/E08/E10; native-context/integration-scopes and example direct session opening. Allocation: R03,R06 / ARCH,TRACE; A02/A06; capture final Profile, roles, content/mappings/tools once; Scenario coordinates; existing Evidence adapter may project internally. Org: 10.33-case-actual-and-target-architecture.org::#case-target-architecture. State: proposed target, not implemented. */
        }
        part <'DE-T04'> contentProjection {
            doc /* architecture/product/decision observers and facts. Content/source: E13/E08/E04; 10.31 duties and existing result/register/query seams. Allocation: R02,R04,R06 / ARCH,DOC,TRACE; A03/A07; explicit content criteria, independent semantic review and precise footprints; no generic prose-to-truth ingestion. Org: 10.33-case-actual-and-target-architecture.org::#case-target-architecture. State: proposed target, not implemented. */
        }
        part <'DE-T05'> independentReview {
            doc /* exact case review/dossier adapter. Content/source: E11 plus E13 inventory; existing content/stage verification seam at I10. Allocation: R05 / REVIEW; A04/A06; bind C1 policy and actual inventory/assignees/evidence; obtain real owner disposition. Org: 10.33-case-actual-and-target-architecture.org::#case-target-architecture. State: proposed target, not implemented. */
        }
        part <'DE-T06'> recipientUse {
            doc /* qualified recipient use. Content/source: E01/E03/E11 plus X02/X04/X06 publication/intake boundaries. Allocation: R05 / TRACE,REVIEW; A02/A04/A06; accessible dependency/reference closure and fresh recipient admission; not receipt copying. Org: 10.33-case-actual-and-target-architecture.org::#case-target-architecture. State: proposed target, not implemented. */
        }
        part <'DE-T07'> sysmlOrganization {
            doc /* selected repository SysML projection. Content/source: E13/E09/E08 and X05; declared architecture-to-SysML mapping, currently absent. Allocation: R02,R04 / ARCH,DOC,TRACE; A05/A07; preserve native IDs, declare losses and supported checks; optional under C1, not a mandatory current-stage pass. Org: 10.33-case-actual-and-target-architecture.org::#case-target-architecture. State: proposed target, not implemented. */
        }
    }
    package external {
        part <'DE-X01'> poo {
            doc /* POO. Content/source: :clan/poo objects and native Types/validation; ObjectContract (../../../.gerbil/pkg/github.com/tao3k/gerbil-poo/object-contract.ss). Allocation: A01: prototype derivation, validation returns and semantic review differ; no new schema owner; R01 / ARCH. Org: 10.33-case-actual-and-target-architecture.org::#case-architecture-boundaries. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-X02'> yuanxu {
            doc /* Core. Content/source: explicit selection (../../../.gerbil/pkg/github.com/tao3k/poo-flow-core/module-system/selection/init-syntax.ss), admission (../../../.gerbil/pkg/github.com/tao3k/poo-flow-core/types.ss), ProcessScript and verification imported by actual callers. Allocation: A02: source-visible capability requires a compatible compiled baseline; cold Scenario regression unresolved; R01,R03 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-architecture-boundaries. State: documented baseline allocation, not a new execution claim. Current dependency/API qualification: 10.76 and 10.77, Yuanxu migration remains open. */
        }
        part <'DE-X03'> ascent {
            doc /* gerbil-ascent. Content/source: Session, Evidence declaration, trajectory and clue-exchange imports in E04/E08/E10. Allocation: A03: rules are finite explicit facts; checked/issued inputs need a trusted observer; support and counter can coexist; R04 / TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-architecture-boundaries. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-X04'> aitia {
            doc /* Aitia. Content/source: Review/lifecycle APIs imported by E11; existing owner map (10.19-standard-identities-and-aitia-review-traceability.org). Allocation: A04: project policy, assignees and current review context must be established; no inferred NASA class or receipt authority; R05 / REVIEW. Org: 10.33-case-actual-and-target-architecture.org::#case-architecture-boundaries. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-X05'> tools {
            doc /* tool/runtime execution. Content/source: Selected Cargo/rustc, Quint/TLC/Java, Lean and OpenSysML; E08 observers and E12 inputs. Allocation: A05: tool closure/platform and finite/runtime premises matter; local transitive installation trust is recorded, not universally authenticated; R04 / ARCH,TRACE. Org: 10.33-case-actual-and-target-architecture.org::#case-architecture-boundaries. State: documented baseline allocation, not a new execution claim. */
        }
        part <'DE-X06'> custody {
            doc /* filesystem/content custody. Content/source: Local source/configuration, .data artifacts, references and recipient access. Allocation: A06: mutable files require appropriate currentness checks/owned copies; historical local paths are not portable closure; R03,R05 / TRACE,REVIEW. Org: 10.33-case-actual-and-target-architecture.org::#case-architecture-boundaries. State: documented baseline allocation, not a new execution claim. */
        }
    }
    package requirements {
        requirement <'DE-R01'> nativeReuse {
            doc /* reuse POO/Core framework owners. Org: 10.30-current-repository-engineering-case.org::#actual-case-requirements. No satisfaction assertion. */
        }
        requirement <'DE-R02'> reviewableArchitecture {
            doc /* make architecture and rationale reviewable. Org: 10.30-current-repository-engineering-case.org::#actual-case-requirements. No satisfaction assertion. */
        }
        requirement <'DE-R03'> coherentUse {
            doc /* bind each use coherently. Org: 10.30-current-repository-engineering-case.org::#actual-case-requirements. No satisfaction assertion. */
        }
        requirement <'DE-R04'> evidenceMeaning {
            doc /* preserve evidence meaning. Org: 10.30-current-repository-engineering-case.org::#actual-case-requirements. No satisfaction assertion. */
        }
        requirement <'DE-R05'> qualifiedDelivery {
            doc /* deliver reusable knowledge through qualified recipient use. Org: 10.30-current-repository-engineering-case.org::#actual-case-requirements. No satisfaction assertion. */
        }
        requirement <'DE-R06'> realCase {
            doc /* use this repository as the first real case. Org: 10.30-current-repository-engineering-case.org::#actual-case-requirements. No satisfaction assertion. */
        }
    }
    package products {
        part <'D01'> brief {
            doc /* D01 brief and scope. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.30-current-repository-engineering-case.org::#case-design-review-scope. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D02'> composition {
            doc /* D02 composition. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.26-backpressure-public-contracts.org::#backpressure-public-contracts. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D03'> capturePlan {
            doc /* D03 Scenario capture plan. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.31-architecture-document-and-decision-contracts.org::#case-content-binding. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D04'> architecture {
            doc /* D04 architecture model. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.33-case-actual-and-target-architecture.org::#case-architecture-models. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D05'> decisions {
            doc /* D05 decision records. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.30-current-repository-engineering-case.org::#actual-case-decisions. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D06'> obligations {
            doc /* D06 obligation ledger. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.31-architecture-document-and-decision-contracts.org::#content-obligations-and-evidence. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D07'> evidence {
            doc /* D07 evidence inventory. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.34-case-design-review-dossier-draft.org::#case-evidence-inventory. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D08'> negatives {
            doc /* D08 repair and negative record. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.30-current-repository-engineering-case.org::#case-decision-reconsideration. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D09'> explanation {
            doc /* D09 query explanation. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.34-case-design-review-dossier-draft.org::#case-draft-review-questions. Binding inventory: 10.34::#case-product-input-bindings. */
        }
        part <'D10'> dossier {
            doc /* D10 dossier draft. Authored candidate/role, not fulfilled or reviewed by this declaration. Org: 10.34-case-design-review-dossier-draft.org::#case-product-input-bindings. Binding inventory: 10.34::#case-product-input-bindings. */
        }
    }
    package decisions {
        part <'DE-D01'> frameworkOwners {
            doc /* Recorded design choice, actual assignees and independent disposition unresolved. Rationale/alternatives/revision/triggers: 10.30-current-repository-engineering-case.org::#case-decision-allocation and #case-decision-reconsideration. No supersession or approval asserted. */
        }
        part <'DE-D02'> modelAndDocuments {
            doc /* Recorded design choice, actual assignees and independent disposition unresolved. Rationale/alternatives/revision/triggers: 10.30-current-repository-engineering-case.org::#case-decision-allocation and #case-decision-reconsideration. No supersession or approval asserted. */
        }
        part <'DE-D03'> realRepositoryFirst {
            doc /* Recorded design choice, actual assignees and independent disposition unresolved. Rationale/alternatives/revision/triggers: 10.30-current-repository-engineering-case.org::#case-decision-allocation and #case-decision-reconsideration. No supersession or approval asserted. */
        }
        part <'DE-D04'> oneCaptureAndScopedEvidence {
            doc /* Recorded design choice, actual assignees and independent disposition unresolved. Rationale/alternatives/revision/triggers: 10.30-current-repository-engineering-case.org::#case-decision-allocation and #case-decision-reconsideration. No supersession or approval asserted. */
        }
        part <'DE-D05'> receiverQualification {
            doc /* Recorded design choice, actual assignees and independent disposition unresolved. Rationale/alternatives/revision/triggers: 10.30-current-repository-engineering-case.org::#case-decision-allocation and #case-decision-reconsideration. No supersession or approval asserted. */
        }
    }
    package assumptions {
        part <'DE-A01'> a1 {
            doc /* POO composition and normalized returns do not establish semantic adequacy. Declared premise/limit, not a proved global truth. Org: 10.33::#case-architecture-boundaries. */
        }
        part <'DE-A02'> a2 {
            doc /* actual source/compiled/load and current Core API compatibility required. Declared premise/limit, not a proved global truth. Org: 10.33::#case-architecture-boundaries. */
        }
        part <'DE-A03'> a3 {
            doc /* finite pure projection needs qualified input origins. Declared premise/limit, not a proved global truth. Org: 10.33::#case-architecture-boundaries. */
        }
        part <'DE-A04'> a4 {
            doc /* actual policy, roles, mandate and current review must be established. Declared premise/limit, not a proved global truth. Org: 10.33::#case-architecture-boundaries. */
        }
        part <'DE-A05'> a5 {
            doc /* tool closure/platform/model/conditional theorem premises remain bounded. Declared premise/limit, not a proved global truth. Org: 10.33::#case-architecture-boundaries. */
        }
        part <'DE-A06'> a6 {
            doc /* actual custody/access/currentness and receiver reference closure required. Declared premise/limit, not a proved global truth. Org: 10.33::#case-architecture-boundaries. */
        }
        part <'DE-A07'> a7 {
            doc /* model/view/document correspondence is not semantic approval. Declared premise/limit, not a proved global truth. Org: 10.33::#case-architecture-boundaries. */
        }
        part <'DE-A08'> a8 {
            doc /* six-case controlled runtime is not general liveness, refinement or empirical effect. Declared premise/limit, not a proved global truth. Org: 10.33::#case-architecture-boundaries. */
        }
    }
    package obligations {
        verification <'DE-O-ARCH'> architecture {
            doc /* Planned verification obligation only; no executable test body, result or verdict. Architecture/source/target boundaries. */
            objective {
                verify requirements::nativeReuse;
                verify requirements::coherentUse;
            }
        }
        verification <'DE-O-DOC'> documentation {
            doc /* Planned verification obligation only; no executable test body, result or verdict. Document roles, selectors, links and content. */
            objective {
                verify requirements::reviewableArchitecture;
                verify requirements::realCase;
            }
        }
        verification <'DE-O-DEC'> decision {
            doc /* Planned verification obligation only; no executable test body, result or verdict. Decision rationale, role, alternatives and reconsideration. */
            objective {
                verify requirements::reviewableArchitecture;
                verify requirements::realCase;
            }
        }
        verification <'DE-O-TRACE'> traceability {
            doc /* Planned verification obligation only; no executable test body, result or verdict. Complete requirement/model/decision/method applicability links. */
            objective {
                verify requirements::reviewableArchitecture;
                verify requirements::evidenceMeaning;
            }
        }
        verification <'DE-O-REVIEW'> review {
            doc /* Planned verification obligation only; no executable test body, result or verdict. Independent content/context/inventory and exact authority. */
            objective {
                verify requirements::qualifiedDelivery;
            }
        }
    }
    package organization {
        part <'DE-ORG-library'> reusableLibrary {
            doc /* Publishes reusable model, integration, policies, Contracts, methods, product roles and required obligations; sole Contract generation remains in runtime declaration, never here. */
        }
        part <'DE-ORG-profile'> profile {
            doc /* Selects checked Library model/Integration/two policies and intended product/use demand; does not authorize project or appoint roles. */
        }
        part <'DE-ORG-scenario'> scenario {
            doc /* Acquires project inputs and actual source/mandate/product basis into one C; calls real owners, not a second framework. */
        }
        part <'DE-ORG-org'> org {
            doc /* Carries rationale, explanations, authoritative prose clauses and status. Each relationship assertion has one declared owner. */
        }
        part <'DE-ORG-sysml'> sysml {
            doc /* Carries stable organization nodes and typed model dependencies; no runtime issuer or authorization. */
        }
        part <'DE-ORG-d2'> d2 {
            doc /* Selected presentation of named model relationships; no new semantic authority. */
        }
        part <'DE-ORG-ascent'> ascent {
            doc /* Consumes actual captured/projection inputs for deterministic Q at a qualified accepted cut, not causal truth. */
        }
        part <'DE-ORG-aitia'> aitia {
            doc /* Independent context/content/history/authority at real owners, original C/Q/R plus fresh use. */
        }
        part <'DE-ORG-receiver'> receiver {
            doc /* Own project capture, trust, C1/Q1/R1 and actual adoption/current operation authority. */
        }
    }
    dependency requirementDecision1 from requirements::nativeReuse to decisions::frameworkOwners;
    dependency requirementDecision2 from requirements::reviewableArchitecture to decisions::modelAndDocuments;
    dependency requirementDecision3 from requirements::coherentUse to decisions::oneCaptureAndScopedEvidence;
    dependency requirementDecision4 from requirements::evidenceMeaning to decisions::oneCaptureAndScopedEvidence;
    dependency requirementDecision5 from requirements::qualifiedDelivery to decisions::receiverQualification;
    dependency requirementDecision6 from requirements::realCase to decisions::realRepositoryFirst;
    dependency libraryAllocationgenericLibrary from organization::reusableLibrary to actual::genericLibrary;
    dependency libraryAllocationrustLibrary from organization::reusableLibrary to actual::rustLibrary;
    dependency profileAllocationprofiles from organization::profile to actual::profiles;
    dependency scenarioAllocationlifecycle from organization::scenario to actual::lifecycle;
    dependency scenarioAllocationgateway from organization::scenario to actual::gateway;
    dependency productRationalebrief from products::brief to organization::org;
    dependency productRationalecomposition from products::composition to organization::org;
    dependency productRationalecapturePlan from products::capturePlan to organization::org;
    dependency productRationalearchitecture from products::architecture to organization::org;
    dependency productRationaledecisions from products::decisions to organization::org;
    dependency productRationaleobligations from products::obligations to organization::org;
    dependency productRationaleevidence from products::evidence to organization::org;
    dependency productRationalenegatives from products::negatives to organization::org;
    dependency productRationaleexplanation from products::explanation to organization::org;
    dependency productRationaledossier from products::dossier to organization::org;
    dependency profileSelects from organization::profile to organization::reusableLibrary;
    dependency scenarioConsumes from organization::scenario to organization::profile;
    dependency structuralSource from organization::sysml to products::architecture;
    dependency viewProjection from organization::d2 to organization::sysml;
    dependency caseReview from products::dossier to organization::aitia;
    dependency queryExplanation from products::explanation to organization::ascent;
    dependency receiverBoundary from organization::receiver to organization::aitia;
    dependency baselineLink1 from actual::selection to actual::genericLibrary { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink2 from actual::rustLibrary to actual::genericLibrary { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink3 from actual::lifecycle to actual::methods { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink4 from actual::lifecycle to actual::evidence { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink5 from actual::profiles to actual::lifecycle { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink6 from actual::methods to external::tools { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink7 from actual::methods to actual::oracles { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink8 from actual::evidence to external::ascent { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink9 from actual::review to external::aitia { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency baselineLink10 from actual::documents to products::architecture { doc /* Documented dependency, not an execution or message sequence. */ }
    dependency captureEndpointlifecycle from boundaries::captureBoundary to actual::lifecycle;
    dependency captureEndpointmethods from boundaries::captureBoundary to actual::methods;
    dependency captureEndpointevidence from boundaries::captureBoundary to actual::evidence;
    dependency targetAllocation1 from target::effectiveContracts to actual::rustLibrary;
    dependency targetAllocation2 from target::publishedIntegration to actual::oracles;
    dependency targetAllocation3 from target::oneCapture to actual::lifecycle;
    dependency targetAllocation4 from target::contentProjection to actual::evidence;
    dependency targetAllocation5 from target::independentReview to actual::review;
    dependency targetAllocation6 from target::recipientUse to organization::receiver;
    dependency targetAllocation7 from target::sysmlOrganization to organization::sysml;
    dependency architectureDemand from products::architecture to requirements::coherentUse;
    dependency architectureVerification from products::architecture to obligations::architecture;
    dependency briefDemand from products::brief to requirements::nativeReuse;
    dependency briefVerification from products::brief to obligations::documentation;
    dependency decisionsDemand from products::decisions to requirements::reviewableArchitecture;
    dependency decisionsVerification from products::decisions to obligations::decision;
    dependency obligationsDemand from products::obligations to requirements::evidenceMeaning;
    dependency obligationsVerification from products::obligations to obligations::traceability;
    dependency dossierDemand from products::dossier to requirements::qualifiedDelivery;
    dependency dossierVerification from products::dossier to obligations::review;
    dependency compositionVerification from products::composition to obligations::architecture;
    dependency capturePlanVerification from products::capturePlan to obligations::traceability;
    dependency evidenceVerification from products::evidence to obligations::traceability;
    dependency negativesVerification from products::negatives to obligations::decision;
    dependency explanationVerification from products::explanation to obligations::traceability;
    dependency captureImpact from boundaries::captureBoundary to target::oneCapture;
    dependency captureDecision from target::oneCapture to decisions::oneCaptureAndScopedEvidence;
    dependency capturePremise from decisions::oneCaptureAndScopedEvidence to assumptions::a2;
    dependency receiverPremise from organization::receiver to assumptions::a6;
    dependency plannedCheckarchitecture from obligations::architecture to organization::aitia { doc /* Planned interpretation/review association only; actual method evidence is absent. */ }
    dependency plannedCheckdocumentation from obligations::documentation to organization::aitia { doc /* Planned interpretation/review association only; actual method evidence is absent. */ }
    dependency plannedCheckdecision from obligations::decision to organization::aitia { doc /* Planned interpretation/review association only; actual method evidence is absent. */ }
    dependency plannedChecktraceability from obligations::traceability to organization::aitia { doc /* Planned interpretation/review association only; actual method evidence is absent. */ }
    dependency plannedCheckreview from obligations::review to organization::aitia { doc /* Planned interpretation/review association only; actual method evidence is absent. */ }
    package workflow {
        doc /* Proposed Agent formation path, not an installed orchestrator or evidence of actual user approval for a future project. */
        part <'DE-WF-INTENT'> confirmedIntent {
            doc /* Actual repo identity/source cut; user-confirmed goals, constraints, non-goals and open questions. User confirmation permits scoped model drafting, not action authority. */
        }
        part <'DE-WF-CANDIDATE'> candidateArchitecture {
            doc /* LLM authored proposals with stable subject IDs, interfaces, alternatives, explicit assumptions, project inputs and evidence gaps. Proposed facts are not observations or verified claims. */
        }
        part <'DE-WF-RULES'> reasoningRules {
            doc /* Actual selected Library applicability rules, required-role/requirement/closure and supported constraints. Trusted rule definitions are separate from candidate proposal facts. No new general solver is implied. */
        }
        part <'DE-WF-REASONING'> reasoningView {
            doc /* ASCENT finite deterministic candidate-selection/coverage/conflict/gap result at actual program/input cut. This early design view is not the later evidence Q, a causal estimate or review approval. */
        }
        part <'DE-WF-SYSML-LIBRARY'> sysmlLibrary {
            doc /* Reusable supported SysML model definitions, interfaces, requirements, allocation and view templates, associated with actual Library Contract identity. POO/Yuanxu remains the runtime declaration and sole contract-version owner. Missing domain definition stays a gap. */
        }
        part <'DE-WF-SELECTION'> selectedDefinitions {
            doc /* Exact checked Library model/Integration/policy and SysML definition refs, supported parameters and explicit selection rationale. Profile selects intent; Scenario binds actual project inputs. */
        }
        part <'DE-WF-LAYOUT'> repositoryLayout {
            doc /* Current repo-specific SysML architecture and document-role layout: actual/target elements, requirements, duties, decision and Org locators. No automatic directory movement or claim of completed implementation. */
        }
        part <'DE-WF-FEEDBACK'> unresolvedFeedback {
            doc /* Counter, conflict, unsupported construct or missing domain knowledge returns to LLM/user with original rule/input basis retained. Changed intent needs actual reconfirmation, no best-looking candidate auto-admission. */
        }
        action def RepoArchitectureFormation {
            doc /* Conceptual successful path only. Each stage needs the input/output/refusal boundary in 10.78 Org. No LLM/tool side effect or acceptance execution is encoded here. */
            action createRepository;
            action discussIntent;
            action confirmIntent;
            action generateCandidate;
            action reasonWithAscent;
            action selectSysmlLibrary;
            action formRepositoryLayout;
            first start;
            succession first start then createRepository;
            succession first createRepository then discussIntent;
            succession first discussIntent then confirmIntent;
            succession first confirmIntent then generateCandidate;
            succession first generateCandidate then reasonWithAscent;
            succession first reasonWithAscent then selectSysmlLibrary;
            succession first selectSysmlLibrary then formRepositoryLayout;
            succession first formRepositoryLayout then done;
        }
    }
    dependency wfCandidateBasis from workflow::candidateArchitecture to workflow::confirmedIntent;
    dependency wfReasonInput from workflow::reasoningView to workflow::candidateArchitecture;
    dependency wfReasonRules from workflow::reasoningView to workflow::reasoningRules;
    dependency wfLibraryCriteria from workflow::reasoningRules to workflow::sysmlLibrary;
    dependency wfSelectionReason from workflow::selectedDefinitions to workflow::reasoningView;
    dependency wfSelectionLibrary from workflow::selectedDefinitions to workflow::sysmlLibrary;
    dependency wfLayoutSelection from workflow::repositoryLayout to workflow::selectedDefinitions;
    dependency wfLayoutCapture from workflow::repositoryLayout to organization::scenario;
    dependency wfFeedback from workflow::unresolvedFeedback to workflow::reasoningView;
    dependency wfCaseLayout from workflow::repositoryLayout to products::architecture;
    dependency wfCaseDocuments from workflow::repositoryLayout to products::composition;
    dependency wfCaseDecisions from workflow::repositoryLayout to products::decisions;
    dependency formationLibrary from actual::projectFormation::scenario to actual::projectFormation::organizationLibrary;
    dependency formationEngine from actual::projectFormation::scenario to actual::projectFormation::reasoning;
    dependency formationProfile from actual::projectFormation::scenario to actual::projectFormation::profile;
    dependency formationEntry from actual::projectFormation::projectEntry to actual::projectFormation::scenario;
    dependency formationRuleOwner from actual::projectFormation::reasoning to external::ascent;
    dependency formationLinkOwner from actual::projectFormation::projectEntry to external::yuanxu;

}

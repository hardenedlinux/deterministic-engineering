// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 30 (10.178): Machine-Verifiable LeanPoo Library Export Manifest &
 * Single-Shot 76-Theorem Fleet Attestation Gate (`deterministic-engineering-qnt` -> `cedar-poo-spec`).
 *
 * Enforces the Library <-> Consuming Authorization Host separation mechanically:
 *   1. ZERO Mathlib imports across all 6 exported LeanPoo modules.
 *   2. ZERO Cedar imports across all 6 exported LeanPoo modules (concrete policies
 *      live strictly in `cedar-poo-spec`).
 *   3. ZERO `sorry` / `admit` / custom `axiom` / `unsafe` / `implemented_by` backdoors.
 *   4. Single-shot batched `lake env lean --stdin` `#print axioms` verification via
 *      `LibraryExportContract` transitive import, pinning an immutable `M1` fleet
 *      attestation receipt in `ContentAddressedKvStore`.
 */

import {spawnSync} from 'node:child_process';
import {existsSync, readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {ContentAddressedKvStore, sha256Digest} from './durable-merkle-store.ts';
import {
  auditLeanSourceAntiFabrication,
  parseLeanPrintAxiomsOutput,
  type LeanAxiomAuditVerdict,
  type LeanSourceFinding,
} from './lean-proof-oracle.ts';

export interface LeanPooExportModuleSpec {
  readonly moduleName: string;
  readonly relativeLeanPath: string;
  readonly pillars: readonly string[];
  readonly theorems: readonly string[];
}

export const LEANPOO_EXPORT_FACADE_MODULE =
  'DeterministicEngineering.Engineering.LibraryExportContract';

export const LEANPOO_FOUR_PARADIGM_FACADE_MODULE =
  'DeterministicEngineering.Engineering.FourParadigmConsistency';

export const LEANPOO_LIBRARY_EXPORT_MANIFEST: readonly LeanPooExportModuleSpec[] = [
  {
    moduleName: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
    relativeLeanPath: 'DeterministicEngineering/Engineering/DurableGovernanceQuorum.lean',
    pillars: ['B3', 'B6', 'B10', 'B10b', 'B10c', 'R3'],
    theorems: [
      'bft_quorum_intersection_honest_witness',
      'bft_no_conflicting_finality',
      'handover_chain_monotonic',
      'handover_chain_rejects_all_retired_epochs',
      'm1_persistable_forbids_any_m3_descendant',
      'm3_leak_always_refused',
      'split_preserves_total_budget',
      'spend_preserves_total_budget',
      'attenuation_chain_bounded_by_root',
      'ancestor_revocation_invalidates_chain',
      'durableQuorumContract_preserves_rejection',
      'hostPolicyRefinement_preserves_library_rejection',
      'gossipTuning_preserves_quorum_certificate',
      'batchSizeTuning_preserves_quorum_certificate',
      'droppingExternalPolicyHost_invalidates_reuse',
      'slashed_witness_is_byzantine',
      'slashed_witness_never_reenters_future_epochs',
      'hostPolicyOverSlashing_preserves_library_rejection',
      'droppingSlashReentryGuard_invalidates_reuse',
    ],
  },
  {
    moduleName: 'DeterministicEngineering.Engineering.HostAuthorizationBridge',
    relativeLeanPath: 'DeterministicEngineering/Engineering/HostAuthorizationBridge.lean',
    pillars: ['DualSovereignty', 'R1', 'R3'],
    theorems: [
      'forbid_always_overrides_permit',
      'default_deny_when_no_permit',
      'cedar_permit_cannot_bypass_library_refusal',
      'library_finalized_cannot_bypass_host_forbid',
      'library_finalized_cannot_bypass_host_pending',
      'cross_operation_permit_replay_blocked',
      'stale_policy_snapshot_permit_blocked',
      'revoked_use_time_authority_blocked',
      'dualSovereignBridge_preserves_library_rejection',
      'disjointHostPolicyEvolution_preserves_bridge_certificate',
      'weakeningBoundOperation_invalidates_reuse',
    ],
  },
  {
    moduleName: 'DeterministicEngineering.Engineering.InformationFlowAndTms',
    relativeLeanPath: 'DeterministicEngineering/Engineering/InformationFlowAndTms.lean',
    pillars: ['B7', 'B8'],
    theorems: [
      'difc_secrecy_monotonic_without_declass',
      'difc_no_write_down_blocks_exfiltration',
      'difc_failed_declass_preserves_taint',
      'camel_integrity_meet_never_elevates',
      'camel_control_slot_blocks_untrusted',
      'doyle_single_justification_retraction_cascades',
      'atms_clean_alternative_justification_survives',
      'poison_immunization_tombstone_blocks_reproposal',
      'difcAtmsContract_preserves_rejection',
      'retentionTuning_preserves_difc_atms_certificate',
      'disablingCamelIntegrity_invalidates_reuse',
    ],
  },
  {
    moduleName: 'DeterministicEngineering.Engineering.SagaAndSsi',
    relativeLeanPath: 'DeterministicEngineering/Engineering/SagaAndSsi.lean',
    pillars: ['B4', 'B6', 'DE01'],
    theorems: [
      'post_pivot_rollback_always_forbidden',
      'pending_unknown_fences_both_forward_and_rollback',
      'reverse_compensation_covers_all_executed_steps',
      'second_pivot_breaks_at_most_one_pivot',
      'mutual_write_skew_always_blocked',
      'direct_ww_conflict_always_blocked',
      'de01_independent_peer_always_admitted',
      'read_only_agents_never_conflict',
      'sagaSsiContract_preserves_rejection',
      'retryBackoffTuning_preserves_saga_ssi_certificate',
      'disablingPivotFence_invalidates_reuse',
    ],
  },
  {
    moduleName: 'DeterministicEngineering.Engineering.HitlAndCoevolution',
    relativeLeanPath: 'DeterministicEngineering/Engineering/HitlAndCoevolution.lean',
    pillars: ['B1', 'B2', 'B5', 'R1', 'R5'],
    theorems: [
      'sod_forbids_requester_self_approval',
      'duplicate_approver_rejected_in_quorum',
      'baseline_drift_invalidates_hitl_resume',
      'intersecting_policy_drift_invalidates_approval',
      'disjoint_policy_upgrade_preserves_approval',
      'veto_tombstone_blocks_nagging_retry_forever',
      'cross_tenant_aead_read_always_refused',
      'ciphertext_transplant_across_row_or_tenant_refused',
      'unrevoked_m3_or_veto_or_freeze_blocks_resume',
      'hitlCoevolutionContract_preserves_rejection',
      'briefRenderLimitTuning_preserves_hitl_certificate',
      'disablingVetoPersistence_invalidates_reuse',
    ],
  },
  {
    moduleName: LEANPOO_EXPORT_FACADE_MODULE,
    relativeLeanPath: 'DeterministicEngineering/Engineering/LibraryExportContract.lean',
    pillars: ['B1', 'B2', 'B3', 'B4', 'B5', 'B6', 'B7', 'B8', 'B9', 'B10', 'B10b', 'B10c', 'R1', 'R2', 'R3', 'R4', 'R5', 'LibraryExport'],
    theorems: [
      'unifiedLibraryContract_accepts_all_enabled',
      'missing_quorum_slashing_rejected',
      'missing_difc_atms_rejected',
      'missing_saga_ssi_rejected',
      'missing_hitl_aead_rejected',
      'missing_r3_budget_rejected',
      'consumingHost_oneStep_refinement_preserves_library_rejection',
      'consumingHost_twoStep_cedar_governance_refinement_preserves_rejection',
      'consumingHost_threeStep_full_cedar_stack_preserves_rejection',
      'unifiedLibrary_telemetryTuning_preserves_certificate',
      'unifiedLibrary_hostPolicyBundlePatch_preserves_certificate',
      'unifiedLibrary_disablingDualSovereignty_invalidates_reuse',
    ],
  },
  {
    moduleName: LEANPOO_FOUR_PARADIGM_FACADE_MODULE,
    relativeLeanPath: 'DeterministicEngineering/Engineering/FourParadigmConsistency.lean',
    pillars: ['FourParadigmConsistency', 'NVersionGate'],
    theorems: [
      'any_paradigm_refuted_blocks_library_admit',
      'any_paradigm_pending_blocks_library_admit',
      'any_paradigm_setup_defect_blocks_library_admit',
      'host_permit_cannot_override_four_paradigm_failure',
      'four_paradigm_proven_cannot_override_host_refusal',
      'four_paradigm_admit_iff_all_proven',
      'paradigm_list_convergence_requires_every_entry_proven',
      'fourParadigmContract_preserves_rejection',
      'reportFormatTuning_preserves_fourParadigm_certificate',
      'disablingLeanPooGate_invalidates_reuse',
    ],
  },
];

export interface LibraryBoundaryAuditResult {
  passed: boolean;
  moduleCount: number;
  theoremCount: number;
  violations: Array<{
    moduleName: string;
    kind: 'mathlib-import' | 'cedar-import' | 'missing-spdx' | 'anti-fabrication';
    detail: string;
    findings?: LeanSourceFinding[];
  }>;
}

const DEFAULT_LEAN_DIR = resolve(import.meta.dir, '../../../../packages/lean-models');

/**
 * Statically verifies that all 6 exported LeanPoo modules strictly respect:
 *   - ZERO Mathlib imports
 *   - ZERO Cedar imports (host policies stay in `cedar-poo-spec`)
 *   - Valid SPDX headers
 *   - Zero `sorry`/`admit`/custom `axiom`/`unsafe` backdoors
 */
export function auditLeanPooLibraryBoundaries(
  leanDir = DEFAULT_LEAN_DIR,
  manifest: readonly LeanPooExportModuleSpec[] = LEANPOO_LIBRARY_EXPORT_MANIFEST,
): LibraryBoundaryAuditResult {
  const violations: LibraryBoundaryAuditResult['violations'] = [];
  let theoremCount = 0;

  for (const mod of manifest) {
    theoremCount += mod.theorems.length;
    const fullPath = resolve(leanDir, mod.relativeLeanPath);
    const src = readFileSync(fullPath, 'utf8');

    if (!src.slice(0, 400).includes('SPDX-License-Identifier:')) {
      violations.push({
        moduleName: mod.moduleName,
        kind: 'missing-spdx',
        detail: `${mod.relativeLeanPath} is missing SPDX-License-Identifier header`,
      });
    }

    for (const line of src.split('\n')) {
      const trimmed = line.trim();
      if (/^import\s+Mathlib\b/.test(trimmed)) {
        violations.push({
          moduleName: mod.moduleName,
          kind: 'mathlib-import',
          detail: `Forbidden Mathlib dependency: ${trimmed}`,
        });
      }
      if (/^import\s+Cedar\b/.test(trimmed)) {
        violations.push({
          moduleName: mod.moduleName,
          kind: 'cedar-import',
          detail: `Forbidden Cedar host dependency in reusable Library: ${trimmed}`,
        });
      }
    }

    const antiFab = auditLeanSourceAntiFabrication(src);
    if (!antiFab.passed) {
      violations.push({
        moduleName: mod.moduleName,
        kind: 'anti-fabrication',
        detail: `Anti-fabrication findings (${antiFab.findings.length})`,
        findings: antiFab.findings,
      });
    }
  }

  return {
    passed: violations.length === 0,
    moduleCount: manifest.length,
    theoremCount,
    violations,
  };
}

export type LeanPooFleetAttestationVerdict =
  | {
      kind: 'Proven';
      facadeModule: string;
      moduleCount: number;
      verifiedTheoremCount: number;
      theoremAxioms: Record<string, string[]>;
      fleetAttestationDigest: string;
      pinnedReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'library-boundary-violation'
        | 'unverified-sorry-or-custom-axiom'
        | 'missing-theorem-axiom-report';
      details: unknown;
    }
  | {kind: 'PendingMethod'; reason: 'lean-toolchain-unavailable'}
  | {kind: 'SetupDefect'; reason: string};

/**
 * Single-shot live `lake env lean --stdin` attestation across the ENTIRE 6-module,
 * 76-theorem `LeanPoo` Library via the single `LibraryExportContract` facade import.
 * Pins an immutable `M1` attestation receipt in `kv` for downstream `cedar-poo-spec` consumption.
 */
export function verifyLeanPooLibraryFleet(params?: {
  kv?: ContentAddressedKvStore;
  leanDir?: string;
  lakeBinary?: string;
  manifest?: readonly LeanPooExportModuleSpec[];
}): LeanPooFleetAttestationVerdict {
  const leanDir = params?.leanDir ?? DEFAULT_LEAN_DIR;
  const lakeBin = params?.lakeBinary ?? 'lake';
  const manifest = params?.manifest ?? LEANPOO_LIBRARY_EXPORT_MANIFEST;

  const boundary = auditLeanPooLibraryBoundaries(leanDir, manifest);
  if (!boundary.passed) {
    return {
      kind: 'Refuted',
      reason: 'library-boundary-violation',
      details: boundary.violations,
    };
  }

  if (!existsSync(resolve(leanDir, 'lakefile.toml'))) {
    return {kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'};
  }

  const fullyQualifiedTheorems: string[] = [];
  for (const mod of manifest) {
    for (const thm of mod.theorems) {
      fullyQualifiedTheorems.push(`${mod.moduleName}.${thm}`);
    }
  }

  const facadeToImport = manifest.some(
    m => m.moduleName === LEANPOO_FOUR_PARADIGM_FACADE_MODULE,
  )
    ? LEANPOO_FOUR_PARADIGM_FACADE_MODULE
    : LEANPOO_EXPORT_FACADE_MODULE;

  const stdinScript = [
    `import ${facadeToImport}`,
    ...fullyQualifiedTheorems.map(fqn => `#print axioms ${fqn}`),
    '',
  ].join('\n');

  const proc = spawnSync(lakeBin, ['env', 'lean', '--stdin'], {
    cwd: leanDir,
    input: stdinScript,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });

  if (proc.error) {
    const code = (proc.error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return {kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'};
    }
    return {kind: 'SetupDefect', reason: `lake-spawn-error: ${proc.error.message}`};
  }
  if (proc.status !== 0) {
    return {
      kind: 'SetupDefect',
      reason: `lean-exit-${proc.status}: ${(proc.stderr || proc.stdout).slice(0, 300)}`,
    };
  }

  const parsed: LeanAxiomAuditVerdict = parseLeanPrintAxiomsOutput(
    proc.stdout,
    fullyQualifiedTheorems,
  );
  if (parsed.kind !== 'Proven') {
    return {
      kind: 'Refuted',
      reason: parsed.kind === 'Refuted' ? parsed.reason : 'missing-theorem-axiom-report',
      details: parsed,
    };
  }

  const fleetAttestationDigest = sha256Digest({
    facadeModule: LEANPOO_EXPORT_FACADE_MODULE,
    moduleCount: manifest.length,
    verifiedTheoremCount: fullyQualifiedTheorems.length,
    theoremAxioms: parsed.theoremAxioms,
  });

  let pinnedReceiptHash: string | undefined;
  if (params?.kv) {
    pinnedReceiptHash = params.kv.putBlob(
      'leanpoo-library-fleet-attestation',
      {
        facadeModule: LEANPOO_EXPORT_FACADE_MODULE,
        moduleCount: manifest.length,
        verifiedTheoremCount: fullyQualifiedTheorems.length,
        fleetAttestationDigest,
        zeroMathlib: true,
        zeroCedar: true,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedReceiptHash);
  }

  return {
    kind: 'Proven',
    facadeModule: LEANPOO_EXPORT_FACADE_MODULE,
    moduleCount: manifest.length,
    verifiedTheoremCount: fullyQualifiedTheorems.length,
    theoremAxioms: parsed.theoremAxioms,
    fleetAttestationDigest,
    pinnedReceiptHash,
  };
}

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM38 (ADV-L4): Defense Pillar Cryptographic & State-Machine Integrity
;;; Confinement.
;;; Formalizes five real ADV-L4 boundary defects discovered in
;;; marlin-agent-kernel's unified B9/B14/B16/B18/B20/B21 defense pillar gates:
;;;  1. key_rotation_shredding.rs (B16): shred_retired_epoch only checked
;;;     epoch == active_epoch, letting callers tombstone future epochs (> active)
;;;     or epoch 0 to permanently DoS rotate_to_epoch; admit_rewrap admitted
;;;     non-existent epoch 0; rotate_to_epoch used saturating_add(1) overwriting
;;;     at u64::MAX; and new() accepted blank tenant_id.
;;;  2. zk_selective_disclosure.rs (B18): admit_disclosure matched
;;;     forbidden_secret_fields case-sensitively without trimming (letting
;;;     "RAW_PII" or " raw_pii " leak forbidden "raw_pii"), while
;;;     issue_challenge_nonce lacked consumed_challenges tracking and blank
;;;     nonce refusal, enabling challenge nonce replay.
;;;  3. supply_chain_provenance.rs (B14): admit_build compared builder_a_id ==
;;;     builder_b_id without case/whitespace normalization (single-builder
;;;     spoofing), register_pinned_dependency silently overwrote existing pins
;;;     and admitted CVE-tombstoned/blank coordinates, and admit_build admitted
;;;     duplicate dependency specs and replayed release_id values.
;;;  4. federated_org_reciprocity.rs (B20): register_treaty blindly overwrote
;;;     existing treaties, wiping active dispute_freeze_active=true without
;;;     arbitration and allowing treaty_epoch rollback, while register_treaty
;;;     and admit_federated_op checked org_a == org_b / origin_org == target_org
;;;     without case/whitespace normalization (self-reciprocity bypass).
;;;  5. transparency_log.rs (B9) & model_weight_attestation.rs (B21):
;;;     verify_tree_head_progression accepted forged non-empty root hashes at
;;;     tree_size == 0 and skipped proof size parity on equal/zero branches,
;;;     while compute_shard_merkle_root duplicated odd trailing nodes
;;;     (CVE-2012-2459 Merkle second-preimage malleability: root([A,B,C]) ==
;;;     root([A,B,C,C])).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DefensePillarCryptoStateConfinementModel)

(.def (DefensePillarCryptoStateConfinementModel @ ThreatModel.)
  identity: 'threat.execution.defense-pillar-crypto-state-confinement
  family: 'threat.execution.defense-pillar-crypto-state-confinement
  title: "Defense Pillar Cryptographic & State-Machine Integrity Confinement (SM38)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM38 ADV-L4 defense-pillar cryptographic and state-machine confinement forbidding B16 future-epoch shredding DoS and epoch-0 rewrap, B18 case/whitespace secret over-disclosure and challenge nonce replay, B14 case/whitespace 2-builder spoofing and silent pin overwrite/release replay, B20 treaty dispute-freeze wipeout, epoch rollback, and self-reciprocity case spoofing, and B9/B21 RFC 6962 empty-head forgery plus CVE-2012-2459 odd-leaf Merkle duplication.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-kernel B9/B14/B16/B18/B20/B21 gates admitted future-epoch tombstoning in shred_retired_epoch, raw case-sensitive forbidden secret checks and unconsumed challenge replay in ZkSelectiveDisclosureGate, case/whitespace single-builder spoofing and blind pin overwrite in SupplyChainProvenanceGate, dispute-freeze wipeout and epoch rollback on treaty re-registration in FederatedOrgReciprocityGate, forged empty-tree root hashes in verify_tree_head_progression, and odd-leaf Merkle duplication in compute_shard_merkle_root."))
  quint-module: "execution_defense_pillar_crypto_state_confinement"
  quint-file: "DefensePillarCryptoStateConfinement.qnt"
  domain-dir: "threat/execution/defense-pillar-crypto-state-confinement"
  rules:
  '((defense-pillar-crypto-state-safe DE-SM38-SAFE quint)
    (defense-pillar-crypto-state-countermodel DE-SM38-COUNTER quint))
  dependencies:
  '((DE-SM38-SAFE source)
    (DE-SM38-SAFE profile)
    (DE-SM38-SAFE method)
    (DE-SM38-COUNTER source)
    (DE-SM38-COUNTER profile)
    (DE-SM38-COUNTER method))
  invariant: "B16 restricts shredding strictly to retired epochs (0 < epoch < activeEpoch) and rewrap strictly to live committed epochs (keyEpochBreaches == 0 and keyEpochGuarded and shreddedMaxEpoch < activeEpoch), B18 enforces canonical case/whitespace-folded secret filtering and consumed-challenge anti-replay (zkDisclosureBreaches == 0 and zkNormalizedAndFresh), B14 enforces canonical 2-builder distinctness, immutable CVE-checked dependency pinning, and non-replayed releases (supplyChainBreaches == 0 and supplyChainPinnedAndDistinct), B20 preserves active dispute freezes and monotonic treaty epochs with canonical anti-self-reciprocity (treatyReciprocityBreaches == 0 and treatyFreezeAndEpochMonotonic), and B9/B21 enforce RFC 6962 empty-root/size parity and non-duplicating domain-separated Merkle roots (merkleIntegrityBreaches == 0 and merkleNoDupAndEmptyRootChecked)."
  limits: "Finite bounded defense-pillar cryptographic and state-machine integrity confinement model (1 <= activeEpoch <= 12, 0 <= shreddedMaxEpoch < activeEpoch, stepCount <= 12); models fail-closed B16 retired-only epoch shredding and live-epoch rewrap, B18 canonical case/whitespace-folded forbidden secret filtering with consumed-challenge anti-replay, B14 canonical 2-builder distinctness with immutable CVE-checked dependency pinning and single-use release admission, B20 monotonic bilateral treaty epochs preserving active dispute freezes and canonical anti-self-reciprocity, and B9/B21 RFC 6962 empty-head and non-duplicating Merkle root integrity, without modeling underlying SHA-256 collision hardness or network Byzantine timing.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Reusable threat-model profiles (composition, depth, seed, required countermodels).
(import
  :clan/poo/object
  (only-in :clan/poo/type validate)
  (only-in "../threat-capabilities/objects.ss" CapabilitiesModel)
  (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel)
  (only-in "../effect-handoff/objects.ss" EffectHandoffModel)
  (only-in "../effect-containment/objects.ss" EffectContainmentModel)
  (only-in "../state-rollback/objects.ss" StateRollbackModel)
  (only-in "../zero-trust-pep-pdp/objects.ss" ZeroTrustPepPdpModel)
  (only-in "../workload-identity-rotation/objects.ss" WorkloadIdentityRotationModel)
  (only-in "../microsegmentation-egress/objects.ss" MicrosegmentationEgressModel)
  (only-in "../oauth-token-lifecycle/objects.ss" OAuthTokenLifecycleModel)
  (only-in "../oidc-federation/objects.ss" OidcFederationModel)
  (only-in "../device-authorization/objects.ss" DeviceAuthorizationModel)
  (only-in "../governance-sod/objects.ss" GovernanceSodModel)
  (only-in "../data-lineage-disclosure/objects.ss" DataLineageDisclosureModel)
  (only-in "../oauth-revocation-recovery/objects.ss" OAuthRevocationRecoveryModel)
  (only-in "../agent-ifc-capability/objects.ss" AgentIfcCapabilityModel)
  (only-in "../dpop-sender-constrain/objects.ss" DpopSenderConstrainModel)
  (only-in "../supply-chain-tuf/objects.ss" SupplyChainTufModel)
  (only-in "../macaroon-delegation-chain/objects.ss" MacaroonDelegationModel)
  (only-in "../webauthn-passkey-ceremony/objects.ss" WebAuthnPasskeyCeremonyModel)
  (only-in "../transparency-log-gossip/objects.ss" TransparencyLogGossipModel)
  (only-in "../wasm-sandbox-confinement/objects.ss" WasmSandboxConfinementModel)
  (only-in "../tls13-0rtt-forward-secrecy/objects.ss" Tls13ZeroRttForwardSecrecyModel)
  (only-in "../gc-tricolor-barrier/objects.ss" TricolorWriteBarrierModel)
  (only-in "../gc-safepoint-handshake/objects.ss" SafepointHandshakeModel)
  (only-in "../parallel-epoch-reclamation/objects.ss" EpochReclamationModel)
  (only-in "../parallel-work-stealing/objects.ss" WorkStealingDequeModel)
  (only-in "../parallel-hazard-pointers-tso/objects.ss" HazardPointersTsoModel)
  (only-in "../concurrency-structured-cancel/objects.ss" StructuredCancelModel)
  (only-in "../concurrency-lease-fencing/objects.ss" LeaseFencingModel)
  (only-in "../concurrency-saga-compensation/objects.ss" SagaCompensationModel)
  (only-in "../storage-wal-crash-recovery/objects.ss" WalCrashRecoveryModel)
  (only-in "../storage-mvcc-ssi/objects.ss" MvccSsiWriteSkewModel)
  (only-in "../consensus-raft-commitment/objects.ss" RaftLeaderCommitmentModel)
  (only-in "../quint-methods/types.ss" QuintProfileType))
(export ThreatModelProfiles)

(def (checked-profile profile) (validate QuintProfileType profile))

(def ThreatModelProfiles
  (.o
    threat-capabilities:
    (checked-profile
      (.o identity: 'threat-capabilities
          model: CapabilitiesModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #f))
    authority-currentness:
    (checked-profile
      (.o identity: 'authority-currentness
          model: AuthorityCurrentnessModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #f))
    effect-handoff:
    (checked-profile
      (.o identity: 'effect-handoff
          model: EffectHandoffModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    effect-containment:
    (checked-profile
      (.o identity: 'effect-containment
          model: EffectContainmentModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    exact-effect-host:
    (checked-profile
      (.o identity: 'exact-effect-host
          model: StateRollbackModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    zero-trust-pep-pdp:
    (checked-profile
      (.o identity: 'zero-trust-pep-pdp
          model: ZeroTrustPepPdpModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    workload-identity-rotation:
    (checked-profile
      (.o identity: 'workload-identity-rotation
          model: WorkloadIdentityRotationModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    microsegmentation-egress:
    (checked-profile
      (.o identity: 'microsegmentation-egress
          model: MicrosegmentationEgressModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    oauth-token-lifecycle:
    (checked-profile
      (.o identity: 'oauth-token-lifecycle
          model: OAuthTokenLifecycleModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    oidc-federation:
    (checked-profile
      (.o identity: 'oidc-federation
          model: OidcFederationModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    device-authorization:
    (checked-profile
      (.o identity: 'device-authorization
          model: DeviceAuthorizationModel
          seed: 7
          positive-depth: 12
          negative-depth: 5
          require-countermodels?: #t))
    governance-sod:
    (checked-profile
      (.o identity: 'governance-sod
          model: GovernanceSodModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    data-lineage-disclosure:
    (checked-profile
      (.o identity: 'data-lineage-disclosure
          model: DataLineageDisclosureModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    oauth-revocation-recovery:
    (checked-profile
      (.o identity: 'oauth-revocation-recovery
          model: OAuthRevocationRecoveryModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    agent-ifc-capability:
    (checked-profile
      (.o identity: 'agent-ifc-capability
          model: AgentIfcCapabilityModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    dpop-sender-constrain:
    (checked-profile
      (.o identity: 'dpop-sender-constrain
          model: DpopSenderConstrainModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    supply-chain-tuf:
    (checked-profile
      (.o identity: 'supply-chain-tuf
          model: SupplyChainTufModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    macaroon-delegation-chain:
    (checked-profile
      (.o identity: 'macaroon-delegation-chain
          model: MacaroonDelegationModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    webauthn-passkey-ceremony:
    (checked-profile
      (.o identity: 'webauthn-passkey-ceremony
          model: WebAuthnPasskeyCeremonyModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    transparency-log-gossip:
    (checked-profile
      (.o identity: 'transparency-log-gossip
          model: TransparencyLogGossipModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    wasm-sandbox-confinement:
    (checked-profile
      (.o identity: 'wasm-sandbox-confinement
          model: WasmSandboxConfinementModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    tls13-0rtt-forward-secrecy:
    (checked-profile
      (.o identity: 'tls13-0rtt-forward-secrecy
          model: Tls13ZeroRttForwardSecrecyModel
          seed: 7
          positive-depth: 10
          negative-depth: 6
          require-countermodels?: #t))
    gc-tricolor-barrier:
    (checked-profile
      (.o identity: 'gc-tricolor-barrier
          model: TricolorWriteBarrierModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    gc-safepoint-handshake:
    (checked-profile
      (.o identity: 'gc-safepoint-handshake
          model: SafepointHandshakeModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    parallel-epoch-reclamation:
    (checked-profile
      (.o identity: 'parallel-epoch-reclamation
          model: EpochReclamationModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    parallel-work-stealing:
    (checked-profile
      (.o identity: 'parallel-work-stealing
          model: WorkStealingDequeModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    parallel-hazard-pointers-tso:
    (checked-profile
      (.o identity: 'parallel-hazard-pointers-tso
          model: HazardPointersTsoModel
          seed: 7
          positive-depth: 12
          negative-depth: 9
          require-countermodels?: #t))
    concurrency-structured-cancel:
    (checked-profile
      (.o identity: 'concurrency-structured-cancel
          model: StructuredCancelModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))
    concurrency-lease-fencing:
    (checked-profile
      (.o identity: 'concurrency-lease-fencing
          model: LeaseFencingModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    concurrency-saga-compensation:
    (checked-profile
      (.o identity: 'concurrency-saga-compensation
          model: SagaCompensationModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    storage-wal-crash-recovery:
    (checked-profile
      (.o identity: 'storage-wal-crash-recovery
          model: WalCrashRecoveryModel
          seed: 7
          positive-depth: 12
          negative-depth: 6
          require-countermodels?: #t))
    storage-mvcc-ssi:
    (checked-profile
      (.o identity: 'storage-mvcc-ssi
          model: MvccSsiWriteSkewModel
          seed: 7
          positive-depth: 10
          negative-depth: 9
          require-countermodels?: #t))
    consensus-raft-commitment:
    (checked-profile
      (.o identity: 'consensus-raft-commitment
          model: RaftLeaderCommitmentModel
          seed: 7
          positive-depth: 10
          negative-depth: 9
          require-countermodels?: #t))))

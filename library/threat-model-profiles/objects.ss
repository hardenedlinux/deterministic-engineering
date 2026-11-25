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
  (only-in "../gc-tricolor-barrier/objects.ss" TricolorWriteBarrierModel)
  (only-in "../gc-safepoint-handshake/objects.ss" SafepointHandshakeModel)
  (only-in "../parallel-epoch-reclamation/objects.ss" EpochReclamationModel)
  (only-in "../parallel-work-stealing/objects.ss" WorkStealingDequeModel)
  (only-in "../concurrency-structured-cancel/objects.ss" StructuredCancelModel)
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
    concurrency-structured-cancel:
    (checked-profile
      (.o identity: 'concurrency-structured-cancel
          model: StructuredCancelModel
          seed: 7
          positive-depth: 12
          negative-depth: 4
          require-countermodels?: #t))))

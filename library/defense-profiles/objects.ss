;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; G3/G4 Orthogonal by-tag Defense Profiles & Band-5 Monotonic Floors (10.153).
;;; Enforces scoped defenses strictly on matching mutability/guard tags:
;;;   - M3 mutable-root      -> require-use-time-witness?: #t (monotonic OR)
;;;   - M2 negative-domain   -> allow-global-purge?: #f (monotonic AND), require-dependency-manifest?: #t
;;;   - M1 immutable         -> allow-sufficiency-stop?: #t (runtime-switchable)
;;;   - guard-declared       -> require-guard-necessity-countermodel?: #t, require-admission-five-tuple?: #t
(import :clan/poo/object
        (only-in :tao3k/yuanxu/module-system/convergence/types
                 make-slot-spec make-global-profile by-tag)
        (only-in :tao3k/yuanxu/module-system/convergence/bridge
                 converge-selected-graph apply-graph-runtime-overlay))
(export DefenseSlotSpecs
        DefenseDefaultSlots
        DefenseGovernanceFloor
        DefenseProfiles
        DefenseProfileRegistry
        converge-defense-graph
        apply-defense-runtime-profile)

(def (monotonic-require-meet a b) (or a b))
(def (monotonic-forbid-meet a b) (and a b))

(def DefenseSlotSpecs
  (list
    (make-slot-spec 'require-use-time-witness?
      stage: 'assembly
      combiner: 'meet
      default: #f
      meet: monotonic-require-meet)
    (make-slot-spec 'allow-global-purge?
      stage: 'assembly
      combiner: 'meet
      default: #t
      meet: monotonic-forbid-meet)
    (make-slot-spec 'require-dependency-manifest?
      stage: 'assembly
      combiner: 'meet
      default: #f
      meet: monotonic-require-meet)
    (make-slot-spec 'require-guard-necessity-countermodel?
      stage: 'assembly
      combiner: 'meet
      default: #f
      meet: monotonic-require-meet)
    (make-slot-spec 'require-admission-five-tuple?
      stage: 'assembly
      combiner: 'meet
      default: #f
      meet: monotonic-require-meet)
    (make-slot-spec 'allow-sufficiency-stop?
      stage: 'runtime
      combiner: 'exclusive
      default: #f)
    (make-slot-spec 'review-tier
      stage: 'runtime
      combiner: 'exclusive
      default: 'bounded-contract
      allowed: '(mechanical-syntax bounded-contract semantic-review))))

(def DefenseDefaultSlots
  (.o require-use-time-witness?: #f
      allow-global-purge?: #t
      require-dependency-manifest?: #f
      require-guard-necessity-countermodel?: #f
      require-admission-five-tuple?: #f
      allow-sufficiency-stop?: #f
      review-tier: 'bounded-contract))

(def DefenseGovernanceFloor
  (.o require-guard-necessity-countermodel?: #t
      require-admission-five-tuple?: #t))

(def DefenseProfiles
  (.o
    mutable-root-floor:
    (make-global-profile 'defense.mutable-root-floor
      (list (by-tag 'defense.mutability.mutable-root))
      (.o require-use-time-witness?: #t))
    negative-domain-floor:
    (make-global-profile 'defense.negative-domain-floor
      (list (by-tag 'defense.mutability.negative-domain))
      (.o allow-global-purge?: #f
          require-dependency-manifest?: #t))
    immutable-sufficiency:
    (make-global-profile 'defense.immutable-sufficiency
      (list (by-tag 'defense.mutability.immutable))
      (.o allow-sufficiency-stop?: #t))
    guard-necessity-floor:
    (make-global-profile 'defense.guard-necessity-floor
      (list (by-tag 'defense.property.guard-declared))
      (.o require-guard-necessity-countermodel?: #t
          require-admission-five-tuple?: #t))))

(def DefenseProfileRegistry
  (object<-alist
    (list
      (cons 'defense.mutable-root-floor (.get DefenseProfiles mutable-root-floor))
      (cons 'defense.negative-domain-floor (.get DefenseProfiles negative-domain-floor))
      (cons 'defense.immutable-sufficiency (.get DefenseProfiles immutable-sufficiency))
      (cons 'defense.guard-necessity-floor (.get DefenseProfiles guard-necessity-floor)))))

(def (converge-defense-graph graph (extra-registry #f))
  (converge-selected-graph graph
    global-profile-registry: (or extra-registry DefenseProfileRegistry)
    module-profile-registry: (or extra-registry DefenseProfileRegistry)))

(def (apply-defense-runtime-profile graph assembly-result runtime-overrides)
  (apply-graph-runtime-overlay graph assembly-result runtime-overrides))

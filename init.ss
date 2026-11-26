;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-window Yuanxu root declaration for deterministic-engineering.
;;; Core Scheme methods/contracts live in ./library; co-located Quint model units
;;; mount by symmetric 3-level formal domain hierarchy (<domain>/<subdomain>/<model>/)
;;; with orthogonal dotted tags and 3-axis Profiles (assurance.*, bound.*, governance.*).
(import :tao3k/yuanxu/module-system/selection/init-syntax)

(yuanxu!
  ;; Core Gerbil/Yuanxu Scheme library (methods, contracts, profiles, organization).
  :load-modules "./library"
    mode: auto
    profile: engineering
    mount: Library
    :test-dir "./t"

  ;; ── Engineering Formal State Models (5 subdomains) ──
  :load-modules "./packages/quint-models/engineering/storage"
    mode: auto
    mount: Quint.Engineering.Storage
    export: QuintEngineeringStorageSource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"
  (mvcc-ssi-write-skew profiles: (bound.extended-counterexample))

  :load-modules "./packages/quint-models/engineering/consensus"
    mode: auto
    mount: Quint.Engineering.Consensus
    export: QuintEngineeringConsensusSource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"
  (raft-leader-commitment profiles: (bound.extended-counterexample))

  :load-modules "./packages/quint-models/engineering/concurrency"
    mode: auto
    mount: Quint.Engineering.Concurrency
    export: QuintEngineeringConcurrencySource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"
  (backpressure-memory profiles: (bound.compact))

  :load-modules "./packages/quint-models/engineering/parallel"
    mode: auto
    mount: Quint.Engineering.Parallel
    export: QuintEngineeringParallelSource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"
  (hazard-pointers-tso profiles: (bound.deep-counterexample))

  :load-modules "./packages/quint-models/engineering/gc"
    mode: auto
    mount: Quint.Engineering.GC
    export: QuintEngineeringGcSource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"

  ;; ── Threat-First Formal Security Models (5 subdomains) ──
  :load-modules "./packages/quint-models/threat/zero-trust"
    mode: auto
    mount: Quint.Threat.ZeroTrust
    export: QuintThreatZeroTrustSource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"

  :load-modules "./packages/quint-models/threat/identity"
    mode: auto
    mount: Quint.Threat.Identity
    export: QuintThreatIdentitySource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"

  :load-modules "./packages/quint-models/threat/protocol"
    mode: auto
    mount: Quint.Threat.Protocol
    export: QuintThreatProtocolSource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"
  (tls13-0rtt-forward-secrecy profiles: (bound.compact))

  :load-modules "./packages/quint-models/threat/supply-chain"
    mode: auto
    mount: Quint.Threat.SupplyChain
    export: QuintThreatSupplyChainSource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t"

  :load-modules "./packages/quint-models/threat/execution"
    mode: auto
    mount: Quint.Threat.Execution
    export: QuintThreatExecutionSource
    :profiles (assurance.bounded-proof bound.standard governance.mandatory-countermodels)
    :test-dir "./t")

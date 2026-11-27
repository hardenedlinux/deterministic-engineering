;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; CI/CD scientific content-addressed caching, subdomain sharding conflict freedom,
;;; hermetic engine+source action-key soundness, and active-set cache quota GC (SM18).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export CiCacheSoundnessAndShardingModel)

(.def (CiCacheSoundnessAndShardingModel @ ThreatModel.)
  identity: 'engineering.concurrency.ci-cache-soundness-and-sharding
  family: 'engineering.concurrency.ci-cache-soundness-and-sharding
  title: "CI/CD Scientific Content-Addressed Caching, Subdomain Sharding & Active-Set GC"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("A. Mokhov, N. Mitchell & S. Peyton Jones (ACM ICFP 2018)"
     "Build Systems a la Carte — constructive cryptographic action keys prevent stale false-hit poisoning across source, flag, and engine changes.")
    ("E. Dolstra, M. de Jonge & E. Visser (USENIX LISA 2004)"
     "Nix: Purely Functional Deployment — hermetic toolchain and transitive dependency hashing makes CI cache reuse sound and reproducible.")
    ("M. Grottke & K. S. Trivedi (IEEE Computer 2007)"
     "Fighting Bugs — shard-disjoint immutable cache namespaces eliminate parallel matrix write conflicts while active-set GC bounds cache quota watermarks."))
  quint-module: "concurrency_ci_cache_soundness_and_sharding"
  quint-file: "CiCacheSoundnessAndSharding.qnt"
  domain-dir: "engineering/concurrency/ci-cache-soundness-and-sharding"
  rules:
  '((conc-cicache-hermetic-key CONC-CICACHE-HERMETIC-KEY quint)
    (conc-cicache-disjoint-shards CONC-CICACHE-DISJOINT-SHARDS quint)
    (conc-cicache-active-set-gc CONC-CICACHE-ACTIVE-SET-GC quint))
  dependencies:
  '((CONC-CICACHE-HERMETIC-KEY source)
    (CONC-CICACHE-HERMETIC-KEY profile)
    (CONC-CICACHE-HERMETIC-KEY method)
    (CONC-CICACHE-DISJOINT-SHARDS source)
    (CONC-CICACHE-DISJOINT-SHARDS profile)
    (CONC-CICACHE-DISJOINT-SHARDS method)
    (CONC-CICACHE-ACTIVE-SET-GC source)
    (CONC-CICACHE-ACTIVE-SET-GC profile)
    (CONC-CICACHE-ACTIVE-SET-GC method))
  invariant: "Every CI cache hit requires exact engine+source+flag cryptographic ActionKey equality (falseHitCount == 0), parallel subdomain shards own disjoint immutable cache namespaces (writeConflictCount == 0 and shardNamespacesDisjoint == true), and active-set GC bounds retained cache entries <= maxCacheEntries."
  limits: "Finite 3-epoch source/engine and 4-entry cache quota abstraction; verifies hermetic ActionKey invalidation, disjoint parallel shard namespaces, and active-set GC quota bounding, not network CDN transport latency or compression ratios.")

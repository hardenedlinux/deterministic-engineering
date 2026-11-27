;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Bounded stateful projection, session-slot LRU eviction & cascade side-map cleanup model.
;;; Co-located Yuanxu unit: single source of truth alongside BoundedProjectionEviction.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BoundedProjectionEvictionModel
        UnboundedProjectionGrowthCountermodel
        OrphanSideMapLeakCountermodel)

(.def (BoundedProjectionEvictionModel @ ThreatModel.)
  identity: 'engineering.concurrency.bounded-projection-eviction
  family: 'engineering.concurrency.bounded-projection-eviction
  title: "Bounded Stateful Projection, Idle Eviction & Cascade Side-Map Cleanup"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("Y. Huang, C. Kintala, N. Kolettis & N. D. Fulton (IEEE FTCS 1995)"
     "Software Rejuvenation: Analysis, Module and Applications — bounding monotonically accumulating runtime state.")
    ("M. Jump & K. S. McKinley (ACM POPL 2007)"
     "Cork: Dynamic Memory Leak Detection for Garbage-Collected Languages — detecting growing long-lived maps and caches.")
    ("G. Xu, N. Mitchell, M. Arnold, A. Rountev, E. Schonberg & G. Sevitsky (ACM PLDI 2010)"
     "Finding Low-Utility Data Structures — evicting idle retained state and orphaned auxiliary maps."))
  quint-module: "concurrency_bounded_projection_eviction"
  quint-file: "BoundedProjectionEviction.qnt"
  domain-dir: "engineering/concurrency/bounded-projection-eviction"
  quint-imports: '()
  rules:
  '((conc-proj-cap CONC-PROJ-CAP quint)
    (conc-proj-orphan CONC-PROJ-ORPHAN quint))
  dependencies:
  '((CONC-PROJ-CAP source)
    (CONC-PROJ-CAP profile)
    (CONC-PROJ-CAP method)
    (CONC-PROJ-ORPHAN source)
    (CONC-PROJ-ORPHAN profile)
    (CONC-PROJ-ORPHAN method))
  invariant: "Long-lived projection/session/artifact tables stay within their entry cap, reclaim idle slots on capacity pressure without permanent lockout, and cascade-delete auxiliary side maps with zero orphaned keys."
  parameters: '()
  state:
  '((entries "int" "0")
    (activeCount "int" "0")
    (orphanedSideMap "int" "0")
    (evictions "int" "0"))
  guards:
  '((bounded-entry-cap (< (. h entries) 2))
    (cascade-delete-sidemap 0))
  transitions:
  '((admitEntry
      (action admitEntry ()
        (if (and (< (. h entries) 3)
                 (guard bounded-entry-cap (< (. h entries) 2)))
          (set-h (entries (+ (. h entries) 1))
                 (activeCount (+ (. h activeCount) 1)))
          (keep-h))))
    (deactivateEntry
      (action deactivateEntry ()
        (if (> (. h activeCount) 0)
          (set-h (activeCount (- (. h activeCount) 1)))
          (keep-h))))
    (evictIdleEntry
      (action evictIdleEntry ()
        (if (> (. h entries) (. h activeCount))
          (set-h (entries (- (. h entries) 1))
                 (evictions (+ (. h evictions) 1))
                 (orphanedSideMap (guard cascade-delete-sidemap 0 (+ (. h orphanedSideMap) 1))))
          (keep-h))))
    (admitWithIdleEviction
      (action admitWithIdleEviction ()
        (if (and (= (. h entries) 2) (< (. h activeCount) (. h entries)))
          (set-h (activeCount (+ (. h activeCount) 1))
                 (evictions (+ (. h evictions) 1)))
          (keep-h))))
    (step
      (action step ()
        (any admitEntry deactivateEntry evictIdleEntry admitWithIdleEviction))))
  safety:
  '(and (<= (. h entries) 2)
        (<= (. h activeCount) (. h entries))
        (= (. h orphanedSideMap) 0))
  traces:
  '((checkBoundedReclaimed
      (action checkBoundedReclaimed ()
        (all (assert (<= (. h entries) 2))
             (assert (> (. h evictions) 0))
             (assert (= (. h orphanedSideMap) 0))
             (assert safety)
             (keep-h))))
    (checkEvictionViolation
      (action checkEvictionViolation ()
        (all (assert (or (> (. h entries) 2) (> (. h orphanedSideMap) 0)))
             (assert (not safety))
             (keep-h))))
    (evictionReclaimsFullTableTest
      (run evictionReclaimsFullTableTest
        (then init admitEntry admitEntry deactivateEntry admitWithIdleEviction deactivateEntry evictIdleEntry checkBoundedReclaimed)))
    (unboundedGrowthRefutedTest
      (run unboundedGrowthRefutedTest
        (then init admitEntry admitEntry admitEntryUnbounded checkEvictionViolation)))
    (orphanSideMapRefutedTest
      (run orphanSideMapRefutedTest
        (then init admitEntry deactivateEntry evictIdleEntryOrphan checkEvictionViolation))))
  countermodels: (list UnboundedProjectionGrowthCountermodel OrphanSideMapLeakCountermodel)
  limits: "Finite 2-slot projection/session table abstraction; models bounded retention, idle eviction reclaimability, and cascade side-map deletion, not physical LRU hash-table internals or disk WAL compaction.")

(.def (UnboundedProjectionGrowthCountermodel @ BoundedProjectionEvictionModel)
  identity: 'engineering.concurrency.bounded-projection-eviction.unbounded-growth
  dropped-guard: 'bounded-entry-cap
  step-action: "stepUnboundedGrowth"
  derive-from-transition: 'admitEntry
  derive-action-name: 'admitEntryUnbounded
  expected-itf-predicate: "h.entries > 2")

(.def (OrphanSideMapLeakCountermodel @ BoundedProjectionEvictionModel)
  identity: 'engineering.concurrency.bounded-projection-eviction.orphan-sidemap
  dropped-guard: 'cascade-delete-sidemap
  step-action: "stepOrphanSideMap"
  derive-from-transition: 'evictIdleEntry
  derive-action-name: 'evictIdleEntryOrphan
  expected-itf-predicate: "h.orphanedSideMap > 0")

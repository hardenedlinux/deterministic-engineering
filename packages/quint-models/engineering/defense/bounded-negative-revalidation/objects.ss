;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F2: Negative dependencies, immutable frozen cuts, and bounded revalidation (20.16-20.18 DE01 / 10.153).
;;; Proves that expanding a negative domain invalidates only dependent current reviews while
;;; preserving frozen historical snapshots and independent M1 method results, and forbids
;;; re-closing current review by repeating the falsified negative-absence premise.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BoundedNegativeRevalidationModel)

(.def (BoundedNegativeRevalidationModel @ ThreatModel.)
  identity: 'engineering.defense.bounded-negative-revalidation
  family: 'engineering.defense.bounded-negative-revalidation
  title: "Negative Dependencies, Immutable Cuts & Bounded Revalidation (DE01)"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (20.16 / 20.17 / 20.18)"
     "DE01 / ND / MV / AM: scoped revalidation on negative-dependency changes without global purge or false-reason replay.")
    ("R. Reiter (1980) / Stratified Datalog"
     "Non-monotonic negative dependencies over named finite closed domains."))
  quint-module: "bounded_negative_revalidation"
  quint-file: "BoundedNegativeRevalidation.qnt"
  domain-dir: "engineering/defense/bounded-negative-revalidation"
  rules:
  '((bounded-reval-safe DE-REVAL-SAFE quint)
    (bounded-reval-countermodel DE-REVAL-COUNTER quint))
  dependencies:
  '((DE-REVAL-SAFE source)
    (DE-REVAL-SAFE profile)
    (DE-REVAL-SAFE method)
    (DE-REVAL-COUNTER source)
    (DE-REVAL-COUNTER profile)
    (DE-REVAL-COUNTER method))
  invariant: "Frozen historical cuts and independent M1 method bytes remain intact across negative-domain expansion; stale negative-absence reviews are invalidated upon relevant counter arrival; re-closing current review requires an admitted replacement reason."
  limits: "Finite single-counter expansion model of DE01 negative-dependency invalidation; does not model arbitrary multi-domain policy hierarchies or external artifact byte hashing.")

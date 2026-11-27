;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F1: Six-state epistemic and contract lattice (10.153 / 20.16 DE01).
;;; Prevents P1 silent-fallback masking, P1 last-writer-wins conflict erasure,
;;; and P3 collapsing pending/unknown states into established violations.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export EpistemicStateLatticeModel)

(.def (EpistemicStateLatticeModel @ ThreatModel.)
  identity: 'engineering.defense.epistemic-state-lattice
  family: 'engineering.defense.epistemic-state-lattice
  title: "Six-State Epistemic Lattice & Non-Collapsing Defense Boundaries"
  subdomain: 'quint.engineering.defense
  papers:
  '(("N. D. Belnap (1977)"
     "A Useful Four-Valued Logic: separating Proven, Refuted, Unknown, and Conflict without explosion.")
    ("Deterministic Engineering (20.16 / 10.153)"
     "F1 six-state contract lattice: SetupDefect, PendingMethod, PendingScope, Proven, Refuted, and Conflict."))
  quint-module: "epistemic_state_lattice"
  quint-file: "EpistemicStateLattice.qnt"
  domain-dir: "engineering/defense/epistemic-state-lattice"
  rules:
  '((epistemic-safe DE-EPI-SAFE quint)
    (epistemic-countermodel DE-EPI-COUNTER quint))
  dependencies:
  '((DE-EPI-SAFE source)
    (DE-EPI-SAFE profile)
    (DE-EPI-SAFE method)
    (DE-EPI-COUNTER source)
    (DE-EPI-COUNTER profile)
    (DE-EPI-COUNTER method))
  invariant: "Missing expected body (SetupDefect), incomplete method/scope (PendingMethod/PendingScope), and unresolved contradictory records (Conflict) never collapse into Proven (3) or Refuted (4)."
  limits: "Finite six-state epistemic abstraction (0=SetupDefect, 1=PendingMethod, 2=PendingScope, 3=Proven, 4=Refuted, 5=Conflict); does not model cryptographic signature verification or external authority transport.")

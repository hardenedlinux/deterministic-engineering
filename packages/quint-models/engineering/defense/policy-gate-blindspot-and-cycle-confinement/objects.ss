;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM27 (ADV-L4): Policy-Gate Blind-Spot, Dependency-Cycle Masking & Entrypoint Confinement.
;;; Models the empirically observed multi-crate governance erosion pattern where local
;;; dev-dependency cycles panic and blind workspace policy gates, critical control-plane
;;; crates omit per-crate policy gates or downgrade mode=fail to warn/allow, fat binary
;;; and root test entrypoints accumulate shadow logic outside owned library modules, and
;;; CI workflows omit workspace policy enforcement.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PolicyGateBlindspotAndCycleConfinementModel)

(.def (PolicyGateBlindspotAndCycleConfinementModel @ ThreatModel.)
  identity: 'engineering.defense.policy-gate-blindspot-and-cycle-confinement
  family: 'engineering.defense.policy-gate-blindspot-and-cycle-confinement
  title: "Policy-Gate Blind-Spot, Dependency-Cycle Masking & Entrypoint Confinement (SM27)"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM27 ADV-L4 policy-gate blind-spot confinement: acyclic workspace DAGs, universal fail-closed crate gates, thin binary/test entrypoints, and mandatory CI policy enforcement.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "Three Cargo local dev-dependency cycles blinded workspace_policy while ungated marlin-agent-app-server and marlin-agent-kernel accumulated 65.7% of workspace architectural warnings and repeated SM24-SM26 bypasses."))
  quint-module: "defense_policy_gate_blindspot_and_cycle_confinement"
  quint-file: "PolicyGateBlindspotAndCycleConfinement.qnt"
  domain-dir: "engineering/defense/policy-gate-blindspot-and-cycle-confinement"
  rules:
  '((policy-gate-blindspot-safe DE-SM27-SAFE quint)
    (policy-gate-blindspot-countermodel DE-SM27-COUNTER quint))
  dependencies:
  '((DE-SM27-SAFE source)
    (DE-SM27-SAFE profile)
    (DE-SM27-SAFE method)
    (DE-SM27-COUNTER source)
    (DE-SM27-COUNTER profile)
    (DE-SM27-COUNTER method))
  invariant: "No patch or release is admitted while workspace dev-dependency cycles blind the policy gate (blindedAdmits == 0), while any critical crate is ungated or downgraded out of fail-closed mode (ungatedOrDowngradedAdmits == 0), while fat binary or root-test entrypoints carry shadow implementation (fatEntrypointAdmits == 0), or while CI omits policy-gate execution (ciOmittedReleases == 0)."
  limits: "Finite bounded workspace policy-gate governance model (cyclicSccs <= 2, stepCount <= 12); models Cargo dev-dependency cycle blinding, per-crate policy gate coverage & fail-closed mode, thin binary/test entrypoint confinement, and CI policy-gate invocation, without modeling external registry compromise or arbitrary proc-macro code execution.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM28 (ADV-L4): Plugin Grant, Anti-Rollback, Entry-Path & Bound-Lease Confinement.
;;; Formalizes the AI sibling-clone defensive drift anti-pattern where a newly added
;;; panel/device host keeps decorative grant storage and lease APIs while dropping
;;; capability-grant enforcement and revocation closure, release anti-rollback and
;;; publisher continuity, entry_path traversal confinement, bound device-lease
;;; validation under E-Stop, and digest-checked idempotency replay.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PluginGrantRollbackAndLeaseConfinementModel)

(.def (PluginGrantRollbackAndLeaseConfinementModel @ ThreatModel.)
  identity: 'threat.execution.plugin-grant-rollback-and-lease-confinement
  family: 'threat.execution.plugin-grant-rollback-and-lease-confinement
  title: "Plugin Grant, Anti-Rollback, Entry-Path & Bound-Lease Confinement (SM28)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM28 ADV-L4 capability grant enforcement, revocation closure, release anti-rollback, entry_path confinement, bound device-lease verification under E-Stop, and digest-verified idempotency replay.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "PanelPluginHost stored project capability grants without checking them on enable_panel, blindly overwrote installed releases across versions/publishers with unvalidated entry_path, returned cached action receipts on conflicting args_json, and MyGoBridgeHost accepted forged device lease IDs evicting real devices while ApprovalGateService bypassed E-Stop."))
  quint-module: "execution_plugin_grant_rollback_and_lease_confinement"
  quint-file: "PluginGrantRollbackAndLeaseConfinement.qnt"
  domain-dir: "threat/execution/plugin-grant-rollback-and-lease-confinement"
  rules:
  '((plugin-grant-lease-safe DE-SM28-SAFE quint)
    (plugin-grant-lease-countermodel DE-SM28-COUNTER quint))
  dependencies:
  '((DE-SM28-SAFE source)
    (DE-SM28-SAFE profile)
    (DE-SM28-SAFE method)
    (DE-SM28-COUNTER source)
    (DE-SM28-COUNTER profile)
    (DE-SM28-COUNTER method))
  invariant: "No panel activation proceeds without granted required capabilities (ungrantedActivations == 0 and (activeGen == 0 or grantHeld)), no release downgrade, cross-publisher hijack, or traversal entry_path is admitted (rollbackOrHijacks == 0), no forged device lease or E-Stop device dispatch mutates state (forgedLeaseMutations == 0), and no conflicting idempotency replay returns a stale receipt (idempotencyConflicts == 0)."
  limits: "Finite bounded control-plane plugin lifecycle and device-lease state machine (installedVersion <= 3, stepCount <= 12); models capability grant enforcement and revocation closure, monotonic release version and publisher continuity with confined entry_path, bound device-lease verification under E-Stop, and digest-checked idempotent action replay, without modeling OS kernel or cryptographic primitive breaks.")

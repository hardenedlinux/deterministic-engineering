;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM33 (ADV-L4): Hook Configuration Fail-Closed Parsing, Unique Registry
;;; Anti-Shadowing, Bounded Async Fan-Out, Immutable Trust-Floor Audit &
;;; Protocol Contract Confinement.
;;; Formalizes five real ADV-L4 vulnerabilities discovered in marlin-agent-hooks
;;; and marlin-agent-protocol:
;;;  1. HookConfigurationEnvelope, HookPolicyConfiguration, and
;;;     HookRegistrationDefaults used #[serde(default)] without
;;;     #[serde(deny_unknown_fields)] while defaulting to ObserveOnly, letting
;;;     misspelled/unknown TOML fields silently downgrade EnforceTrusted to
;;;     ObserveOnly; from_toml_path also read unboundedly and GerbilScheme
;;;     extensions admitted empty or path-traversal module/procedure names.
;;;  2. HookRegistry::register pushed duplicate hook_id entries without
;;;     deduplication while set_enabled(.find) and unregister(.position) acted
;;;     on only the first copy, leaving sticky ghost shadow hooks executing
;;;     after disable/unregister; run_permitted_hook_registrations also spawned
;;;     unbounded concurrent Async hook tasks with no semaphore cap.
;;;  3. apply_dynamic_decision_action overwrote Rust trust-floor rejections
;;;     (UntrustedRejected / ModifiedRejected) with ExtensionDeferred /
;;;     ExtensionRejected, erasing security trust violations from receipts,
;;;     while prepare_dispatch accepted unbounded dynamic actions and
;;;     unbounded/NUL Rewrite replacements.
;;;  4. SubAgentSpawnConfigSet admitted contradictory permissions
;;;     (read_only=true && workspace_write=true), zero-budget deadlocks
;;;     (max_concurrency=0 / timeout_ms=0 / token_budget=0), unbounded
;;;     descendant recursion, invalid Scheme module paths, control chars in
;;;     profile_id, and unbounded from_toml_path reads.
;;;  5. RuntimeSessionId derived Serde Deserialize bypassing try_new (admitting
;;;     empty/blank/control/traversal IDs), and ModelEndpoint::validate_contract
;;;     admitted CRLF/NUL/whitespace and URL meta-characters (?, #, @, \, ..).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export HookPolicyAndProtocolContractConfinementModel)

(.def (HookPolicyAndProtocolContractConfinementModel @ ThreatModel.)
  identity: 'threat.execution.hook-policy-and-protocol-contract-confinement
  family: 'threat.execution.hook-policy-and-protocol-contract-confinement
  title: "Hook Policy Confinement, Anti-Shadowing Registry & Protocol Contract Validation (SM33)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM33 ADV-L4 deny_unknown_fields + bounded TOML config parsing with validated GerbilScheme extensions, unique hook_id registry upsert preventing sticky ghost hooks + semaphore-bounded async hook fanout, immutable Rust trust-floor rejection reasons under bounded dynamic actions/rewrites, contradiction/zero-budget/recursion-depth rejection in SubAgentSpawnConfigSet, validated RuntimeSessionId Deserialize parity, and control/URL-meta refusal in ModelEndpoint::validate_contract.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-hooks silently fell back to ObserveOnly on unknown TOML keys, allowed duplicate hook_id shadow copies to keep executing after set_enabled(false)/unregister, spawned unbounded concurrent Async hook tasks, and let extension Defer/Deny erase UntrustedRejected audit reasons; marlin-agent-protocol admitted contradictory read_only+workspace_write and zero-budget SubAgentSpawnConfigSet profiles, bypassed RuntimeSessionId::try_new via derived Deserialize, and admitted CRLF/?/#/@ injection in ModelEndpoint::validate_contract."))
  quint-module: "execution_hook_policy_and_protocol_contract_confinement"
  quint-file: "HookPolicyAndProtocolContractConfinement.qnt"
  domain-dir: "threat/execution/hook-policy-and-protocol-contract-confinement"
  rules:
  '((hook-policy-protocol-safe DE-SM33-SAFE quint)
    (hook-policy-protocol-countermodel DE-SM33-COUNTER quint))
  dependencies:
  '((DE-SM33-SAFE source)
    (DE-SM33-SAFE profile)
    (DE-SM33-SAFE method)
    (DE-SM33-COUNTER source)
    (DE-SM33-COUNTER profile)
    (DE-SM33-COUNTER method))
  invariant: "Hook TOML configuration rejects unknown fields, oversize files, and malformed GerbilScheme extensions fail-closed (configFailOpenBreaches == 0 and strictConfigEnforced), hook registry maintains unique hook_id entries with zero ghost shadows after disable/unregister and caps concurrent async hooks (hookShadowOrFanoutBreaches == 0 and uniqueHookIdsEnforced and asyncTasksRunning <= 4), dynamic extension actions never overwrite UntrustedRejected/ModifiedRejected audit reasons and stay bounded (trustMaskOrActionBreaches == 0 and trustFloorImmutable), and protocol contracts refuse contradictory SubAgent permissions, zero budgets, invalid RuntimeSessionId deserialization, and ModelEndpoint injection (protocolContractBreaches == 0 and protocolContractsEnforced)."
  limits: "Finite bounded hook policy dispatch, registry uniqueness & protocol contract validation state machine (registeredHooks <= 6, asyncTasksRunning <= 4, validatedProfiles <= 4, stepCount <= 12); models deny_unknown_fields + bounded TOML config + validated GerbilScheme extension, unique hook_id upsert preventing sticky ghost hooks + semaphore-bounded async hook fanout, immutable Rust trust-floor rejections (UntrustedRejected/ModifiedRejected) + bounded dynamic policy actions/rewrites, contradictory SubAgentPermissionSet / zero-budget / recursive-depth rejection, validated RuntimeSessionId Deserialize parity, and control/URL-meta refusal in ModelEndpoint::validate_contract, without modeling OS memory pressure or cryptographic signature verification.")

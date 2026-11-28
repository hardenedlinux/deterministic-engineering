;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM34 (ADV-L4): Runtime Environment Activation Isolation, Symlink-Safe
;;; Envrc/Org Store Confinement, Monotonic Org/Channel Ledger Anti-Rollback
;;; & Recomputed Two-Zone KV-Prefix Integrity.
;;; Formalizes five real ADV-L4 vulnerabilities discovered in
;;; marlin-agent-runtime (environment/) and marlin-agent-context:
;;;  1. apply_direnv_json admitted LD_PRELOAD/DYLD_INSERT_LIBRARIES/BASH_ENV
;;;     loader hijacks, denylisted shell vars, and invalid/NUL env keys/values;
;;;     direnv_output called unbounded wait_with_output() without byte cap or
;;;     timeout, and allow ran bare `direnv allow` walking parent directories.
;;;  2. direnv_cwd accepted explicit .envrc files escaping cwd/project.root,
;;;     empty parent paths, and symlinked .envrc files; resolve_sub_agent
;;;     admitted arbitrary escaping home_path overrides; ensure_layout followed
;;;     symlinks via raw create_dir_all.
;;;  3. FileSystemOrgSourceStore relied on lexical-only path validation, letting
;;;     intermediate/leaf symlinks exfiltrate or overwrite files outside store
;;;     root, read unbounded document sizes, and staged temp files using
;;;     timestamp-only paths without an AtomicU64 sequence counter.
;;;  4. OrgGovernanceLedger::register_snapshot allowed generation rollbacks,
;;;     mutated invalid spans, and active lease staleness; commit_subtree lacked
;;;     lease digest parity, replacement byte bounds, and atomic rebase ordering;
;;;     SharedContextGovernanceLedger::create_channel overwrote existing channels
;;;     resetting acl_epoch to 1 and wiping tainted=true.
;;;  5. assemble_two_zone_gateway_messages checked envelope.kv_prefix_digest
;;;     without recomputing SHA-256 over envelope.frozen_prefix, allowing Zone-1
;;;     System prompt injection with a copied digest; commit_governed_org_subtree
;;;     omitted proposal.task_id == cursor.task_id binding.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export RuntimeEnvActivationAndContextConfinementModel)

(.def (RuntimeEnvActivationAndContextConfinementModel @ ThreatModel.)
  identity: 'threat.execution.runtime-env-activation-and-context-confinement
  family: 'threat.execution.runtime-env-activation-and-context-confinement
  title: "Runtime Environment Activation & Governed Context Confinement (SM34)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM34 ADV-L4 direnv export loader-hijack & denylist filtering with bounded subprocess capture, symlink-safe .envrc / sub-agent home / state-home / Org source store confinement, monotonic OrgGovernanceLedger & SharedContextGovernanceLedger anti-rollback with atomic rebase, and recomputed Two-Zone KV-Prefix SHA-256 verification with cursor/proposal task_id parity.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-runtime/environment admitted LD_PRELOAD/DYLD_INSERT_LIBRARIES/denylisted direnv exports, unbounded direnv wait_with_output(), escaping/symlinked explicit .envrc paths, and unconfined sub-agent home_path overrides; marlin-agent-context suffered symlink read/write escapes in FileSystemOrgSourceStore, generation/epoch/taint rollbacks in OrgGovernanceLedger & SharedContextGovernanceLedger, and forged Zone-1 frozen_prefix prompt injection with copied kv_prefix_digest in assemble_two_zone_gateway_messages."))
  quint-module: "execution_runtime_env_activation_and_context_confinement"
  quint-file: "RuntimeEnvActivationAndContextConfinement.qnt"
  domain-dir: "threat/execution/runtime-env-activation-and-context-confinement"
  rules:
  '((runtime-env-context-safe DE-SM34-SAFE quint)
    (runtime-env-context-countermodel DE-SM34-COUNTER quint))
  dependencies:
  '((DE-SM34-SAFE source)
    (DE-SM34-SAFE profile)
    (DE-SM34-SAFE method)
    (DE-SM34-COUNTER source)
    (DE-SM34-COUNTER profile)
    (DE-SM34-COUNTER method))
  invariant: "Direnv exports refuse loader-hijack, denylisted, and malformed env entries under bounded subprocess capture (direnvHijackBreaches == 0 and direnvFilterEnforced), explicit .envrc, sub-agent homes, state-home layout, and Org source stores refuse symlink and root escapes (symlinkEscapeBreaches == 0 and symlinkConfinementEnforced), Org snapshot generations and shared-channel ACL epochs/taint advance monotonically with atomic lease rebasing (rollbackBreaches == 0 and monotonicRollbackGuardEnforced and orgGen >= 1 and channelEpoch >= 1), and Two-Zone KV-Prefix assembly recomputes SHA-256 over frozen_prefix while binding proposal.task_id to cursor.task_id (prefixOrTaskBreaches == 0 and twoZoneDigestVerified)."
  limits: "Finite bounded runtime environment activation, Org store confinement & governed context bridge state machine (activeLeases <= 4, orgGen <= 12, channelEpoch <= 12, stepCount <= 12); models direnv export loader-hijack/denylist/size filtering + bounded subprocess stdout/timeout, explicit .envrc/sub-agent home/Org store symlink confinement, monotonic OrgGovernanceLedger snapshot generation + atomic commit rebasing + non-resetting SharedContextGovernanceLedger channel epoch/taint, and recomputed Two-Zone KV-Prefix frozen_prefix digest + cursor/proposal task_id binding, without modeling OS kernel VFS race internals or cryptographic hash preimage resistance.")

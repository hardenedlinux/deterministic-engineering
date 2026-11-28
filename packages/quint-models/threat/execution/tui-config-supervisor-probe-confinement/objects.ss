;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM39 (ADV-L4): TUI Config, ASP Supervisor, Diagnostic Probe & Bootstrap
;;; Confinement.
;;; Formalizes four real ADV-L4 boundary defects discovered in
;;; marlin-agent-tui:
;;;  1. config.rs: Config::load read TOML files via unbounded fs::read_to_string
;;;     without symlink refusal or byte cap; ModelProfile::route read arbitrary
;;;     ambient OS/loader credential_env variables (PATH/HOME/LD_PRELOAD/
;;;     SSH_AUTH_SOCK); catalog_with accepted timeout_seconds == 0 or unbounded
;;;     multi-year timeouts; and tui_ui_package omitted path/module validation.
;;;  2. app/asp_supervisor.rs: spawn_managed_asp_gateway spawned asp-gateway
;;;     without .env_clear() leaking ambient host API secrets and loader vars,
;;;     blocked indefinitely on silent child stdout without a boot timeout,
;;;     accepted @-userinfo/control-char spoofed loopback endpoints from child
;;;     JSON, and discover_asp_gateway_binary executed relative PATH entries.
;;;  3. app/runtime_probe.rs: RuntimeProbe::start used File::create(path)
;;;     following leaf and parent symlinks to truncate arbitrary files and wrote
;;;     CSV rows every 250ms indefinitely without a cumulative byte cap.
;;;  4. bootstrap.rs: resolve_local_scheme_prefix prioritized untrusted CWD
;;;     ./scheme ahead of the compiled binary's own repository prefix and
;;;     followed symlinked scheme/.gerbil/init.ssi paths, enabling CWD Scheme
;;;     hijack when launching marlin-tui inside an untrusted checkout.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export TuiConfigSupervisorProbeConfinementModel)

(.def (TuiConfigSupervisorProbeConfinementModel @ ThreatModel.)
  identity: 'threat.execution.tui-config-supervisor-probe-confinement
  family: 'threat.execution.tui-config-supervisor-probe-confinement
  title: "TUI Config, ASP Supervisor, Probe & Bootstrap Confinement (SM39)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM39 ADV-L4 terminal-client config symlink/size/timeout/credential_env confinement, env_clear()-scrubbed boot-timeout-bounded strict-loopback absolute-PATH ASP gateway supervision, O_NOFOLLOW byte-capped diagnostic probe persistence, and executable-first non-symlink Scheme package bootstrap trust ordering.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-tui Config::load performed unbounded symlink-following TOML reads and admitted ambient PATH/HOME/LD_PRELOAD credential_env and unbounded timeouts, spawn_managed_asp_gateway inherited ambient host secrets without .env_clear(), lacked a boot timeout, accepted @-userinfo spoofed endpoints, and searched relative PATH entries, RuntimeProbe::start truncated symlink targets and grew CSV files unboundedly, and bootstrap::resolve_local_scheme_prefix prioritized untrusted CWD ./scheme ahead of the binary repository."))
  quint-module: "execution_tui_config_supervisor_probe_confinement"
  quint-file: "TuiConfigSupervisorProbeConfinement.qnt"
  domain-dir: "threat/execution/tui-config-supervisor-probe-confinement"
  rules:
  '((tui-config-supervisor-probe-safe DE-SM39-SAFE quint)
    (tui-config-supervisor-probe-countermodel DE-SM39-COUNTER quint))
  dependencies:
  '((DE-SM39-SAFE source)
    (DE-SM39-SAFE profile)
    (DE-SM39-SAFE method)
    (DE-SM39-COUNTER source)
    (DE-SM39-COUNTER profile)
    (DE-SM39-COUNTER method))
  invariant: "TUI TOML loading enforces non-symlink byte caps, finite timeouts, and non-ambient credential_env hygiene (configConfinementBreaches == 0 and configConfinementEnforced), ASP gateway supervision enforces env_clear() secret scrubbing, boot timeouts, strict loopback endpoints, and absolute-PATH discovery (supervisorIsolationBreaches == 0 and supervisorIsolationEnforced), runtime metrics probes enforce O_NOFOLLOW non-symlink creation and cumulative byte ceilings (probeFileBreaches == 0 and probeFileConfinementEnforced and probeChunksWritten <= 12), and local Scheme bootstrap prioritizes the binary-owned repository over untrusted CWD without following symlinks (bootstrapTrustBreaches == 0 and bootstrapTrustOrderEnforced)."
  limits: "Finite bounded terminal-client config, ASP gateway supervisor, runtime diagnostic probe, and local Scheme bootstrap confinement state machine (probeChunksWritten <= 12, stepCount <= 12); models non-symlink byte-bounded TOML config loading with bounded HTTP timeouts and ambient-system-env-free credential_env validation, env_clear()-scrubbed boot-timeout-bounded loopback-endpoint-validated absolute-PATH ASP gateway supervision, O_NOFOLLOW non-symlink byte-capped runtime metrics probe persistence, and executable-first non-symlink local Scheme package discovery, without modeling OS kernel page-cache eviction or PTY driver internals.")

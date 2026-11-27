;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM36 (ADV-L4): Telemetry OTLP/Observer/Watchdog Isolation & Deck Single-VM
;;; Module/Timer Capacity and Delay Confinement.
;;; Formalizes four real ADV-L4 boundary defects discovered in
;;; marlin-agent-telemetry and marlin-deck-runtime:
;;;  1. OpenTelemetry::otlp_http admitted remote cleartext http:// collectors,
;;;     empty hosts, %40 userinfo/query/fragment smuggling, and blank or
;;;     control-character TelemetryServiceName / TraceTarget labels.
;;;  2. start_host_observer spawned the detached observer sidecar subprocess
;;;     without env_clear(), leaking ambient host secrets and dynamic-loader
;;;     variables (OPENAI_API_KEY, MARLIN_BRIDGE_TOKEN, DYLD_*), without
;;;     parent-symlink checks, and run_host_observer_if_requested accepted
;;;     extra arguments or invalid PIDs (<= 1).
;;;  3. HostObserver::drain_pulses trusted sender-supplied future timestamps
;;;     (u64::MAX permanently blinding HeartbeatMissed detection), and
;;;     HostObserver::attach accepted pid == 0 or Duration::ZERO (causing
;;;     immediate false HeartbeatMissed alarms on healthy hosts).
;;;  4. marlin-deck-runtime left Controls.modules and Controls.timers
;;;     unbounded under repeated activate/timer requests and permitted near-
;;;     infinite u64 microsecond timer delays pinning native VM slots.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export TelemetryWatchdogAndDeckVmConfinementModel)

(.def (TelemetryWatchdogAndDeckVmConfinementModel @ ThreatModel.)
  identity: 'threat.execution.telemetry-watchdog-and-deck-vm-confinement
  family: 'threat.execution.telemetry-watchdog-and-deck-vm-confinement
  title: "Telemetry/Watchdog & Deck Single-VM Confinement (SM36)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM36 ADV-L4 TLS-mandatory remote OTLP endpoints with loopback-only HTTP and clean labels, env_clear()-scrubbed symlink-safe host observer sidecars, monotonic-bounded watchdog heartbeat timestamps preventing u64::MAX blinding plus non-zero PID/timeout guards, and bounded Deck single-VM active module/timer capacities with finite timer delay ceilings.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-telemetry admitted remote cleartext http:// OTLP exfiltration, unscrubbed host-observer sidecar environments, and u64::MAX watchdog future-timestamp blinding with zero-timeout attach; marlin-deck-runtime left single-VM Controls.modules and Controls.timers unbounded and accepted unbounded u64 microsecond timer delays."))
  quint-module: "execution_telemetry_watchdog_and_deck_vm_confinement"
  quint-file: "TelemetryWatchdogAndDeckVmConfinement.qnt"
  domain-dir: "threat/execution/telemetry-watchdog-and-deck-vm-confinement"
  rules:
  '((telemetry-deck-vm-safe DE-SM36-SAFE quint)
    (telemetry-deck-vm-countermodel DE-SM36-COUNTER quint))
  dependencies:
  '((DE-SM36-SAFE source)
    (DE-SM36-SAFE profile)
    (DE-SM36-SAFE method)
    (DE-SM36-COUNTER source)
    (DE-SM36-COUNTER profile)
    (DE-SM36-COUNTER method))
  invariant: "OTLP export enforces remote HTTPS with loopback-only HTTP and clean labels (otlpExfilBreaches == 0 and otlpTlsEnforced), host observer sidecars scrub ambient env via env_clear() and reject symlinked parents (observerEnvBreaches == 0 and observerEnvScrubbed), watchdog clocks reject future/zero timestamps and zero PID/timeout (watchdogBlindBreaches == 0 and watchdogClockBounded), and Deck single-VM active modules, timers, and delays remain strictly bounded (deckVmExhaustionBreaches == 0 and deckVmBoundsEnforced and activeModules >= 1 and activeModules <= 12 and activeTimers >= 0 and activeTimers <= 12)."
  limits: "Finite bounded telemetry/watchdog and Deck single-VM confinement state machine (activeModules <= 12, activeTimers <= 12, stepCount <= 12); models loopback-only HTTP / remote HTTPS OTLP endpoint and label confinement, env_clear()-scrubbed non-symlink host observer sidecar spawning, monotonic-bounded watchdog heartbeat timestamps preventing u64::MAX blinding plus non-zero PID/timeout guards, and bounded Deck single-VM active module/timer capacities and finite timer delay ceilings, without modeling OS kernel kqueue internals or live network packet loss.")

// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.tui-config-supervisor-probe-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-tui-config-symlink-or-ambient-cred-env step=stepConfigSymlinkOrAmbientCred max-steps=6 itf="h.configConfinementBreaches > 0"
// @countermodel forbid-asp-supervisor-unscrubbed-env-hang-or-ssrf step=stepAspSupervisorLeakHangOrSsrf max-steps=6 itf="h.supervisorIsolationBreaches > 0"
// @countermodel forbid-runtime-probe-symlink-or-unbounded-disk step=stepProbeSymlinkOrDiskFlood max-steps=6 itf="h.probeFileBreaches > 0"
// @countermodel forbid-bootstrap-cwd-hijack-or-symlink-scheme step=stepBootstrapCwdOrSymlinkHijack max-steps=6 itf="h.bootstrapTrustBreaches > 0"
// Limits: Finite bounded terminal-client config, ASP gateway supervisor, runtime diagnostic probe, and local Scheme bootstrap confinement state machine (probeChunksWritten <= 12, stepCount <= 12); models non-symlink byte-bounded TOML config loading with bounded HTTP timeouts and ambient-system-env-free credential_env validation, env_clear()-scrubbed boot-timeout-bounded loopback-endpoint-validated absolute-PATH ASP gateway supervision, O_NOFOLLOW non-symlink byte-capped runtime metrics probe persistence, and executable-first non-symlink local Scheme package discovery, without modeling OS kernel page-cache eviction or PTY driver internals.
module execution_tui_config_supervisor_probe_confinement {
  type State = { probeChunksWritten: int, configConfinementEnforced: bool, supervisorIsolationEnforced: bool, probeFileConfinementEnforced: bool, bootstrapTrustOrderEnforced: bool, configConfinementBreaches: int, supervisorIsolationBreaches: int, probeFileBreaches: int, bootstrapTrustBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { probeChunksWritten: 0, configConfinementEnforced: true, supervisorIsolationEnforced: true, probeFileConfinementEnforced: true, bootstrapTrustOrderEnforced: true, configConfinementBreaches: 0, supervisorIsolationBreaches: 0, probeFileBreaches: 0, bootstrapTrustBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action loadBoundedSafeTuiConfig = if ((h.stepCount < 12 and h.configConfinementEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action spawnScrubbedBoundedAspGateway = if ((h.stepCount < 12 and h.supervisorIsolationEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action writeBoundedNoFollowProbeRow = if ((h.stepCount < 12 and h.probeFileConfinementEnforced and h.probeChunksWritten < 12)) h' = h.with("probeChunksWritten", (h.probeChunksWritten + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action resolveExeFirstNonSymlinkBootstrap = if ((h.stepCount < 12 and h.bootstrapTrustOrderEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { loadBoundedSafeTuiConfig, spawnScrubbedBoundedAspGateway, writeBoundedNoFollowProbeRow, resolveExeFirstNonSymlinkBootstrap }
  val safety = (h.configConfinementBreaches == 0 and h.supervisorIsolationBreaches == 0 and h.probeFileBreaches == 0 and h.bootstrapTrustBreaches == 0 and h.configConfinementEnforced and h.supervisorIsolationEnforced and h.probeFileConfinementEnforced and h.bootstrapTrustOrderEnforced and h.probeChunksWritten >= 0 and h.probeChunksWritten <= 12 and h.stepCount <= 12)
  // Countermodel threat.execution.tui-config-supervisor-probe-confinement.config-symlink-or-ambient-cred (dropped guard: forbid-tui-config-symlink-or-ambient-cred-env)
  action exploitConfigSymlinkOrAmbientCred = if ((h.stepCount < 12)) h' = h.with("configConfinementEnforced", false).with("configConfinementBreaches", (h.configConfinementBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepConfigSymlinkOrAmbientCred = any { step, exploitConfigSymlinkOrAmbientCred }
  // Countermodel threat.execution.tui-config-supervisor-probe-confinement.asp-supervisor-leak-hang-or-ssrf (dropped guard: forbid-asp-supervisor-unscrubbed-env-hang-or-ssrf)
  action exploitAspSupervisorLeakHangOrSsrf = if ((h.stepCount < 12)) h' = h.with("supervisorIsolationEnforced", false).with("supervisorIsolationBreaches", (h.supervisorIsolationBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepAspSupervisorLeakHangOrSsrf = any { step, exploitAspSupervisorLeakHangOrSsrf }
  // Countermodel threat.execution.tui-config-supervisor-probe-confinement.probe-symlink-or-disk-flood (dropped guard: forbid-runtime-probe-symlink-or-unbounded-disk)
  action exploitProbeSymlinkOrDiskFlood = if ((h.stepCount < 12)) h' = h.with("probeFileConfinementEnforced", false).with("probeFileBreaches", (h.probeFileBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepProbeSymlinkOrDiskFlood = any { step, exploitProbeSymlinkOrDiskFlood }
  // Countermodel threat.execution.tui-config-supervisor-probe-confinement.bootstrap-cwd-or-symlink-hijack (dropped guard: forbid-bootstrap-cwd-hijack-or-symlink-scheme)
  action exploitBootstrapCwdOrSymlinkHijack = if ((h.stepCount < 12)) h' = h.with("bootstrapTrustOrderEnforced", false).with("bootstrapTrustBreaches", (h.bootstrapTrustBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepBootstrapCwdOrSymlinkHijack = any { step, exploitBootstrapCwdOrSymlinkHijack }
  action checkSm39Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm39Violated = all { assert((h.configConfinementBreaches > 0 or h.supervisorIsolationBreaches > 0 or h.probeFileBreaches > 0 or h.bootstrapTrustBreaches > 0)), assert(not(safety)), h' = h }
  run cleanTuiConfigSupervisorProbeSafeTest = init.then(loadBoundedSafeTuiConfig).then(spawnScrubbedBoundedAspGateway).then(writeBoundedNoFollowProbeRow).then(resolveExeFirstNonSymlinkBootstrap).then(checkSm39Safe)
  run configSymlinkOrAmbientCredRefutedTest = init.then(exploitConfigSymlinkOrAmbientCred).then(checkSm39Violated)
  run aspSupervisorLeakHangOrSsrfRefutedTest = init.then(exploitAspSupervisorLeakHangOrSsrf).then(checkSm39Violated)
  run probeSymlinkOrDiskFloodRefutedTest = init.then(exploitProbeSymlinkOrDiskFlood).then(checkSm39Violated)
  run bootstrapCwdOrSymlinkHijackRefutedTest = init.then(exploitBootstrapCwdOrSymlinkHijack).then(checkSm39Violated)
}

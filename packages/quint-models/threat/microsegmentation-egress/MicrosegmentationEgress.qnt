// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.microsegmentation-egress
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel sidecar-attestation step=stepBypassSidecar max-steps=6 itf="h.activeFlowDest > 0 and (h.quarantined == true or not(h.sidecarAttested))"
// @countermodel tenant-policy step=stepBypassTenantPolicy max-steps=6 itf="h.activeFlowDest > 0 and h.activeFlowDest != h.tenantId and not(h.crossTenantAllowed)"
// Limits: Finite 2-tenant egress mediation abstraction; does not model L3/L4 packet filtering, DNS tunneling, or kernel namespace escapes.
module microsegmentation_egress {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { tenantId: int, crossTenantAllowed: bool, sidecarAttested: bool, quarantined: bool, delivered: int, activeFlowDest: int }
  var h: State
  action init = h' = { tenantId: 1, crossTenantAllowed: false, sidecarAttested: true, quarantined: false, delivered: 0, activeFlowDest: 0 }
  action mediateEgressAs(dest: int): bool = if (((h.sidecarAttested and not(h.quarantined)) and (dest == h.tenantId or h.crossTenantAllowed))) h' = h.with("delivered", (h.delivered + 1)).with("activeFlowDest", dest) else h' = h
  action mediateEgress = { nondet dest = Set(1, 2).oneOf()
    mediateEgressAs(dest) }
  action allowCrossTenant = h' = h.with("crossTenantAllowed", true)
  action denyCrossTenant = h' = h.with("crossTenantAllowed", false).with("activeFlowDest", if (h.activeFlowDest != h.tenantId) 0 else h.activeFlowDest)
  action loseAttestation = h' = h.with("sidecarAttested", false).with("activeFlowDest", 0)
  action quarantineWorkload = h' = h.with("quarantined", true).with("activeFlowDest", 0)
  action step = any { mediateEgress, allowCrossTenant, denyCrossTenant, loseAttestation, quarantineWorkload }
  val safety = (h.activeFlowDest == 0 or (h.sidecarAttested and not(h.quarantined) and (h.activeFlowDest == h.tenantId or h.crossTenantAllowed)))
  // Countermodel threat.microsegmentation-egress.bypass-sidecar (dropped guard: sidecar-attestation)
  action mediateEgressBypass(dest: int): bool = if ((true and (dest == h.tenantId or h.crossTenantAllowed))) h' = h.with("delivered", (h.delivered + 1)).with("activeFlowDest", dest) else h' = h
  action stepBypassSidecar = any { step, { nondet dest = Set(1, 2).oneOf()
    mediateEgressBypass(dest) } }
  // Countermodel threat.microsegmentation-egress.bypass-tenant-policy (dropped guard: tenant-policy)
  action mediateEgressNoPolicy(dest: int): bool = if (((h.sidecarAttested and not(h.quarantined)) and true)) h' = h.with("delivered", (h.delivered + 1)).with("activeFlowDest", dest) else h' = h
  action stepBypassTenantPolicy = any { step, { nondet dest = Set(1, 2).oneOf()
    mediateEgressNoPolicy(dest) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkBlocked = all { assert(h.delivered == 0), assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run sameTenantAllowedTest = init.then(mediateEgressAs(1)).then(all { assert(h.delivered == 1), assert(h.activeFlowDest == 1), assert(safety), h' = h })
  run crossTenantBlockedByDefaultTest = init.then(mediateEgressAs(2)).then(checkBlocked)
  run quarantineBlocksEgressTest = init.then(quarantineWorkload).then(mediateEgressAs(1)).then(checkBlocked)
  run bypassSidecarLeaksTest = init.then(quarantineWorkload).then(mediateEgressBypass(1)).then(checkUnsafe)
  run bypassTenantPolicyLeaksTest = init.then(mediateEgressNoPolicy(2)).then(checkUnsafe)
}

// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module threat.microsegmentation-egress. Do not edit by hand.
// Limits: Finite 2-tenant egress mediation abstraction; does not model L3/L4 packet filtering, DNS tunneling, or kernel namespace escapes.
module microsegmentation_egress {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { tenantId: int, crossTenantAllowed: bool, sidecarAttested: bool, quarantined: bool, delivered: int, leaked: bool }
  var h: State
  action init = h' = { tenantId: 1, crossTenantAllowed: false, sidecarAttested: true, quarantined: false, delivered: 0, leaked: false }
  action mediateEgressAs(dest: int): bool = if (h.sidecarAttested and not(h.quarantined) and (dest == h.tenantId or h.crossTenantAllowed))
    h' = h.with("delivered", h.delivered + 1).with("leaked", h.leaked or (dest != h.tenantId and not(h.crossTenantAllowed)) or h.quarantined or not(h.sidecarAttested))
    else h' = h
  action mediateEgress = { nondet dest = Set(1, 2).oneOf()
    mediateEgressAs(dest) }
  action allowCrossTenant = h' = h.with("crossTenantAllowed", true)
  action denyCrossTenant = h' = h.with("crossTenantAllowed", false)
  action loseAttestation = h' = h.with("sidecarAttested", false)
  action quarantineWorkload = h' = h.with("quarantined", true)
  action step = any { mediateEgress, allowCrossTenant, denyCrossTenant, loseAttestation, quarantineWorkload }
  val safety = not(h.leaked)
  // Countermodel threat.microsegmentation-egress.bypass-sidecar (dropped guard: sidecar-attestation)
  action directEgressBypass = h' = h.with("delivered", h.delivered + 1).with("leaked", h.leaked or not(h.crossTenantAllowed) or h.quarantined or not(h.sidecarAttested))
  action stepBypassSidecar = any { step, directEgressBypass }
  action checkSafe = all { assert(safety), h' = h }
  action checkBlocked = all { assert(h.delivered == 0), assert(safety), h' = h }
  action checkLeaked = all { assert(h.leaked), assert(not(safety)), h' = h }
  run sameTenantAllowedTest = init.then(mediateEgressAs(1)).then(all { assert(h.delivered == 1), assert(safety), h' = h })
  run crossTenantBlockedByDefaultTest = init.then(mediateEgressAs(2)).then(checkBlocked)
  run quarantineBlocksEgressTest = init.then(quarantineWorkload).then(mediateEgressAs(1)).then(checkBlocked)
  run bypassSidecarLeaksTest = init.then(quarantineWorkload).then(directEgressBypass).then(checkLeaked)
}

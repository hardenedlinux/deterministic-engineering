// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.zero-trust.multi-tenant-isolation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel tenant-resource-match step=stepCrossTenantDeputy max-steps=6 itf="h.crossTenantLeak == true"
// @countermodel tenant-membership-current step=stepRevokedTenantUse max-steps=6 itf="h.staleTenantUse == true"
// @countermodel outbox-tenant-binding step=stepCrossTenantFlush max-steps=6 itf="h.crossTenantFlush == true"
// Limits: Finite two-tenant authorization, revocation epoch, and offline outbox pinning abstraction; does not model database row-level security engines, tenant KMS key rotation, or side-channel microarchitectural leaks.
module multi_tenant_isolation {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { activeTenant: int, tenant1Epoch: int, tenant2Epoch: int, tenant1Revoked: bool, tenant2Revoked: bool, ticketIssued: bool, ticketTenant: int, ticketEpoch: int, outboxPending: bool, outboxTenant: int, executedCount: int, crossTenantLeak: bool, staleTenantUse: bool, crossTenantFlush: bool }
  var h: State
  action init = h' = { activeTenant: 1, tenant1Epoch: 1, tenant2Epoch: 1, tenant1Revoked: false, tenant2Revoked: false, ticketIssued: false, ticketTenant: 0, ticketEpoch: 0, outboxPending: false, outboxTenant: 0, executedCount: 0, crossTenantLeak: false, staleTenantUse: false, crossTenantFlush: false }
  action switchTenant = h' = h.with("activeTenant", if (h.activeTenant == 1) 2 else 1)
  action issueTicket = if ((h.activeTenant == 1 and not(h.tenant1Revoked))) h' = h.with("ticketIssued", true).with("ticketTenant", 1).with("ticketEpoch", h.tenant1Epoch) else if ((h.activeTenant == 2 and not(h.tenant2Revoked))) h' = h.with("ticketIssued", true).with("ticketTenant", 2).with("ticketEpoch", h.tenant2Epoch) else h' = h
  action revokeTenant1 = if ((not(h.tenant1Revoked) and h.tenant1Epoch < 3)) h' = h.with("tenant1Revoked", true).with("tenant1Epoch", (h.tenant1Epoch + 1)) else h' = h
  action revokeTenant2 = if ((not(h.tenant2Revoked) and h.tenant2Epoch < 3)) h' = h.with("tenant2Revoked", true).with("tenant2Epoch", (h.tenant2Epoch + 1)) else h' = h
  action enforceTicketAs(targetTenant: int): bool = if ((h.ticketIssued and h.executedCount < 4 and h.ticketTenant == targetTenant and ((h.ticketTenant == 1 and not(h.tenant1Revoked) and epochCurrent(h.tenant1Epoch, h.ticketEpoch)) or (h.ticketTenant == 2 and not(h.tenant2Revoked) and epochCurrent(h.tenant2Epoch, h.ticketEpoch))))) h' = h.with("ticketIssued", false).with("executedCount", (h.executedCount + 1)).with("crossTenantLeak", (h.crossTenantLeak or h.ticketTenant != targetTenant)).with("staleTenantUse", (h.staleTenantUse or (h.ticketTenant == 1 and (h.tenant1Revoked or h.tenant1Epoch != h.ticketEpoch)) or (h.ticketTenant == 2 and (h.tenant2Revoked or h.tenant2Epoch != h.ticketEpoch)))) else h' = h
  action enforceTicket = { nondet targetTenant = Set(1, 2).oneOf()
    enforceTicketAs(targetTenant) }
  action enqueueOutbox = if ((not(h.outboxPending) and ((h.activeTenant == 1 and not(h.tenant1Revoked)) or (h.activeTenant == 2 and not(h.tenant2Revoked))))) h' = h.with("outboxPending", true).with("outboxTenant", h.activeTenant) else h' = h
  action flushOutbox = if ((h.outboxPending and (h.outboxTenant == h.activeTenant and ((h.outboxTenant == 1 and not(h.tenant1Revoked)) or (h.outboxTenant == 2 and not(h.tenant2Revoked)))))) h' = h.with("outboxPending", false).with("outboxTenant", 0).with("crossTenantFlush", (h.crossTenantFlush or h.outboxTenant != h.activeTenant)) else h' = h
  action step = any { switchTenant, issueTicket, revokeTenant1, revokeTenant2, enforceTicket, enqueueOutbox, flushOutbox }
  val safety = (not(h.crossTenantLeak) and not(h.staleTenantUse) and not(h.crossTenantFlush))
  // Countermodel threat.zero-trust.multi-tenant-isolation.cross-tenant-deputy (dropped guard: tenant-resource-match)
  action enforceTicketNoTenantMatch(targetTenant: int): bool = if ((h.ticketIssued and h.executedCount < 4 and true and ((h.ticketTenant == 1 and not(h.tenant1Revoked) and epochCurrent(h.tenant1Epoch, h.ticketEpoch)) or (h.ticketTenant == 2 and not(h.tenant2Revoked) and epochCurrent(h.tenant2Epoch, h.ticketEpoch))))) h' = h.with("ticketIssued", false).with("executedCount", (h.executedCount + 1)).with("crossTenantLeak", (h.crossTenantLeak or h.ticketTenant != targetTenant)).with("staleTenantUse", (h.staleTenantUse or (h.ticketTenant == 1 and (h.tenant1Revoked or h.tenant1Epoch != h.ticketEpoch)) or (h.ticketTenant == 2 and (h.tenant2Revoked or h.tenant2Epoch != h.ticketEpoch)))) else h' = h
  action stepCrossTenantDeputy = any { step, { nondet targetTenant = Set(1, 2).oneOf()
    enforceTicketNoTenantMatch(targetTenant) } }
  // Countermodel threat.zero-trust.multi-tenant-isolation.revoked-tenant-ticket (dropped guard: tenant-membership-current)
  action enforceTicketNoMembership(targetTenant: int): bool = if ((h.ticketIssued and h.executedCount < 4 and h.ticketTenant == targetTenant and true)) h' = h.with("ticketIssued", false).with("executedCount", (h.executedCount + 1)).with("crossTenantLeak", (h.crossTenantLeak or h.ticketTenant != targetTenant)).with("staleTenantUse", (h.staleTenantUse or (h.ticketTenant == 1 and (h.tenant1Revoked or h.tenant1Epoch != h.ticketEpoch)) or (h.ticketTenant == 2 and (h.tenant2Revoked or h.tenant2Epoch != h.ticketEpoch)))) else h' = h
  action stepRevokedTenantUse = any { step, { nondet targetTenant = Set(1, 2).oneOf()
    enforceTicketNoMembership(targetTenant) } }
  // Countermodel threat.zero-trust.multi-tenant-isolation.cross-tenant-outbox-flush (dropped guard: outbox-tenant-binding)
  action flushOutboxNoTenantPin = if ((h.outboxPending and true)) h' = h.with("outboxPending", false).with("outboxTenant", 0).with("crossTenantFlush", (h.crossTenantFlush or h.outboxTenant != h.activeTenant)) else h' = h
  action stepCrossTenantFlush = any { step, flushOutboxNoTenantPin }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run sameTenantEnforceAndFlushSafeTest = init.then(issueTicket).then(enforceTicketAs(1)).then(enqueueOutbox).then(flushOutbox).then(all { assert(h.executedCount == 1), assert(not(h.outboxPending)), assert(safety), h' = h })
  run crossTenantEnforceBlockedTest = init.then(issueTicket).then(switchTenant).then(enforceTicketAs(2)).then(all { assert(h.executedCount == 0), assert(safety), h' = h })
  run revokedTenantBlocksTicketTest = init.then(issueTicket).then(revokeTenant1).then(enforceTicketAs(1)).then(all { assert(h.executedCount == 0), assert(safety), h' = h })
  run crossTenantOutboxFlushBlockedTest = init.then(enqueueOutbox).then(switchTenant).then(flushOutbox).then(all { assert(h.outboxPending), assert(h.outboxTenant == 1), assert(safety), h' = h })
  run crossTenantDeputyCountermodelTest = init.then(issueTicket).then(enforceTicketNoTenantMatch(2)).then(checkUnsafe)
  run revokedTenantCountermodelTest = init.then(issueTicket).then(revokeTenant1).then(enforceTicketNoMembership(1)).then(checkUnsafe)
  run crossTenantFlushCountermodelTest = init.then(enqueueOutbox).then(switchTenant).then(flushOutboxNoTenantPin).then(checkUnsafe)
}

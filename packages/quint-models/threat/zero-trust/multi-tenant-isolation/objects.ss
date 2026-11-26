;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-Tenant Isolation, Tenant-Bound Authorization & Offline Outbox Pinning threat model.
;;; Co-located Yuanxu unit: single source of truth alongside MultiTenantIsolation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export MultiTenantIsolationModel
        CrossTenantConfusedDeputyCountermodel
        RevokedTenantTicketCountermodel
        CrossTenantOutboxFlushCountermodel)

(.def (MultiTenantIsolationModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust.multi-tenant-isolation
  family: 'threat.zero-trust.multi-tenant-isolation
  title: "Multi-Tenant Authorization Isolation & Tenant-Pinned Outbox Continuity"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("S. Rose, O. Borchert, S. Mitchell & S. Connelly (NIST SP 800-207, 2020)"
     "Zero Trust Architecture: continuous per-tenant authorization, membership revocation, and resource scoping.")
    ("J. W. Cutler et al. (OOPSLA 2024)"
     "Cedar: A Language for Expressive, Fast, Safe, and Analyzable Authorization for multi-tenant policies."))
  quint-module: "multi_tenant_isolation"
  quint-file: "MultiTenantIsolation.qnt"
  domain-dir: "threat/zero-trust/multi-tenant-isolation"
  quint-imports:
  '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules:
  '((tenant-resource-match MT-RESOURCE-BIND quint)
    (tenant-membership-current MT-EPOCH-CURRENT quint)
    (outbox-tenant-binding MT-OUTBOX-PIN quint))
  dependencies:
  '((MT-RESOURCE-BIND source)
    (MT-RESOURCE-BIND profile)
    (MT-RESOURCE-BIND method)
    (MT-EPOCH-CURRENT source)
    (MT-EPOCH-CURRENT profile)
    (MT-EPOCH-CURRENT method)
    (MT-OUTBOX-PIN source)
    (MT-OUTBOX-PIN profile)
    (MT-OUTBOX-PIN method))
  invariant: "Tenant-scoped tickets never enforce against a foreign tenant resource or after tenant membership revocation, and queued offline outbox items never flush into a different active tenant."
  parameters: '()
  state:
  '((activeTenant "int" "1")
    (tenant1Epoch "int" "1")
    (tenant2Epoch "int" "1")
    (tenant1Revoked "bool" "false")
    (tenant2Revoked "bool" "false")
    (ticketIssued "bool" "false")
    (ticketTenant "int" "0")
    (ticketEpoch "int" "0")
    (outboxPending "bool" "false")
    (outboxTenant "int" "0")
    (executedCount "int" "0")
    (crossTenantLeak "bool" "false")
    (staleTenantUse "bool" "false")
    (crossTenantFlush "bool" "false"))
  guards:
  '((tenant-resource-match (= (. h ticketTenant) targetTenant))
    (tenant-membership-current
      (or (and (= (. h ticketTenant) 1)
               (not (. h tenant1Revoked))
               (call epochCurrent (. h tenant1Epoch) (. h ticketEpoch)))
          (and (= (. h ticketTenant) 2)
               (not (. h tenant2Revoked))
               (call epochCurrent (. h tenant2Epoch) (. h ticketEpoch)))))
    (outbox-tenant-binding
      (and (= (. h outboxTenant) (. h activeTenant))
           (or (and (= (. h outboxTenant) 1) (not (. h tenant1Revoked)))
               (and (= (. h outboxTenant) 2) (not (. h tenant2Revoked)))))))
  transitions:
  '((switchTenant
      (action switchTenant ()
        (set-h (activeTenant (if (= (. h activeTenant) 1) 2 1)))))
    (issueTicket
      (action issueTicket ()
        (if (and (= (. h activeTenant) 1) (not (. h tenant1Revoked)))
          (set-h (ticketIssued #t)
                 (ticketTenant 1)
                 (ticketEpoch (. h tenant1Epoch)))
          (if (and (= (. h activeTenant) 2) (not (. h tenant2Revoked)))
            (set-h (ticketIssued #t)
                   (ticketTenant 2)
                   (ticketEpoch (. h tenant2Epoch)))
            (keep-h)))))
    (revokeTenant1
      (action revokeTenant1 ()
        (if (and (not (. h tenant1Revoked)) (< (. h tenant1Epoch) 3))
          (set-h (tenant1Revoked #t)
                 (tenant1Epoch (+ (. h tenant1Epoch) 1)))
          (keep-h))))
    (revokeTenant2
      (action revokeTenant2 ()
        (if (and (not (. h tenant2Revoked)) (< (. h tenant2Epoch) 3))
          (set-h (tenant2Revoked #t)
                 (tenant2Epoch (+ (. h tenant2Epoch) 1)))
          (keep-h))))
    (enforceTicketAs
      (action enforceTicketAs ((targetTenant "int")) "bool"
        (if (and (. h ticketIssued)
                 (< (. h executedCount) 4)
                 (guard tenant-resource-match (= (. h ticketTenant) targetTenant))
                 (guard tenant-membership-current
                        (or (and (= (. h ticketTenant) 1)
                                 (not (. h tenant1Revoked))
                                 (call epochCurrent (. h tenant1Epoch) (. h ticketEpoch)))
                            (and (= (. h ticketTenant) 2)
                                 (not (. h tenant2Revoked))
                                 (call epochCurrent (. h tenant2Epoch) (. h ticketEpoch))))))
          (set-h (ticketIssued #f)
                 (executedCount (+ (. h executedCount) 1))
                 (crossTenantLeak (or (. h crossTenantLeak) (!= (. h ticketTenant) targetTenant)))
                 (staleTenantUse
                   (or (. h staleTenantUse)
                       (and (= (. h ticketTenant) 1)
                            (or (. h tenant1Revoked) (!= (. h tenant1Epoch) (. h ticketEpoch))))
                       (and (= (. h ticketTenant) 2)
                            (or (. h tenant2Revoked) (!= (. h tenant2Epoch) (. h ticketEpoch)))))))
          (keep-h))))
    (enforceTicket
      (action enforceTicket ()
        (nondet ((targetTenant (set 1 2)))
          (call enforceTicketAs targetTenant))))
    (enqueueOutbox
      (action enqueueOutbox ()
        (if (and (not (. h outboxPending))
                 (or (and (= (. h activeTenant) 1) (not (. h tenant1Revoked)))
                     (and (= (. h activeTenant) 2) (not (. h tenant2Revoked)))))
          (set-h (outboxPending #t)
                 (outboxTenant (. h activeTenant)))
          (keep-h))))
    (flushOutbox
      (action flushOutbox ()
        (if (and (. h outboxPending)
                 (guard outbox-tenant-binding
                        (and (= (. h outboxTenant) (. h activeTenant))
                             (or (and (= (. h outboxTenant) 1) (not (. h tenant1Revoked)))
                                 (and (= (. h outboxTenant) 2) (not (. h tenant2Revoked)))))))
          (set-h (outboxPending #f)
                 (outboxTenant 0)
                 (crossTenantFlush
                   (or (. h crossTenantFlush)
                       (!= (. h outboxTenant) (. h activeTenant)))))
          (keep-h))))
    (step
      (action step ()
        (any switchTenant issueTicket revokeTenant1 revokeTenant2
             enforceTicket enqueueOutbox flushOutbox))))
  safety:
  '(and (not (. h crossTenantLeak))
        (not (. h staleTenantUse))
        (not (. h crossTenantFlush)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (sameTenantEnforceAndFlushSafeTest
      (run sameTenantEnforceAndFlushSafeTest
        (then init issueTicket (call enforceTicketAs 1) enqueueOutbox flushOutbox
              (all (assert (= (. h executedCount) 1))
                   (assert (not (. h outboxPending)))
                   (assert safety)
                   (keep-h)))))
    (crossTenantEnforceBlockedTest
      (run crossTenantEnforceBlockedTest
        (then init issueTicket switchTenant (call enforceTicketAs 2)
              (all (assert (= (. h executedCount) 0))
                   (assert safety)
                   (keep-h)))))
    (revokedTenantBlocksTicketTest
      (run revokedTenantBlocksTicketTest
        (then init issueTicket revokeTenant1 (call enforceTicketAs 1)
              (all (assert (= (. h executedCount) 0))
                   (assert safety)
                   (keep-h)))))
    (crossTenantOutboxFlushBlockedTest
      (run crossTenantOutboxFlushBlockedTest
        (then init enqueueOutbox switchTenant flushOutbox
              (all (assert (. h outboxPending))
                   (assert (= (. h outboxTenant) 1))
                   (assert safety)
                   (keep-h)))))
    (crossTenantDeputyCountermodelTest
      (run crossTenantDeputyCountermodelTest
        (then init issueTicket (call enforceTicketNoTenantMatch 2) checkUnsafe)))
    (revokedTenantCountermodelTest
      (run revokedTenantCountermodelTest
        (then init issueTicket revokeTenant1 (call enforceTicketNoMembership 1) checkUnsafe)))
    (crossTenantFlushCountermodelTest
      (run crossTenantFlushCountermodelTest
        (then init enqueueOutbox switchTenant flushOutboxNoTenantPin checkUnsafe))))
  countermodels:
  (list CrossTenantConfusedDeputyCountermodel
        RevokedTenantTicketCountermodel
        CrossTenantOutboxFlushCountermodel)
  limits: "Finite two-tenant authorization, revocation epoch, and offline outbox pinning abstraction; does not model database row-level security engines, tenant KMS key rotation, or side-channel microarchitectural leaks.")

(.def (CrossTenantConfusedDeputyCountermodel @ MultiTenantIsolationModel)
  identity: 'threat.zero-trust.multi-tenant-isolation.cross-tenant-deputy
  dropped-guard: 'tenant-resource-match
  step-action: "stepCrossTenantDeputy"
  derive-from-transition: 'enforceTicketAs
  derive-action-name: 'enforceTicketNoTenantMatch
  derive-step-call: '(nondet ((targetTenant (set 1 2)))
                       (call enforceTicketNoTenantMatch targetTenant))
  expected-itf-predicate: "h.crossTenantLeak == true")

(.def (RevokedTenantTicketCountermodel @ MultiTenantIsolationModel)
  identity: 'threat.zero-trust.multi-tenant-isolation.revoked-tenant-ticket
  dropped-guard: 'tenant-membership-current
  step-action: "stepRevokedTenantUse"
  derive-from-transition: 'enforceTicketAs
  derive-action-name: 'enforceTicketNoMembership
  derive-step-call: '(nondet ((targetTenant (set 1 2)))
                       (call enforceTicketNoMembership targetTenant))
  expected-itf-predicate: "h.staleTenantUse == true")

(.def (CrossTenantOutboxFlushCountermodel @ MultiTenantIsolationModel)
  identity: 'threat.zero-trust.multi-tenant-isolation.cross-tenant-outbox-flush
  dropped-guard: 'outbox-tenant-binding
  step-action: "stepCrossTenantFlush"
  derive-from-transition: 'flushOutbox
  derive-action-name: 'flushOutboxNoTenantPin
  expected-itf-predicate: "h.crossTenantFlush == true")

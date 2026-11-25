;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust cross-tenant microsegmentation and egress mediation model.
;;; Enforces sidecar attestation, quarantine retention, and explicit cross-tenant allowlist.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export MicrosegmentationEgressModel BypassSidecarCountermodel)

(.def (MicrosegmentationEgressModel @ AuthorityCurrentnessModel)
  identity: 'threat.microsegmentation-egress
  family: 'threat.microsegmentation-egress
  quint-module: "microsegmentation_egress"
  quint-file: "MicrosegmentationEgress.qnt"
  domain-dir: "threat/microsegmentation-egress"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((zt-egress-mediate ZT-EGRESS-MED quint)
           (zt-egress-bypass ZT-EGRESS-BYP quint))
  dependencies: '((ZT-EGRESS-MED source) (ZT-EGRESS-MED profile) (ZT-EGRESS-MED method)
                  (ZT-EGRESS-BYP source) (ZT-EGRESS-BYP profile) (ZT-EGRESS-BYP method))
  invariant: "Cross-tenant egress never leaks without attested sidecar mediation, active non-quarantined standing, and explicit cross-tenant authorization."
  parameters: '()
  state: '((tenantId "int" "1")
           (crossTenantAllowed "bool" "false")
           (sidecarAttested "bool" "true")
           (quarantined "bool" "false")
           (delivered "int" "0")
           (leaked "bool" "false"))
  guards: '((sidecar-attestation "h.sidecarAttested and not(h.quarantined)")
            (tenant-policy "dest == h.tenantId or h.crossTenantAllowed"))
  transitions:
  '((mediateEgressAs "action mediateEgressAs(dest: int): bool = if (h.sidecarAttested and not(h.quarantined) and (dest == h.tenantId or h.crossTenantAllowed))\n    h' = h.with(\"delivered\", h.delivered + 1).with(\"leaked\", h.leaked or (dest != h.tenantId and not(h.crossTenantAllowed)) or h.quarantined or not(h.sidecarAttested))\n    else h' = h")
    (mediateEgress "action mediateEgress = { nondet dest = Set(1, 2).oneOf()\n    mediateEgressAs(dest) }")
    (allowCrossTenant "action allowCrossTenant = h' = h.with(\"crossTenantAllowed\", true)")
    (denyCrossTenant "action denyCrossTenant = h' = h.with(\"crossTenantAllowed\", false)")
    (loseAttestation "action loseAttestation = h' = h.with(\"sidecarAttested\", false)")
    (quarantineWorkload "action quarantineWorkload = h' = h.with(\"quarantined\", true)")
    (step "action step = any { mediateEgress, allowCrossTenant, denyCrossTenant, loseAttestation, quarantineWorkload }"))
  safety: "not(h.leaked)"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkBlocked "action checkBlocked = all { assert(h.delivered == 0), assert(safety), h' = h }")
    (checkLeaked "action checkLeaked = all { assert(h.leaked), assert(not(safety)), h' = h }")
    (sameTenantAllowedTest "run sameTenantAllowedTest = init.then(mediateEgressAs(1)).then(all { assert(h.delivered == 1), assert(safety), h' = h })")
    (crossTenantBlockedByDefaultTest "run crossTenantBlockedByDefaultTest = init.then(mediateEgressAs(2)).then(checkBlocked)")
    (quarantineBlocksEgressTest "run quarantineBlocksEgressTest = init.then(quarantineWorkload).then(mediateEgressAs(1)).then(checkBlocked)")
    (bypassSidecarLeaksTest "run bypassSidecarLeaksTest = init.then(quarantineWorkload).then(directEgressBypass).then(checkLeaked)"))
  countermodels: (list BypassSidecarCountermodel)
  limits: "Finite 2-tenant egress mediation abstraction; does not model L3/L4 packet filtering, DNS tunneling, or kernel namespace escapes.")

;; Weakened descendant: workload emits cross-tenant traffic directly bypassing sidecar attestation and quarantine.
(.def (BypassSidecarCountermodel @ MicrosegmentationEgressModel)
  identity: 'threat.microsegmentation-egress.bypass-sidecar
  dropped-guard: 'sidecar-attestation
  step-action: "stepBypassSidecar"
  counter-action: "action directEgressBypass = h' = h.with(\"delivered\", h.delivered + 1).with(\"leaked\", h.leaked or not(h.crossTenantAllowed) or h.quarantined or not(h.sidecarAttested))\n  action stepBypassSidecar = any { step, directEgressBypass }"
  expected-itf-predicate: "h.leaked == true and h.delivered >= 1")

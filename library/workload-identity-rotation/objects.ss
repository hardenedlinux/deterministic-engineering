;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust short-lived workload identity (SVID) rotation and emergency revocation.
;;; Models overlap-window rotation vs. immediate revocation precedence.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export WorkloadIdentityRotationModel GraceWindowRevokedCountermodel)

(.def (WorkloadIdentityRotationModel @ AuthorityCurrentnessModel)
  identity: 'threat.workload-identity-rotation
  family: 'threat.workload-identity-rotation
  quint-module: "workload_identity_rotation"
  quint-file: "WorkloadIdentityRotation.qnt"
  domain-dir: "threat/workload-identity-rotation"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((zt-svid-rotate ZT-SVID-ROT quint)
           (zt-svid-revoked-grace ZT-SVID-GRACE quint))
  dependencies: '((ZT-SVID-ROT source) (ZT-SVID-ROT profile) (ZT-SVID-ROT method)
                  (ZT-SVID-GRACE source) (ZT-SVID-GRACE profile) (ZT-SVID-GRACE method))
  invariant: "Emergency revocation overrides any overlap/TTL window; only non-revoked active or overlap-window workload credentials are accepted."
  parameters: '()
  state: '((activeGen "int" "1")
           (overlapGen "int" "0")
           (revokedGen "int" "0")
           (credGen "int" "1")
           (credExpired "bool" "false")
           (accepted "int" "0")
           (unsafe "bool" "false"))
  guards: '((revocation-overrides-overlap "h.credGen != h.revokedGen")
            (valid-generation "h.credGen == h.activeGen or (h.overlapGen > 0 and h.credGen == h.overlapGen)"))
  transitions:
  '((inWindow "val inWindow = not(h.credExpired) and (h.credGen == h.activeGen or (h.overlapGen > 0 and h.credGen == h.overlapGen))")
    (rotateStart "action rotateStart = if (h.overlapGen == 0 and h.activeGen < 3)\n    h' = h.with(\"overlapGen\", h.activeGen).with(\"activeGen\", h.activeGen + 1)\n    else h' = h")
    (retireOverlap "action retireOverlap = if (h.overlapGen > 0)\n    h' = h.with(\"overlapGen\", 0)\n    else h' = h")
    (renewWorkloadCred "action renewWorkloadCred = h' = h.with(\"credGen\", h.activeGen).with(\"credExpired\", false)")
    (expireCred "action expireCred = h' = h.with(\"credExpired\", true)")
    (emergencyRevoke "action emergencyRevoke = h' = h.with(\"revokedGen\", h.credGen)")
    (authenticate "action authenticate = if (inWindow and h.credGen != h.revokedGen)\n    h' = h.with(\"accepted\", h.accepted + 1).with(\"unsafe\", h.unsafe or h.credGen == h.revokedGen or h.credExpired)\n    else h' = h")
    (step "action step = any { rotateStart, retireOverlap, renewWorkloadCred, expireCred, emergencyRevoke, authenticate }"))
  safety: "not(h.unsafe)"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkBlocked "action checkBlocked = all { assert(h.accepted == 0), assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (overlapRotationTest "run overlapRotationTest = init.then(rotateStart).then(authenticate).then(all { assert(h.accepted == 1), assert(safety), h' = h })")
    (retireBlocksOldCredTest "run retireBlocksOldCredTest = init.then(rotateStart).then(retireOverlap).then(authenticate).then(checkBlocked)")
    (revocationOverridesOverlapTest "run revocationOverridesOverlapTest = init.then(rotateStart).then(emergencyRevoke).then(authenticate).then(checkBlocked)")
    (revokedGraceCountermodelTest "run revokedGraceCountermodelTest = init.then(rotateStart).then(emergencyRevoke).then(authIgnoreRevocation).then(checkUnsafe)"))
  countermodels: (list GraceWindowRevokedCountermodel)
  limits: "Finite SVID generation-rotation abstraction; does not model X.509/JWT cryptography, clock drift, or CRL/OCSP transport latency.")

;; Weakened descendant: acceptor trusts TTL/overlap window without checking revocation list.
(.def (GraceWindowRevokedCountermodel @ WorkloadIdentityRotationModel)
  identity: 'threat.workload-identity-rotation.revoked-in-grace-window
  dropped-guard: 'revocation-overrides-overlap
  step-action: "stepGraceWindowReuse"
  counter-action: "action authIgnoreRevocation = if (inWindow)\n    h' = h.with(\"accepted\", h.accepted + 1).with(\"unsafe\", h.unsafe or h.credGen == h.revokedGen or h.credExpired)\n    else h' = h\n  action stepGraceWindowReuse = any { step, authIgnoreRevocation }"
  expected-itf-predicate: "h.unsafe == true and h.accepted >= 1")

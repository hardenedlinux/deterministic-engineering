// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module threat.workload-identity-rotation. Do not edit by hand.
// Limits: Finite SVID generation-rotation abstraction; does not model X.509/JWT cryptography, clock drift, or CRL/OCSP transport latency.
module workload_identity_rotation {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { activeGen: int, overlapGen: int, revokedGen: int, credGen: int, credExpired: bool, accepted: int, unsafe: bool }
  var h: State
  action init = h' = { activeGen: 1, overlapGen: 0, revokedGen: 0, credGen: 1, credExpired: false, accepted: 0, unsafe: false }
  val inWindow = not(h.credExpired) and (h.credGen == h.activeGen or (h.overlapGen > 0 and h.credGen == h.overlapGen))
  action rotateStart = if (h.overlapGen == 0 and h.activeGen < 3)
    h' = h.with("overlapGen", h.activeGen).with("activeGen", h.activeGen + 1)
    else h' = h
  action retireOverlap = if (h.overlapGen > 0)
    h' = h.with("overlapGen", 0)
    else h' = h
  action renewWorkloadCred = h' = h.with("credGen", h.activeGen).with("credExpired", false)
  action expireCred = h' = h.with("credExpired", true)
  action emergencyRevoke = h' = h.with("revokedGen", h.credGen)
  action authenticate = if (inWindow and h.credGen != h.revokedGen)
    h' = h.with("accepted", h.accepted + 1).with("unsafe", h.unsafe or h.credGen == h.revokedGen or h.credExpired)
    else h' = h
  action step = any { rotateStart, retireOverlap, renewWorkloadCred, expireCred, emergencyRevoke, authenticate }
  val safety = not(h.unsafe)
  // Countermodel threat.workload-identity-rotation.revoked-in-grace-window (dropped guard: revocation-overrides-overlap)
  action authIgnoreRevocation = if (inWindow)
    h' = h.with("accepted", h.accepted + 1).with("unsafe", h.unsafe or h.credGen == h.revokedGen or h.credExpired)
    else h' = h
  action stepGraceWindowReuse = any { step, authIgnoreRevocation }
  action checkSafe = all { assert(safety), h' = h }
  action checkBlocked = all { assert(h.accepted == 0), assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run overlapRotationTest = init.then(rotateStart).then(authenticate).then(all { assert(h.accepted == 1), assert(safety), h' = h })
  run retireBlocksOldCredTest = init.then(rotateStart).then(retireOverlap).then(authenticate).then(checkBlocked)
  run revocationOverridesOverlapTest = init.then(rotateStart).then(emergencyRevoke).then(authenticate).then(checkBlocked)
  run revokedGraceCountermodelTest = init.then(rotateStart).then(emergencyRevoke).then(authIgnoreRevocation).then(checkUnsafe)
}

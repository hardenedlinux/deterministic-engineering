// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module threat.authority-currentness. Do not edit by hand.
// Limits: Trusted boolean bits abstract real clock freshness, revocation checks, signature verification and writer fencing.
module authority_currentness {
  pure def isCurrent(paused: bool, fresh: bool, credential: bool, bytes: bool): bool =
    not(paused) and fresh and credential and bytes
  pure def epochCurrent(epoch: int, planned: int): bool =
    epoch == planned
  run currentnessTest = all {
    assert(isCurrent(false, true, true, true)),
    assert(not(isCurrent(true, true, true, true))),
    assert(not(isCurrent(false, false, true, true))),
    assert(not(isCurrent(false, true, false, true))),
    assert(not(isCurrent(false, true, true, false))),
    assert(epochCurrent(0, 0)),
    assert(not(epochCurrent(1, 0)))
  }
}

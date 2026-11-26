// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.capabilities
// @quint-version 0.33.0
// @apalache-version 0.62.1
// Limits: Finite acquisition projection; does not model timing, side channels or cryptographic compromise.
module threat_capabilities {
  pure def canLearn(known: Set[str], rules: Set[{ needs: Set[str], grants: str }], target: str): bool = rules.exists(rule => (rule.grants == target and rule.needs.subseteq(known)))
  pure val sampleRules = Set({ needs: Set("a"), grants: "b" })
  run learnableTest = all { assert(canLearn(Set("a"), sampleRules, "b")), assert(not(canLearn(Set(), sampleRules, "b"))) }
}

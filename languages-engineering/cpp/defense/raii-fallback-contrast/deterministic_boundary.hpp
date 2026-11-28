// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <cstddef>
#include <limits>
#include <string>
#include <variant>
#include <vector>

namespace de::defense::good {

struct Proven { std::size_t value; };
struct Refuted { std::string reason; };
struct PendingScope { std::string missing_premise; };
struct Conflict { std::string detail; };
struct SetupDefect { std::string defect; };

using EpistemicBudget = std::variant<Proven, Refuted, PendingScope, Conflict, SetupDefect>;

// C2 Deterministic single trust-boundary parsing:
// Distinguishes missing input (SetupDefect), malformed/overflow input (Refuted), and valid value (Proven).
inline EpistemicBudget parse_budget_boundary(const std::string* raw) {
  if (raw == nullptr || raw->empty()) {
    return SetupDefect{"missing-expected-budget-input"};
  }
  std::size_t acc = 0;
  for (char c : *raw) {
    if (c < '0' || c > '9') {
      return Refuted{"non-digit-budget-token"};
    }
    std::size_t digit = static_cast<std::size_t>(c - '0');
    if (acc > (std::numeric_limits<std::size_t>::max() - digit) / 10) {
      return Refuted{"budget-overflow"};
    }
    acc = acc * 10 + digit;
  }
  return Proven{acc};
}

struct Permit {
  std::vector<std::string>* log;
  ~Permit() { log->push_back("permit-released"); }
};

struct Payload {
  std::vector<std::string>* log;
  ~Payload() { log->push_back("payload-destroyed"); }
};

// C2 Deterministic C++ RAII ownership boundary:
// Because C++ destroys members in REVERSE declaration order (opposite of Rust's declaration order),
// declaring `permit` BEFORE `payload` guarantees `~Payload()` completes BEFORE `~Permit()` releases budget.
struct DeterministicOwnedWork {
  Permit permit;
  Payload payload;
};

} // namespace de::defense::good

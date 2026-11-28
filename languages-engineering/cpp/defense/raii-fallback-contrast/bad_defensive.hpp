// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace de::defense::bad {

// P1 Masking: catch-all swallows domain/setup failures and returns 0 ("safe default").
inline std::size_t bad_parse_budget(const std::string& raw) noexcept {
  try {
    std::size_t idx = 0;
    unsigned long long v = std::stoull(raw, &idx);
    if (idx != raw.size()) return 0;
    return static_cast<std::size_t>(v);
  } catch (...) {
    return 0;
  }
}

struct BadPermit {
  std::vector<std::string>* log;
  ~BadPermit() { log->push_back("permit-released"); }
};

struct BadPayload {
  std::vector<std::string>* log;
  ~BadPayload() { log->push_back("payload-destroyed"); }
};

// P2 Misplaced RAII order in C++:
// C++ destroys data members in REVERSE declaration order!
// Declaring payload BEFORE permit destroys permit FIRST (releasing budget while payload is still alive).
struct BadOwnedWork {
  BadPayload payload;
  BadPermit permit;
};

} // namespace de::defense::bad

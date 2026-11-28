// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace de::stability::bad {

enum class Outcome { Ok, Error, Cancel };

class BadHandleManager {
 public:
  std::size_t active = 0;
  std::size_t held = 0;

  void run_cycle(Outcome o) {
    ++active;
    ++held;
    if (o == Outcome::Error) {
      // SM2 ARB: exception skips manual release.
      --active;
      throw std::runtime_error("injected-error");
    }
    if (o == Outcome::Cancel) {
      // SM4 ARB: early return on cancel leaks handle.
      --active;
      return;
    }
    --held;
    --active;
  }
};

class BadBufferPool {
 public:
  std::vector<std::vector<std::uint8_t>> pool;

  std::vector<std::uint8_t> acquire(std::size_t bytes) {
    if (!pool.empty()) {
      auto buf = std::move(pool.back());
      pool.pop_back();
      buf.resize(bytes);
      return buf;
    }
    return std::vector<std::uint8_t>(bytes);
  }

  void release(std::vector<std::uint8_t> buf) {
    // SM3 ARB: clear() retains spike capacity() forever and pool has no slot cap!
    buf.clear();
    pool.push_back(std::move(buf));
  }

  std::size_t retained_capacity_bytes() const {
    std::size_t total = 0;
    for (const auto& b : pool) total += b.capacity();
    return total;
  }
};

}  // namespace de::stability::bad

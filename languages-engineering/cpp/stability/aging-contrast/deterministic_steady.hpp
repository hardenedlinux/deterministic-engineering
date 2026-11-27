// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include "bad_aging.hpp"

namespace de::stability::good {

class DeterministicHandleManager {
 public:
  std::size_t active = 0;
  std::size_t held = 0;

  struct ScopedHandle {
    DeterministicHandleManager* owner;
    explicit ScopedHandle(DeterministicHandleManager* m) : owner(m) {
      ++owner->active;
      ++owner->held;
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ~ScopedHandle() {
      --owner->held;
      --owner->active;
    }
  };

  void run_cycle(bad::Outcome o) {
    ScopedHandle guard(this);
    if (o == bad::Outcome::Error) {
      throw std::runtime_error("injected-error");
    }
    if (o == bad::Outcome::Cancel) {
      return;
    }
  }
};

class DeterministicBufferPool {
 public:
  std::size_t slot_cap;
  std::size_t max_retain_cap;
  std::vector<std::vector<std::uint8_t>> pool;

  DeterministicBufferPool(std::size_t slots, std::size_t max_retain)
      : slot_cap(slots), max_retain_cap(max_retain) {}

  std::vector<std::uint8_t> acquire(std::size_t bytes) {
    if (bytes <= max_retain_cap && !pool.empty()) {
      auto buf = std::move(pool.back());
      pool.pop_back();
      buf.resize(bytes);
      return buf;
    }
    std::vector<std::uint8_t> fresh;
    fresh.reserve(bytes);
    fresh.resize(bytes);
    return fresh;
  }

  void release(std::vector<std::uint8_t> buf) {
    // SM3 deterministic boundary: discard buffers whose capacity() ratcheted past max_retain_cap.
    buf.clear();
    if (buf.capacity() > max_retain_cap || pool.size() >= slot_cap) {
      return;
    }
    pool.push_back(std::move(buf));
  }

  std::size_t retained_capacity_bytes() const {
    std::size_t total = 0;
    for (const auto& b : pool) total += b.capacity();
    return total;
  }
};

}  // namespace de::stability::good

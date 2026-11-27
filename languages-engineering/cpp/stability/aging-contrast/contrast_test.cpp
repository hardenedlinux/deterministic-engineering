// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <cassert>
#include <cstddef>
#include <stdexcept>
#include "bad_aging.hpp"
#include "deterministic_steady.hpp"

int main() {
  using de::stability::bad::BadBufferPool;
  using de::stability::bad::BadHandleManager;
  using de::stability::bad::Outcome;
  using de::stability::good::DeterministicBufferPool;
  using de::stability::good::DeterministicHandleManager;

  constexpr std::size_t kNormal = 1024;
  constexpr std::size_t kSpike = 65536;
  constexpr std::size_t kSlotCap = 4;

  BadHandleManager bad_h;
  DeterministicHandleManager good_h;
  BadBufferPool bad_p;
  DeterministicBufferPool good_p(kSlotCap, kNormal);

  for (std::size_t c = 1; c <= 120; ++c) {
    const Outcome o = (c % 7 == 0) ? Outcome::Error : ((c % 11 == 0) ? Outcome::Cancel : Outcome::Ok);
    try {
      bad_h.run_cycle(o);
    } catch (const std::runtime_error&) {
    }
    try {
      good_h.run_cycle(o);
    } catch (const std::runtime_error&) {
    }

    const std::size_t sz = (c % 15 == 0) ? kSpike : kNormal;
    auto b1 = bad_p.acquire(sz);
    auto b2 = bad_p.acquire(kNormal);
    bad_p.release(std::move(b1));
    bad_p.release(std::move(b2));

    auto g1 = good_p.acquire(sz);
    auto g2 = good_p.acquire(kNormal);
    good_p.release(std::move(g1));
    good_p.release(std::move(g2));
  }

  // Bad C++ aging implementation leaks handles and ratchets std::vector::capacity():
  assert(bad_h.held > 0);
  assert(bad_p.retained_capacity_bytes() > kSlotCap * kNormal);

  // Deterministic RAII + capped buffer pool preserves exact zero drift and strict capacity ceiling:
  assert(good_h.active == 0);
  assert(good_h.held == 0);
  assert(good_p.pool.size() <= kSlotCap);
  assert(good_p.retained_capacity_bytes() <= kSlotCap * kNormal);
  return 0;
}

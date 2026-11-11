// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DE_SLOT_HPP
#define DE_SLOT_HPP

/* A single externally tracked resource. Native code and the verifier compile
 * this same implementation. The caller keeps the live counter alive and never
 * duplicates an ownership token. This is not an allocator or a concurrency API. */
class ResourceSlot {
  unsigned *live_;

public:
  ResourceSlot() : live_(nullptr) {}
  explicit ResourceSlot(unsigned *live) : live_(live) { ++*live_; }
  ResourceSlot(const ResourceSlot &) = delete;
  ResourceSlot &operator=(const ResourceSlot &) = delete;

  /* Transfer is explicit and refuses an occupied destination without changing
   * either owner. This Profile covers this operation, not C++ move constructors. */
  bool transfer_to(ResourceSlot &destination) {
    if (destination.owns())
      return false;
    destination.live_ = live_;
    live_ = nullptr;
    return true;
  }

  ~ResourceSlot() { reset(); }

  bool owns() const { return live_ != nullptr; }

  void reset() {
    if (live_) {
      --*live_;
      live_ = nullptr;
    }
  }
};

#endif

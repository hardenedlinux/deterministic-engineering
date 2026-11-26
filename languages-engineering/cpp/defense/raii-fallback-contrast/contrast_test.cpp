// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <cassert>
#include <string>
#include <variant>
#include <vector>
#include "bad_defensive.hpp"
#include "deterministic_boundary.hpp"

int main() {
  using namespace de::defense;

  // 1. P1 silent fallback vs. C2 explicit epistemic boundary parsing
  assert(bad::bad_parse_budget("") == 0);
  assert(bad::bad_parse_budget("corrupt") == 0);
  assert(bad::bad_parse_budget("99999999999999999999999999999") == 0);

  auto missing = good::parse_budget_boundary(nullptr);
  assert(std::holds_alternative<good::SetupDefect>(missing));

  std::string empty;
  auto empty_res = good::parse_budget_boundary(&empty);
  assert(std::holds_alternative<good::SetupDefect>(empty_res));

  std::string bad_tok = "12abc";
  auto bad_res = good::parse_budget_boundary(&bad_tok);
  assert(std::holds_alternative<good::Refuted>(bad_res));

  std::string overflow_tok = "99999999999999999999999999999";
  auto ovf_res = good::parse_budget_boundary(&overflow_tok);
  assert(std::holds_alternative<good::Refuted>(ovf_res));

  std::string valid_tok = "42";
  auto ok_res = good::parse_budget_boundary(&valid_tok);
  assert(std::holds_alternative<good::Proven>(ok_res));
  assert(std::get<good::Proven>(ok_res).value == 42);

  // 2. P2 premature permit release vs. C2 deterministic C++ reverse-declaration RAII order
  std::vector<std::string> bad_log;
  {
    bad::BadOwnedWork w{bad::BadPayload{&bad_log}, bad::BadPermit{&bad_log}};
    (void)w;
  }
  assert(bad_log.size() == 2);
  assert(bad_log[0] == "permit-released");
  assert(bad_log[1] == "payload-destroyed");

  std::vector<std::string> good_log;
  {
    good::DeterministicOwnedWork w{good::Permit{&good_log}, good::Payload{&good_log}};
    (void)w;
  }
  assert(good_log.size() == 2);
  assert(good_log[0] == "payload-destroyed");
  assert(good_log[1] == "permit-released");

  return 0;
}

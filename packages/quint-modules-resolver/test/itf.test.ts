// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {expect, test} from 'bun:test';
import {type ItfTrace, traceSatisfiesItfPredicate} from '../src/itf.ts';

test('ITF predicate evaluator checks boolean, bigint, negation and qualified vars', () => {
  const trace: ItfTrace = {
    vars: ['consumer::state_rollback::h'],
    states: [
      {'consumer::state_rollback::h': {unsafe: false, sent: {'#bigint': '0'}, durable: false}},
      {'consumer::state_rollback::h': {unsafe: true, sent: {'#bigint': '2'}, durable: true}},
    ],
  };
  expect(traceSatisfiesItfPredicate(trace, 'h.unsafe == true and h.sent >= 2')).toBe(true);
  expect(traceSatisfiesItfPredicate(trace, 'h.unsafe == true and not(h.durable)')).toBe(false);
  expect(traceSatisfiesItfPredicate(trace, 'h.sent == 2 or h.sent == 3')).toBe(true);
});

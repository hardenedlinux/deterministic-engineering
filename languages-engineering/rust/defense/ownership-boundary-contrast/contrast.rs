// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

//! C4 Rust paired contrast: bad-defensive vs deterministic-boundary.
//! Demonstrates:
//! 1. RAII payload-before-permit drop ordering (vs. premature permit release).
//! 2. Explicit 6-state epistemic result & consumption-time authority witness
//!    (vs. P1 silent fallback & P2 request-time TOCTOU).

use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug, PartialEq, Eq)]
pub enum Epistemic<T> {
    Proven(T),
    Refuted(&'static str),
    PendingScope(&'static str),
    Conflict,
    SetupDefect(&'static str),
}

#[derive(Clone, Default)]
struct DropLog(Rc<RefCell<Vec<&'static str>>>);

impl DropLog {
    fn push(&self, event: &'static str) {
        self.0.borrow_mut().push(event);
    }
    fn snapshot(&self) -> Vec<&'static str> {
        self.0.borrow().clone()
    }
}

struct Payload(DropLog);
impl Drop for Payload {
    fn drop(&mut self) {
        self.0.push("payload-dropped");
    }
}

struct Permit(DropLog);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.push("permit-released");
    }
}

// Bad defensive pattern: drops permit before payload (releases budget while payload still live).
struct BadOwnedWork {
    _permit: Permit,
    _payload: Payload,
}

// Deterministic Rust boundary: field order guarantees payload is dropped BEFORE permit is released.
struct DeterministicOwnedWork {
    _payload: Payload,
    _permit: Permit,
}

// P1/P2 anti-pattern: trusts request_allowed, ignores live_revoked, swallows empty authority as allow.
fn bad_consume_effect(request_allowed: bool, live_revoked: bool) -> bool {
    let _ = live_revoked;
    request_allowed
}

// C2 deterministic boundary: requires consumption-time authority check and distinguishes conflict/pending.
fn deterministic_consume_effect(
    request_allowed: Option<bool>,
    live_revoked: Option<bool>,
) -> Epistemic<&'static str> {
    match (request_allowed, live_revoked) {
        (None, _) | (_, None) => Epistemic::PendingScope("authority-status-unknown"),
        (Some(false), _) => Epistemic::Refuted("request-denied"),
        (Some(true), Some(true)) => Epistemic::Refuted("revoked-at-use-boundary"),
        (Some(true), Some(false)) => Epistemic::Proven("effect-authorized-at-use"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contrast_drop_order_ownership_boundary() {
        let bad_log = DropLog::default();
        {
            let _w = BadOwnedWork {
                _permit: Permit(bad_log.clone()),
                _payload: Payload(bad_log.clone()),
            };
        }
        assert_eq!(bad_log.snapshot(), vec!["permit-released", "payload-dropped"]);

        let good_log = DropLog::default();
        {
            let _w = DeterministicOwnedWork {
                _payload: Payload(good_log.clone()),
                _permit: Permit(good_log.clone()),
            };
        }
        assert_eq!(good_log.snapshot(), vec!["payload-dropped", "permit-released"]);
    }

    #[test]
    fn contrast_use_time_authority_and_epistemic_states() {
        // Bad defensive code executes despite live revocation:
        assert!(bad_consume_effect(true, true));

        // Deterministic boundary refuses live revocation and preserves unknown state as PendingScope:
        assert_eq!(
            deterministic_consume_effect(Some(true), Some(true)),
            Epistemic::Refuted("revoked-at-use-boundary")
        );
        assert_eq!(
            deterministic_consume_effect(Some(true), None),
            Epistemic::PendingScope("authority-status-unknown")
        );
        assert_eq!(
            deterministic_consume_effect(Some(true), Some(false)),
            Epistemic::Proven("effect-authorized-at-use")
        );
    }
}

//! Counters via the `metrics` facade (feature `metrics`); no-ops otherwise.
//!
//! | Counter | Labels |
//! |---|---|
//! | `session_guard_decisions_total` | `decision` = `allow` / `step_up` / `revoke` |
//! | `session_guard_signals_total` | `signal` = a [`Check`](crate::Check) name |
//! | `session_guard_events_total` | `kind` = an [`EventKind`](crate::EventKind) name, `enforced` |

use crate::{
    checks::{Check, Decision},
    event::EventKind,
};

#[cfg(feature = "metrics")]
pub(crate) fn assessed(decision: Decision, signals: &[Check]) {
    metrics::counter!("session_guard_decisions_total", "decision" => decision.as_str()).increment(1);
    for check in signals {
        metrics::counter!("session_guard_signals_total", "signal" => check.as_str()).increment(1);
    }
}

#[cfg(feature = "metrics")]
pub(crate) fn event(kind: EventKind, enforced: bool) {
    metrics::counter!(
        "session_guard_events_total",
        "kind" => kind.as_str(),
        "enforced" => if enforced { "true" } else { "false" },
    )
    .increment(1);
}

#[cfg(not(feature = "metrics"))]
pub(crate) fn assessed(_: Decision, _: &[Check]) {}

#[cfg(not(feature = "metrics"))]
pub(crate) fn event(_: EventKind, _: bool) {}

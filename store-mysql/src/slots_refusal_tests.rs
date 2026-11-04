// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::is_refusal;

/// 1366 (a string the column's charset cannot hold) is the same deterministic bad-value family
/// as 1292: the write can never apply, so it is REFUSED, not FAILED (which the host would replay
/// forever).
#[test]
fn a_bad_value_for_a_field_is_a_refusal() {
    for code in [1264, 1292, 1366, 1406, 1452, 1690, 3819] {
        assert!(is_refusal(code), "{code} is a deterministic value refusal");
    }
    assert!(!is_refusal(1213), "a deadlock is retryable, not a refusal");
}

#[test]
fn rollback_failure_preserves_permanent_refusal_classification() {
    use super::{after_rollback, Error, OpRefused};
    let error = after_rollback(
        OpRefused::Refused("invalid value".into()),
        Err(Error::IoError("disconnected".into())),
    );
    assert!(
        matches!(error, OpRefused::Refused(text) if text.contains("invalid value") && text.contains("rollback also failed"))
    );
}

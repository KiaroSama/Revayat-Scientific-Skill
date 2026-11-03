use super::*;
#[test]
fn controller_markers_preserve_validation_order() {
    let mut state = Lifecycle::Prepared;
    for next in [
        Lifecycle::Suspended,
        Lifecycle::Attached,
        Lifecycle::Qualified,
        Lifecycle::Running,
        Lifecycle::Reaped,
        Lifecycle::Restored,
        Lifecycle::Closed,
    ] {
        state.advance(next).unwrap();
    }
    assert_eq!(state, Lifecycle::Closed);
}
#[test]
fn timeout_keeps_capture_after_reader_cleanup() {
    let value = complete();
    let receipt = frame();
    assert_eq!(value.finish(OUTPUT_LIMIT).unwrap(), "fixed\n");
    assert_eq!(
        Receipt::parse(receipt.wire().unwrap().as_bytes()).unwrap(),
        receipt
    );
}
#[test]
fn primary_and_recovery_failures_remain_ordered() {
    let mut value = frame();
    value.retain(Phase::Restore, Fault::Cleanup);
    value.retain(Phase::Close, Fault::Cleanup);
    assert_eq!(
        Receipt::parse(value.wire().unwrap().as_bytes())
            .unwrap()
            .failures,
        [
            (Phase::Capture, Fault::Timeout),
            (Phase::Restore, Fault::Cleanup),
            (Phase::Close, Fault::Cleanup)
        ]
    );
}
#[test]
fn recovery_requires_reaping() {
    for state in [
        Lifecycle::Prepared,
        Lifecycle::Suspended,
        Lifecycle::Attached,
        Lifecycle::Qualified,
        Lifecycle::Running,
    ] {
        let mut current = state;
        assert!(current.advance(Lifecycle::Restored).is_err());
        assert_eq!(current, state);
    }
}
#[test]
fn success_keeps_capture_once() {
    let mut value = complete();
    assert_eq!(value.finish(OUTPUT_LIMIT).unwrap(), "fixed\n");
    assert!(value.append(b"second", OUTPUT_LIMIT).is_err());
    assert_eq!(value.finish(OUTPUT_LIMIT).unwrap(), "fixed\n");
}
#[test]
fn timeout_and_cleanup_failure_are_both_preserved() {
    let mut value = frame();
    value.retain(Phase::Close, Fault::Cleanup);
    assert!(value.wire().unwrap().contains("timeout"));
    assert!(value.wire().unwrap().contains("cleanup"));
}
#[test]
fn timeout_and_invalid_encoding_are_distinct() {
    let mut value = Capture::default();
    value.append(&[0xff], OUTPUT_LIMIT).unwrap();
    value.end();
    assert!(value.finish(OUTPUT_LIMIT).is_err());
    let mut receipt = frame();
    receipt.retain(Phase::Capture, Fault::Decode);
    assert_eq!(receipt.failures.len(), 2);
}
#[test]
fn failure_categories_are_closed_and_bounded() {
    let mut value = frame();
    for _ in 0..32 {
        value.retain(Phase::Prerequisite, Fault::Cleanup);
    }
    let wire = value.wire().unwrap();
    assert!(wire.len() <= ERROR_LIMIT);
    assert_eq!(value.failures.len(), 8);
    assert!(Receipt::parse(wire.replace("timeout", "private-path").as_bytes()).is_err());
}

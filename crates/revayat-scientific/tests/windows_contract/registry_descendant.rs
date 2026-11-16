use super::*;
#[test]
fn observed_exit_includes_natural_259() {
    for code in [0, 7, 259, u32::MAX] {
        let mut value = frame();
        value.observe_exit(code);
        assert_eq!(
            Receipt::parse(value.wire().unwrap().as_bytes())
                .unwrap()
                .child_exit,
            Some(code)
        );
    }
}
#[test]
fn primary_output_has_exact_two_record_schema() {
    let primary = authority::record("primary", 2, 0).unwrap();
    let child = authority::record("descendant", 2, 0).unwrap();
    assert_eq!(format!("{primary}{child}").lines().count(), 2);
    assert_eq!(child.replace("descendant", "primary"), primary);
}
#[test]
fn extra_terminators_cannot_be_trimmed_into_success() {
    let wire = authority::record("descendant", 2, 0).unwrap();
    for suffix in ["\n", "\r\n", " ", "\0"] {
        assert!(authority::child_record(format!("{wire}{suffix}").as_bytes()).is_err());
    }
}
#[test]
fn newline_conversion_cannot_precede_raw_caps() {
    let wire = authority::record("descendant", 2, 0).unwrap();
    assert!(authority::child_record(wire.replace('\n', "\r\n").as_bytes()).is_err());
    let mut value = Capture::default();
    assert!(
        value
            .append(&vec![b'\r'; OUTPUT_LIMIT + 1], OUTPUT_LIMIT)
            .is_err()
    );
}
#[test]
fn nonascii_receipt_retains_decode_fault() {
    let mut bytes = frame().wire().unwrap().into_bytes();
    bytes.insert(0, 0xff);
    assert!(Receipt::parse(&bytes).is_err());
    let value = Receipt::new(Phase::Capture, Fault::Decode);
    assert_eq!(value.failures, [(Phase::Capture, Fault::Decode)]);
}
#[test]
fn acquisition_failures_have_closed_native_stage() {
    for stage in authority::NATIVE_CHECKS {
        let failure = authority::descendant_result(false, Some(5), stage).unwrap_err();
        assert_eq!(failure.native_error, Some(5));
        assert_eq!(failure.events, [("descendant", *stage)]);
    }
}
#[test]
fn exact_cap_refuses_overflow_and_missing_eof() {
    let mut value = Capture::default();
    value
        .append(&vec![b'x'; OUTPUT_LIMIT], OUTPUT_LIMIT)
        .unwrap();
    assert!(value.finish(OUTPUT_LIMIT).is_err());
    assert!(value.append(b"x", OUTPUT_LIMIT).is_err());
    value.end();
    assert_eq!(value.finish(OUTPUT_LIMIT).unwrap().len(), OUTPUT_LIMIT);
}
#[test]
fn malformed_read_and_cleanup_are_fatal() {
    let mut value = Capture::default();
    value.append(b"ab", 2).unwrap();
    assert!(value.append(b"c", 2).is_err());
    let mut receipt = Receipt::new(Phase::Capture, Fault::Overflow);
    receipt.retain(Phase::Close, Fault::Cleanup);
    assert_eq!(receipt.failures.len(), 2);
}
#[test]
fn cleanup_overrun_is_fatal_after_all_owners() {
    let mut value = Receipt::new(Phase::Reap, Fault::Timeout);
    for _ in 0..7 {
        value.retain(Phase::Close, Fault::Cleanup);
    }
    assert_eq!(
        Receipt::parse(value.wire().unwrap().as_bytes())
            .unwrap()
            .failures
            .len(),
        8
    );
}
#[test]
fn child_failure_survives_transport_and_cleanup() {
    let mut value = Receipt::new(Phase::Wait, Fault::Exit);
    value.observe_exit(7);
    value.retain(Phase::Capture, Fault::Decode);
    value.retain(Phase::Close, Fault::Cleanup);
    assert_eq!(value.child_exit, Some(7));
    assert_eq!(value.failures[0], (Phase::Wait, Fault::Exit));
}
#[test]
fn natural_exit_survives_eof_and_close_failure() {
    let mut value = Receipt::new(Phase::Capture, Fault::Control);
    value.observe_exit(259);
    value.retain(Phase::Close, Fault::Cleanup);
    assert_eq!(
        Receipt::parse(value.wire().unwrap().as_bytes())
            .unwrap()
            .child_exit,
        Some(259)
    );
}
#[test]
fn timeout_retains_bounded_bootstrap() {
    let mut value = frame();
    value.retain(Phase::Reap, Fault::Cleanup);
    assert_eq!(value.failures[0], (Phase::Capture, Fault::Timeout));
    assert!(value.wire().unwrap().len() <= ERROR_LIMIT);
}
#[test]
fn native_adapter_rejects_inconsistent_success_error() {
    for state in [(true, Some(5)), (false, None)] {
        assert!(authority::descendant_result(state.0, state.1, "control-create-process").is_err());
    }
}
#[test]
fn exact_three_standard_phases_are_closed() {
    for stage in ["control-stdin", "control-stdout", "control-stderr"] {
        assert!(authority::token_need(true, stage).is_ok());
    }
    for stage in ["control-extra-handle", "stdin-file", "stdin-network"] {
        assert!(authority::token_need(true, stage).is_err());
    }
}
#[test]
fn fixed_ordinary_cap_does_not_change_registry_defaults() {
    assert_eq!(authority::READ, 0x20019);
    assert_eq!(OUTPUT_LIMIT, 2048);
    assert!(authority::record("descendant", 257, 0).is_err());
    assert!(authority::record("descendant", 1, 2).is_err());
}
#[test]
fn spawn_cannot_bypass_detached_job_checks() {
    for stage in [
        "control-console",
        "control-job",
        "control-stdin",
        "control-stdout",
        "control-stderr",
    ] {
        assert_eq!(
            authority::token_need(false, stage).unwrap_err().events,
            [("token", stage)]
        );
    }
}

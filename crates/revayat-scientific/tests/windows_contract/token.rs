use super::*;
#[test]
fn predicates_keep_first_failure_and_occurrence() {
    let mut value = Receipt::new(Phase::Token, Fault::Control);
    value.retain(Phase::Token, Fault::Native);
    value.retain(Phase::Token, Fault::Control);
    assert_eq!(
        value.failures,
        [
            (Phase::Token, Fault::Control),
            (Phase::Token, Fault::Native),
            (Phase::Token, Fault::Control)
        ]
    );
}
#[test]
fn privileges_require_complete_luid() {
    assert!(privilege_inventory(&privileges(&[(23, 2)]), 16).is_ok());
    for luid in [0, 20, 24, 23 + (1u64 << 32)] {
        assert!(privilege_inventory(&privileges(&[(luid, 2)]), 16).is_err());
    }
}
#[test]
fn restrictions_decode_only_returned_span() {
    let data = [1, 255, 254, 253];
    assert!(restricted_value(&data[..1]).unwrap());
    assert!(restricted_value(&data).is_err());
}
#[test]
fn preamble_stops_at_each_boundary() {
    for state in [
        Lifecycle::Prepared,
        Lifecycle::Suspended,
        Lifecycle::Attached,
    ] {
        let mut value = state;
        assert!(value.advance(Lifecycle::Running).is_err());
        assert_eq!(value, state);
    }
}
#[test]
fn operation_close_and_report_failures_are_fatal() {
    let mut value = Receipt::new(Phase::Token, Fault::Native);
    value.retain(Phase::Close, Fault::Cleanup);
    value.retain(Phase::Report, Fault::Native);
    assert_eq!(
        Receipt::parse(value.wire().unwrap().as_bytes()).unwrap(),
        value
    );
}
#[test]
fn closed_phases_retain_exit_and_transport_limits() {
    let mut value = frame();
    value.observe_exit(0xc0000022);
    value.observe_exit(0);
    assert_eq!(value.child_exit, Some(0xc0000022));
    assert!(Receipt::parse(&vec![b' '; ERROR_LIMIT + 1]).is_err());
}
#[test]
fn controller_and_authority_share_closed_token_inventory() {
    for stage in authority::TOKEN_CHECKS {
        let error = authority::token_need(false, stage).unwrap_err();
        assert_eq!(error.events, [("token", *stage)]);
        assert!(error.wire("primary").len() <= ERROR_LIMIT);
    }
    assert!(authority::token_need(true, "unknown-private").is_err());
}
#[test]
fn private_policy_requires_primary_unelevated_restricted_identity() {
    for kind in 0..=2 {
        for elevated in 0..=1 {
            for filtered in 0..=2 {
                assert_eq!(
                    authority::token_fields(kind, elevated, filtered),
                    (kind, elevated, filtered) == (1, 0, 1)
                );
            }
        }
    }
    assert!(package_sid("S-1-15-2-1").is_err());
    assert!(package_sid("S-1-15-2-1-2-3-4-5-6-7").is_ok());
    assert!(package_sid("S-1-15-2-01-2-3-4-5-6-7").is_err());
}
#[test]
fn native_failure_reads_last_error_once() {
    use std::cell::Cell;
    let calls = Cell::new(0);
    let result = authority::descendant_native(false, "control-create-process", || {
        calls.set(calls.get() + 1);
        5
    });
    assert_eq!(calls.get(), 1);
    assert_eq!(result.unwrap_err().native_error, Some(5));
}
#[test]
fn ordinary_privileges_do_not_resolve_names() {
    for flags in [4, 8, 0x80000000, u32::MAX] {
        assert!(privilege_inventory(&privileges(&[(23, flags)]), 16).is_err());
    }
    assert!(privilege_inventory(&privileges(&[]), 4).is_ok());
}

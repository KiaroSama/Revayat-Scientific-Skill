use super::*;
use revayat_scientific::windows_security::preparation;
use std::{cell::Cell, sync::Arc};
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

    // This remains one registered pure-controller check, as in the original
    // Check-RuntimePreparation script. Every site is observed after its assertions.
    let mut journal = super::runtime_preparation::SiteJournal::default();
    let mut output = Vec::new();
    let value = preparation::invoke_bootstrap_stage(
        "managed",
        7,
        |phase, state, index| {
            preparation::write_bootstrap_progress(&mut output, phase, state, index)
        },
        || Ok("fixed-result"),
    )
    .unwrap();
    assert_eq!(value, "fixed-result");
    journal.observe(26, &[], "invoke_bootstrap_stage");
    assert_eq!(
        String::from_utf8(output.clone()).unwrap(),
        format!(
            "WINDOWS_BOOTSTRAP phase=managed state=before index=7{}WINDOWS_BOOTSTRAP phase=managed state=after index=7{}",
            preparation::NEWLINE,
            preparation::NEWLINE
        )
    );
    journal.observe(27, &[], "invoke_bootstrap_stage");

    output.clear();
    let original: preparation::SharedError =
        Arc::new(std::io::Error::other("fixed operation failure"));
    let caught = preparation::invoke_bootstrap_stage(
        "managed",
        8,
        |phase, state, index| {
            preparation::write_bootstrap_progress(&mut output, phase, state, index)
        },
        || Err::<(), _>(original.clone()),
    )
    .unwrap_err();
    assert!(Arc::ptr_eq(&caught, &original));
    journal.observe(32, &[], "invoke_bootstrap_stage");
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!(
            "WINDOWS_BOOTSTRAP phase=managed state=before index=8{}",
            preparation::NEWLINE
        )
    );
    journal.observe(33, &[], "invoke_bootstrap_stage");

    let mut refused = Vec::new();
    for (id, phase, state, index) in [
        ("private-phase", "private/path", "before", 0),
        ("private-state", "managed", "private", 0),
        ("negative-index", "managed", "before", -1),
        ("index-65", "managed", "before", 65),
    ] {
        let mut output = Vec::new();
        assert!(preparation::write_bootstrap_progress(&mut output, phase, state, index).is_err());
        assert!(output.is_empty());
        refused.push(id.to_owned());
    }
    journal.observe(37, &refused, "write_bootstrap_progress");

    let mut variants: [Vec<String>; 6] = Default::default();
    for operation_failure in 0..=2 {
        for failed_marker in -1..=3 {
            let mut markers = Vec::new();
            let marker_failure: preparation::SharedError =
                Arc::new(std::io::Error::other("fixed marker failure"));
            let operation_error: preparation::SharedError =
                Arc::new(std::io::Error::other("fixed recovery failure"));
            let compile_calls = Cell::new(0);
            let recover_calls = Cell::new(0);
            let caught = preparation::invoke_bootstrap_recovery(
                |phase, state, index| {
                    assert_eq!(index, 0);
                    let position = markers.len() as i32;
                    markers.push(format!("{phase}/{state}"));
                    if position == failed_marker {
                        Err(marker_failure.clone())
                    } else {
                        Ok(())
                    }
                },
                || {
                    compile_calls.set(compile_calls.get() + 1);
                    if operation_failure == 1 {
                        Err(operation_error.clone())
                    } else {
                        Ok(())
                    }
                },
                || {
                    recover_calls.set(recover_calls.get() + 1);
                    if operation_failure == 2 {
                        Err(operation_error.clone())
                    } else {
                        Ok(())
                    }
                },
            )
            .err();
            let expected = match operation_failure {
                1 => vec!["recovery-compile/before"],
                2 => vec![
                    "recovery-compile/before",
                    "recovery-compile/after",
                    "recovery/before",
                ],
                _ => vec![
                    "recovery-compile/before",
                    "recovery-compile/after",
                    "recovery/before",
                    "recovery/after",
                ],
            };
            let id = format!("operation-{operation_failure}/marker-{failed_marker}");
            assert_eq!(markers, expected);
            variants[0].push(id.clone());
            assert_eq!(compile_calls.get(), 1);
            assert_eq!(recover_calls.get(), i32::from(operation_failure != 1));
            variants[1].push(id.clone());
            let report_failed = failed_marker >= 0 && (failed_marker as usize) < expected.len();
            let count = usize::from(operation_failure != 0) + usize::from(report_failed);
            assert_eq!(caught.is_some(), count != 0);
            variants[2].push(id.clone());
            if count != 0 {
                let caught = caught.unwrap();
                assert_eq!(caught.errors.len(), count);
                assert_eq!(
                    caught.to_string(),
                    "Bootstrap recovery operation/reporting failed"
                );
                variants[3].push(id.clone());
                if operation_failure != 0 {
                    assert!(Arc::ptr_eq(&caught.errors[0], &operation_error));
                    variants[4].push(id.clone());
                }
                if report_failed {
                    assert!(Arc::ptr_eq(&caught.errors[count - 1], &marker_failure));
                    variants[5].push(id);
                }
            }
        }
    }
    for (site, observed) in [68, 69, 72, 74, 75, 76].into_iter().zip(variants) {
        journal.observe(site, &observed, "invoke_bootstrap_recovery");
    }
    super::runtime_preparation::assert_original_preparation_contract(&mut journal);
    journal.finish();
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
    let operation: preparation::SharedError = Arc::new(std::io::Error::other("primary"));
    let markers: [preparation::SharedError; 3] = std::array::from_fn(|index| {
        Arc::new(std::io::Error::other(format!("marker {index}"))) as preparation::SharedError
    });
    let mut reached = 0;
    let error = preparation::invoke_bootstrap_recovery(
        |_, _, _| {
            let error = markers[reached].clone();
            reached += 1;
            Err(error)
        },
        || Ok(()),
        || Err(operation.clone()),
    )
    .unwrap_err();
    assert_eq!(reached, 3);
    assert_eq!(error.errors.len(), 4);
    assert!(Arc::ptr_eq(&error.errors[0], &operation));
    for (actual, expected) in error.errors[1..].iter().zip(&markers) {
        assert!(Arc::ptr_eq(actual, expected));
    }
    // The production controller uses anyhow. The generic operation path must keep
    // that exact owned error allocation, including its downcastable native cause.
    let original = anyhow::Error::new(std::io::Error::other("controller operation"));
    let original_address = original.downcast_ref::<std::io::Error>().unwrap() as *const _;
    let caught = preparation::invoke_bootstrap_stage(
        "prerequisite",
        0,
        |_, _, _| Ok::<(), anyhow::Error>(()),
        || Err::<(), _>(original),
    )
    .unwrap_err();
    assert_eq!(
        caught.downcast_ref::<std::io::Error>().unwrap() as *const _,
        original_address
    );
    let reporting = anyhow::Error::new(std::io::Error::other("controller report"));
    let reporting_address = reporting.downcast_ref::<std::io::Error>().unwrap() as *const _;
    let mut reporting = Some(reporting);
    let aggregate = preparation::invoke_bootstrap_recovery(
        |_, _, _| reporting.take().map_or(Ok(()), Err),
        || Ok(()),
        || Err(caught),
    )
    .unwrap_err();
    assert_eq!(aggregate.errors.len(), 2);
    assert_eq!(
        aggregate.errors[0]
            .downcast_ref::<std::io::Error>()
            .unwrap() as *const _,
        original_address
    );
    assert_eq!(
        aggregate.errors[1]
            .downcast_ref::<std::io::Error>()
            .unwrap() as *const _,
        reporting_address
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

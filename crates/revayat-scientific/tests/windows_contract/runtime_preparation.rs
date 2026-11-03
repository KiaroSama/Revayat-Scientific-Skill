use super::*;
#[test]
fn diagnostics_precede_independent_admission() {
    let diagnostic = Receipt::new(Phase::Prepare, Fault::Control);
    assert!(authority::child_record(diagnostic.wire().unwrap().as_bytes()).is_err());
}
#[test]
fn scratch_observer_is_not_admission() {
    let directory = tempfile::tempdir().unwrap();
    plain_path(directory.path()).unwrap();
    assert!(authority::child_record(b"plain_path=true\n").is_err());
}
#[test]
fn supported_policy_refuses_nested_or_repeated_trial() {
    let mut state = Lifecycle::Running;
    assert!(state.advance(Lifecycle::Suspended).is_err());
    assert!(state.advance(Lifecycle::Running).is_err());
}
#[test]
fn owned_lifecycle_recovery_requires_reap() {
    let mut value = Lifecycle::Running;
    assert!(value.advance(Lifecycle::Closed).is_err());
    value.advance(Lifecycle::Reaped).unwrap();
    value.advance(Lifecycle::Restored).unwrap();
    value.advance(Lifecycle::Closed).unwrap();
}
#[test]
fn successful_consumer_requires_independent_token_control() {
    let record = authority::record("descendant", 0, 0).unwrap();
    assert!(
        authority::child_record(record.replace("\"lpac\":true", "\"lpac\":false").as_bytes())
            .is_err()
    );
}
#[test]
fn native_authority_is_distinct_from_diagnostics() {
    assert!(authority::child_record(b"WINDOWS_PREFLIGHT_FAILURE\n").is_err());
    assert!(
        authority::child_record(authority::record("primary", 0, 0).unwrap().as_bytes()).is_err()
    );
}
#[test]
fn image_preparation_refuses_unsafe_leaf_names() {
    for name in [
        "image.exe:",
        "image.exe.",
        "image.exe ",
        "COM1.exe",
        "../image.exe",
    ] {
        assert!(relative_leaf(Path::new(name)).is_err());
    }
    assert!(relative_leaf(Path::new("registry-authority.exe")).is_ok());
}
#[test]
fn token_stage_allowlist_does_not_accept_private_values() {
    assert!(authority::token_kind("control-priv-value").is_some());
    for bad in [
        "control-priv-value\n",
        "private-token",
        "CONTROL-PRIV-VALUE",
    ] {
        assert!(authority::token_kind(bad).is_none());
    }
}
#[test]
fn descendant_errors_keep_native_boundary() {
    let error = authority::descendant_native(false, "control-resume", || 0xc0000022).unwrap_err();
    assert_eq!(error.events, [("descendant", "control-resume")]);
    assert_eq!(error.native_error, Some(0xc0000022));
}
#[test]
fn restrictions_query_uses_immediate_failure_only() {
    use std::cell::Cell;
    let calls = Cell::new(0);
    assert!(
        authority::restriction_need(1, 4, || {
            calls.set(1);
            99
        })
        .is_ok()
    );
    assert_eq!(calls.get(), 0);
    assert!(
        authority::restriction_need(0, 4, || {
            calls.set(1);
            5
        })
        .is_err()
    );
    assert_eq!(calls.get(), 1);
}
#[test]
fn privilege_full_luid_cannot_alias_by_low_part() {
    assert!(privilege_inventory(&privileges(&[(23, 2), (23 | (1u64 << 32), 2)]), 28).is_err());
}
#[test]
fn admission_requires_fresh_exact_record() {
    let fresh = authority::record("descendant", 2, 0).unwrap();
    for altered in [
        fresh.replace("true", "false"),
        fresh.replace("\"accessible\":0", "\"accessible\":00"),
        format!("{fresh}{fresh}"),
    ] {
        assert!(authority::child_record(altered.as_bytes()).is_err());
    }
}
#[test]
fn native_launch_preserves_aggregate_job_prerequisites() {
    let expected = JobLimits::default();
    assert_eq!(expected.processes, 8);
    assert_eq!(expected.job_memory, 512 * 1024 * 1024);
    assert_eq!(expected.cpu_seconds, 30);
    assert!(expected.validate().is_ok());
}
#[test]
fn preparation_failure_has_one_ordered_boundary() {
    let mut receipt = Receipt::new(Phase::Prepare, Fault::Native);
    receipt.retain(Phase::Close, Fault::Cleanup);
    assert_eq!(
        Receipt::parse(receipt.wire().unwrap().as_bytes())
            .unwrap()
            .failures[0],
        (Phase::Prepare, Fault::Native)
    );
}
#[test]
fn prerequisite_failures_are_private_and_nonzero() {
    let value = Receipt::new(Phase::Prerequisite, Fault::Control);
    assert!(value.wire().unwrap().contains("prerequisite"));
    assert!(Receipt::parse(b"{}\n").is_err());
}
#[test]
fn reported_metadata_is_closed() {
    let wire = frame().wire().unwrap();
    for unknown in ["{\"path\":\"private\",", "{\"command\":\"secret\","] {
        assert!(Receipt::parse(wire.replacen('{', unknown, 1).as_bytes()).is_err());
    }
}
#[test]
fn fixed_controls_can_be_checked_without_kernel_claim() {
    assert!(JobLimits::browser().validate().is_ok());
    assert!(JobLimits::ownership().validate().is_ok());
    let invalid = JobLimits {
        processes: 9,
        ..Default::default()
    };
    assert!(invalid.validate().is_err());
}
#[test]
fn failure_projection_preserves_exit_order_and_privacy() {
    let mut value = Receipt::new(Phase::Wait, Fault::Exit);
    value.observe_exit(u32::MAX);
    value.retain(Phase::Close, Fault::Cleanup);
    let wire = value.wire().unwrap();
    assert_eq!(Receipt::parse(wire.as_bytes()).unwrap(), value);
    assert!(!wire.contains("private"));
}
#[test]
fn streaming_copy_refuses_reparse_source() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::write(&source, b"content").unwrap();
    let link = directory.path().join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&source, &link).unwrap();
    #[cfg(windows)]
    {
        let target = directory.path().join("junction-target");
        std::fs::create_dir(&target).unwrap();
        super::windows_junction::create(&link, &target).unwrap();
    }
    assert!(plain_path(&link).is_err());
    assert!(plain_path(&source).is_ok());
}

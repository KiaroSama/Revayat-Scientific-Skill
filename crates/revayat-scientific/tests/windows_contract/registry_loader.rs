use super::*;
#[test]
fn reusable_policy_helpers_do_not_launch_children() {
    activation::fixtures::registry_loader::check_validation().unwrap();
    revayat_scientific::windows_security::loader_comparison::check_validation().unwrap();
    let baseline = registry_authority::protocol::machine_baseline_record(0xC0000022, 0).unwrap();
    registry_authority::protocol::require_machine_baseline(baseline.as_bytes()).unwrap();
    for (status, handle) in [(0, 0), (1, 0), (0xC0000022, 4), (u32::MAX, 0)] {
        assert!(registry_authority::protocol::machine_baseline_record(status, handle).is_err());
    }
    assert!(
        registry_authority::protocol::require_machine_baseline(
            format!("{baseline}extra").as_bytes()
        )
        .is_err()
    );
    policy::registry_comparison::check_startup_validation().unwrap();
    policy::registry_comparison::check_causal_validation().unwrap();
    policy::registry_comparison::check_authority_validation().unwrap();
    policy::registry_comparison::check_supported_validation().unwrap();
    let source = registry_authority::oracle::generate();
    assert_eq!(source.lines().count(), 41);
    assert_eq!(
        source
            .lines()
            .filter(|line| line.starts_with("wire\t"))
            .count(),
        6
    );
}
#[test]
fn scratch_entry_failure_is_bounded_and_private() {
    let receipt = Receipt::new(Phase::Prepare, Fault::Control);
    let wire = receipt.wire().unwrap();
    assert!(wire.len() < ERROR_LIMIT);
    assert!(!wire.contains(&std::env::temp_dir().display().to_string()));
}
#[test]
fn positive_write_preserves_exact_bytes() {
    let directory = tempfile::tempdir().unwrap();
    revayat_scientific::windows_security::activation::fixtures::python_startup::check_validation(
        directory.path(),
    )
    .unwrap();
    plain_path(directory.path()).unwrap();
    let path = directory.path().join("write-control");
    let bytes = b"\0fixed\r\n\xff";
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
#[test]
fn preflight_frame_has_closed_source_metadata() {
    let wire = frame().wire().unwrap();
    assert!(Receipt::parse(wire.replace("capture", "../private-source").as_bytes()).is_err());
    assert!(Receipt::parse(wire.replace("timeout", "os-error-with-path").as_bytes()).is_err());
}
#[test]
fn first_receipt_precedes_effects() {
    let mut state = Lifecycle::Attached;
    assert!(state.advance(Lifecycle::Running).is_err());
    state.advance(Lifecycle::Qualified).unwrap();
    state.advance(Lifecycle::Running).unwrap();
    assert_eq!(state, Lifecycle::Running);
}
#[test]
fn fixed_file_binding_rejects_noncanonical_identity() {
    let data = identity(&[65]);
    assert_eq!(authority::identity(0, 6, &data, 2).unwrap(), "A");
    assert!(authority::identity(0, 6, &data, 4).is_err());
    assert!(authority::identity(1, 6, &data, 2).is_err());
}
#[test]
fn first_receipt_survives_timeout_and_unqualified_tail() {
    let mut value = Receipt::new(Phase::Token, Fault::Control);
    value.retain(Phase::Wait, Fault::Timeout);
    value.observe_exit(7);
    assert_eq!(value.failures[0], (Phase::Token, Fault::Control));
    assert!(Receipt::parse(format!("{}private-tail", value.wire().unwrap()).as_bytes()).is_err());
}

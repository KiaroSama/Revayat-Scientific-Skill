use super::*;
#[test]
fn owned_lifetime_does_not_admit_host_descriptor() {
    revayat_scientific::windows_security::scratch::check_access_validation().unwrap();
    revayat_scientific::windows_security::scratch::check_attachment_validation().unwrap();
    let mut state = Lifecycle::Prepared;
    assert!(state.advance(Lifecycle::Running).is_err());
    assert!(authority::child_record(b"descriptor_checked=true\n").is_err());
}
#[test]
fn suspended_lifetime_precedes_discovery() {
    let mut state = Lifecycle::Prepared;
    state.advance(Lifecycle::Suspended).unwrap();
    assert!(state.advance(Lifecycle::Qualified).is_err());
    state.advance(Lifecycle::Attached).unwrap();
    assert_eq!(state, Lifecycle::Attached);
}
#[test]
fn receipt_precedes_mutation_and_recovery_precedes_detach() {
    revayat_scientific::windows_security::scratch::check_volume_policy_validation().unwrap();
    let mut state = Lifecycle::Running;
    assert!(state.advance(Lifecycle::Restored).is_err());
    state.advance(Lifecycle::Reaped).unwrap();
    state.advance(Lifecycle::Restored).unwrap();
    state.advance(Lifecycle::Closed).unwrap();
}
#[test]
fn frames_follow_restore_and_retain_close_failure() {
    revayat_scientific::windows_security::scratch::check_cleanup_validation().unwrap();
    let mut value = Receipt::new(Phase::Restore, Fault::Cleanup);
    value.retain(Phase::Close, Fault::Cleanup);
    let parsed = Receipt::parse(value.wire().unwrap().as_bytes()).unwrap();
    assert_eq!(
        parsed.failures,
        [
            (Phase::Restore, Fault::Cleanup),
            (Phase::Close, Fault::Cleanup)
        ]
    );
}
#[test]
fn supported_role_qualification_is_exact() {
    revayat_scientific::windows_security::scratch::check_supported_validation().unwrap();
    let record = authority::record("descendant", 0, 0).unwrap();
    for role in ["primary", "Descendant", "descendant-child"] {
        assert!(authority::child_record(record.replace("descendant", role).as_bytes()).is_err());
    }
}
#[test]
fn create_only_request_never_overwrites_foreign_file() {
    revayat_scientific::windows_security::scratch::check_file_creation_validation().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control");
    std::fs::write(&path, b"foreign").unwrap();
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
}
#[test]
fn handle_only_identity_refuses_utf16_aliases() {
    revayat_scientific::windows_security::scratch::check_volume_access_validation().unwrap();
    for units in [&[0u16][..], &[0xd800][..], &[0xdc00][..]] {
        let bytes = identity(units);
        assert!(authority::identity(0, bytes.len(), &bytes, units.len() * 2).is_err());
    }
    let bytes = identity(&[0xd83d, 0xde42]);
    assert_eq!(
        authority::identity(0, bytes.len(), &bytes, 4).unwrap(),
        "🙂"
    );
}

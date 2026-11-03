use super::*;
#[test]
fn exact_control_request_rejects_path_escape() {
    for value in ["../outside", "/outside", "C:\\outside", "a:b", "a\\b"] {
        assert!(relative_leaf(Path::new(value)).is_err(), "{value}");
    }
    assert!(relative_leaf(Path::new("scratch/control.bin")).is_ok());
}
#[test]
fn acquisition_failures_never_reach_resume() {
    for state in [Lifecycle::Prepared, Lifecycle::Suspended] {
        let mut value = state;
        assert!(value.advance(Lifecycle::Qualified).is_err());
        assert_eq!(value, state);
    }
}
#[test]
fn creation_and_binding_have_distinct_boundaries() {
    let create = Receipt::new(Phase::Create, Fault::Native);
    let attach = Receipt::new(Phase::Attach, Fault::Native);
    assert_ne!(create.wire().unwrap(), attach.wire().unwrap());
}
#[test]
fn clean_cleanup_preserves_original_failure() {
    let value = Receipt::new(Phase::Prepare, Fault::Control);
    assert_eq!(
        Receipt::parse(value.wire().unwrap().as_bytes()).unwrap(),
        value
    );
}
#[test]
fn independent_cleanup_failures_are_retained() {
    let mut value = frame();
    for phase in [Phase::Reap, Phase::Restore, Phase::Close] {
        value.retain(phase, Fault::Cleanup);
    }
    assert_eq!(value.failures.len(), 4);
    assert_eq!(value.failures[3], (Phase::Close, Fault::Cleanup));
}
#[test]
fn cleanup_refuses_foreign_path_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("owned");
    std::fs::write(&path, b"one").unwrap();
    let before = revayat_scientific::identity::file_identity(&path, None).unwrap();
    std::fs::write(&path, b"foreign").unwrap();
    let after = revayat_scientific::identity::file_identity(&path, None).unwrap();
    assert!(!before.same_bytes(&after));
}
#[test]
fn native_root_shape_refuses_dos_device_names() {
    for name in ["NUL", "nul.txt", "CON", "LPT1", "AUX.csv", "COM9"] {
        assert!(relative_leaf(Path::new(name)).is_err());
    }
}
#[test]
fn success_never_reads_stale_native_error() {
    let result = authority::descendant_native(true, "control-create-process", || {
        panic!("successful API must not read error")
    });
    assert!(result.is_ok());
}
#[test]
fn private_parent_binding_is_checked_before_admission() {
    let mut state = Lifecycle::Suspended;
    assert!(state.advance(Lifecycle::Running).is_err());
    state.advance(Lifecycle::Attached).unwrap();
    state.advance(Lifecycle::Qualified).unwrap();
    state.advance(Lifecycle::Running).unwrap();
}
#[test]
fn authority_consumer_retains_actual_controls() {
    assert!(authority::basic(0, 56, 0, 0x20019));
    for access in [0x19, 0x2001b, 0xf003f] {
        assert!(!authority::basic(0, 56, 0, access));
    }
    assert!(!authority::denied(0xc0000022, 4));
}

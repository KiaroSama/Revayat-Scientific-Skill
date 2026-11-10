//! Actual Windows ownership boundary, not an exit-code recovery certificate.
#![cfg(windows)]
use revayat_scientific::runtime::{
    self, CommandSpec, DeadlineExceeded, ReapedProcessTree, run_with_recovery,
};
use std::{cell::Cell, fs, time::Duration};

fn spec(mode: &str) -> CommandSpec {
    let mut value = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-test-tool")).args([mode]);
    value.timeout = Duration::from_secs(5);
    value
}

#[test]
fn recovery_receives_only_matching_bound_proof_after_real_process_finalization() {
    let binding = "a".repeat(64);
    let calls = Cell::new(0);
    let output = run_with_recovery(&spec("diagnostics"), &binding, |proof| {
        proof.require_binding(&binding)?;
        assert!(proof.require_binding(&"b".repeat(64)).is_err());
        calls.set(calls.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(output.code, 7);
    assert_eq!(calls.get(), 1);
}

#[test]
fn timeout_reaps_actual_descendant_before_recovery_and_preserves_primary_error() {
    let root = tempfile::tempdir().unwrap();
    let pid = root.path().join("owned descendant.pid");
    let mut command = spec("wait-grandchild");
    command.args.push(pid.as_os_str().to_owned());
    command.timeout = Duration::from_secs(1);
    let called = Cell::new(false);
    let error = run_with_recovery(&command, &"c".repeat(64), |_| {
        let child: u32 = fs::read_to_string(&pid)?.parse()?;
        assert!(revayat_scientific::windows_security::native::process_exited(child)?);
        called.set(true);
        anyhow::bail!("owned recovery fixture failure")
    })
    .unwrap_err();
    assert!(error.downcast_ref::<DeadlineExceeded>().is_some());
    assert!(error.downcast_ref::<runtime::CleanupFailure>().is_some());
    assert!(called.get());
}

#[test]
fn invalid_binding_and_missing_launch_never_authorize_recovery() {
    for binding in ["", "abc", &"A".repeat(64)] {
        let called = Cell::new(false);
        assert!(
            run_with_recovery(&spec("diagnostics"), binding, |_| {
                called.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!called.get());
    }
    let called = Cell::new(false);
    let error = run_with_recovery(
        &CommandSpec::new("revayat-nonexistent-recovery-fixture-executable"),
        &"d".repeat(64),
        |_| {
            called.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(runtime::is_missing_executable(&error));
    assert!(!called.get());
}

#[test]
fn native_cli_rejects_public_owned_locators_before_creating_state_and_worker_bad_arity() {
    let root = tempfile::tempdir().unwrap();
    let mut command = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args([
        "security-windows",
        "--authority-image",
        "missing-fixed-image.exe",
        "--owned-run",
        "not-state",
        "not-run",
        "not-binding",
        "not-identity",
    ]);
    command.cwd = Some(root.path().to_owned());
    command.timeout = Duration::from_secs(10);
    let refused = runtime::run(&command).unwrap();
    assert_eq!(refused.code, 2);
    assert!(
        refused
            .stderr_text()
            .contains("owned native run locators are internal")
    );
    assert!(!root.path().join(".scratch").exists());
    command.args.insert(0, "--worker".into());
    command.args.pop();
    let malformed = runtime::run(&command).unwrap();
    assert_eq!(malformed.code, 2);
    assert!(!root.path().join(".scratch").exists());
}

// A caller can name/borrow the proof type, but cannot construct or deserialize it.
fn _proof_is_borrowed_only(_: &ReapedProcessTree) {}

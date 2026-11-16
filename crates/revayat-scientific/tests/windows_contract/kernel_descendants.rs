use super::*;
#[test]
fn token_capture_keeps_role_and_cap() {
    let child = authority::record("descendant", 2, 0).unwrap();
    assert_eq!(authority::child_record(child.as_bytes()).unwrap(), child);
    assert!(authority::child_record(&vec![b'X'; 1025]).is_err());
}
#[test]
fn capture_failure_retains_original_and_redacts_private_stderr() {
    let mut value = Capture::default();
    value.append(b"private sentinel", OUTPUT_LIMIT).unwrap();
    value.clear();
    value.end();
    assert_eq!(value.finish(OUTPUT_LIMIT).unwrap(), "");
    assert!(!frame().wire().unwrap().contains("sentinel"));
}
#[test]
fn child_roles_retain_exact_allowlist() {
    for role in ["sleep", "pid", "host", "descendant ", ""] {
        assert!(authority::record(role, 0, 0).is_err());
    }
    assert!(authority::record("descendant", 0, 0).is_ok());
}
#[test]
fn partial_acquisition_and_close_failures_remain_fatal() {
    let mut value = Receipt::new(Phase::Create, Fault::Native);
    value.retain(Phase::Close, Fault::Cleanup);
    assert_eq!(value.failures[0], (Phase::Create, Fault::Native));
    assert_eq!(
        Receipt::parse(value.wire().unwrap().as_bytes())
            .unwrap()
            .failures
            .len(),
        2
    );
}
#[test]
fn extra_pid_denial_cannot_be_reported_as_success() {
    assert!(Receipt::parse(b"{\"failures\":[],\"child_exit\":0}\n").is_err());
    assert!(authority::child_record(b"0\n").is_err());
}

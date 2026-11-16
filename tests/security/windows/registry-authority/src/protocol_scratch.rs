//! Closed scratch stages retain only the actual scalar OS error, never a path or message.
use super::Failure;
pub const SCRATCH_CHECKS: &[&str] = &[
    "scratch-cwd",
    "scratch-create",
    "scratch-write",
    "scratch-flush",
    "scratch-sync",
    "scratch-seek",
    "scratch-read",
    "scratch-retire",
];
pub fn scratch_kind(value: &str) -> Option<&'static str> {
    SCRATCH_CHECKS.iter().copied().find(|kind| *kind == value)
}
pub fn scratch_failure(kind: &str, error: Option<&std::io::Error>) -> Failure {
    let Some(kind) = scratch_kind(kind) else {
        return Failure::new("mutation", "control");
    };
    let mut failure = Failure::new("mutation", kind);
    failure.native_error = error
        .and_then(std::io::Error::raw_os_error)
        .map(|code| code as u32);
    failure
}
#[cfg(test)]
pub(super) fn check_diagnostics() {
    use super::failure_summary;
    for &stage in SCRATCH_CHECKS {
        for code in [0u32, 5, 32, u32::MAX] {
            let error = std::io::Error::from_raw_os_error(code as i32);
            let mut failure = scratch_failure(stage, Some(&error));
            assert_eq!(failure.events, [("mutation", stage)]);
            assert_eq!(failure.native_error, Some(code));
            let expected =
                format!("events=mutation:{stage} child_exit=none native_error={code:08X}");
            assert_eq!(failure_summary(&failure.wire("primary")), Some(expected));
            assert!(!failure.wire("descendant").contains("native_error="));
            failure.events.push(("close", "cleanup"));
            assert!(
                failure_summary(&failure.wire("primary"))
                    .unwrap()
                    .contains("close:cleanup")
            );
        }
        let private = std::io::Error::other("C:\\private-scratch\\secret content");
        let failure = scratch_failure(stage, Some(&private));
        assert!(failure.native_error.is_none());
        assert!(!failure.wire("primary").contains("private"));
        assert!(failure_summary(&failure.wire("primary")).is_some());
    }
    for stage in [
        "scratch-private-sentinel",
        "native",
        "control",
        "C:\\private",
    ] {
        let failure = scratch_failure(stage, Some(&std::io::Error::from_raw_os_error(5)));
        assert_eq!(failure.events, [("mutation", "control")]);
        assert!(failure.native_error.is_none());
    }
    for body in [
        "mutation:scratch-create native_error=private-path",
        "mutation:scratch-create native_error=0000000a",
        "mutation:scratch-create native_error=000000005",
        "mutation:scratch-private native_error=00000005",
        "mutation:control native_error=00000005",
        "mutation:scratch-create native_error=00000005 extra=private",
        "mutation:scratch-create native_error=00000005 native_error=00000005",
    ] {
        assert!(
            failure_summary(&format!(
                "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors={body}\n"
            ))
            .is_none()
        );
    }
}

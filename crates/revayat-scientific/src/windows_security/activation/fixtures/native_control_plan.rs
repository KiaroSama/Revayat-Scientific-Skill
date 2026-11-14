//! Original independent startup-before-debug build order, shared by the real producer.
use super::*;

pub(super) fn execute<T>(mut build: impl FnMut(NativeControlRole) -> Result<T>) -> Result<[T; 2]> {
    Ok([
        build(NativeControlRole::Startup)?,
        build(NativeControlRole::DebugControl)?,
    ])
}

/// Assertion callbacks never attest compiled images or native observations.
pub fn check_order_validation() -> Result<()> {
    #[derive(Debug)]
    struct Failure(std::sync::Arc<()>);
    impl std::fmt::Display for Failure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fixed independent build failure")
        }
    }
    impl std::error::Error for Failure {}
    let original = [NativeControlRole::Startup, NativeControlRole::DebugControl];
    for fail_at in 0..=original.len() {
        let identity = std::sync::Arc::new(());
        let mut observed = Vec::new();
        let result = execute(|role| {
            observed.push(role);
            if observed.len() - 1 == fail_at {
                return Err(Failure(identity.clone()).into());
            }
            Ok(())
        });
        ensure!(
            observed == original[..(fail_at + 1).min(original.len())],
            "independent native producer order or first-failure boundary differs"
        );
        if fail_at == original.len() {
            result?;
        } else {
            ensure!(
                result
                    .unwrap_err()
                    .downcast_ref::<Failure>()
                    .is_some_and(|error| std::sync::Arc::ptr_eq(&error.0, &identity)),
                "independent native build failure identity was replaced"
            );
        }
    }
    Ok(())
}

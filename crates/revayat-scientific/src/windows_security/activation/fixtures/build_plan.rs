//! Frozen Run-WindowsSecurity fixture preparation order, shared by the actual builder.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Step {
    Single(FixtureKind, &'static str),
    Module,
}
const ORDER: [Step; 7] = [
    Step::Single(FixtureKind::Child, "child"),
    Step::Single(FixtureKind::DllRequest, "dll-request"),
    Step::Single(FixtureKind::Default, "default"),
    Step::Module,
    Step::Single(FixtureKind::SelfHost(SelfRole::Original), "self"),
    Step::Single(FixtureKind::SelfHost(SelfRole::Manual), "manual"),
    Step::Single(FixtureKind::SelfHost(SelfRole::ExplicitId2), "explicit-id2"),
];
pub(super) fn execute(mut build: impl FnMut(Step) -> Result<()>) -> Result<()> {
    for step in ORDER {
        build(step)?;
    }
    Ok(())
}
/// A failed producer must prevent every later build; successful callbacks here
/// are assertion inputs, never compiled-image or native-execution evidence.
pub fn check_order_validation() -> Result<()> {
    #[derive(Debug)]
    struct Failure(std::sync::Arc<()>);
    impl std::fmt::Display for Failure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fixed build failure")
        }
    }
    impl std::error::Error for Failure {}
    let original = [
        "child",
        "dll-request",
        "default",
        "module",
        "self",
        "manual",
        "explicit-id2",
    ];
    for fail_at in 0..=original.len() {
        let identity = std::sync::Arc::new(());
        let mut observed = Vec::new();
        let result = execute(|step| {
            observed.push(match step {
                Step::Single(_, label) => label,
                Step::Module => "module",
            });
            if observed.len() - 1 == fail_at {
                return Err(Failure(identity.clone()).into());
            }
            Ok(())
        });
        ensure!(
            observed == original[..(fail_at + 1).min(original.len())],
            "fixture producer order or first-failure boundary differs"
        );
        if fail_at == original.len() {
            result?;
        } else {
            ensure!(
                result
                    .unwrap_err()
                    .downcast_ref::<Failure>()
                    .is_some_and(|error| std::sync::Arc::ptr_eq(&error.0, &identity)),
                "fixture build failure identity was replaced"
            );
        }
    }
    Ok(())
}

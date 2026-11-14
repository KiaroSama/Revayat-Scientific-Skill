//! Required real owned-debug fixture. It never substitutes for LPAC or fixed CSR acceptance.
#![cfg(windows)]
use revayat_scientific::windows_security::activation::diagnostics;
use revayat_scientific::windows_security::native::{
    DebugBoundary, observe_authority_entry, observe_authority_entry_observed,
};
#[derive(Debug)]
struct InjectedExitWait(std::sync::Arc<()>);
impl std::fmt::Display for InjectedExitWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("injected exit-wait boundary failure")
    }
}
impl std::error::Error for InjectedExitWait {}
#[test]
fn actual_owned_authority_entry_debug_state_is_restored_before_natural_exit() {
    let executable = std::env::current_exe().unwrap();
    let authority = revayat_scientific::executable_paths::binary_directory(&executable)
        .unwrap()
        .join("registry-authority.exe");
    let proof = observe_authority_entry(&authority).unwrap();
    assert!(
        proof.creation_bound
            && proof.entry_captured
            && proof.live_restored
            && proof.natural_exit
            && proof.reaped
    );
    assert!(proof.events > 0 && proof.events <= 128);
    assert!(proof.creator_capture);
}
#[test]
fn actual_fixed_explicit_id2_pairs_csr_only_with_real_os_profile_and_restoration() {
    use revayat_scientific::{
        runtime,
        windows_security::activation::fixtures::{
            build::RustTools, native_producers::CompiledIndependentId2,
        },
    };
    let work = tempfile::tempdir().unwrap();
    let result = (|| {
        let mut tools = RustTools::discover(work.path())?;
        let result = (|| {
            let mut fixture = CompiledIndependentId2::build(&mut tools, work.path())?;
            let observed =
                revayat_scientific::windows_security::native::observe_explicit_id2_dispatch(
                    &mut fixture,
                );
            runtime::with_cleanup(observed, fixture.close())
        })();
        runtime::with_cleanup(result, tools.close())
    })();
    let proof = runtime::with_cleanup(result, work.close().map_err(Into::into))
        .unwrap_or_else(|error| panic!("{}", diagnostics::summary(&error)));
    assert!(
        proof.creation_bound
            && proof.entry_captured
            && proof.live_restored
            && proof.natural_exit
            && proof.reaped
    );
    assert!(proof.dispatch_target_equal && proof.dispatch_return.is_some());
    // A host observation is not LPAC denial or equivalence with the historical Python manifest.
}
#[test]
fn actual_exit_wait_failure_still_retires_generation_handles_once() {
    let executable = std::env::current_exe().unwrap();
    let authority = revayat_scientific::executable_paths::binary_directory(&executable)
        .unwrap()
        .join("registry-authority.exe");
    let mut order = Vec::new();
    let injected = std::sync::Arc::new(());
    let error = observe_authority_entry_observed(&authority, |boundary| {
        order.push(boundary);
        if boundary == DebugBoundary::BeforeExitWait {
            return Err(InjectedExitWait(injected.clone()).into());
        }
        Ok(())
    })
    .unwrap_err();
    assert!(
        diagnostics::find::<InjectedExitWait>(&error)
            .is_some_and(|cause| std::sync::Arc::ptr_eq(&cause.0, &injected)),
        "{}",
        diagnostics::summary(&error)
    );
    assert_eq!(
        order,
        [
            DebugBoundary::BeforeExitWait,
            DebugBoundary::BeforeRetire,
            DebugBoundary::AfterRetire
        ]
    );
}

//! Required real owned-debug fixture. It never substitutes for LPAC or fixed CSR acceptance.
#![cfg(windows)]
use revayat_scientific::windows_security::native::{
    DebugBoundary, observe_authority_entry, observe_authority_entry_observed,
};
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
    let executable = std::env::current_exe().unwrap();
    let fixture = revayat_scientific::executable_paths::binary_directory(&executable)
        .unwrap()
        .join("startup-explicit-id2.exe");
    let proof =
        revayat_scientific::windows_security::native::observe_explicit_id2_dispatch(&fixture)
            .unwrap();
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
    let error = observe_authority_entry_observed(&authority, |boundary| {
        order.push(boundary);
        if boundary == DebugBoundary::BeforeExitWait {
            anyhow::bail!("injected exit-wait boundary failure");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("injected exit-wait boundary failure"));
    assert_eq!(
        order,
        [
            DebugBoundary::BeforeExitWait,
            DebugBoundary::BeforeRetire,
            DebugBoundary::AfterRetire
        ]
    );
}

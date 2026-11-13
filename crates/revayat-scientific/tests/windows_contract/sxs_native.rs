//! Hosted-only capture uses the real qualified authority and its actual profile, never a synthetic SID.
#![cfg(windows)]
use revayat_scientific::windows_security::sxs::native::{
    Boundary, collect_authority, collect_authority_observed,
};
use std::path::PathBuf;
fn inputs() -> (PathBuf, PathBuf) {
    let executable = std::env::current_exe().unwrap();
    let authority = revayat_scientific::executable_paths::binary_directory(&executable)
        .unwrap()
        .join("registry-authority.exe");
    let text = executable.to_str().unwrap();
    assert!(text.as_bytes()[0].is_ascii_uppercase() && text.as_bytes()[1] == b':');
    (authority, PathBuf::from(&text[..3]))
}
#[test]
fn actual_standard_sxs_collector_is_owned_stopped_reaped_and_control_qualified() {
    let (authority, volume) = inputs();
    let proof = collect_authority(&authority, &volume).unwrap();
    assert!(
        proof.starter_reaped
            && proof.session_stopped
            && proof.storage_qualified
            && proof.authority_completed
    );
    assert!(
        proof
            .evidence
            .contains("collector_recording_verified=True consumer_qualified=True")
    );
    assert!(proof.evidence.contains("child_visibility_claimed=False"));
    assert!(
        !proof.evidence.contains("capture.etl") && !proof.evidence.contains("collector.manifest")
    );
}
#[test]
fn actual_after_bind_failure_never_reaches_resume_and_still_stops_owned_session() {
    let (authority, volume) = inputs();
    let mut order = Vec::new();
    let result = collect_authority_observed(&authority, &volume, |boundary| {
        order.push(boundary);
        if boundary == Boundary::AfterBind {
            anyhow::bail!("injected after-bind failure");
        }
        Ok(())
    });
    assert!(result.is_err());
    assert!(order.contains(&Boundary::AfterBind));
    assert!(!order.contains(&Boundary::BeforeAuthorityResume));
    assert!(!order.contains(&Boundary::BeforeControl));
    assert_eq!(
        &order[order.len() - 2..],
        &[Boundary::BeforeStop, Boundary::AfterStop]
    );
}

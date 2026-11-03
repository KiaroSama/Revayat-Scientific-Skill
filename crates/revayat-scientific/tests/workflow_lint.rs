use revayat_scientific::{ci_tools as c, render};
use std::{fs, path::Path, process::Command};
fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}
fn legacy() -> String {
    "name: CI\non: workflow_dispatch\njobs:\n  security:\n    uses: $/.github/workflows/security-ci.yml\n  codeql:\n    uses: $/.github/workflows/codeql.yml\n  dependency-review:\n    uses: $/.github/workflows/dependency-review.yml\n    with:\n      base_ref: ${{ inputs.base_ref }}\n".into()
}
#[test]
fn test_only_three_literal_job_references_change_in_memory() {
    let original = legacy();
    let translated = c::actionlint_source(".github/workflows/ci.yml", &original).unwrap();
    assert_eq!(original.len(), translated.len());
    assert_eq!(
        original
            .bytes()
            .zip(translated.bytes())
            .filter(|(a, b)| a != b)
            .collect::<Vec<_>>(),
        vec![(b'$', b'.'); 3]
    );
    assert!(translated.contains("base_ref: ${{ inputs.base_ref }}"));
    let crlf = original.replace('\n', "\r\n");
    assert_eq!(
        c::actionlint_source(".github/workflows/ci.yml", &crlf).unwrap(),
        translated.replace('\n', "\r\n")
    );
}
#[test]
fn test_unsupported_references_never_disappear_from_validation() {
    let original = legacy();
    for altered in [
        original.replace("security-ci.yml", "security-ci.yml@main"),
        original.replace("  security:\n", "  other:\n"),
        original.replace("security-ci.yml", "missing.yml"),
        format!("{original}\n# unsupported $/ syntax\n"),
    ] {
        assert!(c::actionlint_source(".github/workflows/ci.yml", &altered).is_err());
    }
    assert!(c::actionlint_source(".github/workflows/codeql.yml", &original).is_err());
    let ordinary = "name: plain\non: workflow_dispatch\njobs: {}\n";
    assert_eq!(
        c::actionlint_source(".github/workflows/codeql.yml", ordinary).unwrap(),
        ordinary
    );
}
#[test]
fn test_windows_browser_selection_uses_paired_managed_binary() {
    let scratch = root().join(".scratch");
    fs::create_dir_all(&scratch).unwrap();
    let temp = tempfile::tempdir_in(scratch).unwrap();
    let present = temp.path().join(if cfg!(windows) {
        "chromium.exe"
    } else {
        "chromium"
    });
    fs::write(&present, b"synthetic managed path").unwrap();
    assert_eq!(
        render::discover_browser(Some(present.to_str().unwrap())).unwrap(),
        present
    );
    let missing = temp.path().join("missing-chromium");
    assert!(render::discover_browser(Some(missing.to_str().unwrap())).is_err());
    let source = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    assert!(source.contains("windows-latest"));
    assert!(source.contains("--include-ignored"));
    assert!(!source.contains("playwright"));
}
#[test]
fn test_actual_callee_contract_still_rejects_missing_input() {
    let source = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    c::validate_workflow_contract(root(), ".github/workflows/ci.yml", &source).unwrap();
    let altered = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("base_ref: ${{"))
        .collect::<Vec<_>>()
        .join("\n");
    let error = c::validate_workflow_contract(root(), ".github/workflows/ci.yml", &altered)
        .unwrap_err()
        .to_string();
    assert!(error.contains("base_ref") && error.contains("required"));
}
#[test]
#[ignore = "requires the actual pinned actionlint binary; scientific and quality CI execute this regression"]
fn test_original_filename_and_failed_linter_exit_are_preserved() {
    let fixture = tempfile::tempdir_in(root().join(".scratch")).unwrap();
    fs::create_dir_all(fixture.path().join(".github/workflows")).unwrap();
    fs::write(fixture.path().join(".github/workflows/broken.yml"),"name: broken\non: workflow_dispatch\njobs:\n  fail:\n    runs-on: nonexistent-runner\n    steps:\n      - run: echo broken\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .arg("check-workflows")
        .env("REVAYAT_REPOSITORY", fixture.path())
        .current_dir(fixture.path())
        .output()
        .expect("actual pinned actionlint is required");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains(".github/workflows/broken.yml"));
}

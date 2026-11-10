use revayat_scientific::{
    ci_tools as c, render,
    runtime::{self, CommandSpec},
};
use std::{fs, path::Path, time::Duration};

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
    for target in ["security-ci", "codeql", "dependency-review"] {
        assert!(translated.contains(&format!("uses: ./.github/workflows/{target}.yml")));
    }
    assert!(translated.contains("base_ref: ${{ inputs.base_ref }}"));
    assert!(original.contains("uses: $/.github/workflows/security-ci.yml"));
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
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().canonicalize().unwrap();
    let present = directory.join(format!("browser-protocol{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &present).unwrap();
    assert_eq!(
        render::discover_browser(Some(present.to_str().unwrap())).unwrap(),
        present
    );
    let missing = directory.join("missing-chromium");
    assert!(render::discover_browser(Some(missing.to_str().unwrap())).is_err());
    let early = directory.join(format!("browser-early{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &early).unwrap();
    let environment = directory.join("github-env");
    for (selected, exists) in [(&present, true), (&missing, false), (&early, false)] {
        let mut spec = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"))
            .args(["check-workflows", "select-browser"]);
        spec.cwd = Some(directory.clone());
        spec.timeout = Duration::from_secs(30);
        spec.max_output = 1024 * 1024;
        spec.env
            .insert("REVAYAT_BROWSER".into(), selected.as_os_str().to_owned());
        spec.env
            .insert("GITHUB_ENV".into(), environment.as_os_str().to_owned());
        spec.env
            .insert("RUNNER_TEMP".into(), directory.as_os_str().to_owned());
        fs::write(&environment, b"previous=value\n").unwrap();
        let result = runtime::run(&spec).unwrap();
        assert_eq!(result.success(), exists, "{}", result.stderr_text());
        let expected = if exists {
            format!("previous=value\nREVAYAT_BROWSER={}\n", present.display())
        } else {
            "previous=value\n".into()
        };
        assert_eq!(fs::read_to_string(&environment).unwrap(), expected);
    }
    let source = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    assert!(source.contains("windows-latest"));
    assert!(source.contains("--tier scientific --profile debug --ignored"));
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
#[ignore = "requires actual actionlint; equipped CI runs this missing-input proof"]
fn equipped_actionlint_rejects_missing_callee_input() {
    let source = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    let altered = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("base_ref: ${{"))
        .collect::<Vec<_>>()
        .join("\n");
    let output = c::lint_one(root(), ".github/workflows/ci.yml", &altered).unwrap();
    assert!(!output.success());
    assert!(
        format!("{}{}", output.stdout_text(), output.stderr_text())
            .contains("input \"base_ref\" is required")
    );
}
#[test]
#[ignore = "requires the actual pinned actionlint binary; scientific and quality CI execute this regression"]
fn test_original_filename_and_failed_linter_exit_are_preserved() {
    let result = c::lint_one_with(
        root(),
        ".github/workflows/ci.yml",
        &legacy(),
        |spec, input| {
            assert_eq!(spec.program, "actionlint");
            assert_eq!(
                spec.args,
                ["-stdin-filename", ".github/workflows/ci.yml", "-"].map(std::ffi::OsString::from)
            );
            assert_eq!(spec.cwd.as_deref(), Some(root()));
            assert_eq!(spec.timeout, Duration::from_secs(30));
            assert!(
                std::str::from_utf8(input)
                    .unwrap()
                    .contains("uses: ./.github/workflows/security-ci.yml")
            );
            Ok(runtime::CommandOutput {
                code: 7,
                stdout: vec![],
                stderr: vec![],
            })
        },
    )
    .unwrap();
    assert_eq!(result.code, 7);
    let fixture = tempfile::tempdir().unwrap();
    fs::create_dir_all(fixture.path().join(".github/workflows")).unwrap();
    fs::write(fixture.path().join(".github/workflows/broken.yml"),"name: broken\non: workflow_dispatch\njobs:\n  fail:\n    runs-on: nonexistent-runner\n    steps:\n      - run: cargo --version\n").unwrap();
    let mut spec =
        CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args(["check-workflows"]);
    spec.cwd = Some(fixture.path().to_owned());
    spec.timeout = Duration::from_secs(45);
    spec.max_output = 1024 * 1024;
    spec.env.insert(
        "REVAYAT_REPOSITORY".into(),
        fixture.path().as_os_str().to_owned(),
    );
    let output = runtime::run(&spec).expect("actual pinned actionlint is required");
    assert_eq!(output.code, 1);
    assert!(String::from_utf8_lossy(&output.stdout).contains(".github/workflows/broken.yml"));
}

use revayat_scientific::migration::execution::{
    BinaryExecution, CollectedExecution, parse_test_artifacts, validate_report,
    validate_report_matrix, validate_runner_args, write_execution_report,
};
use revayat_scientific::migration::{CaseOutcome, parse_test_execution};
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;

fn expected() -> BTreeSet<String> {
    BTreeSet::from(["case::one".into(), "case::two".into()])
}

#[test]
fn execution_requires_actual_named_results_and_complete_summary() {
    let text = "running 2 tests\ntest case::one ... ok\ntest case::two ... ignored, needs tool\n\ntest result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n";
    let result = parse_test_execution(text.as_bytes(), 0, &expected()).unwrap();
    assert_eq!(result["case::one"], CaseOutcome::Passed);
    assert_eq!(result["case::two"], CaseOutcome::Skipped);
    assert!(parse_test_execution(b"case::one: test\ncase::two: test\n", 0, &expected()).is_err());
}

#[test]
fn zero_exit_does_not_excuse_missing_duplicate_filtered_or_contradictory_results() {
    let valid = "running 2 tests\ntest case::one ... ok\ntest case::two ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n";
    for text in [
        valid.replace("test case::two ... ok\n", ""),
        valid.replace("test case::two ... ok", "test case::one ... ok"),
        valid.replace("0 filtered out", "1 filtered out"),
        valid.replace("2 passed", "1 passed"),
        valid.replace("case::two ... ok", "unknown ... ok"),
        valid.replace("test result: ok.", "test result: FAILED."),
    ] {
        assert!(parse_test_execution(text.as_bytes(), 0, &expected()).is_err());
    }
    assert!(parse_test_execution(valid.as_bytes(), 1, &expected()).is_err());
}

#[test]
fn should_panic_decoration_is_not_part_of_the_registered_identity() {
    let text = "running 2 tests\ntest case::one - should panic ... ok\ntest case::two ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n";
    assert_eq!(
        parse_test_execution(text.as_bytes(), 0, &expected()).unwrap()["case::one"],
        CaseOutcome::Passed
    );
    assert!(
        parse_test_execution(
            text.replace("running 2 tests", "running 1 test").as_bytes(),
            0,
            &expected()
        )
        .is_err()
    );
    assert!(
        parse_test_execution(
            text.replace("test result: ok.", "test result: ok.\ntest result: ok.")
                .as_bytes(),
            0,
            &expected()
        )
        .is_err()
    );
}

#[test]
fn failed_case_is_preserved_and_never_upgraded_by_a_success_summary() {
    let text = "running 2 tests\ntest case::one ... ok\ntest case::two ... FAILED\nfailures:\n    case::two\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n";
    let result = parse_test_execution(text.as_bytes(), 101, &expected()).unwrap();
    assert_eq!(result["case::two"], CaseOutcome::Failed);
    assert!(parse_test_execution(text.as_bytes(), 0, &expected()).is_err());
}

fn native_windows_cases() -> BinaryExecution {
    BinaryExecution {
        target: "crates/revayat-scientific/test/windows_standalone".into(),
        mapping_target: Some("windows_standalone".into()),
        exit: Some(0),
        cleanup_complete: true,
        error: None,
        cases: [
            "native_opc_consumer_recognizes_case_variant_relationship_part",
            "junction_destination_admission_preserves_owned_controls",
            "junction_publication_refuses_and_preserves_stage_and_sentinels",
            "ordinary_publication_commits_exact_bytes",
            "public_build_junction_refusal_precedes_lint_and_renderer",
        ]
        .into_iter()
        .map(|name| (name.into(), CaseOutcome::Passed))
        .collect(),
    }
}

fn report() -> CollectedExecution {
    CollectedExecution {
        schema: 1,
        tested_sha: "0123456789abcdef0123456789abcdef01234567".into(),
        run_id: "42".into(),
        run_attempt: "1".into(),
        repository: "example/project".into(),
        workflow_ref: "example/project/.github/workflows/ci.yml@refs/heads/main".into(),
        job: "portable".into(),
        platform: "linux".into(),
        tier: "portable".into(),
        profile: "debug".into(),
        ignored_only: false,
        final_parity_verified: false,
        error: None,
        discovery_exit: None,
        binaries: vec![BinaryExecution {
            target: "crates/revayat-scientific/test/suite".into(),
            mapping_target: Some("suite".into()),
            exit: Some(0),
            cleanup_complete: true,
            cases: [("one".into(), CaseOutcome::Passed)].into(),
            error: None,
        }, BinaryExecution {
            target: "crates/revayat-scientific/bin/license-notices".into(),
            mapping_target: None, exit: Some(0), cleanup_complete: true, error: None,
            cases: [
                "expression_tests::all_observed_locked_expressions_include_the_exact_constant_time_eq_terms",
                "expression_tests::compound_admission_keeps_every_shipped_notice_and_declared_expression",
                "dedup::tests::shared_bodies_expand_to_every_original_byte_and_attribution",
                "dedup::tests::retained_budget_checks_boundaries_overflow_and_duplicate_occurrences_before_mutation",
                "dedup::tests::stale_hash_or_same_hash_with_different_bytes_fails_before_reference",
            ].into_iter().map(|name| (name.into(), CaseOutcome::Passed)).collect(),
        }],
    }
}

#[test]
fn cargo_json_keeps_package_and_target_kinds_distinct_and_ignores_nonharness_bins() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let package = root.join("crates/revayat-scientific");
    fs::create_dir_all(&package).unwrap();
    fs::create_dir_all(root.join("target/debug/deps")).unwrap();
    fs::write(package.join("Cargo.toml"), "[package]").unwrap();
    let mut messages = Vec::new();
    for (index, kind) in ["lib", "bin", "test"].into_iter().enumerate() {
        let executable = root.join(format!("target/debug/deps/harness-{index}"));
        fs::write(&executable, b"fixture, never executed").unwrap();
        messages.push(json!({"reason":"compiler-artifact", "profile":{"test":true},
            "manifest_path":package.join("Cargo.toml"), "target":{"name":"same", "kind":[kind]}, "executable":executable}));
    }
    messages.push(json!({"reason":"compiler-artifact", "profile":{"test":false},
        "target":{"name":"revayat-test-runner", "kind":["bin"]}, "executable":"untrusted-normal-bin"}));
    let encoded = |values: &[serde_json::Value]| {
        values
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    };
    let parsed =
        parse_test_artifacts(&root, &root.join("target"), &encoded(&messages), "debug").unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(
        parsed
            .iter()
            .filter(|value| value.mapping_target.as_deref() == Some("same"))
            .count(),
        1
    );
    messages[0]["executable"] = json!(package.join("Cargo.toml"));
    assert!(
        parse_test_artifacts(&root, &root.join("target"), &encoded(&messages), "debug").is_err()
    );
    messages[0]["executable"] = json!(root.join("target/debug/deps/harness-0"));
    let foreign = tempfile::tempdir().unwrap();
    fs::write(foreign.path().join("Cargo.toml"), "[package]").unwrap();
    messages[0]["manifest_path"] = json!(foreign.path().join("Cargo.toml"));
    assert!(
        parse_test_artifacts(&root, &root.join("target"), &encoded(&messages), "debug").is_err()
    );
    assert!(parse_test_artifacts(&root, &root.join("target"), b"not JSON", "debug").is_err());
}

#[test]
fn foreign_incomplete_and_wrong_tier_reports_cannot_be_reconciled() {
    let original = report();
    let identity = (
        original.tested_sha.as_str(),
        "42",
        "1",
        "portable",
        "linux",
        "debug",
    );
    assert!(validate_report(&original, identity).is_ok());
    for field in [
        "tested_sha",
        "run_id",
        "run_attempt",
        "job",
        "platform",
        "tier",
        "profile",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = json!("foreign");
        let altered = serde_json::from_value(value).unwrap();
        assert!(validate_report(&altered, identity).is_err(), "{field}");
    }
    let mut value = serde_json::to_value(&original).unwrap();
    value["error"] = json!("Cargo discovery incomplete");
    assert!(validate_report(&serde_json::from_value(value).unwrap(), identity).is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value["binaries"] = json!([]);
    assert!(validate_report(&serde_json::from_value(value).unwrap(), identity).is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value["binaries"][0]["cleanup_complete"] = json!(false);
    assert!(validate_report(&serde_json::from_value(value).unwrap(), identity).is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value["ignored_only"] = json!(true);
    assert!(validate_report(&serde_json::from_value(value).unwrap(), identity).is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    let duplicate = value["binaries"][0].clone();
    value["binaries"].as_array_mut().unwrap().push(duplicate);
    assert!(validate_report(&serde_json::from_value(value).unwrap(), identity).is_err());
}

#[test]
fn failed_execution_report_retains_cases_and_exit_even_if_publication_fails() {
    use revayat_scientific::migration::execution::discovery_failure_summary;
    let private = anyhow::anyhow!("private /manuscript/path secret payload")
        .context("Cargo artifact selection failed");
    assert_eq!(
        discovery_failure_summary(&private),
        "stage=artifact-selection"
    );
    for (cause, expected) in [
        (
            "owned runtime operation failed (operation-group-cleanup-os-1)",
            "stage=cargo-run runtime=group-cleanup os_error=1",
        ),
        (
            "owned runtime operation failed (operation-unknown)",
            "stage=cargo-run runtime=unknown",
        ),
        (
            "owned runtime operation failed (operation-group-cleanup-os-private)",
            "stage=cargo-run",
        ),
        (
            "ownership protocol deadline exceeded",
            "stage=cargo-run runtime=transport-deadline",
        ),
        (
            "tool diagnostics exceeded 16777216 byte limit",
            "stage=cargo-run runtime=output-limit limit=16777216",
        ),
        (
            "tool diagnostics exceeded private-sentinel byte limit",
            "stage=cargo-run",
        ),
    ] {
        assert_eq!(
            discovery_failure_summary(
                &anyhow::anyhow!(cause).context("bounded test artifact discovery failed")
            ),
            expected
        );
    }
    let cleanup = anyhow::anyhow!("private /manuscript/path secret payload")
        .context("owned runtime operation failed (operation-group-cleanup-os-3)");
    let cleanup = anyhow::Error::new(revayat_scientific::runtime::CleanupFailure(cleanup));
    let summary = discovery_failure_summary(&cleanup);
    assert!(summary.contains("cleanup_uncertain=true"));
    assert!(summary.contains("cleanup_detail=[stage=unknown runtime=group-cleanup os_error=3]"));
    assert!(!summary.contains("manuscript"));
    assert!(!summary.contains("secret payload"));
    let mut nested = cleanup;
    for _ in 0..8 {
        nested = anyhow::Error::new(revayat_scientific::runtime::CleanupFailure(nested));
    }
    assert_eq!(
        discovery_failure_summary(&nested)
            .matches("cleanup_detail=[")
            .count(),
        3
    );
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("results.json");
    let mut failed = report();
    failed.binaries[0].exit = Some(101);
    failed.binaries[0]
        .cases
        .insert("one".into(), CaseOutcome::Failed);
    let mut discovery_failed = report();
    discovery_failed.binaries.clear();
    discovery_failed.error = Some("Cargo discovery incomplete".into());
    discovery_failed.discovery_exit = Some(101);
    let discovery_path = temp.path().join("discovery-failure.json");
    assert!(
        write_execution_report(&discovery_path, &discovery_failed)
            .unwrap_err()
            .to_string()
            .contains("test_exit=101")
    );
    let saved: CollectedExecution =
        serde_json::from_slice(&fs::read(discovery_path).unwrap()).unwrap();
    assert!(saved.error.is_some() && saved.binaries.is_empty());
    let error = write_execution_report(&path, &failed).unwrap_err();
    assert!(error.to_string().contains("test_exit=101"));
    let saved: CollectedExecution = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved.binaries[0].exit, Some(101));
    assert_eq!(saved.binaries[0].cases["one"], CaseOutcome::Failed);
    fs::write(&path, b"retain original report").unwrap();
    assert!(
        write_execution_report(&path, &failed)
            .unwrap_err()
            .to_string()
            .contains("test_exit=101")
    );
    assert_eq!(fs::read(path).unwrap(), b"retain original report");
    let artifact = revayat_scientific::migration::execution::Artifact {
        target: "test/suite".into(),
        mapping_target: Some("suite".into()),
        executable: temp.path().join("never-executed"),
        directory: temp.path().into(),
    };
    let executed = revayat_scientific::runtime::CommandOutput {
        code: 101, stdout: b"running 2 tests\ntest case::one ... ok\ntest case::two ... FAILED\nPRIVATE_TEST_CANARY\n".to_vec(),
        stderr: b"PRIVATE_TEST_CANARY".to_vec(),
    };
    let recorded = revayat_scientific::migration::execution::record_execution(
        &artifact,
        &executed,
        &expected(),
        0,
    );
    assert_eq!(recorded.exit, Some(101));
    assert_eq!(recorded.cases["case::two"], CaseOutcome::Failed);
    assert!(recorded.error.is_some());
    assert!(
        !serde_json::to_string(&recorded)
            .unwrap()
            .contains("PRIVATE_TEST_CANARY")
    );
}

#[test]
fn execution_and_reconciliation_cli_modes_are_exclusive_before_any_process() {
    let args = |values: &[&str]| {
        values
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>()
    };
    assert!(
        validate_runner_args(&args(&[
            "--tier",
            "portable",
            "--profile",
            "debug",
            "--output",
            "out.json"
        ]))
        .is_ok()
    );
    assert!(
        validate_runner_args(&args(&[
            "--reconcile",
            "--profile",
            "debug",
            "--ledger",
            "ledger.json",
            "--report",
            "report.json"
        ]))
        .is_ok()
    );
    assert!(
        validate_runner_args(&args(&[
            "--aggregate",
            "--ledger",
            "ledger.json",
            "--report",
            "report.json"
        ]))
        .is_ok()
    );
    assert!(
        validate_runner_args(&args(&[
            "--tier",
            "portable",
            "--profile",
            "release",
            "--output",
            "out.json"
        ]))
        .is_ok()
    );
    assert!(
        validate_runner_args(&args(&[
            "--aggregate",
            "--census",
            "verifier",
            "--ledger",
            "tests/behavior/verifier.json",
            "--report",
            "report.json",
        ]))
        .is_ok()
    );
    assert!(
        validate_runner_args(&args(&[
            "--aggregate",
            "--census",
            "invented-population",
            "--ledger",
            "ledger.json",
            "--report",
            "report.json",
        ]))
        .is_err()
    );
    for values in [
        vec![],
        vec!["--tier", "portable", "--output", "a"],
        vec![
            "--aggregate",
            "--profile",
            "debug",
            "--ledger",
            "a",
            "--report",
            "b",
        ],
        vec![
            "--reconcile",
            "--profile",
            "debug",
            "--ledger",
            "a",
            "--ledger",
            "b",
            "--report",
            "c",
        ],
        vec![
            "--tier",
            "portable",
            "--profile",
            "debug",
            "--output",
            "a",
            "--timeout",
            "0",
        ],
        vec!["--tier", "portable"],
        vec!["--reconcile"],
        vec![
            "--reconcile",
            "--ledger",
            "a",
            "--report",
            "b",
            "--tier",
            "portable",
        ],
        vec!["--tier", "portable", "--output", "a", "--timeout", "0"],
    ] {
        assert!(validate_runner_args(&args(&values)).is_err());
    }
}

#[test]
fn debug_artifacts_and_reports_cannot_be_reused_as_release_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir_all(root.join("target/debug/deps")).unwrap();
    fs::create_dir_all(root.join("target/release/deps")).unwrap();
    fs::write(root.join("Cargo.toml"), "[package]").unwrap();
    let message = |profile: &str| {
        let executable = root.join(format!("target/{profile}/deps/harness"));
        fs::write(&executable, b"fixture, never executed").unwrap();
        json!({"reason":"compiler-artifact","profile":{"test":true},
            "manifest_path":root.join("Cargo.toml"),"target":{"name":"suite","kind":["test"]},
            "executable":executable})
        .to_string()
        .into_bytes()
    };
    let debug = message("debug");
    let release = message("release");
    // Cargo 1.100 moves test executables while profile-level binaries stay put.
    for profile in ["debug", "release"] {
        let executable = root.join(format!(
            "target/{profile}/build/revayat-scientific/0123456789abcdef/out/harness-0123456789abcdef"
        ));
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"fixture, never executed").unwrap();
        assert_eq!(
            revayat_scientific::executable_paths::binary_directory(&executable).unwrap(),
            root.join(format!("target/{profile}"))
        );
        let bytes = json!({"reason":"compiler-artifact","profile":{"test":true},
            "manifest_path":root.join("Cargo.toml"),"target":{"name":"suite","kind":["test"]},
            "executable":executable})
        .to_string()
        .into_bytes();
        assert!(parse_test_artifacts(&root, &root.join("target"), &bytes, profile).is_ok());
        let other = if profile == "debug" {
            "release"
        } else {
            "debug"
        };
        assert!(parse_test_artifacts(&root, &root.join("target"), &bytes, other).is_err());
    }
    // A fixed shape is required: arbitrary deeper descendants and malformed hashes
    // never become evidence for this profile or a route to its companion binaries.
    for relative in [
        "debug/build/pkg/not-a-cargo-hash/out/harness",
        "debug/build/pkg/0123456789ABCDEF/out/harness",
        "debug/build/pkg/0123456789abcdef/other/harness",
        "nested/extra/debug/build/pkg/0123456789abcdef/out/harness",
        "debug/arbitrary/harness",
    ] {
        let executable = root.join("target").join(relative);
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"fixture, never executed").unwrap();
        let bytes = json!({"reason":"compiler-artifact","profile":{"test":true},
            "manifest_path":root.join("Cargo.toml"),"target":{"name":"suite","kind":["test"]},
            "executable":executable})
        .to_string()
        .into_bytes();
        assert!(parse_test_artifacts(&root, &root.join("target"), &bytes, "debug").is_err());
    }
    let installed = root.join("installed/out/revayat-scientific");
    assert_eq!(
        revayat_scientific::executable_paths::binary_directory(&installed).unwrap(),
        installed.parent().unwrap()
    );
    for binary in [
        "revayat-scientific",
        "revayat-process-owner",
        "registry-authority.exe",
        "revayat-quota-worker.exe",
    ] {
        let installed = root
            .join("installed/debug/build/pkg/0123456789abcdef/out")
            .join(binary);
        assert_eq!(
            revayat_scientific::executable_paths::binary_directory(&installed).unwrap(),
            installed.parent().unwrap()
        );
    }
    assert!(
        revayat_scientific::executable_paths::binary_directory(std::path::Path::new(
            "relative/tool"
        ))
        .is_err()
    );
    for (bytes, profile) in [(&debug, "debug"), (&release, "release")] {
        assert!(parse_test_artifacts(&root, &root.join("target"), bytes, profile).is_ok());
    }
    assert!(parse_test_artifacts(&root, &root.join("target"), &debug, "release").is_err());
    assert!(parse_test_artifacts(&root, &root.join("target"), &release, "debug").is_err());
    assert!(
        validate_report(
            &report(),
            (
                "0123456789abcdef0123456789abcdef01234567",
                "42",
                "1",
                "portable",
                "linux",
                "release"
            )
        )
        .is_err()
    );
}

#[test]
fn every_required_os_profile_and_native_slot_is_mandatory() {
    let mut reports = Vec::new();
    for platform in ["linux", "macos", "windows"] {
        for profile in ["debug", "release"] {
            let mut value = report();
            value.platform = platform.into();
            value.profile = profile.into();
            reports.push(value);
        }
    }
    for (tier, platform, job) in [
        ("scientific", "linux", "scientific"),
        ("scientific", "macos", "portable"),
        ("scientific", "windows", "portable"),
        ("native", "linux", "linux-security"),
        ("native", "windows", "windows-security"),
    ] {
        let mut value = report();
        value.tier = tier.into();
        value.platform = platform.into();
        value.job = job.into();
        value.ignored_only = true;
        if tier == "native" && platform == "windows" {
            value.binaries.push(native_windows_cases());
        }
        reports.push(value);
    }
    let identity = (
        "0123456789abcdef0123456789abcdef01234567",
        "42",
        "1",
        "example/project",
        "example/project/.github/workflows/ci.yml@refs/heads/main",
    );
    assert!(validate_report_matrix(&reports, identity).is_ok());
    let ledger = |tier: &str, platforms: Vec<&str>| {
        serde_json::from_value::<revayat_scientific::migration::BehaviorLedger>(json!({
            "schema":1,"baseline_commit":"0123456789abcdef0123456789abcdef01234567",
            "identities":[],"obligations":[{"id":"scope","baseline_ids":["source"],
            "rust_test":"suite::one","assertions":["scope must execute"],
            "tier":tier,"platforms":platforms}]
        }))
        .unwrap()
    };
    for (tier, platforms) in [
        ("portable", vec![]),
        ("scientific", vec![]),
        ("native", vec!["linux", "windows"]),
    ] {
        assert!(
            revayat_scientific::migration::execution::validate_obligation_scopes(&ledger(
                tier, platforms
            ))
            .is_ok()
        );
    }
    for (tier, platforms) in [
        ("scientific", vec!["unsupported-os"]),
        ("unknown-tier", vec!["linux"]),
        ("native", vec!["macos"]),
    ] {
        assert!(validate_report_matrix(&reports, identity).is_ok());
        assert!(
            revayat_scientific::migration::execution::validate_obligation_scopes(&ledger(
                tier, platforms
            ))
            .is_err()
        );
    }
    for index in 0..reports.len() {
        let mut altered: Vec<CollectedExecution> =
            serde_json::from_value(serde_json::to_value(&reports).unwrap()).unwrap();
        altered.remove(index);
        assert!(validate_report_matrix(&altered, identity).is_err());
    }
    for field in [
        "run_attempt",
        "profile",
        "job",
        "repository",
        "workflow_ref",
    ] {
        let mut encoded = serde_json::to_value(&reports).unwrap();
        encoded[8][field] = json!("foreign");
        assert!(
            validate_report_matrix(
                &serde_json::from_value::<Vec<_>>(encoded).unwrap(),
                identity
            )
            .is_err()
        );
    }
    let duplicate = serde_json::from_value(serde_json::to_value(&reports[0]).unwrap()).unwrap();
    reports.push(duplicate);
    assert!(validate_report_matrix(&reports, identity).is_err());
}

#[test]
fn portable_notice_regressions_cannot_disappear_skip_or_fail_with_zero_harness_exit() {
    let original = report();
    let identity = (
        original.tested_sha.as_str(),
        "42",
        "1",
        "portable",
        "linux",
        "debug",
    );
    assert!(validate_report(&original, identity).is_ok());
    let mut variants = Vec::new();
    let copy = || {
        serde_json::from_value::<CollectedExecution>(serde_json::to_value(&original).unwrap())
            .unwrap()
    };
    let mut missing_harness = copy();
    missing_harness.binaries.pop();
    variants.push(missing_harness);
    for case in original.binaries[1].cases.keys() {
        let mut missing = copy();
        missing.binaries[1].cases.remove(case);
        variants.push(missing);
        for outcome in [CaseOutcome::Skipped, CaseOutcome::Failed] {
            let mut not_passed = copy();
            not_passed.binaries[1].cases.insert(case.clone(), outcome);
            variants.push(not_passed);
        }
    }
    let root = tempfile::tempdir().unwrap();
    for (index, invalid) in variants.iter().enumerate() {
        assert!(validate_report(invalid, identity).is_err());
        let path = root.path().join(format!("notice-floor-{index}.json"));
        assert!(write_execution_report(&path, invalid).is_err());
        let saved: CollectedExecution = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(saved.binaries.len(), invalid.binaries.len());
        assert!(!saved.final_parity_verified);
    }
}

#[test]
fn native_windows_standalone_cases_require_every_actual_pass() {
    let mut native = report();
    native.tier = "native".into();
    native.platform = "windows".into();
    native.job = "windows-security".into();
    native.ignored_only = true;
    let names: Vec<_> = native_windows_cases().cases.into_keys().collect();
    let identity = (
        native.tested_sha.clone(),
        "42",
        "1",
        "windows-security",
        "windows",
        "debug",
    );
    let check = |value: &CollectedExecution| {
        validate_report(
            value,
            (
                &identity.0,
                identity.1,
                identity.2,
                identity.3,
                identity.4,
                identity.5,
            ),
        )
    };
    assert!(check(&native).is_err());
    native.binaries.push(native_windows_cases());
    assert!(check(&native).is_ok()); // Necessary case floor, not native qualification or 53-stage proof.
    let original = serde_json::to_value(&native).unwrap();
    let root = tempfile::tempdir().unwrap();
    for (index, name) in names.into_iter().enumerate() {
        for outcome in [None, Some(CaseOutcome::Skipped), Some(CaseOutcome::Failed)] {
            let mut value: CollectedExecution = serde_json::from_value(original.clone()).unwrap();
            let cases = &mut value.binaries.last_mut().unwrap().cases;
            if let Some(outcome) = outcome {
                cases.insert(name.clone(), outcome);
            } else {
                cases.remove(&name);
            }
            assert!(check(&value).is_err());
            let path = root.path().join(format!("native-{index}-{outcome:?}.json"));
            assert!(write_execution_report(&path, &value).is_err());
            assert!(path.is_file());
        }
    }
}

#[test]
fn harness_header_summary_and_utf8_are_required_even_for_an_empty_binary() {
    let empty = BTreeSet::new();
    let text = b"running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
    assert!(parse_test_execution(text, 0, &empty).unwrap().is_empty());
    assert!(parse_test_execution(b"", 0, &empty).is_err());
    assert!(parse_test_execution(b"\xff", 0, &empty).is_err());
    assert!(parse_test_execution(b"running 1 test\n", 0, &expected()).is_err());
}

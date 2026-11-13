//! Synthetic inputs test the boundary, never attest to actual operation execution.
use super::*;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, CollectedExecution, serde_json::Value) {
    fixture_for(&ORACLE)
}
fn fixture_for(config: &Config) -> (tempfile::TempDir, CollectedExecution, serde_json::Value) {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tests")).unwrap();
    let rows: Vec<_> = (1..=config.count)
        .map(|i| format!("synthetic-{}::{i}", config.population))
        .collect();
    let entries: Vec<_> = rows
        .iter()
        .enumerate()
        .map(|(i, id)| {
            json!({
                "id": id, "parent_id": config.owner, "invokes_ids": [],
                "obligation_ids": [format!("SYNTHETIC-{}", i + 1)], "variant_ids": [], "checks": []
            })
        })
        .collect();
    let scope =
        json!({"platform":"linux", "tier":"scientific", "profile":"debug", "job":"scientific"});
    fs::write(root.path().join(config.census), serde_json::to_vec(&json!({
        "schema": 1, "baseline_commit": "b".repeat(40), (config.key): rows.iter().map(|id| json!({"id":id})).collect::<Vec<_>>(),
        "execution_contract": {"entries": entries, "scopes": [{"scope":scope, "owner_case_id":config.owner, "entry_ids":rows}]}
    })).unwrap()).unwrap();
    let binary = BinaryExecution {
        target: config.target.into(),
        mapping_target: None,
        exit: Some(0),
        cleanup_complete: true,
        error: None,
        cases: [(config.case.into(), CaseOutcome::Passed)].into(),
    };
    let identity = CollectedExecution {
        schema: 1,
        tested_sha: "a".repeat(40),
        run_id: "42".into(),
        run_attempt: "1".into(),
        repository: "example/project".into(),
        workflow_ref: "example/workflow".into(),
        platform: "linux".into(),
        tier: "scientific".into(),
        profile: "debug".into(),
        job: "scientific".into(),
        ignored_only: true,
        error: None,
        discovery_exit: None,
        final_parity_verified: false,
        binaries: vec![binary],
    };
    let raw = json!({"schema":1, "population":config.population, "owner_case_id":config.owner,
        "events": (1..=config.count).map(|i| json!({
            "case_id":format!("synthetic-{}::{i}", config.population), "parent_id":config.owner, "sequence":i,
            "invokes_ids":[], "obligation_ids":[format!("SYNTHETIC-{i}")], "source":"execution",
            "outcome":"passed", "exit":0, "cleanup_complete":false, "assertions_complete":true,
            "variants":[], "check_results":[]
        })).collect::<Vec<_>>()});
    (root, identity, raw)
}
fn captured(raw: &serde_json::Value) -> OracleCapture {
    let capture = OracleCapture(tempfile::tempdir().unwrap());
    fs::write(
        capture.0.path().join("oracle-observations.json"),
        serde_json::to_vec(raw).unwrap(),
    )
    .unwrap();
    capture
}
fn captured_for(raw: &serde_json::Value, config: &'static Config) -> Capture {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join(config.journal),
        serde_json::to_vec(raw).unwrap(),
    )
    .unwrap();
    Capture { directory, config }
}

#[test]
fn complete_raw_rows_bind_to_outer_identity_and_publish_without_overwrite() {
    let (root, identity, raw) = fixture();
    let capture = captured(&raw);
    let private = capture.0.path().to_owned();
    let report = capture
        .finish(root.path(), &identity, &identity.binaries[0])
        .unwrap();
    assert!(!private.exists());
    assert!(report.events.iter().all(|event| event.cleanup_complete));
    assert_eq!(report.tested_sha, identity.tested_sha);
    assert_eq!(report.run_id, identity.run_id);
    let output = root.path().join("execution/portable-debug.json");
    publish(
        root.path(),
        &output,
        &identity,
        std::slice::from_ref(&report),
    )
    .unwrap();
    let destination = root.path().join("execution/oracle-debug.json");
    let original = fs::read(&destination).unwrap();
    assert!(publish(root.path(), &output, &identity, &[report]).is_err());
    assert_eq!(fs::read(destination).unwrap(), original);
    assert!(publish(root.path(), &output, &identity, &[]).is_err());
    let valid = captured(&raw)
        .finish(root.path(), &identity, &identity.binaries[0])
        .unwrap();
    for field in [
        "tested_sha",
        "run_id",
        "run_attempt",
        "census_sha256",
        "baseline_commit",
    ] {
        let mut value = serde_json::to_value(&valid).unwrap();
        value[field] = "foreign".into();
        let foreign: events::OperationReport = serde_json::from_value(value).unwrap();
        let different_output = root.path().join(field).join("portable-debug.json");
        assert!(
            publish(root.path(), &different_output, &identity, &[foreign]).is_err(),
            "{field}"
        );
        assert!(
            !different_output
                .parent()
                .unwrap()
                .join("oracle-debug.json")
                .exists()
        );
    }
    // Exercise the same outer-owner boundary and all-or-missing publication
    // for the two additional authored populations without new registrations.
    let (batch_root, mut batch_identity, oracle_raw) = fixture();
    let mut batch = vec![
        captured(&oracle_raw)
            .finish(
                batch_root.path(),
                &batch_identity,
                &batch_identity.binaries[0],
            )
            .unwrap(),
    ];
    for config in [&ENGINE, &PREPARATION] {
        let (additional_root, mut additional_identity, raw) = fixture_for(config);
        fs::copy(
            additional_root.path().join(config.census),
            batch_root.path().join(config.census),
        )
        .unwrap();
        let binary = additional_identity.binaries.pop().unwrap();
        let report = captured_for(&raw, config)
            .finish(batch_root.path(), &batch_identity, &binary)
            .unwrap();
        assert_eq!(report.population, config.population);
        assert_eq!(report.events.len(), config.count);
        assert!(report.events.iter().all(|event| event.cleanup_complete));
        let mut self_certified = raw;
        self_certified["events"][0]["cleanup_complete"] = true.into();
        assert!(
            captured_for(&self_certified, config)
                .finish(batch_root.path(), &batch_identity, &binary)
                .is_err()
        );
        batch.push(report);
        batch_identity.binaries.push(binary);
    }
    let batch_output = batch_root.path().join("execution/portable-debug.json");
    assert!(
        publish_all(
            batch_root.path(),
            &batch_output,
            &batch_identity,
            &batch[..2]
        )
        .is_err()
    );
    assert!(!batch_output.parent().unwrap().exists());
    publish_all(batch_root.path(), &batch_output, &batch_identity, &batch).unwrap();
    for config in CONFIGS {
        assert!(
            batch_output
                .parent()
                .unwrap()
                .join(format!("{}-debug.json", config.population))
                .is_file()
        );
    }
}

#[test]
fn missing_foreign_partial_self_certified_and_duplicate_rows_never_finalize() {
    let (root, identity, raw) = fixture();
    assert!(
        OracleCapture(tempfile::tempdir().unwrap())
            .finish(root.path(), &identity, &identity.binaries[0])
            .is_err()
    );
    for field in ["owner_case_id", "population", "unexpected_binding"] {
        let mut changed = raw.clone();
        changed[field] = "foreign".into();
        assert!(
            captured(&changed)
                .finish(root.path(), &identity, &identity.binaries[0])
                .is_err()
        );
    }
    for field in [
        "cleanup_complete",
        "parent_id",
        "sequence",
        "source",
        "outcome",
        "assertions_complete",
        "exit",
    ] {
        let mut changed = raw.clone();
        changed["events"][0][field] = match field {
            "cleanup_complete" => true.into(),
            "assertions_complete" => false.into(),
            "sequence" => 2.into(),
            "exit" => 3.into(),
            "outcome" => "skipped".into(),
            _ => "foreign".into(),
        };
        assert!(
            captured(&changed)
                .finish(root.path(), &identity, &identity.binaries[0])
                .is_err(),
            "{field}"
        );
    }
    let mut changed = raw.clone();
    changed["events"][1]["case_id"] = changed["events"][0]["case_id"].clone();
    assert!(
        captured(&changed)
            .finish(root.path(), &identity, &identity.binaries[0])
            .is_err()
    );
    let mut changed = raw;
    changed["events"].as_array_mut().unwrap().pop();
    assert!(
        captured(&changed)
            .finish(root.path(), &identity, &identity.binaries[0])
            .is_err()
    );
}

#[test]
fn failed_carrier_cleanup_or_noncanonical_rows_block_report_publication() {
    let (root, mut identity, raw) = fixture();
    for field in ["cleanup_complete", "exit", "error", "cases"] {
        let mut value = serde_json::to_value(&identity.binaries[0]).unwrap();
        value[field] = match field {
            "cleanup_complete" => false.into(),
            "exit" => 9.into(),
            "error" => "incomplete".into(),
            _ => json!({(CASE):"skipped"}),
        };
        let binary: BinaryExecution = serde_json::from_value(value).unwrap();
        assert!(
            captured(&raw)
                .finish(root.path(), &identity, &binary)
                .is_err()
        );
    }
    let mut changed = raw;
    changed["events"][0]["obligation_ids"] = json!(["noncanonical"]);
    let report = captured(&changed)
        .finish(root.path(), &identity, &identity.binaries[0])
        .unwrap();
    let output = root.path().join("execution/portable-debug.json");
    assert!(publish(root.path(), &output, &identity, &[report]).is_err());
    assert!(!root.path().join("execution/oracle-debug.json").exists());
    identity.binaries[0].cleanup_complete = false;
    assert!(
        captured(&changed)
            .finish(root.path(), &identity, &identity.binaries[0])
            .is_err()
    );
}

#[test]
fn raw_reads_are_actual_bounded_and_routing_only_targets_the_actual_carrier() {
    let (root, _, _) = fixture();
    let path = root.path().join("oversized");
    let file = fs::File::create(&path).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(bounded(&path).is_err());
    let artifact = Artifact {
        target: TARGET.into(),
        mapping_target: None,
        executable: "never-executed".into(),
        directory: root.path().to_owned(),
    };
    assert!(
        OracleCapture::create(&artifact, "scientific")
            .unwrap()
            .is_none()
    );
    let capture = OracleCapture::create(&artifact, "portable")
        .unwrap()
        .unwrap();
    let mut spec = command(root.path(), "never-executed", Duration::from_secs(1));
    assert!(spec.env.is_empty());
    assert!(
        spec.env_remove
            .iter()
            .any(|key| key == std::ffi::OsStr::new("REVAYAT_ORACLE_EVENT_DIR"))
    );
    capture.configure(&mut spec).unwrap();
    let routed = spec
        .env
        .get(std::ffi::OsStr::new("REVAYAT_ORACLE_EVENT_DIR"))
        .unwrap();
    assert_eq!(Path::new(routed), capture.0.path().canonicalize().unwrap());
    let unrelated = Artifact {
        target: "unrelated/lib/fixture".into(),
        ..artifact
    };
    assert!(
        OracleCapture::create(&unrelated, "portable")
            .unwrap()
            .is_none()
    );
    for config in CONFIGS {
        let artifact = Artifact {
            target: config.target.into(),
            mapping_target: None,
            executable: "never-executed".into(),
            directory: root.path().to_owned(),
        };
        assert!(Capture::create(&artifact, "scientific").unwrap().is_none());
        let capture = Capture::create(&artifact, "portable").unwrap().unwrap();
        assert_eq!(capture.config.population, config.population);
        let mut spec = command(root.path(), "never-executed", Duration::from_secs(1));
        for other in CONFIGS {
            assert!(
                spec.env_remove
                    .iter()
                    .any(|key| key == std::ffi::OsStr::new(other.environment))
            );
        }
        capture.configure(&mut spec).unwrap();
        assert_eq!(spec.env.len(), 1);
        assert_eq!(
            Path::new(
                spec.env
                    .get(std::ffi::OsStr::new(config.environment))
                    .unwrap()
            ),
            capture.directory.path().canonicalize().unwrap()
        );
    }
    assert!(Capture::create(&unrelated, "portable").unwrap().is_none());
}

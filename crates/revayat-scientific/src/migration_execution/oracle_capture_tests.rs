//! Synthetic inputs test the boundary, never attest to actual oracle execution.
use super::*;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, CollectedExecution, serde_json::Value) {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tests")).unwrap();
    let rows: Vec<_> = (1..=41).map(|i| format!("synthetic-oracle::{i}")).collect();
    let entries: Vec<_> = rows.iter().enumerate().map(|(i, id)| json!({
        "id": id, "parent_id": OWNER, "invokes_ids": [],
        "obligation_ids": [format!("SYNTHETIC-{}", i + 1)], "variant_ids": [], "checks": []
    })).collect();
    let scope = json!({"platform":"linux", "tier":"scientific", "profile":"debug", "job":"scientific"});
    fs::write(root.path().join("tests/oracle-census.json"), serde_json::to_vec(&json!({
        "schema": 1, "baseline_commit": "b".repeat(40), "cases": rows.iter().map(|id| json!({"id":id})).collect::<Vec<_>>(),
        "execution_contract": {"entries": entries, "scopes": [{"scope":scope, "owner_case_id":OWNER, "entry_ids":rows}]}
    })).unwrap()).unwrap();
    let binary = BinaryExecution { target: TARGET.into(), mapping_target: None, exit: Some(0),
        cleanup_complete: true, error: None, cases: [(CASE.into(), CaseOutcome::Passed)].into() };
    let identity = CollectedExecution { schema:1, tested_sha:"a".repeat(40), run_id:"42".into(), run_attempt:"1".into(),
        repository:"example/project".into(), workflow_ref:"example/workflow".into(), platform:"linux".into(),
        tier:"scientific".into(), profile:"debug".into(), job:"scientific".into(), ignored_only:true,
        error:None, discovery_exit:None, final_parity_verified:false, binaries:vec![binary] };
    let raw = json!({"schema":1, "population":"oracle", "owner_case_id":OWNER,
        "events": (1..=41).map(|i| json!({
            "case_id":format!("synthetic-oracle::{i}"), "parent_id":OWNER, "sequence":i,
            "invokes_ids":[], "obligation_ids":[format!("SYNTHETIC-{i}")], "source":"execution",
            "outcome":"passed", "exit":0, "cleanup_complete":false, "assertions_complete":true,
            "variants":[], "check_results":[]
        })).collect::<Vec<_>>()});
    (root, identity, raw)
}
fn captured(raw: &serde_json::Value) -> OracleCapture {
    let capture = OracleCapture(tempfile::tempdir().unwrap());
    fs::write(capture.0.path().join("oracle-observations.json"), serde_json::to_vec(raw).unwrap()).unwrap();
    capture
}

#[test]
fn complete_raw_rows_bind_to_outer_identity_and_publish_without_overwrite() {
    let (root, identity, raw) = fixture();
    let capture = captured(&raw);
    let private = capture.0.path().to_owned();
    let report = capture.finish(root.path(), &identity, &identity.binaries[0]).unwrap();
    assert!(!private.exists());
    assert!(report.events.iter().all(|event| event.cleanup_complete));
    assert_eq!(report.tested_sha, identity.tested_sha);
    assert_eq!(report.run_id, identity.run_id);
    let output = root.path().join("execution/portable-debug.json");
    publish(root.path(), &output, &identity, std::slice::from_ref(&report)).unwrap();
    let destination = root.path().join("execution/oracle-debug.json");
    let original = fs::read(&destination).unwrap();
    assert!(publish(root.path(), &output, &identity, &[report]).is_err());
    assert_eq!(fs::read(destination).unwrap(), original);
    assert!(publish(root.path(), &output, &identity, &[]).is_err());
    let valid = captured(&raw).finish(root.path(), &identity, &identity.binaries[0]).unwrap();
    for field in ["tested_sha", "run_id", "run_attempt", "census_sha256", "baseline_commit"] {
        let mut value = serde_json::to_value(&valid).unwrap();
        value[field] = "foreign".into();
        let foreign: events::OperationReport = serde_json::from_value(value).unwrap();
        let different_output = root.path().join(field).join("portable-debug.json");
        assert!(publish(root.path(), &different_output, &identity, &[foreign]).is_err(), "{field}");
        assert!(!different_output.parent().unwrap().join("oracle-debug.json").exists());
    }
}

#[test]
fn missing_foreign_partial_self_certified_and_duplicate_rows_never_finalize() {
    let (root, identity, raw) = fixture();
    assert!(OracleCapture(tempfile::tempdir().unwrap()).finish(root.path(), &identity, &identity.binaries[0]).is_err());
    for field in ["owner_case_id", "population", "unexpected_binding"] {
        let mut changed = raw.clone();
        changed[field] = "foreign".into();
        assert!(captured(&changed).finish(root.path(), &identity, &identity.binaries[0]).is_err());
    }
    for field in ["cleanup_complete", "parent_id", "sequence", "source", "outcome", "assertions_complete", "exit"] {
        let mut changed = raw.clone();
        changed["events"][0][field] = match field {
            "cleanup_complete" => true.into(), "assertions_complete" => false.into(),
            "sequence" => 2.into(), "exit" => 3.into(), "outcome" => "skipped".into(), _ => "foreign".into(),
        };
        assert!(captured(&changed).finish(root.path(), &identity, &identity.binaries[0]).is_err(), "{field}");
    }
    let mut changed = raw.clone();
    changed["events"][1]["case_id"] = changed["events"][0]["case_id"].clone();
    assert!(captured(&changed).finish(root.path(), &identity, &identity.binaries[0]).is_err());
    let mut changed = raw;
    changed["events"].as_array_mut().unwrap().pop();
    assert!(captured(&changed).finish(root.path(), &identity, &identity.binaries[0]).is_err());
}

#[test]
fn failed_carrier_cleanup_or_noncanonical_rows_block_report_publication() {
    let (root, mut identity, raw) = fixture();
    for field in ["cleanup_complete", "exit", "error", "cases"] {
        let mut value = serde_json::to_value(&identity.binaries[0]).unwrap();
        value[field] = match field {
            "cleanup_complete" => false.into(), "exit" => 9.into(), "error" => "incomplete".into(),
            _ => json!({(CASE):"skipped"}),
        };
        let binary: BinaryExecution = serde_json::from_value(value).unwrap();
        assert!(captured(&raw).finish(root.path(), &identity, &binary).is_err());
    }
    let mut changed = raw;
    changed["events"][0]["obligation_ids"] = json!(["noncanonical"]);
    let report = captured(&changed).finish(root.path(), &identity, &identity.binaries[0]).unwrap();
    let output = root.path().join("execution/portable-debug.json");
    assert!(publish(root.path(), &output, &identity, &[report]).is_err());
    assert!(!root.path().join("execution/oracle-debug.json").exists());
    identity.binaries[0].cleanup_complete = false;
    assert!(captured(&changed).finish(root.path(), &identity, &identity.binaries[0]).is_err());
}

#[test]
fn raw_reads_are_actual_bounded_and_routing_only_targets_the_actual_carrier() {
    let (root, _, _) = fixture();
    let path = root.path().join("oversized");
    let file = fs::File::create(&path).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(bounded(&path).is_err());
    let artifact = Artifact { target:TARGET.into(), mapping_target:None, executable:"never-executed".into(), directory:root.path().to_owned() };
    assert!(OracleCapture::create(&artifact, "scientific").unwrap().is_none());
    let capture = OracleCapture::create(&artifact, "portable").unwrap().unwrap();
    let mut spec = command(root.path(), "never-executed", Duration::from_secs(1));
    assert!(spec.env.is_empty());
    assert!(spec.env_remove.iter().any(|key| key == std::ffi::OsStr::new("REVAYAT_ORACLE_EVENT_DIR")));
    capture.configure(&mut spec).unwrap();
    let routed = spec.env.get(std::ffi::OsStr::new("REVAYAT_ORACLE_EVENT_DIR")).unwrap();
    assert_eq!(Path::new(routed), capture.0.path().canonicalize().unwrap());
    let unrelated = Artifact { target:"unrelated/lib/fixture".into(), ..artifact };
    assert!(OracleCapture::create(&unrelated, "portable").unwrap().is_none());
}

//! Reviewed Linux subset metadata; the public aggregate still requires all six scenarios.
use super::*;

const PATH: &str = "tests/coverage-linux-contract.json";
const BYTES: &[u8] = include_bytes!("../../../../tests/coverage-linux-contract.json");
const SOURCE: &[u8] = include_bytes!("../../../../tests/security/coverage.json");
const BASELINE: &str = "4e24f3da8df19f83eb3c3b424e3618252d03a36c";
const COMPLETENESS: &str =
    "linux-subcontract-only; global six-scenario and five-population validation remains required";
const SCENARIOS: &[&str] = &[
    "coverage::linux-controls",
    "coverage::windows-controls",
    "coverage::docx-case-relationships",
    "coverage::static-output-links",
    "coverage::html-work-admission",
    "coverage::tex-output-budget",
];
const ORDINALS: [usize; 3] = [1, 5, 6];
const QUALIFICATION: &[&str] = &[
    "crates/revayat-scientific/tests/runtime_build_integration.rs::test_production_launch_enforces_isolation_and_cleans_owned_container",
    "crates/revayat-scientific/src/migration_execution/native_coverage.rs::qualify",
    "crates/revayat-scientific/src/sandbox.rs::probe",
    "crates/revayat-scientific/src/sandbox_helper.rs::security",
    "crates/revayat-scientific/src/bin/security_helper/mod.rs::preflight_then_worker",
    "crates/revayat-scientific/src/security_cases.rs::Cases::run",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema: u8,
    population: String,
    baseline_commit: String,
    source_census: String,
    source: String,
    completeness: String,
    qualification_sources: Vec<String>,
    execution_contract: events::EventContract,
    obligations: Vec<Obligation>,
}
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Obligation {
    id: String,
    scenario_id: String,
    scenario_ordinal: usize,
    check_id: String,
    check_ordinal: usize,
    source_pointer: String,
}

pub(super) fn obligation_ids(ordinal: usize, checks: usize) -> Vec<String> {
    (1..=checks)
        .map(|index| format!("COVERAGE-{ordinal:03}-{index:02}"))
        .collect()
}
fn scope() -> events::EventScope {
    events::EventScope {
        platform: "linux".into(),
        tier: "native".into(),
        profile: "debug".into(),
        job: "linux-security".into(),
    }
}

/// Metadata describes the graph; no metadata field is an execution outcome.
fn validate(
    bytes: &[u8],
    census_bytes: &[u8],
    graph: &[events::OperationEvent],
) -> Result<events::CensusContract> {
    let metadata: Metadata = serde_json::from_slice(bytes)?;
    ensure!(
        metadata.schema == 1
            && metadata.population == "coverage"
            && metadata.baseline_commit == BASELINE
            && metadata.source_census == "tests/coverage-census.json"
            && metadata.source == "tests/security/coverage.json"
            && metadata.completeness == COMPLETENESS
            && metadata.qualification_sources == QUALIFICATION,
        "Linux coverage metadata identity requires source review"
    );
    let census: serde_json::Value = serde_json::from_slice(census_bytes)?;
    let source: serde_json::Value = serde_json::from_slice(SOURCE)?;
    ensure!(
        census["schema"] == 1
            && census["baseline_commit"] == BASELINE
            && census["source"] == metadata.source
            && source["schema"] == 1,
        "Linux metadata source identity differs from global census"
    );
    let global: events::EventContract = serde_json::from_value(
        census
            .get("execution_contract")
            .filter(|value| !value.is_null())
            .context("required execution contract is not source-closed")?
            .clone(),
    )?;
    ensure!(
        global.entries.len() == 6 && global.scopes.len() == 2,
        "global coverage contract must contain six scenarios and two scopes"
    );
    let linux = global
        .scopes
        .iter()
        .find(|entry| entry.scope == scope())
        .context("global Linux coverage scope missing")?;
    ensure!(
        serde_json::to_value(linux)?
            == serde_json::to_value(
                metadata
                    .execution_contract
                    .scopes
                    .first()
                    .context("Linux subcontract scope missing")?
            )?,
        "global Linux coverage scope differs from subcontract"
    );
    for entry in &metadata.execution_contract.entries {
        let actual = global
            .entries
            .iter()
            .find(|row| row.id == entry.id)
            .context("global Linux coverage entry missing")?;
        ensure!(
            serde_json::to_value(actual)? == serde_json::to_value(entry)?,
            "global Linux coverage entry differs from subcontract"
        );
    }
    let rows = census["scenarios"]
        .as_array()
        .context("coverage census scenarios missing")?;
    let originals = source["scenarios"]
        .as_array()
        .context("original coverage scenarios missing")?;
    ensure!(
        rows.len() == SCENARIOS.len() && originals.len() == SCENARIOS.len(),
        "complete six-scenario inventory requires source review"
    );
    for (index, entry) in global.entries.iter().enumerate() {
        let checks = entry
            .checks
            .iter()
            .map(|check| check.id.as_str())
            .collect::<Vec<_>>();
        ensure!(
            entry.id == SCENARIOS[index]
                && serde_json::to_value(checks)? == rows[index]["checks"]
                && entry.obligation_ids == obligation_ids(index + 1, entry.checks.len())
                && entry
                    .checks
                    .iter()
                    .all(|check| !check.witness_ids.is_empty()),
            "global scenario check or obligation inventory differs"
        );
    }
    for ((row, original), id) in rows.iter().zip(originals).zip(SCENARIOS) {
        ensure!(
            row["id"] == *id
                && original["id"] == id.trim_start_matches("coverage::")
                && original["required"] == true,
            "original scenario identity or requirement differs"
        );
    }
    ensure!(graph.len() == ORDINALS.len(), "Linux graph size differs");
    let mut obligations = Vec::new();
    let mut entries = Vec::new();
    let mut linux_count = 0;
    for row in rows {
        if row["platforms"]
            .as_array()
            .is_some_and(|platforms| platforms.iter().any(|platform| platform == "linux"))
        {
            linux_count += 1;
        }
    }
    ensure!(linux_count == graph.len(), "Linux census scope differs");
    for (event, ordinal) in graph.iter().zip(ORDINALS) {
        let row = &rows[ordinal - 1];
        let check_ids: Vec<_> = event
            .check_results
            .iter()
            .map(|check| check.check_id.as_str())
            .collect();
        ensure!(
            event.case_id == SCENARIOS[ordinal - 1]
                && row["checks"] == serde_json::to_value(check_ids)?
                && row["checks"] == originals[ordinal - 1]["checks"]
                && row["platforms"] == serde_json::json!(["linux"])
                && row["tier"] == "native"
                && row["source_lines"] == format!("L{}", ordinal + 3)
                && event.parent_id == OWNER
                && event.invokes_ids.is_empty()
                && event.variants.is_empty()
                && event.obligation_ids == obligation_ids(ordinal, event.check_results.len()),
            "compiled Linux source graph differs from original census"
        );
        for (index, check) in event.check_results.iter().enumerate() {
            obligations.push(Obligation {
                id: event.obligation_ids[index].clone(),
                scenario_id: event.case_id.clone(),
                scenario_ordinal: ordinal,
                check_id: check.check_id.clone(),
                check_ordinal: index + 1,
                source_pointer: format!("/scenarios/{}/checks/{index}", ordinal - 1),
            });
        }
        entries.push(events::ExpectedEvent {
            id: event.case_id.clone(),
            parent_id: event.parent_id.clone(),
            invokes_ids: event.invokes_ids.clone(),
            obligation_ids: event.obligation_ids.clone(),
            variant_ids: vec![],
            checks: event
                .check_results
                .iter()
                .map(|check| events::ExpectedCheck {
                    id: check.check_id.clone(),
                    witness_ids: check.witness_ids.clone(),
                })
                .collect(),
        });
    }
    let expected = events::EventContract {
        scopes: vec![events::ExpectedScope {
            scope: scope(),
            owner_case_id: OWNER.into(),
            entry_ids: entries.iter().map(|entry| entry.id.clone()).collect(),
        }],
        entries,
    };
    ensure!(
        metadata.obligations == obligations
            && serde_json::to_value(&metadata.execution_contract)?
                == serde_json::to_value(expected)?,
        "Linux metadata obligation or witness graph differs from compiled producer"
    );
    Ok(events::CensusContract {
        population: "coverage".into(),
        baseline_commit: BASELINE.into(),
        census_sha256: format!("{:x}", Sha256::digest(census_bytes)),
        ids: graph.iter().map(|event| event.case_id.clone()).collect(),
        contract: Some(metadata.execution_contract),
    })
}

pub(super) fn load(
    root: &Path,
    census_bytes: &[u8],
    graph: &[events::OperationEvent],
) -> Result<events::CensusContract> {
    let path = root.join(PATH);
    ensure!(
        !crate::identity::is_link(&path)? && fs::metadata(&path)?.is_file(),
        "Linux coverage metadata must be plain"
    );
    let bytes = crate::resource::bounded_read(&path, 65536)?;
    ensure!(
        bytes == BYTES,
        "Linux metadata differs from compiled source"
    );
    validate(&bytes, census_bytes, graph)
}

fn copy_binary(binary: &BinaryExecution) -> BinaryExecution {
    BinaryExecution {
        target: binary.target.clone(),
        mapping_target: binary.mapping_target.clone(),
        exit: binary.exit,
        cleanup_complete: binary.cleanup_complete,
        cases: binary.cases.clone(),
        error: binary.error.clone(),
    }
}

/// Reuse the strict consumer with copies of actual receipts, retaining every failure field.
/// This private subset check does not satisfy the public five-population entry point.
pub(super) fn validate_execution(
    census: &events::CensusContract,
    report: &events::OperationReport,
    identity: &CollectedExecution,
    owner: &BinaryExecution,
    worker: &BinaryExecution,
) -> Result<()> {
    let mut harness = CollectedExecution {
        schema: identity.schema,
        tested_sha: identity.tested_sha.clone(),
        run_id: identity.run_id.clone(),
        run_attempt: identity.run_attempt.clone(),
        repository: identity.repository.clone(),
        workflow_ref: identity.workflow_ref.clone(),
        job: identity.job.clone(),
        platform: identity.platform.clone(),
        tier: identity.tier.clone(),
        profile: identity.profile.clone(),
        ignored_only: identity.ignored_only,
        binaries: identity.binaries.iter().map(copy_binary).collect(),
        error: identity.error.clone(),
        discovery_exit: identity.discovery_exit,
        final_parity_verified: identity.final_parity_verified,
    };
    harness.binaries.push(copy_binary(owner));
    harness.binaries.push(copy_binary(worker));
    ensure!(
        events::validate_populations(
            std::slice::from_ref(census),
            std::slice::from_ref(report),
            &[harness],
            (
                &identity.tested_sha,
                &identity.run_id,
                &identity.run_attempt,
                &identity.repository,
                &identity.workflow_ref,
            ),
        )? == ORDINALS.len(),
        "Linux coverage execution graph incomplete"
    );
    Ok(())
}

/// Inert validator fixtures extend the existing registration; they are never native evidence.
#[cfg(test)]
pub(super) fn test_source_contract_and_global_refusal(cases: &BTreeMap<String, CaseOutcome>) {
    use serde_json::json;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let census_bytes = fs::read(root.join("tests/coverage-census.json")).unwrap();
    let graph = worker_checks().unwrap();
    let census = load(&root, &census_bytes, &graph).unwrap();
    assert_eq!(census.ids.len(), 3);
    assert_eq!(
        graph
            .iter()
            .map(|event| event.obligation_ids.len())
            .sum::<usize>(),
        23
    );
    let metadata: serde_json::Value = serde_json::from_slice(BYTES).unwrap();
    for (path, value) in [
        ("/population", json!("native-stage")),
        ("/baseline_commit", json!("0".repeat(40))),
        ("/completeness", json!("complete")),
        ("/qualification_sources/0", json!("portable-test")),
        (
            "/execution_contract/scopes/0/scope/platform",
            json!("windows"),
        ),
        (
            "/execution_contract/scopes/0/scope/job",
            json!("native-windows"),
        ),
        (
            "/execution_contract/scopes/0/owner_case_id",
            json!("other-owner"),
        ),
        (
            "/execution_contract/entries/0/parent_id",
            json!("other-owner"),
        ),
        (
            "/execution_contract/entries/0/obligation_ids/0",
            json!("COVERAGE-002-01"),
        ),
        (
            "/execution_contract/entries/1/checks/0/witness_ids/0",
            json!(OWNER),
        ),
        ("/obligations/0/check_ordinal", json!(2)),
        (
            "/obligations/0/source_pointer",
            json!("/scenarios/1/checks/0"),
        ),
    ] {
        let mut changed = metadata.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            validate(
                &serde_json::to_vec(&changed).unwrap(),
                &census_bytes,
                &graph
            )
            .is_err(),
            "{path}"
        );
    }
    let mut changed = metadata.clone();
    changed["execution_contract"]["entries"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(
        validate(
            &serde_json::to_vec(&changed).unwrap(),
            &census_bytes,
            &graph
        )
        .is_err()
    );
    let mut changed = metadata;
    changed["unknown_outcome"] = json!("passed");
    assert!(
        validate(
            &serde_json::to_vec(&changed).unwrap(),
            &census_bytes,
            &graph
        )
        .is_err()
    );
    let global: serde_json::Value = serde_json::from_slice(&census_bytes).unwrap();
    for path in [
        "/scenarios/1/id",
        "/scenarios/4/checks/0",
        "/scenarios/0/id",
    ] {
        let mut changed = global.clone();
        *changed.pointer_mut(path).unwrap() = json!("changed");
        assert!(validate(BYTES, &serde_json::to_vec(&changed).unwrap(), &graph).is_err());
    }
    let mut changed = global;
    changed["execution_contract"] = serde_json::Value::Null;
    let refusal = validate(BYTES, &serde_json::to_vec(&changed).unwrap(), &graph)
        .err()
        .unwrap();
    assert!(
        refusal
            .to_string()
            .contains("required execution contract is not source-closed")
    );

    let mut identity = CollectedExecution {
        schema: 1,
        tested_sha: "a".repeat(40),
        run_id: "12345".into(),
        run_attempt: "1".into(),
        repository: "example/revayat".into(),
        workflow_ref: "example/revayat/.github/workflows/ci.yml@refs/heads/test".into(),
        job: "linux-security".into(),
        platform: "linux".into(),
        tier: "native".into(),
        profile: "debug".into(),
        ignored_only: true,
        binaries: vec![],
        error: None,
        discovery_exit: None,
        final_parity_verified: false,
    };
    let mut owner = BinaryExecution {
        target: OWNER_TARGET.into(),
        mapping_target: Some("runtime_build_integration".into()),
        exit: Some(0),
        cleanup_complete: true,
        cases: [(OWNER_CASE.into(), CaseOutcome::Passed)].into(),
        error: None,
    };
    let mut worker = BinaryExecution {
        target: super::super::LINUX_TARGET.into(),
        mapping_target: Some("standalone_security".into()),
        exit: Some(0),
        cleanup_complete: true,
        cases: cases.clone(),
        error: None,
    };
    let report = events::OperationReport {
        schema: 1,
        population: "coverage".into(),
        tested_sha: identity.tested_sha.clone(),
        run_id: identity.run_id.clone(),
        run_attempt: identity.run_attempt.clone(),
        repository: identity.repository.clone(),
        workflow_ref: identity.workflow_ref.clone(),
        scope: scope(),
        baseline_commit: BASELINE.into(),
        census_sha256: census.census_sha256.clone(),
        events: graph,
    };
    validate_execution(&census, &report, &identity, &owner, &worker).unwrap();
    owner.cleanup_complete = false;
    assert!(validate_execution(&census, &report, &identity, &owner, &worker).is_err());
    owner.cleanup_complete = true;
    owner.cases.insert(OWNER_CASE.into(), CaseOutcome::Failed);
    assert!(validate_execution(&census, &report, &identity, &owner, &worker).is_err());
    owner.cases.insert(OWNER_CASE.into(), CaseOutcome::Passed);
    let witness = crate::security_cases::CASE_NAMES
        .iter()
        .find(|(id, _)| *id == "html/depth/parser")
        .unwrap()
        .1;
    worker.cases.remove(witness);
    assert!(validate_execution(&census, &report, &identity, &owner, &worker).is_err());
    worker.cases = cases.clone();
    identity.error = Some("fixture-owner-failure".into());
    assert!(validate_execution(&census, &report, &identity, &owner, &worker).is_err());
    identity.error = None;
    let mut missing = report.clone();
    missing.events[0].obligation_ids.clear();
    assert!(validate_execution(&census, &missing, &identity, &owner, &worker).is_err());
    let mut incomplete = report.clone();
    incomplete.events[2].cleanup_complete = false;
    assert!(validate_execution(&census, &incomplete, &identity, &owner, &worker).is_err());
    let globals = events::load_censuses(&root).unwrap();
    assert_eq!(globals.len(), 5);
    let coverage = globals
        .iter()
        .find(|census| census.population == "coverage")
        .unwrap();
    assert_eq!(coverage.ids.len(), 6);
    assert_eq!(coverage.contract.as_ref().unwrap().entries.len(), 6);
    assert_eq!(coverage.contract.as_ref().unwrap().scopes.len(), 2);
    let mut missing_contract = coverage.clone();
    missing_contract.contract = None;
    let run = (
        &*identity.tested_sha,
        &*identity.run_id,
        &*identity.run_attempt,
        &*identity.repository,
        &*identity.workflow_ref,
    );
    let blocked = events::validate_populations(
        std::slice::from_ref(&missing_contract),
        std::slice::from_ref(&report),
        &[],
        run,
    )
    .unwrap_err();
    assert!(blocked.to_string().contains("not source-closed"));
    assert!(
        events::validate_operation_reports(
            std::slice::from_ref(&census),
            std::slice::from_ref(&report),
            &[],
            run
        )
        .unwrap_err()
        .to_string()
        .contains("five nonflat populations required")
    );
    assert!(
        events::validate_operation_reports(
            &globals,
            &[report],
            std::slice::from_ref(&identity),
            run
        )
        .is_err()
    );
}

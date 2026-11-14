//! Synthetic contract fixtures exercise validation only, never product acceptance.
use revayat_scientific::migration::execution::{
    BinaryExecution, CaseOutcome, CollectedExecution,
    events::{
        CensusContract, CheckOutcome, EventContract, EventScope, ExpectedCheck, ExpectedEvent,
        ExpectedScope, OperationEvent, OperationReport, VariantOutcome, validate_operation_reports,
    },
    validate_runner_args,
};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BASELINE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OWNER: &str = "fixture/lib/fixture::owner";
fn scope() -> EventScope {
    EventScope {
        platform: "linux".into(),
        tier: "scientific".into(),
        profile: "debug".into(),
        job: "scientific".into(),
    }
}
fn fixture() -> (
    Vec<CensusContract>,
    Vec<OperationReport>,
    Vec<CollectedExecution>,
) {
    let harness = CollectedExecution {
        schema: 1,
        tested_sha: SHA.into(),
        run_id: "42".into(),
        run_attempt: "1".into(),
        repository: "example/project".into(),
        workflow_ref: "example/workflow".into(),
        job: "scientific".into(),
        platform: "linux".into(),
        tier: "scientific".into(),
        profile: "debug".into(),
        ignored_only: true,
        error: None,
        discovery_exit: None,
        final_parity_verified: false,
        binaries: vec![BinaryExecution {
            target: "fixture/lib/fixture".into(),
            mapping_target: None,
            exit: Some(0),
            cleanup_complete: true,
            error: None,
            cases: [("owner".into(), CaseOutcome::Passed)].into(),
        }],
    };
    let mut censuses = Vec::new();
    let mut operations = Vec::new();
    for population in [
        "oracle",
        "engine",
        "runtime-preparation",
        "coverage",
        "native-stage",
    ] {
        let id = format!("{population}::fixture");
        let obligations = vec![format!("{population}-obligation")];
        let checks = if population == "coverage" {
            vec![ExpectedCheck {
                id: "check".into(),
                witness_ids: vec![OWNER.into()],
            }]
        } else {
            Vec::new()
        };
        censuses.push(CensusContract {
            population: population.into(),
            baseline_commit: BASELINE.into(),
            census_sha256: "c".repeat(64),
            ids: vec![id.clone()],
            contract: Some(EventContract {
                entries: vec![ExpectedEvent {
                    id: id.clone(),
                    parent_id: OWNER.into(),
                    invokes_ids: vec![],
                    obligation_ids: obligations.clone(),
                    variant_ids: vec!["actual-variant".into()],
                    checks,
                }],
                scopes: vec![ExpectedScope {
                    scope: scope(),
                    owner_case_id: OWNER.into(),
                    entry_ids: vec![id.clone()],
                }],
            }),
        });
        operations.push(OperationReport {
            schema: 1,
            population: population.into(),
            tested_sha: SHA.into(),
            run_id: "42".into(),
            run_attempt: "1".into(),
            repository: "example/project".into(),
            workflow_ref: "example/workflow".into(),
            scope: scope(),
            baseline_commit: BASELINE.into(),
            census_sha256: "c".repeat(64),
            events: vec![OperationEvent {
                case_id: id,
                parent_id: OWNER.into(),
                sequence: 1,
                invokes_ids: vec![],
                obligation_ids: obligations,
                source: "execution".into(),
                outcome: CaseOutcome::Passed,
                exit: 0,
                cleanup_complete: true,
                assertions_complete: true,
                variants: vec![VariantOutcome {
                    id: "actual-variant".into(),
                    outcome: CaseOutcome::Passed,
                }],
                check_results: if population == "coverage" {
                    vec![CheckOutcome {
                        check_id: "check".into(),
                        witness_ids: vec![OWNER.into()],
                        outcome: CaseOutcome::Passed,
                    }]
                } else {
                    Vec::new()
                },
            }],
        });
    }
    (censuses, operations, vec![harness])
}
fn validate(
    censuses: &[CensusContract],
    reports: &[OperationReport],
    harnesses: &[CollectedExecution],
) -> anyhow::Result<usize> {
    validate_operation_reports(
        censuses,
        reports,
        harnesses,
        (SHA, "42", "1", "example/project", "example/workflow"),
    )
}

#[test]
fn complete_synthetic_contract_reconciles_but_missing_real_reports_never_do() {
    let (mut censuses, mut reports, harnesses) = fixture();
    assert_eq!(validate(&censuses, &reports, &harnesses).unwrap(), 5);
    assert!(validate(&censuses, &[], &harnesses).is_err());
    let missing = reports.pop().unwrap();
    assert!(validate(&censuses, &reports, &harnesses).is_err());
    reports.push(missing);
    censuses[0].contract = None;
    assert!(validate(&censuses, &reports, &harnesses).is_err());
}

#[test]
fn foreign_duplicate_parent_cleanup_and_registration_events_fail() {
    let (censuses, reports, harnesses) = fixture();
    for field in [
        "tested_sha",
        "run_id",
        "run_attempt",
        "repository",
        "workflow_ref",
        "baseline_commit",
        "census_sha256",
        "population",
    ] {
        let mut value = serde_json::to_value(&reports).unwrap();
        value[0][field] = "foreign".into();
        let changed = serde_json::from_value::<Vec<OperationReport>>(value).unwrap();
        assert!(
            validate(&censuses, &changed, &harnesses).is_err(),
            "{field}"
        );
    }
    for field in ["platform", "tier", "profile", "job"] {
        let mut changed = reports.clone();
        let mut value = serde_json::to_value(&changed[0]).unwrap();
        value["scope"][field] = "foreign".into();
        changed[0] = serde_json::from_value(value).unwrap();
        assert!(
            validate(&censuses, &changed, &harnesses).is_err(),
            "{field}"
        );
    }
    for field in [
        "parent_id",
        "source",
        "cleanup_complete",
        "assertions_complete",
        "sequence",
        "outcome",
        "exit",
    ] {
        let mut value = serde_json::to_value(&reports).unwrap();
        value[0]["events"][0][field] = match field {
            "cleanup_complete" | "assertions_complete" => false.into(),
            "sequence" => 2.into(),
            "exit" => 9.into(),
            "outcome" => "skipped".into(),
            _ => "registration-or-foreign".into(),
        };
        let changed = serde_json::from_value::<Vec<OperationReport>>(value).unwrap();
        assert!(
            validate(&censuses, &changed, &harnesses).is_err(),
            "{field}"
        );
    }
    let mut changed = reports.clone();
    changed.push(reports[0].clone());
    assert!(validate(&censuses, &changed, &harnesses).is_err());
    let mut changed = reports.clone();
    changed[0].events.push(reports[0].events[0].clone());
    assert!(validate(&censuses, &changed, &harnesses).is_err());
    let mut changed = reports.clone();
    changed[0].events[0].variants.clear();
    assert!(validate(&censuses, &changed, &harnesses).is_err());
    let mut changed = reports.clone();
    changed[0].events[0].obligation_ids.clear();
    assert!(validate(&censuses, &changed, &harnesses).is_err());
    let mut changed = reports.clone();
    changed[0].events[0]
        .invokes_ids
        .push("unrelated-helper".into());
    assert!(validate(&censuses, &changed, &harnesses).is_err());
    let mut changed = reports.clone();
    changed[0].events[0].variants[0].outcome = CaseOutcome::Failed;
    assert!(validate(&censuses, &changed, &harnesses).is_err());
    let mut changed = harnesses;
    changed[0].binaries[0]
        .cases
        .insert("owner".into(), CaseOutcome::Skipped);
    assert!(validate(&censuses, &reports, &changed).is_err());
}

#[test]
fn scenario_checks_require_actual_bound_witnesses_and_all_expected_checks() {
    let (mut censuses, mut reports, harnesses) = fixture();
    reports[3].events[0].check_results.clear();
    assert!(validate(&censuses, &reports, &harnesses).is_err());
    let (_, mut reports, _) = fixture();
    reports[3].events[0].check_results[0].witness_ids = vec!["not-executed".into()];
    censuses[3].contract.as_mut().unwrap().entries[0].checks[0].witness_ids =
        vec!["not-executed".into()];
    assert!(validate(&censuses, &reports, &harnesses).is_err());
    let (_, mut reports, _) = fixture();
    reports[3].events[0].check_results[0].outcome = CaseOutcome::Failed;
    assert!(validate(&censuses, &reports, &harnesses).is_err());
    let (mut cyclic_contract, mut reports, _) = fixture();
    cyclic_contract[3].contract.as_mut().unwrap().entries[0].checks[0].witness_ids =
        vec!["coverage::fixture".into()];
    reports[3].events[0].check_results[0].witness_ids = vec!["coverage::fixture".into()];
    assert!(validate(&cyclic_contract, &reports, &harnesses).is_err());
}

#[test]
fn shared_entries_require_explicit_unique_known_scope_references() {
    let (censuses, reports, harnesses) = fixture();
    for ids in [
        vec![],
        vec!["unknown".into()],
        vec!["oracle::fixture".into(), "oracle::fixture".into()],
    ] {
        let mut changed = censuses.clone();
        changed[0].contract.as_mut().unwrap().scopes[0].entry_ids = ids;
        assert!(validate(&changed, &reports, &harnesses).is_err());
    }
    let mut changed = censuses.clone();
    let mut orphan = changed[0].contract.as_ref().unwrap().entries[0].clone();
    orphan.id = "orphan".into();
    changed[0].contract.as_mut().unwrap().entries.push(orphan);
    assert!(validate(&changed, &reports, &harnesses).is_err());
    let mut duplicate_harnesses = harnesses;
    duplicate_harnesses.push(
        serde_json::from_value(serde_json::to_value(&duplicate_harnesses[0]).unwrap()).unwrap(),
    );
    assert!(validate(&censuses, &reports, &duplicate_harnesses).is_err());
    let mut wire = serde_json::to_value(&reports[0]).unwrap();
    wire["producer_status"] = "passed".into();
    assert!(serde_json::from_value::<OperationReport>(wire).is_err());
}

#[test]
fn one_shared_entry_contract_reconciles_each_explicit_scope_without_copying_rows() {
    let (mut censuses, mut reports, mut harnesses) = fixture();
    let mut second: CollectedExecution =
        serde_json::from_value(serde_json::to_value(&harnesses[0]).unwrap()).unwrap();
    second.platform = "macos".into();
    harnesses.push(second);
    let contract = censuses[0].contract.as_mut().unwrap();
    let mut scope = contract.scopes[0].clone();
    scope.scope.platform = "macos".into();
    contract.scopes.push(scope);
    assert_eq!(contract.entries.len(), 1);
    let mut report = reports[0].clone();
    report.scope.platform = "macos".into();
    reports.push(report);
    assert_eq!(validate(&censuses, &reports, &harnesses).unwrap(), 6);
    reports.pop();
    assert!(validate(&censuses, &reports, &harnesses).is_err());
}

#[test]
fn nested_child_requires_its_actual_earlier_parent_and_rejects_reverse_order() {
    let (mut censuses, mut reports, harnesses) = fixture();
    let child_id = "oracle::child".to_owned();
    censuses[0].ids.push(child_id.clone());
    let contract = censuses[0].contract.as_mut().unwrap();
    let mut child = contract.entries[0].clone();
    child.id = child_id.clone();
    child.parent_id = "oracle::fixture".into();
    contract.entries.push(child);
    contract.scopes[0].entry_ids.push(child_id.clone());
    let mut observed = reports[0].events[0].clone();
    observed.case_id = child_id;
    observed.parent_id = "oracle::fixture".into();
    observed.sequence = 2;
    reports[0].events.push(observed);
    assert_eq!(validate(&censuses, &reports, &harnesses).unwrap(), 6);
    censuses[0].contract.as_mut().unwrap().scopes[0]
        .entry_ids
        .swap(0, 1);
    reports[0].events.swap(0, 1);
    for (index, event) in reports[0].events.iter_mut().enumerate() {
        event.sequence = index + 1;
    }
    assert!(validate(&censuses, &reports, &harnesses).is_err());
}

#[test]
fn event_cli_only_accepts_reports_in_the_public_aggregate() {
    let args = |values: &[&str]| {
        values
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>()
    };
    assert!(
        validate_runner_args(&args(&[
            "--aggregate",
            "--ledger",
            "a",
            "--report",
            "b",
            "--event-report",
            "c"
        ]))
        .is_ok()
    );
    for values in [
        vec![
            "--tier",
            "portable",
            "--profile",
            "debug",
            "--output",
            "a",
            "--event-report",
            "c",
        ],
        vec![
            "--reconcile",
            "--profile",
            "debug",
            "--ledger",
            "a",
            "--report",
            "b",
            "--event-report",
            "c",
        ],
        vec![
            "--aggregate",
            "--census",
            "verifier",
            "--ledger",
            "a",
            "--report",
            "b",
            "--event-report",
            "c",
        ],
    ] {
        assert!(validate_runner_args(&args(&values)).is_err());
    }
}

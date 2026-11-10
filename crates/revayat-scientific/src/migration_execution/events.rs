//! Bound nonflat execution evidence. Census declarations never manufacture outcomes.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventScope {
    pub platform: String,
    pub tier: String,
    pub profile: String,
    pub job: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCheck {
    pub id: String,
    pub witness_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedEvent {
    pub id: String,
    pub parent_id: String,
    pub invokes_ids: Vec<String>,
    pub obligation_ids: Vec<String>,
    pub variant_ids: Vec<String>,
    pub checks: Vec<ExpectedCheck>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedScope {
    pub scope: EventScope,
    pub owner_case_id: String,
    pub entry_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventContract {
    pub entries: Vec<ExpectedEvent>,
    pub scopes: Vec<ExpectedScope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariantOutcome {
    pub id: String,
    pub outcome: CaseOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckOutcome {
    pub check_id: String,
    pub witness_ids: Vec<String>,
    pub outcome: CaseOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEvent {
    pub case_id: String,
    pub parent_id: String,
    pub sequence: usize,
    pub invokes_ids: Vec<String>,
    pub obligation_ids: Vec<String>,
    pub source: String,
    pub outcome: CaseOutcome,
    pub exit: i32,
    pub cleanup_complete: bool,
    pub assertions_complete: bool,
    pub variants: Vec<VariantOutcome>,
    pub check_results: Vec<CheckOutcome>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReport {
    pub schema: u8,
    pub population: String,
    pub tested_sha: String,
    pub run_id: String,
    pub run_attempt: String,
    pub repository: String,
    pub workflow_ref: String,
    pub scope: EventScope,
    pub baseline_commit: String,
    pub census_sha256: String,
    pub events: Vec<OperationEvent>,
}

#[derive(Clone)]
pub struct CensusContract {
    pub population: String,
    pub baseline_commit: String,
    pub census_sha256: String,
    pub ids: Vec<String>,
    pub contract: Option<EventContract>,
}

fn names(values: &[String]) -> Result<BTreeSet<&str>> {
    super::super::unique_names(values.iter().map(String::as_str))
}
fn same_names(actual: &[String], expected: &[String]) -> Result<()> {
    ensure!(names(actual)? == names(expected)?, "operation identity relation differs");
    Ok(())
}
fn report_scope(report: &CollectedExecution) -> EventScope {
    EventScope { platform: report.platform.clone(), tier: report.tier.clone(),
        profile: report.profile.clone(), job: report.job.clone() }
}
fn passed_cases(report: &CollectedExecution) -> BTreeSet<String> {
    report.binaries.iter().flat_map(|binary| binary.cases.iter()
        .filter(|(_, outcome)| **outcome == CaseOutcome::Passed)
        .map(|(case, _)| format!("{}::{case}", binary.target))).collect()
}

/// Reconcile supplied actual reports with reviewed source contracts. This is structural
/// evidence validation, not cryptographic authentication or an assertion-equivalence proof.
pub fn validate_operation_reports(
    censuses: &[CensusContract],
    operations: &[OperationReport],
    harnesses: &[CollectedExecution],
    identity: (&str, &str, &str, &str, &str),
) -> Result<usize> {
    let population_ids: Vec<_> = censuses.iter().map(|census| census.population.clone()).collect();
    let expected_populations: BTreeSet<_> = ["oracle", "engine", "runtime-preparation", "coverage", "native-stage"].into();
    ensure!(names(&population_ids)? == expected_populations, "five nonflat populations required");
    validate_populations(censuses, operations, harnesses, identity)
}

pub(super) fn validate_populations(
    censuses: &[CensusContract], operations: &[OperationReport], harnesses: &[CollectedExecution],
    identity: (&str, &str, &str, &str, &str),
) -> Result<usize> {
    ensure!(operations.len() <= 64, "too many operation reports");
    let (sha, run, attempt, repository, workflow) = identity;
    let mut provided = BTreeMap::new();
    for report in operations {
        ensure!(report.schema == 1 && report.tested_sha == sha && report.run_id == run
            && report.run_attempt == attempt && report.repository == repository
            && report.workflow_ref == workflow, "operation report belongs to a different run");
        ensure!(provided.insert((report.population.as_str(), report.scope.clone()), report).is_none(),
            "duplicate operation report scope");
    }
    let mut required_scopes = BTreeSet::new();
    let mut scoped_events: BTreeMap<EventScope, BTreeSet<String>> = BTreeMap::new();
    let mut total = 0;
    for census in censuses {
        ensure!(super::super::exact_sha(&census.baseline_commit)
            && census.census_sha256.len() == 64
            && census.census_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()), "invalid census binding");
        let ids = names(&census.ids)?;
        ensure!(!ids.is_empty(), "empty nonflat census");
        let contract = census.contract.as_ref().context("required execution contract is not source-closed")?;
        ensure!(!contract.scopes.is_empty() && contract.scopes.len() <= 11, "invalid event scope count");
        let entry_names: Vec<_> = contract.entries.iter().map(|entry| entry.id.clone()).collect();
        ensure!(names(&entry_names)? == ids, "execution contract inventory differs from census");
        let entries: BTreeMap<_, _> = contract.entries.iter().map(|entry| (entry.id.as_str(), entry)).collect();
        let mut covered = BTreeSet::new();
        for expected in &contract.scopes {
            let key = (census.population.as_str(), expected.scope.clone());
            ensure!(required_scopes.insert(key.clone()), "duplicate required event scope");
            let matching: Vec<_> = harnesses.iter().filter(|report| report_scope(report) == expected.scope).collect();
            ensure!(matching.len() == 1, "operation owner harness scope missing or duplicated");
            let harness = matching[0];
            super::validate_report(harness, (sha, run, attempt, &expected.scope.job,
                &expected.scope.platform, &expected.scope.profile))?;
            ensure!(harness.repository == repository && harness.workflow_ref == workflow,
                "operation owner provenance differs");
            let passed = passed_cases(harness);
            ensure!(passed.contains(&expected.owner_case_id), "operation owner did not pass");
            let report = provided.get(&key).context("required actual operation report missing")?;
            ensure!(report.baseline_commit == census.baseline_commit && report.census_sha256 == census.census_sha256,
                "operation census or baseline digest differs");
            ensure!(!expected.entry_ids.is_empty() && expected.entry_ids.len() <= 100_000
                && report.events.len() == expected.entry_ids.len(), "operation event count differs");
            let expected_names = names(&expected.entry_ids)?;
            ensure!(expected_names.is_subset(&ids), "operation contract refers to unknown census identity");
            covered.extend(expected_names.iter().copied());
            let mut seen = BTreeSet::new();
            for (index, (id, event)) in expected.entry_ids.iter().zip(&report.events).enumerate() {
                let entry = entries.get(id.as_str()).context("operation contract entry missing")?;
                ensure!(event.case_id == entry.id && event.sequence == index + 1
                    && seen.insert(event.case_id.as_str()), "operation identity or order differs");
                ensure!(event.parent_id == entry.parent_id
                    && (entry.parent_id == expected.owner_case_id || seen.contains(entry.parent_id.as_str()))
                    && entry.parent_id != entry.id, "operation parent did not execute before child");
                ensure!(!entry.obligation_ids.is_empty(), "operation obligations are not source-closed");
                same_names(&event.obligation_ids, &entry.obligation_ids)?;
                same_names(&event.invokes_ids, &entry.invokes_ids)?;
                ensure!(event.source == "execution" && event.outcome == CaseOutcome::Passed
                    && event.exit == 0 && event.cleanup_complete && event.assertions_complete,
                    "required operation execution or cleanup incomplete");
                let variants: Vec<_> = event.variants.iter().map(|variant| variant.id.clone()).collect();
                same_names(&variants, &entry.variant_ids)?;
                ensure!(event.variants.iter().all(|variant| variant.outcome == CaseOutcome::Passed),
                    "required operation variant failed");
                ensure!(census.population != "coverage" || !entry.checks.is_empty(), "scenario checks are not source-closed");
                let checks: Vec<_> = event.check_results.iter().map(|check| check.check_id.clone()).collect();
                let expected_checks: Vec<_> = entry.checks.iter().map(|check| check.id.clone()).collect();
                same_names(&checks, &expected_checks)?;
                for check in &entry.checks {
                    ensure!(!check.witness_ids.is_empty(), "scenario check witness relation is not closed");
                    let actual = event.check_results.iter().find(|actual| actual.check_id == check.id).unwrap();
                    same_names(&actual.witness_ids, &check.witness_ids)?;
                    ensure!(actual.outcome == CaseOutcome::Passed, "scenario check failed");
                }
                total += 1;
            }
            let all = scoped_events.entry(expected.scope.clone()).or_default();
            for event in &report.events {
                ensure!(all.insert(event.case_id.clone()), "operation identity duplicated across populations");
            }
        }
        ensure!(covered == ids, "nonflat census identity lacks an execution scope");
    }
    ensure!(required_scopes.len() == provided.len()
        && provided.keys().all(|key| required_scopes.contains(key)), "unexpected operation report scope");
    for report in operations {
        let harness = harnesses.iter().find(|harness| report_scope(harness) == report.scope).unwrap();
        let mut graph = BTreeMap::new();
        for event in operations.iter().filter(|other| other.scope == report.scope).flat_map(|other| &other.events) {
            let mut edges: BTreeSet<&str> = event.check_results.iter().flat_map(|check| check.witness_ids.iter().map(String::as_str))
                .filter(|id| scoped_events.get(&report.scope).is_some_and(|events| events.contains(*id))).collect();
            if scoped_events.get(&report.scope).is_some_and(|events| events.contains(&event.parent_id)) {
                edges.insert(event.parent_id.as_str());
            }
            graph.insert(event.case_id.as_str(), edges);
        }
        super::super::acyclic(&graph)?;
        let passed = passed_cases(harness);
        for event in &report.events {
            for check in &event.check_results {
                ensure!(check.witness_ids.iter().all(|id| passed.contains(id)
                    || scoped_events.get(&report.scope).is_some_and(|events| events.contains(id))),
                    "scenario check lacks actual same-scope passed witness");
            }
        }
    }
    Ok(total)
}

/// Load only the five named source-owned census artifacts; no producer metadata is proof.
pub(super) fn reconcile_operations(
    root: &Path, event_paths: &[PathBuf], harnesses: &[CollectedExecution],
    identity: (&str, &str, &str, &str, &str),
) -> Result<usize> {
    ensure!(event_paths.len() <= 64, "too many operation report paths");
    let censuses = load_censuses(root)?;
    let operations = event_paths.iter().map(|path| super::super::read_evidence(path))
        .collect::<Result<Vec<OperationReport>>>()?;
    validate_operation_reports(&censuses, &operations, harnesses, identity)
}

pub(super) fn load_censuses(root: &Path) -> Result<Vec<CensusContract>> {
    let mut censuses = Vec::new();
    for (population, file, key) in [
        ("oracle", "oracle-census.json", "cases"), ("engine", "engine-census.json", "cases"),
        ("runtime-preparation", "runtime-preparation-census.json", "sites"),
        ("coverage", "coverage-census.json", "scenarios"), ("native-stage", "native-stage-census.json", "stages"),
    ] {
        let path = root.join("tests").join(file);
        ensure!(!crate::identity::is_link(&path)? && fs::metadata(&path)?.len() <= 16 * 1024 * 1024,
            "invalid nonflat census file");
        use std::io::Read;
        let mut bytes = Vec::new();
        fs::File::open(&path)?.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16 * 1024 * 1024, "nonflat census grew beyond bound");
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        ensure!(value["schema"] == 1, "unsupported nonflat census schema");
        let mut ids = Vec::new();
        for entry in value[key].as_array().context("nonflat census records missing")? {
            ids.push(entry["id"].as_str().context("nonflat census identity missing")?.to_owned());
        }
        if population == "native-stage" {
            for entry in value["direct_post_bootstrap_checks"].as_array().context("native direct checks missing")? {
                ids.push(entry["id"].as_str().context("native direct identity missing")?.to_owned());
            }
        }
        let contract = value.get("execution_contract").filter(|value| !value.is_null())
            .map(|value| serde_json::from_value(value.clone())).transpose()?;
        censuses.push(CensusContract { population: population.into(),
            baseline_commit: value["baseline_commit"].as_str().context("census baseline missing")?.into(),
            census_sha256: format!("{:x}", Sha256::digest(&bytes)), ids, contract });
    }
    Ok(censuses)
}

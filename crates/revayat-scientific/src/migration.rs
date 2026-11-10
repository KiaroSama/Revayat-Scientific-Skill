//! Auditable one-to-one migration inventory. Counting new tests alone cannot
//! prove that an old scenario survived. Registration and scoped execution
//! witnesses are separate; neither certifies assertion equivalence by itself.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[path = "migration_execution.rs"]
pub mod execution;
pub use execution::{CaseOutcome, parse_test_execution};

#[derive(Clone, Debug, Deserialize)]
pub struct LegacyTest {
    pub id: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct Baseline {
    pub schema: u8,
    pub baseline_commit: String,
    pub public_test_count: usize,
    pub tests: Vec<LegacyTest>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub legacy_id: String,
    /// Integration test target plus fully qualified libtest function name.
    pub rust_test: String,
    /// Reviewed additional variants of this same baseline, never substitutes for the primary.
    #[serde(default)]
    pub additional_rust_tests: Vec<String>,
    /// Explain the behavior retained or interpreter-specific mechanism replaced.
    pub rationale: String,
    #[serde(default)]
    pub platforms: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationMap {
    pub schema: u8,
    pub mappings: Vec<Mapping>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityKind {
    Test,
    Stage,
    Check,
    AssertionHelper,
    OracleCase,
    RequirementSite,
    Scenario,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorIdentity {
    pub id: String,
    pub kind: IdentityKind,
    pub parent_ids: Vec<String>,
    pub invokes_ids: Vec<String>,
    pub obligation_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obligation {
    pub id: String,
    pub baseline_ids: Vec<String>,
    pub rust_test: String,
    pub assertions: Vec<String>,
    pub platforms: Vec<String>,
    pub tier: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorLedger {
    pub schema: u8,
    pub baseline_commit: String,
    pub identities: Vec<BehaviorIdentity>,
    pub obligations: Vec<Obligation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    Execution,
    Registration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Passed,
    Failed,
    Skipped,
    Cancelled,
    TimedOut,
    NotRun,
    Inconclusive,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionWitness {
    pub job: String,
    pub platform: String,
    pub tier: String,
    pub case_id: String,
    #[serde(deserialize_with = "required_parent")]
    pub parent_id: Option<String>,
    pub obligation_ids: Vec<String>,
    pub source: EvidenceSource,
    pub outcome: Outcome,
    pub exit: i32,
    pub cleanup_complete: bool,
}

// Explicit null denotes a reviewed top-level case; an omitted field is not that decision.
fn required_parent<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidence {
    pub schema: u8,
    pub tested_sha: String,
    pub run_id: String,
    pub witnesses: Vec<ExecutionWitness>,
}

fn unique_names<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<BTreeSet<&'a str>> {
    let mut names = BTreeSet::new();
    for value in values {
        ensure!(
            !value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control),
            "invalid migration identity"
        );
        ensure!(names.insert(value), "duplicate migration identity");
    }
    Ok(names)
}

fn exact_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn acyclic<'a>(graph: &BTreeMap<&'a str, BTreeSet<&'a str>>) -> Result<()> {
    let mut pending: BTreeMap<_, _> = graph.iter().map(|(id, edges)| (*id, edges.len())).collect();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (id, edges) in graph {
        for edge in edges {
            dependents.entry(*edge).or_default().push(*id);
        }
    }
    let mut ready: Vec<_> = pending
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect();
    let mut visited = 0;
    while let Some(id) = ready.pop() {
        visited += 1;
        for next in dependents.get(id).into_iter().flatten() {
            let count = pending
                .get_mut(next)
                .context("unknown behavior graph endpoint")?;
            *count -= 1;
            if *count == 0 {
                ready.push(*next);
            }
        }
    }
    ensure!(visited == graph.len(), "cyclic behavior identity relation");
    Ok(())
}

/// Validate one actual platform/tier slice against its incumbent identities and map.
/// This validates evidence structure/reconciliation, not the truth of an uploaded report.
pub fn audit_behavior(
    baseline: &Baseline,
    map: &MigrationMap,
    ledger: &BehaviorLedger,
    evidence: &ExecutionEvidence,
    tested_sha: &str,
    platform: &str,
    tier: &str,
) -> Result<usize> {
    ensure!(
        ledger.schema == 1 && evidence.schema == 1,
        "unsupported behavior schema"
    );
    ensure!(
        exact_sha(tested_sha) && evidence.tested_sha == tested_sha,
        "execution evidence has a stale or invalid tested SHA"
    );
    ensure!(
        exact_sha(&ledger.baseline_commit) && ledger.baseline_commit == baseline.baseline_commit,
        "behavior ledger uses a different baseline"
    );
    ensure!(
        ["linux", "macos", "windows"].contains(&platform) && !tier.is_empty(),
        "invalid execution scope"
    );
    unique_names([evidence.run_id.as_str()])?;
    unique_names([tier])?;
    ensure!(
        !ledger.identities.is_empty() && !ledger.obligations.is_empty(),
        "behavior inventory is empty"
    );
    ensure!(
        ledger.identities.len() <= 100_000
            && ledger.obligations.len() <= 100_000
            && evidence.witnesses.len() <= 100_000,
        "behavior inventory exceeds its record limit"
    );
    let ids = unique_names(
        ledger
            .identities
            .iter()
            .map(|identity| identity.id.as_str()),
    )?;
    let obligations = unique_names(ledger.obligations.iter().map(|value| value.id.as_str()))?;
    let registered = map
        .mappings
        .iter()
        .flat_map(|value| {
            std::iter::once(value.rust_test.clone())
                .chain(value.additional_rust_tests.iter().cloned())
        })
        .collect();
    let registration = audit(baseline, map, &registered, platform)?;
    ensure!(
        registration.pending.is_empty(),
        "behavior mapping is incomplete"
    );
    let mapped: BTreeMap<_, _> = map
        .mappings
        .iter()
        .map(|value| (value.legacy_id.as_str(), value))
        .collect();
    let mapped_cases: BTreeSet<_> = map
        .mappings
        .iter()
        .flat_map(|value| {
            std::iter::once(value.rust_test.as_str())
                .chain(value.additional_rust_tests.iter().map(String::as_str))
        })
        .collect();
    let identity_by_id: BTreeMap<_, _> = ledger
        .identities
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect();
    for legacy in &baseline.tests {
        let identity = identity_by_id
            .get(legacy.id.as_str())
            .context("baseline identity missing from behavior ledger")?;
        ensure!(
            identity.kind != IdentityKind::AssertionHelper,
            "mapped baseline identity relabeled as an assertion helper"
        );
    }
    let mut relations = BTreeMap::new();
    let mut calls = BTreeMap::new();
    for identity in &ledger.identities {
        let parents = unique_names(identity.parent_ids.iter().map(String::as_str))?;
        let invokes = unique_names(identity.invokes_ids.iter().map(String::as_str))?;
        let required = unique_names(identity.obligation_ids.iter().map(String::as_str))?;
        ensure!(
            parents.is_subset(&ids) && invokes.is_subset(&ids),
            "unknown identity relation"
        );
        ensure!(
            required.is_subset(&obligations),
            "unknown behavior obligation"
        );
        ensure!(
            identity.kind == IdentityKind::AssertionHelper || !required.is_empty(),
            "behavior identity has no obligations"
        );
        // Parent containment and call edges are distinct: a parent may invoke its child.
        relations.insert(identity.id.as_str(), parents);
        calls.insert(identity.id.as_str(), invokes);
    }
    // Check containment and calls separately; combining them invents parent/child cycles.
    acyclic(&relations)?;
    acyclic(&calls)?;
    let mut expected = BTreeMap::new();
    for obligation in &ledger.obligations {
        let owners = unique_names(obligation.baseline_ids.iter().map(String::as_str))?;
        ensure!(
            !owners.is_empty() && owners.is_subset(&ids),
            "unknown obligation owner"
        );
        ensure!(
            !obligation.assertions.is_empty()
                && obligation
                    .assertions
                    .iter()
                    .all(|assertion| !assertion.trim().is_empty()),
            "behavior obligation has no assertions"
        );
        let platforms = unique_names(obligation.platforms.iter().map(String::as_str))?;
        ensure!(
            platforms
                .iter()
                .all(|value| ["linux", "macos", "windows"].contains(value))
                && !obligation.tier.trim().is_empty(),
            "invalid obligation execution scope"
        );
        ensure!(
            mapped_cases.contains(obligation.rust_test.as_str()),
            "obligation counterpart is not in the migration map"
        );
        for owner in &owners {
            let identity = identity_by_id
                .get(owner)
                .context("unknown obligation owner")?;
            ensure!(
                identity.obligation_ids.contains(&obligation.id),
                "orphan behavior obligation"
            );
            if let Some(mapping) = mapped.get(owner) {
                ensure!(
                    mapping.rust_test == obligation.rust_test
                        || mapping
                            .additional_rust_tests
                            .contains(&obligation.rust_test),
                    "unrelated obligation counterpart"
                );
                ensure!(
                    mapping.platforms.is_empty()
                        || (!platforms.is_empty()
                            && platforms.iter().all(|value| {
                                mapping
                                    .platforms
                                    .iter()
                                    .any(|mapped| mapped.as_str() == *value)
                            })),
                    "obligation platform conflicts with its mapping"
                );
            }
        }
        if (platforms.is_empty() || platforms.contains(platform)) && obligation.tier == tier {
            expected.insert(obligation.id.as_str(), obligation.rust_test.as_str());
        }
    }
    let obligation_by_id: BTreeMap<_, _> = ledger
        .obligations
        .iter()
        .map(|value| (value.id.as_str(), value))
        .collect();
    for identity in &ledger.identities {
        for required in &identity.obligation_ids {
            ensure!(
                obligation_by_id[required.as_str()]
                    .baseline_ids
                    .contains(&identity.id),
                "obligation relation is not reciprocal"
            );
        }
    }
    for mapping in &map.mappings {
        for counterpart in std::iter::once(&mapping.rust_test).chain(&mapping.additional_rust_tests)
        {
            ensure!(
                ledger
                    .obligations
                    .iter()
                    .any(|obligation| obligation.rust_test == *counterpart
                        && obligation.baseline_ids.contains(&mapping.legacy_id)),
                "mapped primary or required supporting counterpart has no reciprocal obligation"
            );
        }
    }
    ensure!(
        !expected.is_empty(),
        "execution scope contains no behavior obligations"
    );
    let mut approved_parents: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for identity in &ledger.identities {
        let Some(child) = mapped.get(identity.id.as_str()) else {
            continue;
        };
        let child_cases = || {
            std::iter::once(child.rust_test.as_str())
                .chain(child.additional_rust_tests.iter().map(String::as_str))
        };
        for parent_id in &identity.parent_ids {
            if let Some(parent) = mapped.get(parent_id.as_str()) {
                for child_case in child_cases() {
                    approved_parents.entry(child_case).or_default().extend(
                        std::iter::once(parent.rust_test.as_str())
                            .chain(parent.additional_rust_tests.iter().map(String::as_str)),
                    );
                }
            }
        }
        for callee_id in &identity.invokes_ids {
            if let Some(callee) = mapped.get(callee_id.as_str()) {
                for callee_case in std::iter::once(callee.rust_test.as_str())
                    .chain(callee.additional_rust_tests.iter().map(String::as_str))
                {
                    approved_parents
                        .entry(callee_case)
                        .or_default()
                        .extend(child_cases());
                }
            }
        }
    }
    let all_cases = unique_names(
        evidence
            .witnesses
            .iter()
            .map(|value| value.case_id.as_str()),
    )?;
    let mut witness_parents = BTreeMap::new();
    let mut covered = BTreeSet::new();
    for witness in &evidence.witnesses {
        unique_names([witness.job.as_str()])?;
        unique_names([witness.case_id.as_str()])?;
        ensure!(
            witness.platform == platform && witness.tier == tier,
            "wrong witness scope"
        );
        ensure!(
            witness.parent_id.is_some() || !approved_parents.contains_key(witness.case_id.as_str()),
            "reviewed nested behavior requires an execution parent"
        );
        if let Some(parent) = &witness.parent_id {
            ensure!(
                parent != &witness.case_id && all_cases.contains(parent.as_str()),
                "unknown execution parent"
            );
            ensure!(
                approved_parents
                    .get(witness.case_id.as_str())
                    .is_some_and(|parents| parents.contains(parent.as_str())),
                "execution parent is not a reviewed containment or call relation"
            );
        }
        witness_parents.insert(
            witness.case_id.as_str(),
            witness.parent_id.as_deref().into_iter().collect(),
        );
        let claims = unique_names(witness.obligation_ids.iter().map(String::as_str))?;
        ensure!(!claims.is_empty(), "execution witness has no obligations");
        ensure!(
            witness.source == EvidenceSource::Execution
                && witness.outcome == Outcome::Passed
                && witness.exit == 0
                && witness.cleanup_complete,
            "behavior was not successfully executed and cleaned up"
        );
        for claim in claims {
            ensure!(
                expected.get(claim) == Some(&witness.case_id.as_str()),
                "execution witness claims an unknown or unrelated obligation"
            );
            ensure!(
                covered.insert(claim),
                "duplicate obligation execution claim"
            );
        }
    }
    acyclic(&witness_parents)?;
    ensure!(
        covered.len() == expected.len(),
        "required behavior has no execution witness"
    );
    Ok(covered.len())
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub baseline_commit: String,
    pub legacy_tests: usize,
    pub mapped_tests: usize,
    pub registered_rust_tests: usize,
    pub pending: Vec<String>,
    pub unavailable: Vec<String>,
}

/// Independent script inventories must not inflate preservation counts by
/// reusing a public test, another script's case, or a different historical base.
pub fn audit_censuses(censuses: &[(&Baseline, &MigrationMap)]) -> Result<()> {
    let (first, _) = censuses.first().context("migration census is empty")?;
    let mut legacy = BTreeSet::new();
    let mut registered = BTreeSet::new();
    for (baseline, map) in censuses {
        ensure!(
            baseline.baseline_commit == first.baseline_commit,
            "migration inventories refer to different baseline commits"
        );
        for test in &baseline.tests {
            ensure!(
                legacy.insert(test.id.as_str()),
                "legacy scenario counted in multiple inventories: {}",
                test.id
            );
        }
        for mapping in &map.mappings {
            ensure!(
                registered.insert(mapping.rust_test.as_str()),
                "independent inventories reuse a primary Rust test registration"
            );
            unique_names(
                std::iter::once(mapping.rust_test.as_str())
                    .chain(mapping.additional_rust_tests.iter().map(String::as_str)),
            )?;
        }
    }
    Ok(())
}

pub fn audit(
    baseline: &Baseline,
    map: &MigrationMap,
    registered: &BTreeSet<String>,
    platform: &str,
) -> Result<Report> {
    ensure!(
        baseline.schema == 1 && map.schema == 1,
        "unsupported migration schema"
    );
    ensure!(
        baseline.baseline_commit.len() == 40
            && baseline
                .baseline_commit
                .bytes()
                .all(|b| b.is_ascii_hexdigit()),
        "baseline requires exact commit identity"
    );
    let ids: BTreeSet<&str> = baseline.tests.iter().map(|t| t.id.as_str()).collect();
    ensure!(
        !ids.is_empty()
            && ids.len() == baseline.tests.len()
            && ids.len() == baseline.public_test_count,
        "baseline test inventory changed or contains duplicates"
    );
    let mut by_legacy = BTreeMap::new();
    let mut by_rust = BTreeSet::new();
    let mut unavailable = Vec::new();
    for mapping in &map.mappings {
        ensure!(
            ids.contains(mapping.legacy_id.as_str()),
            "unknown legacy test in migration mapping: {}",
            mapping.legacy_id
        );
        ensure!(
            by_legacy
                .insert(mapping.legacy_id.as_str(), mapping)
                .is_none(),
            "duplicate legacy mapping: {}",
            mapping.legacy_id
        );
        ensure!(
            by_rust.insert(mapping.rust_test.as_str()),
            "multiple baseline identities reuse a primary Rust counterpart"
        );
        unique_names(
            std::iter::once(mapping.rust_test.as_str())
                .chain(mapping.additional_rust_tests.iter().map(String::as_str)),
        )?;
        for counterpart in std::iter::once(&mapping.rust_test).chain(&mapping.additional_rust_tests)
        {
            if (mapping.platforms.is_empty()
                || mapping.platforms.iter().any(|value| value == platform))
                && !registered.contains(counterpart)
            {
                unavailable.push(counterpart.clone());
            }
        }
        ensure!(
            !mapping.rationale.trim().is_empty(),
            "migration rationale missing for {}",
            mapping.legacy_id
        );
        ensure!(
            mapping
                .platforms
                .iter()
                .all(|p| ["linux", "macos", "windows"].contains(&p.as_str())),
            "invalid migration platform"
        );
    }
    let pending = ids
        .into_iter()
        .filter(|id| !by_legacy.contains_key(id))
        .map(str::to_owned)
        .collect();
    Ok(Report {
        baseline_commit: baseline.baseline_commit.clone(),
        legacy_tests: baseline.public_test_count,
        mapped_tests: by_legacy.len(),
        registered_rust_tests: registered.len(),
        pending,
        unavailable,
    })
}

/// Query actual libtest executables produced by Cargo rather than searching
/// source strings which might be comments, uncompiled code or placeholders.
pub fn registered_tests(root: &Path) -> Result<BTreeSet<String>> {
    execution::registered_tests(root)
}

fn read_evidence<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    use std::io::Read;
    const LIMIT: u64 = 16 * 1024 * 1024;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "migration evidence exceeds byte limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

#[path = "migration_cli.rs"]
mod command;
pub use command::cli;

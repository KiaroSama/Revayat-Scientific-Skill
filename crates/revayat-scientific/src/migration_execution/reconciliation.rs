//! Report validation, behavioral reconciliation and hosted runner command contract.
use super::*;
use crate::migration::{
    BehaviorLedger, ExecutionEvidence, ExecutionWitness, audit_behavior, read_evidence,
};
use clap::Parser;

pub fn validate_report(
    collected: &CollectedExecution,
    identity: (&str, &str, &str, &str, &str, &str),
) -> Result<()> {
    let (sha, run, attempt, job, platform, profile) = identity;
    ensure!(
        collected.schema == 1
            && collected.tested_sha == sha
            && collected.run_id == run
            && collected.run_attempt == attempt
            && collected.job == job
            && collected.platform == platform
            && collected.profile == profile
            && ["debug", "release"].contains(&profile),
        "execution report belongs to a different run, job, platform, profile or checkout"
    );
    ensure!(
        ["portable", "scientific", "native"].contains(&collected.tier.as_str())
            && (collected.ignored_only == (collected.tier != "portable")),
        "invalid report tier or selection mode"
    );
    ensure!(
        !collected.final_parity_verified
            && collected.error.is_none()
            && collected.discovery_exit.is_none()
            && !collected.binaries.is_empty()
            && collected
                .binaries
                .iter()
                .any(|binary| !binary.cases.is_empty())
            && collected
                .binaries
                .iter()
                .all(|binary| binary.exit == Some(0)
                    && binary.cleanup_complete
                    && binary.error.is_none()),
        "incomplete or contradictory workspace execution report"
    );
    crate::migration::unique_names(
        collected
            .binaries
            .iter()
            .map(|binary| binary.target.as_str()),
    )?;
    crate::migration::unique_names(
        collected
            .binaries
            .iter()
            .filter_map(|binary| binary.mapping_target.as_deref()),
    )?;
    for binary in &collected.binaries {
        crate::migration::unique_names(binary.cases.keys().map(String::as_str))?;
    }
    super::selection::required_outcomes(collected)?;
    Ok(())
}

pub fn reconcile(
    root: &Path,
    ledger_path: &Path,
    report_path: &Path,
    census: &str,
    profile: &str,
) -> Result<usize> {
    let (sha, run, attempt, job) = checked_identity(root)?;
    let collected: CollectedExecution = read_evidence(report_path)?;
    validate_report(
        &collected,
        (&sha, &run, &attempt, &job, std::env::consts::OS, profile),
    )?;
    ensure!(
        collected.repository == hosted_label("GITHUB_REPOSITORY")?
            && collected.workflow_ref == hosted_label("GITHUB_WORKFLOW_REF")?,
        "execution report belongs to a different repository or workflow"
    );
    let ledger: BehaviorLedger = read_evidence(ledger_path)?;
    reconcile_collected(root, &ledger, &collected, census)
}

pub(super) fn reconcile_collected(
    root: &Path,
    ledger: &BehaviorLedger,
    collected: &CollectedExecution,
    census: &str,
) -> Result<usize> {
    let (prefix, map_name) = match census {
        "public" => ("migration", "rust-migration-map"),
        "upstream" => ("upstream", "upstream-rust-migration-map"),
        "security" => ("security", "security-rust-migration-map"),
        "verifier" => ("verifier", "verifier-rust-migration-map"),
        _ => bail!("unknown migration census"),
    };
    let baseline = read_evidence(&root.join(format!("tests/{prefix}-baseline.json")))?;
    let map = read_evidence(&root.join(format!("tests/{map_name}.json")))?;
    let nested: BTreeSet<_> = ledger
        .identities
        .iter()
        .flat_map(|identity| {
            identity
                .invokes_ids
                .iter()
                .map(String::as_str)
                .chain((!identity.parent_ids.is_empty()).then_some(identity.id.as_str()))
        })
        .collect();
    let mut witnesses: BTreeMap<String, ExecutionWitness> = BTreeMap::new();
    for obligation in &ledger.obligations {
        if obligation.tier != collected.tier
            || (!obligation.platforms.is_empty()
                && !obligation.platforms.contains(&collected.platform))
        {
            continue;
        }
        ensure!(
            !obligation
                .baseline_ids
                .iter()
                .any(|id| nested.contains(id.as_str())),
            "nested behavior requires an instrumented execution adapter"
        );
        let (target, case) = obligation
            .rust_test
            .split_once("::")
            .context("invalid counterpart identity")?;
        let binary = collected
            .binaries
            .iter()
            .find(|binary| {
                binary.mapping_target.as_deref() == Some(target) || binary.target == target
            })
            .context("required execution target missing")?;
        ensure!(
            binary.cases.get(case) == Some(&CaseOutcome::Passed),
            "required behavior did not execute successfully"
        );
        witnesses
            .entry(obligation.rust_test.clone())
            .or_insert_with(|| ExecutionWitness {
                job: collected.job.clone(),
                platform: collected.platform.clone(),
                tier: collected.tier.clone(),
                case_id: obligation.rust_test.clone(),
                parent_id: None,
                obligation_ids: Vec::new(),
                source: crate::migration::EvidenceSource::Execution,
                outcome: crate::migration::Outcome::Passed,
                exit: 0,
                cleanup_complete: true,
            })
            .obligation_ids
            .push(obligation.id.clone());
    }
    // Nested native stage/check witnesses need an instrumented adapter. Flat
    // libtest outcomes deliberately do not invent their parent execution.
    audit_behavior(
        &baseline,
        &map,
        ledger,
        &ExecutionEvidence {
            schema: 1,
            tested_sha: collected.tested_sha.clone(),
            run_id: collected.run_id.clone(),
            witnesses: witnesses.into_values().collect(),
        },
        &collected.tested_sha,
        &collected.platform,
        &collected.tier,
    )
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long, value_parser = ["portable", "scientific", "native"])]
    tier: Option<String>,
    #[arg(long, value_parser = ["debug", "release"])]
    profile: Option<String>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    ignored: bool,
    #[arg(long, default_value_t = 1800, value_parser = clap::value_parser!(u64).range(1..=3600))]
    timeout: u64,
    #[arg(long, conflicts_with = "aggregate", requires_all = ["ledger", "report"])]
    reconcile: bool,
    #[arg(long, requires_all = ["ledger", "report"])]
    aggregate: bool,
    #[arg(long)]
    ledger: Vec<PathBuf>,
    #[arg(long)]
    report: Vec<PathBuf>,
    /// Actual bound nonflat reports; only the complete public aggregate consumes them.
    #[arg(long, requires = "aggregate")]
    event_report: Vec<PathBuf>,
    #[arg(long, default_value = "public", value_parser = ["public", "upstream", "security", "verifier"])]
    census: String,
}

fn parsed_args(args: &[String]) -> Result<Args> {
    let args = Args::try_parse_from(
        std::iter::once("revayat-test-runner".to_owned()).chain(args.iter().cloned()),
    )?;
    if args.aggregate || args.reconcile {
        ensure!(
            args.tier.is_none() && args.output.is_none() && !args.ignored,
            "reconciliation cannot execute tests"
        );
        if args.aggregate {
            ensure!(args.event_report.is_empty() || args.census == "public",
                "operation reports belong to the complete public aggregate");
            ensure!(
                args.profile.is_none(),
                "aggregate selects its fixed profile matrix"
            );
        } else {
            ensure!(
                args.profile.is_some() && args.ledger.len() == 1 && args.report.len() == 1,
                "single reconciliation requires one ledger, one report and profile"
            );
        }
    } else {
        ensure!(
            args.profile.is_some() && args.ledger.is_empty() && args.report.is_empty(),
            "execution requires profile and cannot accept reconciliation inputs"
        );
        ensure!(
            args.tier.is_some() && args.output.is_some(),
            "execution tier and output path required"
        );
        ensure!(
            args.ignored == (args.tier.as_deref() != Some("portable")),
            "equipped execution requires --ignored; portable execution forbids it"
        );
    }
    Ok(args)
}

pub fn validate_runner_args(args: &[String]) -> Result<()> {
    parsed_args(args).map(|_| ())
}

pub fn cli(args: &[String]) -> Result<()> {
    let args = parsed_args(args)?;
    let root = args.root.canonicalize()?;
    let mut log = runtime::OperationLog::create("test-runner", &root.join("logs"), None)?;
    log.write(
        "INFO",
        "runner started; raw test diagnostics are not published",
    );
    let result = if args.aggregate {
        super::aggregate::aggregate(&root, &args.ledger, &args.report, &args.census, &args.event_report)
            .map(|count| println!("reconciled_obligations={count} final_parity_verified=false"))
    } else if args.reconcile {
        ensure!(
            args.tier.is_none() && args.output.is_none() && !args.ignored,
            "reconciliation cannot execute tests"
        );
        reconcile(
            &root,
            &args.ledger[0],
            &args.report[0],
            &args.census,
            args.profile.as_deref().context("profile required")?,
        )
        .map(|count| println!("reconciled_obligations={count} final_parity_verified=false"))
    } else {
        collect(
            &root,
            args.tier.as_deref().context("execution tier required")?,
            args.profile.as_deref().context("profile required")?,
            args.output.as_deref().context("output path required")?,
            args.ignored,
            Duration::from_secs(args.timeout),
        )
    };
    log.write(
        if result.is_ok() { "INFO" } else { "ERROR" },
        if result.is_ok() {
            "runner completed"
        } else {
            "runner failed; no final parity claim"
        },
    );
    result
}

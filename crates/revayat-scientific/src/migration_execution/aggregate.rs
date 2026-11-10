//! Required hosted execution scopes, independent of what artifacts happen to arrive.
use super::*;
use crate::migration::{BehaviorLedger, read_evidence};

fn required_scopes() -> BTreeSet<(String, String, String, String)> {
    let mut scopes = BTreeSet::new();
    for platform in ["linux", "macos", "windows"] {
        for profile in ["debug", "release"] {
            scopes.insert((
                "portable".into(),
                platform.into(),
                profile.into(),
                "portable".into(),
            ));
        }
    }
    for (platform, job) in [
        ("linux", "scientific"),
        ("macos", "portable"),
        ("windows", "portable"),
    ] {
        scopes.insert((
            "scientific".into(),
            platform.into(),
            "debug".into(),
            job.into(),
        ));
    }
    for (platform, job) in [("linux", "linux-security"), ("windows", "windows-security")] {
        scopes.insert(("native".into(), platform.into(), "debug".into(), job.into()));
    }
    scopes
}

/// Missing native reports remain blocking even while their instrumented adapter is unfinished.
pub fn validate_report_matrix(
    reports: &[CollectedExecution],
    identity: (&str, &str, &str, &str, &str),
) -> Result<()> {
    let (sha, run, attempt, repository, workflow_ref) = identity;
    let required = required_scopes();
    let mut actual = BTreeSet::new();
    for report in reports {
        ensure!(
            report.repository == repository && report.workflow_ref == workflow_ref,
            "execution report belongs to a different repository or workflow"
        );
        let scope = (
            report.tier.clone(),
            report.platform.clone(),
            report.profile.clone(),
            report.job.clone(),
        );
        ensure!(
            required.contains(&scope),
            "unexpected execution report scope"
        );
        ensure!(actual.insert(scope), "duplicate execution report scope");
        super::validate_report(
            report,
            (
                sha,
                run,
                attempt,
                &report.job,
                &report.platform,
                &report.profile,
            ),
        )?;
    }
    ensure!(
        actual == required,
        "required OS, profile or native execution report missing"
    );
    Ok(())
}

/// Every declared platform/tier must have an explicit required execution slot.
/// An empty platform list retains the ledger's all-platform meaning.
pub fn validate_obligation_scopes(ledger: &BehaviorLedger) -> Result<()> {
    let scopes = required_scopes();
    for obligation in &ledger.obligations {
        let platforms: Vec<&str> = if obligation.platforms.is_empty() {
            vec!["linux", "macos", "windows"]
        } else {
            obligation.platforms.iter().map(String::as_str).collect()
        };
        for platform in platforms {
            ensure!(
                scopes.iter().any(|(tier, supported, _, _)| {
                    tier == &obligation.tier && supported == platform
                }),
                "behavior obligation has no required execution scope: {} ({}/{platform})",
                obligation.id,
                obligation.tier
            );
        }
    }
    Ok(())
}

/// Merge explicitly selected ledger slices without weakening full-census validation.
pub fn aggregate(
    root: &Path,
    ledger_paths: &[PathBuf],
    report_paths: &[PathBuf],
    census: &str,
    event_paths: &[PathBuf],
) -> Result<usize> {
    ensure!(
        !ledger_paths.is_empty() && ledger_paths.len() <= 64,
        "invalid ledger count"
    );
    ensure!(
        report_paths.len() == required_scopes().len(),
        "required execution report count differs"
    );
    let (sha, run, attempt, _) = super::checked_identity(root)?;
    let reports = report_paths
        .iter()
        .map(|path| read_evidence(path))
        .collect::<Result<Vec<CollectedExecution>>>()?;
    validate_report_matrix(
        &reports,
        (
            &sha,
            &run,
            &attempt,
            &super::hosted_label("GITHUB_REPOSITORY")?,
            &super::hosted_label("GITHUB_WORKFLOW_REF")?,
        ),
    )?;
    let mut ledger: Option<BehaviorLedger> = None;
    for path in ledger_paths {
        let mut part: BehaviorLedger = read_evidence(path)?;
        if let Some(combined) = &mut ledger {
            ensure!(
                part.schema == combined.schema && part.baseline_commit == combined.baseline_commit,
                "ledger baseline differs"
            );
            combined.identities.append(&mut part.identities);
            combined.obligations.append(&mut part.obligations);
        } else {
            ledger = Some(part);
        }
    }
    let ledger = ledger.context("ledger required")?;
    crate::migration::unique_names(ledger.identities.iter().map(|value| value.id.as_str()))?;
    crate::migration::unique_names(ledger.obligations.iter().map(|value| value.id.as_str()))?;
    validate_obligation_scopes(&ledger)?;
    let mut verified = 0;
    let mut failures = Vec::new();
    if census == "public" {
        match super::events::reconcile_operations(root, event_paths, &reports, (
            &sha, &run, &attempt, &super::hosted_label("GITHUB_REPOSITORY")?,
            &super::hosted_label("GITHUB_WORKFLOW_REF")?,
        )) {
            Ok(count) => verified += count,
            Err(_) => failures.push("required nonflat operation evidence incomplete".into()),
        }
    } else {
        ensure!(event_paths.is_empty(), "operation reports belong to the complete public aggregate");
    }
    for report in &reports {
        if ledger.obligations.iter().any(|obligation| {
            obligation.tier == report.tier
                && (obligation.platforms.is_empty()
                    || obligation.platforms.contains(&report.platform))
        }) {
            // Reconciliation still rejects nested identities without actual native witnesses.
            match super::reconciliation::reconcile_collected(root, &ledger, report, census) {
                Ok(count) => verified += count,
                Err(_) => failures.push(format!(
                    "{}/{}/{}",
                    report.tier, report.platform, report.profile
                )),
            }
        }
    }
    ensure!(
        failures.is_empty(),
        "behavior reconciliation incomplete in scopes: {}",
        failures.join(", ")
    );
    ensure!(verified > 0, "no behavior obligations reconciled");
    Ok(verified)
}

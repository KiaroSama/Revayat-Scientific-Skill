//! Actual native execution. Flat outcomes never manufacture bootstrap/census events.
use super::*;
#[path = "native_coverage.rs"]
mod coverage;
pub use coverage::observe_linux_coverage;

pub(super) const LINUX_TARGET: &str = "crates/revayat-scientific/bin/revayat-security-worker";
const WINDOWS_TARGETS: &[&str] = &["windows_native", "windows_standalone"];

pub(super) fn validate_targets(artifacts: &[Artifact]) -> Result<()> {
    ensure!(
        WINDOWS_TARGETS.iter().all(|required| artifacts
            .iter()
            .any(|artifact| artifact.mapping_target.as_deref() == Some(*required))),
        "required native Windows harness missing"
    );
    Ok(())
}

pub(super) fn select(
    target: Option<&str>,
    all: &BTreeSet<String>,
    ignored: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    if !target.is_some_and(|target| WINDOWS_TARGETS.contains(&target)) {
        return Ok(BTreeSet::new());
    }
    ensure!(
        !all.is_empty() && ignored.is_empty(),
        "native Windows harness must execute every case"
    );
    Ok(all.clone())
}

pub(super) fn collect_linux(
    root: &Path,
    output: &Path,
    mut report: CollectedExecution,
    artifacts: &[Artifact],
    started: Instant,
    timeout: Duration,
) -> Result<()> {
    let observation = (|| -> Result<()> {
        let mut owners = artifacts
            .iter()
            .filter(|artifact| artifact.target == coverage::OWNER_TARGET);
        let owner = owners
            .next()
            .context("required actual Linux host owner missing")?;
        ensure!(owners.next().is_none(), "ambiguous Linux host owner");
        let remaining = || {
            timeout
                .checked_sub(started.elapsed())
                .context("native collection deadline exceeded")
        };
        let mut spec = command(
            &owner.directory,
            owner.executable.as_os_str(),
            remaining()?.min(Duration::from_secs(30)),
        );
        spec.args = ["--list", "--format", "terse"]
            .into_iter()
            .map(Into::into)
            .collect();
        let all = listed_cases(&spec)?;
        spec.args.push("--ignored".into());
        let ignored = listed_cases(&spec)?;
        ensure!(
            all.contains(coverage::OWNER_CASE) && ignored.contains(coverage::OWNER_CASE),
            "native coverage owner registration differs"
        );
        let capture = coverage::Capture::create()?;
        capture.configure(&mut spec)?;
        spec.timeout = remaining()?.min(Duration::from_secs(900));
        spec.args = [
            "--ignored",
            "--exact",
            coverage::OWNER_CASE,
            "--format",
            "pretty",
            "--color",
            "never",
            "--test-threads=1",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        let executed = match runtime::run_supervised(&spec) {
            Ok(output) => output,
            Err(_) => {
                capture.retain();
                report.error =
                    Some("native host owner execution or outer cleanup incomplete".into());
                return Err(anyhow::anyhow!("native host owner did not finish"));
            }
        };
        let owner_result = record_execution(
            owner,
            &executed,
            &[coverage::OWNER_CASE.into()].into(),
            all.len() - 1,
        );
        let observed = capture.finish(root, &report, &owner_result);
        report.binaries.push(owner_result);
        match observed {
            Ok((worker, events)) => {
                report.binaries.push(worker);
                if coverage::publish(output, &events).is_err() {
                    report.error =
                        Some("native coverage observation publication incomplete".into());
                }
            }
            Err(_) => report.error = Some(
                "native prerequisites, exact worker observations or coverage journal incomplete"
                    .into(),
            ),
        }
        Ok(())
    })();
    if observation.is_err() && report.error.is_none() {
        report.error = Some("native host owner discovery or bounded observation incomplete".into());
    }
    write_execution_report(output, &report)
}

fn linux_cases(helper: &serde_json::Value) -> Result<BTreeMap<String, CaseOutcome>> {
    let names = crate::security_cases::CASE_NAMES
        .iter()
        .copied()
        .collect::<BTreeMap<_, _>>();
    ensure!(
        names.len() == 36
            && names.keys().copied().collect::<BTreeSet<_>>()
                == crate::security_cases::IDS.iter().copied().collect(),
        "native worker counterpart inventory differs"
    );
    ensure!(
        helper["container_cleanup"] == "verified" && helper["preflight"]["status"] == "passed",
        "isolated worker qualification missing"
    );
    let rows = helper["cases"]
        .as_array()
        .context("actual isolated case outcomes missing")?;
    let mut cases = BTreeMap::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .context("isolated case identity missing")?;
        let name = *names.get(id).context("unknown isolated case")?;
        ensure!(
            row == &serde_json::json!({"phase":"security-case","id":id,"status":"passed"})
                && cases.insert(name.to_owned(), CaseOutcome::Passed).is_none(),
            "isolated case failed or duplicated"
        );
    }
    ensure!(
        cases.len() == names.len(),
        "isolated case execution incomplete"
    );
    Ok(cases)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn native_selection_requires_actual_nonignored_harnesses() {
        let all = BTreeSet::from(["one".into(), "two".into()]);
        assert_eq!(
            select(Some("windows_native"), &all, &BTreeSet::new()).unwrap(),
            all
        );
        assert!(select(Some("windows_native"), &all, &all).is_err());
        assert!(
            select(
                Some("windows_standalone"),
                &BTreeSet::new(),
                &BTreeSet::new()
            )
            .is_err()
        );
        assert!(
            select(Some("portable_model"), &all, &BTreeSet::new())
                .unwrap()
                .is_empty()
        );
        assert!(validate_targets(&[]).is_err());
    }
    pub(crate) fn worker_outcomes_require_real_qualification_and_each_exact_case() {
        coverage::tests::native_receipts_require_every_control_and_exact_witness();
        let mut helper = serde_json::json!({"container_cleanup":"verified", "preflight":{"status":"passed"},
            "cases":crate::security_cases::IDS.iter().map(|id|
                serde_json::json!({"phase":"security-case","id":id,"status":"passed"})).collect::<Vec<_>>()});
        assert_eq!(linux_cases(&helper).unwrap().len(), 36);
        helper["container_cleanup"] = serde_json::json!("unknown");
        assert!(linux_cases(&helper).is_err());
        helper["container_cleanup"] = serde_json::json!("verified");
        helper["cases"].as_array_mut().unwrap().pop();
        assert!(linux_cases(&helper).is_err());
        let duplicate = helper["cases"][0].clone();
        helper["cases"].as_array_mut().unwrap().push(duplicate);
        assert!(linux_cases(&helper).is_err());
    }
}

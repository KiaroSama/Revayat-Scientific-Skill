//! Existing libtest harness execution and owned optional nested observation capture.
use super::*;

pub(super) fn execute(
    artifact: &Artifact,
    identity: &CollectedExecution,
    root: &Path,
    started: Instant,
    timeout: Duration,
) -> Result<(Option<BinaryExecution>, Option<events::OperationReport>)> {
    let tier = identity.tier.as_str();
    let remaining = || {
        timeout
            .checked_sub(started.elapsed())
            .context("test collection deadline exceeded")
    };
    let mut spec = command(
        &artifact.directory,
        artifact.executable.as_os_str(),
        remaining()?.min(Duration::from_secs(30)),
    );
    spec.args = ["--list", "--format", "terse"]
        .into_iter()
        .map(Into::into)
        .collect();
    let all = listed_cases(&spec)?;
    spec.args.push("--ignored".into());
    spec.timeout = remaining()?.min(Duration::from_secs(30));
    let ignored = listed_cases(&spec)?;
    ensure!(
        ignored.is_subset(&all),
        "ignored discovery contradicts complete discovery"
    );
    let selected = if tier == "portable" {
        all.clone()
    } else if tier == "native" {
        super::native::select(artifact.mapping_target.as_deref(), &all, &ignored)?
    } else {
        select_equipped_cases(
            tier,
            std::env::consts::OS,
            artifact.mapping_target.as_deref(),
            &ignored,
        )?
    };
    if tier != "portable" && selected.is_empty() {
        return Ok((None, None));
    }
    let capture = super::oracle_capture::OracleCapture::create(artifact, tier)?;
    if let Some(capture) = &capture {
        capture.configure(&mut spec)?;
    }
    let groups: Vec<BTreeSet<String>> = if tier == "portable" {
        vec![selected]
    } else {
        selected.into_iter().map(|case| [case].into()).collect()
    };
    let mut combined: Option<BinaryExecution> = None;
    for expected in groups {
        spec.timeout = remaining()?.min(Duration::from_secs(900));
        spec.args = ["--format", "pretty", "--color", "never", "--test-threads=1"]
            .into_iter()
            .map(Into::into)
            .collect();
        if tier != "portable" {
            if tier == "scientific" {
                spec.args.push("--ignored".into());
            }
            spec.args
                .extend(["--exact".into(), expected.first().unwrap().as_str().into()]);
        }
        // A returned output includes direct wait, capture joins and owned tree/container finalization.
        let executed = match runtime::run_supervised(&spec) {
            Ok(executed) => executed,
            Err(_) => {
                let mut partial = combined.unwrap_or_else(|| BinaryExecution {
                    target: artifact.target.clone(),
                    mapping_target: artifact.mapping_target.clone(),
                    exit: None,
                    cleanup_complete: false,
                    cases: BTreeMap::new(),
                    error: None,
                });
                partial.cleanup_complete = false;
                if partial.exit == Some(0) {
                    partial.exit = None;
                }
                partial.error = Some("test execution or owned cleanup incomplete".into());
                // Do not reclaim the journal while an uncertain child could still access it.
                if let Some(capture) = capture {
                    capture.retain();
                }
                return Ok((Some(partial), None));
            }
        };
        let mut result = record_execution(
            artifact,
            &executed,
            &expected,
            if tier == "portable" { 0 } else { all.len() - 1 },
        );
        if let Some(previous) = &mut combined {
            previous.cases.append(&mut result.cases);
            if previous.exit == Some(0) {
                previous.exit = result.exit;
            }
            if previous.error.is_none() {
                previous.error = result.error;
            }
        } else {
            combined = Some(result);
        }
    }
    let operation = if let Some(capture) = capture {
        let binary = combined.as_mut().context("oracle carrier result missing")?;
        match capture.finish(root, identity, binary) {
            Ok(operation) => Some(operation),
            Err(_) => {
                if binary.error.is_none() {
                    binary.error = Some("oracle observation or journal cleanup incomplete".into());
                }
                None
            }
        }
    } else {
        None
    };
    Ok((combined, operation))
}

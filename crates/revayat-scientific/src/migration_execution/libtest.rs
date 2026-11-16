//! Strict stable-libtest outcome parsing, separate from registration listings.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseOutcome {
    Passed,
    Failed,
    Skipped,
}

/// Listing alone, missing cases and contradictory totals are never execution evidence.
pub fn parse_test_execution(
    bytes: &[u8],
    exit: i32,
    expected: &BTreeSet<String>,
) -> Result<BTreeMap<String, CaseOutcome>> {
    parse_filtered_execution(bytes, exit, expected, 0)
}

pub(super) fn parse_filtered_execution(
    bytes: &[u8],
    exit: i32,
    expected: &BTreeSet<String>,
    filtered: usize,
) -> Result<BTreeMap<String, CaseOutcome>> {
    let text = std::str::from_utf8(bytes).context("test result is not UTF-8")?;
    let mut cases = BTreeMap::new();
    let mut header = None;
    let mut summary = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("running ") {
            let count = value
                .strip_suffix(" tests")
                .or_else(|| value.strip_suffix(" test"));
            if let Some(count) = count {
                ensure!(
                    header.replace(count.parse::<usize>()?).is_none(),
                    "duplicate test header"
                );
            }
        }
        if let Some(line) = line.strip_prefix("test ")
            && let Some((name, result)) = line.split_once(" ... ")
        {
            // libtest decorates should-panic cases, but --list does not.
            let name = name.strip_suffix(" - should panic").unwrap_or(name);
            ensure!(expected.contains(name), "unregistered test result");
            let outcome = match result {
                "ok" => CaseOutcome::Passed,
                "FAILED" => CaseOutcome::Failed,
                "ignored" => CaseOutcome::Skipped,
                value if value.starts_with("ignored, ") => CaseOutcome::Skipped,
                _ => bail!("unsupported test result"),
            };
            ensure!(
                cases.insert(name.to_owned(), outcome).is_none(),
                "duplicate test result"
            );
        }
        if let Some(line) = line.strip_prefix("test result: ") {
            let (status, counts) = line.split_once(". ").context("invalid test summary")?;
            ensure!(
                ["ok", "FAILED"].contains(&status),
                "unknown test summary outcome"
            );
            let parts: Vec<_> = counts.split("; ").collect();
            ensure!(
                parts.len() == 6 && parts[5].starts_with("finished in "),
                "invalid test summary fields"
            );
            let mut values = Vec::new();
            for (part, suffix) in parts.iter().zip([
                " passed",
                " failed",
                " ignored",
                " measured",
                " filtered out",
            ]) {
                values.push(
                    part.strip_suffix(suffix)
                        .context("invalid test summary counts")?
                        .parse::<usize>()?,
                );
            }
            ensure!(summary.is_none(), "duplicate test summary");
            summary = Some((status == "ok", values));
        }
    }
    ensure!(
        header == Some(expected.len()),
        "test discovery/execution count mismatch"
    );
    ensure!(
        cases.len() == expected.len(),
        "registered tests did not all report a result"
    );
    let (success, counts) = summary.context("test execution summary missing")?;
    let passed = cases
        .values()
        .filter(|value| **value == CaseOutcome::Passed)
        .count();
    let failed = cases
        .values()
        .filter(|value| **value == CaseOutcome::Failed)
        .count();
    let skipped = cases
        .values()
        .filter(|value| **value == CaseOutcome::Skipped)
        .count();
    ensure!(
        counts == [passed, failed, skipped, 0, filtered],
        "test summary contradicts case results"
    );
    ensure!(
        success == (failed == 0) && success == (exit == 0),
        "test exit contradicts results"
    );
    Ok(cases)
}

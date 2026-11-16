//! Admit scanner/report agreement and emit only escaped location metadata.
use anyhow::{Result, ensure};
use serde_json::Value;

#[derive(Debug)]
pub struct Location {
    rule: String,
    file: String,
    line: u64,
    commit: String,
}

pub fn gitleaks_locations(
    code: i32,
    stdout: &[u8],
    stderr: &[u8],
    report: &[u8],
) -> Result<Vec<Location>> {
    ensure!(
        matches!(code, 0 | 2),
        "Gitleaks did not return a scan result"
    );
    ensure!(
        stdout.iter().all(u8::is_ascii_whitespace) && stderr.iter().all(u8::is_ascii_whitespace),
        "Gitleaks reported scanner diagnostics; no clean result recorded"
    );
    ensure!(
        report.len() <= 64 * 1024 * 1024,
        "Gitleaks report exceeds bound"
    );
    let report: Value = serde_json::from_slice(report)
        .map_err(|_| anyhow::anyhow!("invalid Gitleaks report JSON"))?;
    let findings = report
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Gitleaks report must be a list"))?;
    ensure!(
        (code == 2) != findings.is_empty(),
        "Gitleaks exit and report disagree"
    );
    ensure!(
        findings.len() <= 100_000,
        "Gitleaks finding count exceeds bound"
    );
    let mut locations = Vec::new();
    for finding in findings {
        let field = |key| {
            finding
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("invalid Gitleaks location metadata"))
        };
        let (rule, file, commit) = (field("RuleID")?, field("File")?, field("Commit")?);
        ensure!(
            !rule.is_empty()
                && rule.len() <= 128
                && rule
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid Gitleaks rule identifier"
        );
        ensure!(
            !file.is_empty() && file.len() <= 4096 && !file.contains('\0'),
            "invalid Gitleaks file location"
        );
        ensure!(
            commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid Gitleaks commit location"
        );
        let line = finding
            .get("StartLine")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("invalid Gitleaks line location"))?;
        locations.push(Location {
            rule: rule.into(),
            file: file.into(),
            line,
            commit: commit.into(),
        });
    }
    Ok(locations)
}

fn cell(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('|', "&#124;")
        .replace(['\n', '\r'], " ")
}

pub fn gitleaks_summary(findings: &[Location], scope: &str) -> Result<String> {
    ensure!(
        [super::FULL_SCOPE, super::PR_SCOPE].contains(&scope),
        "invalid Gitleaks summary scope"
    );
    let mut lines = vec!["## Gitleaks".into(), String::new(), format!("Scanner: **{}**", super::VERSION), String::new(), format!("Scope: **{scope}**"), String::new(), "Rules: Pinned built-in Gitleaks rules with standard exclusions. Full history describes revision coverage, not universal byte or credential coverage.".into(), String::new()];
    if findings.is_empty() {
        lines.push("No matching secrets were found in the scanned Git history.".into());
    } else {
        lines.extend([format!("**{} potential secrets detected.** Review the locations below; rotate any real exposed credentials.", findings.len()), String::new(), "Secret values, source snippets, and commit messages are never included in this summary.".into(), String::new(), "| Rule | File | Line | Commit |".into(), "| --- | --- | --- | --- |".into()]);
        for finding in findings.iter().take(200) {
            lines.push(format!(
                "| <code>{}</code> | <code>{}</code> | <code>{}</code> | <code>{}</code> |",
                cell(&finding.rule),
                cell(&finding.file),
                finding.line,
                cell(&finding.commit)
            ));
        }
        if findings.len() > 200 {
            lines.extend([String::new(), format!("Showing 200 of {} findings. Repeat the same version locally for the complete report.", findings.len())]);
        }
    }
    Ok(lines.join("\n") + "\n")
}

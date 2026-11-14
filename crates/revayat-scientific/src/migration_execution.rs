//! Stable-libtest outcomes, separate from registration and reviewed assertion obligations.
use super::exact_sha;
#[path = "migration_execution/reconciliation.rs"]
mod reconciliation;
pub use reconciliation::{cli, reconcile, validate_report, validate_runner_args};
#[path = "migration_execution/aggregate.rs"]
mod aggregate;
use crate::runtime::{self, CommandSpec};
pub use aggregate::{aggregate, validate_obligation_scopes, validate_report_matrix};
#[path = "migration_execution/events.rs"]
pub mod events;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[path = "migration_execution/libtest.rs"]
mod libtest;
use libtest::parse_filtered_execution;
pub use libtest::{CaseOutcome, parse_test_execution};
#[path = "migration_execution/native.rs"]
mod native;
pub use native::observe_linux_coverage;
#[path = "migration_execution/selection.rs"]
mod selection;
pub use selection::select_equipped_cases;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryExecution {
    /// Workspace-relative package, Cargo target kind and target name.
    pub target: String,
    /// Incumbent integration-test namespace, absent for unit/bin harnesses.
    pub mapping_target: Option<String>,
    pub exit: Option<i32>,
    /// Successful owned runtime-tree termination/reaping and container finalization.
    /// This is not an independent OS-wide post-kill membership scan.
    pub cleanup_complete: bool,
    pub cases: BTreeMap<String, CaseOutcome>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedExecution {
    pub schema: u8,
    pub tested_sha: String,
    pub run_id: String,
    pub run_attempt: String,
    pub repository: String,
    pub workflow_ref: String,
    pub job: String,
    pub platform: String,
    pub tier: String,
    /// Cargo profile of the actual discovered and executed harness artifacts.
    pub profile: String,
    /// Legacy equipped-mode flag: scientific uses ignored libtest cases;
    /// native executes its explicit, nonignored harnesses or isolated worker.
    pub ignored_only: bool,
    pub binaries: Vec<BinaryExecution>,
    /// Fixed category only; raw compiler or child diagnostics are never serialized.
    pub error: Option<String>,
    pub discovery_exit: Option<i32>,
    pub final_parity_verified: bool,
}

#[derive(Debug)]
pub struct Artifact {
    pub target: String,
    pub mapping_target: Option<String>,
    pub executable: PathBuf,
    pub directory: PathBuf,
}

fn command(root: &Path, program: impl Into<std::ffi::OsString>, timeout: Duration) -> CommandSpec {
    let mut spec = CommandSpec::new(program);
    spec.cwd = Some(root.to_owned());
    spec.timeout = timeout;
    spec.max_output = 16 * 1024 * 1024;
    // Discovery and unrelated subprocesses must never inherit a journal destination.
    spec.env_remove.push("REVAYAT_ORACLE_EVENT_DIR".into());
    spec.env_remove.push("REVAYAT_ENGINE_EVENT_DIR".into());
    spec.env_remove
        .push("REVAYAT_RUNTIME_PREPARATION_EVENT_DIR".into());
    spec.env_remove.push("REVAYAT_COVERAGE_EVENT_DIR".into());
    spec
}

fn hosted_label(key: &str) -> Result<String> {
    let value = std::env::var(key).with_context(|| format!("execution requires {key}"))?;
    ensure!(
        !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control),
        "invalid hosted execution provenance"
    );
    Ok(value)
}

fn checked_identity(root: &Path) -> Result<(String, String, String, String)> {
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"),
        "execution requires a hosted workflow"
    );
    let sha = std::env::var("GITHUB_SHA").context("execution requires GitHub tested SHA")?;
    let run = std::env::var("GITHUB_RUN_ID").context("execution requires GitHub run identity")?;
    let attempt =
        std::env::var("GITHUB_RUN_ATTEMPT").context("execution requires GitHub run attempt")?;
    let job = std::env::var("GITHUB_JOB").context("execution requires GitHub job identity")?;
    ensure!(
        exact_sha(&sha)
            && [run.as_str(), attempt.as_str()]
                .iter()
                .all(|value| !value.is_empty()
                    && value.len() <= 32
                    && value.bytes().all(|byte| byte.is_ascii_digit())),
        "invalid GitHub execution identity"
    );
    ensure!(
        !job.is_empty() && job.len() <= 256 && !job.chars().any(char::is_control),
        "invalid GitHub job identity"
    );
    let mut spec = command(root, "git", Duration::from_secs(10));
    spec.args = vec!["rev-parse".into(), "HEAD".into()];
    let output = runtime::run(&spec)?;
    ensure!(
        output.success() && std::str::from_utf8(&output.stdout)?.trim() == sha,
        "checkout differs from GitHub tested SHA"
    );
    Ok((sha, run, attempt, job))
}

fn binaries(root: &Path, profile: &str, timeout: Duration) -> Result<Vec<Artifact>> {
    let mut spec = command(root, "cargo", timeout);
    spec.args = [
        "test",
        "--workspace",
        "--all-targets",
        "--locked",
        "--no-run",
        "--message-format=json",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    ensure!(
        ["debug", "release"].contains(&profile),
        "unknown execution profile"
    );
    if profile == "release" {
        spec.args.push("--release".into());
    }
    let started = Instant::now();
    let output = runtime::run(&spec).context("bounded test artifact discovery failed")?;
    if !output.success() {
        return Err(TestExecutionFailure {
            exit: Some(output.code),
            report_published: false,
        }
        .into());
    }
    spec.timeout = timeout
        .checked_sub(started.elapsed())
        .context("Cargo discovery deadline exceeded")?;
    spec.args = ["metadata", "--locked", "--no-deps", "--format-version", "1"]
        .into_iter()
        .map(Into::into)
        .collect();
    let metadata = runtime::run(&spec).context("bounded Cargo metadata failed")?;
    if !metadata.success() {
        return Err(TestExecutionFailure {
            exit: Some(metadata.code),
            report_published: false,
        }
        .into());
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).context("Cargo metadata JSON is invalid")?;
    let target = metadata["target_directory"]
        .as_str()
        .context("Cargo target directory missing")?;
    parse_test_artifacts(root, Path::new(target), &output.stdout, profile)
        .context("Cargo artifact selection failed")
}

/// Authored discovery stages and numeric OS errors only; never child diagnostics or paths.
pub fn discovery_failure_summary(error: &anyhow::Error) -> String {
    failure_summary(error, 0)
}
fn failure_summary(error: &anyhow::Error, depth: usize) -> String {
    let stages = [
        (
            "test artifact has an unsupported Cargo layout",
            "artifact-layout",
        ),
        (
            "test artifact leaves Cargo target directory",
            "artifact-root",
        ),
        (
            "test artifact does not belong to the requested Cargo profile",
            "artifact-profile",
        ),
        (
            "test artifact is outside the workspace",
            "artifact-workspace",
        ),
        ("invalid test artifact count", "artifact-count"),
        ("Cargo target directory missing", "target-directory"),
        ("test package manifest missing", "manifest"),
        ("Cargo metadata JSON is invalid", "metadata-json"),
        ("Cargo artifact JSON is invalid", "artifact-json"),
        ("bounded Cargo metadata failed", "metadata-run"),
        ("Cargo artifact selection failed", "artifact-selection"),
        ("bounded test artifact discovery failed", "cargo-run"),
        ("Cargo discovery deadline exceeded", "deadline"),
        ("discovery deadline exceeded", "deadline"),
    ];
    let stage = stages
        .iter()
        .find_map(|(message, label)| {
            error
                .chain()
                .any(|cause| cause.to_string() == *message)
                .then_some(*label)
        })
        .unwrap_or("unknown");
    let mut result = format!("stage={stage}");
    for cause in error.chain() {
        let message = cause.to_string();
        for (text, category) in [
            ("cannot start owned external tool", "spawn"),
            ("cannot start Unix runtime companion", "companion-spawn"),
            ("owned external tool is missing", "missing-tool"),
            ("ownership protocol deadline exceeded", "transport-deadline"),
            ("ownership protocol disconnected", "transport-disconnected"),
            (
                "runtime companion response deadline exceeded",
                "response-deadline",
            ),
            (
                "runtime companion disconnected without complete cleanup frame",
                "completion-disconnected",
            ),
            ("ownership response exceeds byte limit", "response-limit"),
            ("runtime companion cleanup incomplete", "cleanup-incomplete"),
            ("runtime caller cancelled or disconnected", "cancelled"),
        ] {
            if message == text {
                result.push_str(&format!(" runtime={category}"));
            }
        }
        if let Some(limit) = message
            .strip_prefix("tool diagnostics exceeded ")
            .and_then(|value| value.strip_suffix(" byte limit"))
            .and_then(|value| value.parse::<u32>().ok())
        {
            result.push_str(&format!(" runtime=output-limit limit={limit}"));
        }
        for operation in ["status-query", "group-cleanup", "child-reap", "unknown"] {
            let prefix = format!("owned runtime operation failed (operation-{operation}");
            if message == format!("{prefix})") {
                result.push_str(&format!(" runtime={operation}"));
            } else if let Some(number) = message
                .strip_prefix(&format!("{prefix}-os-"))
                .and_then(|value| value.strip_suffix(')'))
                .and_then(|value| value.parse::<i32>().ok())
            {
                result.push_str(&format!(" runtime={operation} os_error={number}"));
            }
        }
    }
    if let Some(number) = error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
    {
        result.push_str(&format!(" os_error={number}"));
    }
    if error.downcast_ref::<runtime::CleanupFailure>().is_some() {
        result.push_str(" cleanup_uncertain=true");
    }
    if depth < 3
        && let Some(cleanup) = error.downcast_ref::<runtime::CleanupFailure>()
    {
        result.push_str(" cleanup_detail=[");
        result.push_str(&failure_summary(&cleanup.0, depth + 1));
        result.push(']');
    }
    result
}

/// Cargo compiler-artifact messages, not human stderr or executable filename guesses.
pub fn parse_test_artifacts(
    root: &Path,
    target_directory: &Path,
    bytes: &[u8],
    profile: &str,
) -> Result<Vec<Artifact>> {
    ensure!(
        ["debug", "release"].contains(&profile),
        "unknown execution profile"
    );
    let root = root.canonicalize()?;
    ensure!(
        target_directory.is_absolute(),
        "Cargo target directory must be absolute"
    );
    let target_root = target_directory
        .canonicalize()
        .context("Cargo target directory missing")?;
    let mut found: BTreeMap<PathBuf, Artifact> = BTreeMap::new();
    let mut names = BTreeSet::new();
    for line in bytes
        .split(|value| *value == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: serde_json::Value =
            serde_json::from_slice(line).context("Cargo artifact JSON is invalid")?;
        if value["reason"] != "compiler-artifact" || value["profile"]["test"] != true {
            continue;
        }
        let Some(executable) = value["executable"].as_str() else {
            continue;
        };
        let name = value["target"]["name"]
            .as_str()
            .context("test target identity missing")?;
        super::unique_names([name])?;
        let kinds = value["target"]["kind"]
            .as_array()
            .context("test target kind missing")?;
        ensure!(kinds.len() == 1, "ambiguous Cargo target kind");
        let kind = kinds[0].as_str().context("invalid Cargo target kind")?;
        ensure!(
            ["lib", "bin", "test", "example", "bench", "proc-macro"].contains(&kind),
            "unsupported Cargo target kind"
        );
        let executable = Path::new(executable).canonicalize()?;
        let directory = crate::executable_paths::test_profile_directory(&executable)
            .context("test artifact has an unsupported Cargo layout")?;
        let relative = directory
            .strip_prefix(&target_root)
            .context("test artifact leaves Cargo target directory")?;
        ensure!(
            matches!(relative.components().count(), 1 | 2)
                && directory.file_name() == Some(std::ffi::OsStr::new(profile)),
            "test artifact does not belong to the requested Cargo profile"
        );
        let manifest = Path::new(
            value["manifest_path"]
                .as_str()
                .context("test package manifest missing")?,
        )
        .canonicalize()?;
        let directory = manifest
            .parent()
            .context("test package directory missing")?
            .to_owned();
        ensure!(
            executable.starts_with(&target_root)
                && executable.is_file()
                && directory.starts_with(&root),
            "test artifact is outside the workspace"
        );
        let package = directory
            .strip_prefix(&root)?
            .to_str()
            .context("non-UTF-8 package identity")?
            .replace('\\', "/");
        let target = format!("{package}/{kind}/{name}");
        let mapping_target =
            (kind == "test" && package == "crates/revayat-scientific").then(|| name.to_owned());
        if let Some(previous) = found.get(&executable) {
            ensure!(
                previous.target == target,
                "one executable claimed by unrelated Cargo targets"
            );
        } else {
            ensure!(
                names.insert(target.clone()),
                "duplicate Cargo test target identity"
            );
            found.insert(
                executable.clone(),
                Artifact {
                    target,
                    mapping_target,
                    executable,
                    directory,
                },
            );
        }
    }
    ensure!(
        !found.is_empty() && found.len() <= 1024,
        "invalid test artifact count"
    );
    Ok(found.into_values().collect())
}

fn listed_cases(spec: &CommandSpec) -> Result<BTreeSet<String>> {
    let listed = runtime::run(spec)?;
    ensure!(listed.success(), "test registration listing failed");
    let mut expected = BTreeSet::new();
    for line in std::str::from_utf8(&listed.stdout)?.lines() {
        if let Some(case) = line.strip_suffix(": test") {
            ensure!(
                !case.is_empty()
                    && case.len() <= 4096
                    && !case.chars().any(char::is_control)
                    && expected.insert(case.to_owned()),
                "invalid or duplicate registered test"
            );
        } else {
            // A custom harness or benchmark needs its own actual-outcome adapter.
            ensure!(line.is_empty(), "unsupported test registration output");
        }
    }
    Ok(expected)
}

/// Explicit registration-only callers reuse owned discovery/listing, never infer execution.
pub fn registered_tests(root: &Path) -> Result<BTreeSet<String>> {
    let started = Instant::now();
    let timeout = Duration::from_secs(1800);
    let artifacts = binaries(root, "debug", timeout)?;
    let mut registered = BTreeSet::new();
    for artifact in artifacts {
        let remaining = timeout
            .checked_sub(started.elapsed())
            .context("test registration deadline exceeded")?;
        let mut spec = command(
            &artifact.directory,
            artifact.executable.as_os_str(),
            remaining.min(Duration::from_secs(30)),
        );
        spec.args = ["--list", "--format", "terse"]
            .into_iter()
            .map(Into::into)
            .collect();
        for case in listed_cases(&spec)? {
            registered.insert(format!("{}::{case}", artifact.target));
            if let Some(alias) = &artifact.mapping_target {
                registered.insert(format!("{alias}::{case}"));
            }
        }
    }
    Ok(registered)
}

#[path = "migration_execution/harness.rs"]
mod harness;
#[path = "migration_execution/oracle_capture.rs"]
mod oracle_capture;

/// Retain known named outcomes and original exit on invalid summaries, never raw child text.
/// The fixed error keeps these partial observations ineligible for reconciliation.
pub fn record_execution(
    artifact: &Artifact,
    executed: &runtime::CommandOutput,
    expected: &BTreeSet<String>,
    filtered: usize,
) -> BinaryExecution {
    let parsed = parse_filtered_execution(&executed.stdout, executed.code, expected, filtered);
    let (cases, error) = match parsed {
        Ok(cases) => (cases, None),
        Err(_) => {
            let mut cases = BTreeMap::new();
            let mut duplicated = BTreeSet::new();
            if let Ok(text) = std::str::from_utf8(&executed.stdout) {
                for line in text.lines() {
                    let Some((name, result)) = line
                        .strip_prefix("test ")
                        .and_then(|line| line.split_once(" ... "))
                    else {
                        continue;
                    };
                    let name = name.strip_suffix(" - should panic").unwrap_or(name);
                    if !expected.contains(name) || duplicated.contains(name) {
                        continue;
                    }
                    let outcome = match result {
                        "ok" => CaseOutcome::Passed,
                        "FAILED" => CaseOutcome::Failed,
                        "ignored" => CaseOutcome::Skipped,
                        value if value.starts_with("ignored, ") => CaseOutcome::Skipped,
                        _ => continue,
                    };
                    if cases.insert(name.to_owned(), outcome).is_some() {
                        cases.remove(name);
                        duplicated.insert(name.to_owned());
                    }
                }
            }
            (cases, Some("test outcome validation incomplete".into()))
        }
    };
    BinaryExecution {
        target: artifact.target.clone(),
        mapping_target: artifact.mapping_target.clone(),
        exit: Some(executed.code),
        cleanup_complete: true,
        cases,
        error,
    }
}

/// Execute ordinary harnesses once, or the explicitly selected equipped cases.
/// Environment identity is workflow binding, not cryptographic report authentication.
pub fn collect(
    root: &Path,
    tier: &str,
    profile: &str,
    output: &Path,
    ignored_only: bool,
    timeout: Duration,
) -> Result<()> {
    ensure!(
        std::env::var_os("REVAYAT_RUNTIME_GROUP").is_none(),
        "collector must own its process groups, not borrow a CLI worker group"
    );
    ensure!(
        ["portable", "scientific", "native"].contains(&tier),
        "unknown test execution tier"
    );
    ensure!(
        !timeout.is_zero() && timeout <= Duration::from_secs(3600),
        "invalid execution deadline"
    );
    let started = Instant::now();
    let (tested_sha, run_id, run_attempt, job) = checked_identity(root)?;
    let mut report = CollectedExecution {
        schema: 1,
        tested_sha,
        run_id,
        run_attempt,
        repository: hosted_label("GITHUB_REPOSITORY")?,
        workflow_ref: hosted_label("GITHUB_WORKFLOW_REF")?,
        job,
        platform: std::env::consts::OS.into(),
        tier: tier.into(),
        profile: profile.into(),
        ignored_only,
        binaries: Vec::new(),
        error: None,
        discovery_exit: None,
        final_parity_verified: false,
    };
    if (tier == "portable") == ignored_only {
        report.error = Some("execution tier and ignored selection contradict".into());
        return write_execution_report(output, &report);
    }
    if tier == "native"
        && (profile != "debug" || !["linux", "windows"].contains(&std::env::consts::OS))
    {
        report.error = Some("native execution requires a supported debug scope".into());
        return write_execution_report(output, &report);
    }
    let artifacts = match timeout
        .checked_sub(started.elapsed())
        .context("discovery deadline exceeded")
        .and_then(|remaining| binaries(root, profile, remaining))
    {
        Ok(artifacts) => artifacts,
        Err(error) => {
            report.discovery_exit = error
                .downcast_ref::<TestExecutionFailure>()
                .and_then(|failure| failure.exit);
            let summary = discovery_failure_summary(&error);
            eprintln!("test-discovery: {summary}");
            report.error = Some(format!(
                "Cargo discovery, deadline or owned cleanup incomplete: {}",
                summary
            ));
            return write_execution_report(output, &report);
        }
    };
    selection::validate_collection_targets(&artifacts, &mut report, output)?;
    if tier == "native" && cfg!(target_os = "linux") {
        return native::collect_linux(root, output, report, &artifacts, started, timeout);
    }
    if tier == "native" && native::validate_targets(&artifacts).is_err() {
        report.error = Some("required native Windows harness missing".into());
        return write_execution_report(output, &report);
    }
    let mut interrupted = false;
    let mut operations = Vec::new();
    for artifact in artifacts {
        let result = if interrupted {
            Err(anyhow::anyhow!("earlier binary execution was inconclusive"))
        } else {
            harness::execute(&artifact, &report, root, started, timeout)
        };
        report.binaries.push(match result {
            Ok((Some(binary), operation)) => {
                interrupted |= !binary.cleanup_complete;
                operations.extend(operation);
                binary
            }
            Ok((None, _)) => continue,
            Err(_) => {
                // Do not launch further work after an uncertain cleanup/timeout.
                interrupted = true;
                BinaryExecution {
                    target: artifact.target,
                    mapping_target: artifact.mapping_target,
                    exit: None,
                    cleanup_complete: false,
                    cases: BTreeMap::new(),
                    error: Some("test execution, cleanup or result validation incomplete".into()),
                }
            }
        });
    }
    if tier == "portable"
        && oracle_capture::publish_all(root, output, &report, &operations).is_err()
    {
        report.error = Some("operation evidence or publication incomplete".into());
    }
    write_execution_report(output, &report)
}

#[derive(Debug)]
pub struct TestExecutionFailure {
    pub exit: Option<i32>,
    pub report_published: bool,
}
impl std::fmt::Display for TestExecutionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "test execution failed: test_exit={}; report_published={}",
            self.exit
                .map_or_else(|| "unknown".into(), |exit| exit.to_string()),
            self.report_published
        )
    }
}
impl std::error::Error for TestExecutionFailure {}

/// Publish all safe per-case outcomes even on failure, without replacing a prior report.
/// Test failure remains primary if publishing the diagnostic report also fails.
pub fn write_execution_report(path: &Path, value: &CollectedExecution) -> Result<()> {
    let failure = value
        .binaries
        .iter()
        .find(|binary| binary.exit.is_some_and(|exit| exit != 0));
    let complete = value.error.is_none()
        && selection::required_outcomes(value).is_ok()
        && value.discovery_exit.is_none()
        && !value.binaries.is_empty()
        && value.binaries.iter().any(|binary| !binary.cases.is_empty())
        && value.binaries.iter().all(|binary| {
            binary.error.is_none() && binary.exit == Some(0) && binary.cleanup_complete
        });
    let published = write_report(path, value);
    if !complete {
        return Err(TestExecutionFailure {
            exit: value
                .discovery_exit
                .or_else(|| failure.and_then(|binary| binary.exit)),
            report_published: published.is_ok(),
        }
        .into());
    }
    published
}

fn write_report(path: &Path, value: &CollectedExecution) -> Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "execution report exceeds byte limit"
    );
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("execution report already exists or cannot publish"))?;
    Ok(())
}

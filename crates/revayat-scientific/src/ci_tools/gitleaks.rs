//! Checksum-pinned, private Git-history scanning with an actual-child receipt.
#[path = "gitleaks_archive.rs"]
mod archive;
#[path = "gitleaks_git.rs"]
mod git_child;
#[path = "gitleaks_report.rs"]
mod report;
use crate::runtime::{CommandOutput, CommandSpec};
use anyhow::{Context, Result, ensure};
pub use git_child::{gitleaks_git_main, verify_gitleaks_history};
pub use report::{gitleaks_locations, gitleaks_summary};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(super) const VERSION: &str = "8.30.1";
const SHA256: &str = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb";
const URL: &str = "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz";
const DOWNLOAD_LIMIT: u64 = 16 * 1024 * 1024;
pub(super) const FULL_SCOPE: &str =
    "All fetched branches and tags, including full history and merge diffs";
pub(super) const PR_SCOPE: &str = "Commits introduced by this pull request, including merge diffs";

struct PrivateFailure {
    phase: &'static str,
    _cause: anyhow::Error,
}
impl std::fmt::Display for PrivateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Gitleaks {} failed; no clean result was recorded",
            self.phase
        )
    }
}
impl std::fmt::Debug for PrivateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for PrivateFailure {}
fn private<T>(phase: &'static str, value: Result<T>) -> Result<T> {
    value.map_err(|cause| {
        PrivateFailure {
            phase,
            _cause: cause,
        }
        .into()
    })
}

pub(super) fn token() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub(super) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !crate::identity::is_link(path)? && metadata.len() <= limit,
        "invalid bounded scan artifact"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(metadata.nlink() == 1, "linked scan artifact refused");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "scan artifact grew beyond bound"
    );
    Ok(bytes)
}
fn log(level: &str, message: &str) -> Result<()> {
    ensure!(
        ["INFO", "WARNING", "ERROR", "DEBUG"].contains(&level),
        "unsupported scan log level"
    );
    let stamp =
        crate::runtime::utc_timestamp(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    println!("{stamp} [{level}] {message}");
    Ok(())
}

/// Return fixed scope flags and validated PR revisions, never event/source text.
pub fn gitleaks_log_options(
    event: &str,
    event_json: Option<&Value>,
) -> Result<(String, &'static str, Vec<String>)> {
    ensure!(
        ["push", "pull_request", "schedule", "workflow_dispatch"].contains(&event),
        "unsupported Gitleaks workflow event"
    );
    let mut options =
        "--full-history --diff-filter=uxdb --no-ext-diff --no-textconv --ignore-submodules=all -m"
            .to_owned();
    if event == "pull_request" {
        let event = event_json.context("pull request event is required")?;
        let revision = |side| -> Result<String> {
            let value = event["pull_request"][side]["sha"]
                .as_str()
                .context("pull request revision missing")?;
            ensure!(
                value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid pull request revision"
            );
            Ok(value.to_owned())
        };
        let (base, head) = (revision("base")?, revision("head")?);
        options.push_str(&format!(" {base}..{head}"));
        Ok((options, PR_SCOPE, vec![base, head]))
    } else {
        options.push_str(" --all");
        Ok((options, FULL_SCOPE, Vec::new()))
    }
}

fn controlled(mut command: CommandSpec, seconds: u64) -> Result<CommandOutput> {
    command.timeout = Duration::from_secs(seconds);
    command.max_output = 2 * 1024 * 1024;
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with("GIT_") || key.starts_with("GITLEAKS_"))
        {
            command.env_remove.push(key);
        }
    }
    command.env.extend([
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        (
            "GIT_CONFIG_GLOBAL".into(),
            if cfg!(windows) { "NUL" } else { "/dev/null" }.into(),
        ),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ("GIT_PAGER".into(), "".into()),
    ]);
    crate::runtime::run(&command)
}
fn download(directory: &Path) -> Result<PathBuf> {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let mut response = client.get(URL).send()?.error_for_status()?;
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= DOWNLOAD_LIMIT),
        "Gitleaks download exceeds bound"
    );
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(DOWNLOAD_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    super::automation::verified_download(&bytes, DOWNLOAD_LIMIT, SHA256)?;
    let bytes = archive::executable(&bytes)?;
    let binary = directory.join("gitleaks");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&binary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
    }
    let version = controlled(CommandSpec::new(binary.as_os_str()).args(["version"]), 15)?;
    ensure!(
        version.code == 0
            && version.stdout_text().trim() == VERSION
            && version.stderr.iter().all(u8::is_ascii_whitespace),
        "Gitleaks executable version could not be verified"
    );
    Ok(binary)
}
fn scan(directory: &Path, workspace: &Path, event: &str) -> Result<i32> {
    let repository = workspace.join(".git");
    ensure!(
        repository.is_dir() && !crate::identity::is_link(&repository)?,
        "complete Git checkout unavailable"
    );
    let binary = download(directory)?;
    log(
        "INFO",
        "Verified the scanner version and download checksum.",
    )?;
    let git = crate::runtime::executable("git")?;
    let event_json = if event == "pull_request" {
        Some(serde_json::from_slice::<Value>(&read_bounded(
            &PathBuf::from(
                std::env::var_os("GITHUB_EVENT_PATH").context("GitHub event file missing")?,
            ),
            1024 * 1024,
        )?)?)
    } else {
        None
    };
    let (options, scope, revisions) = gitleaks_log_options(event, event_json.as_ref())?;
    // Explicitly reject a shallow checkout rather than silently certify partial history.
    let mut check = CommandSpec::new(git.as_os_str())
        .args(["--no-replace-objects", "-C"])
        .args([repository.as_os_str()])
        .args(["rev-parse", "--is-shallow-repository"]);
    let complete = controlled(check.clone(), 15)?;
    ensure!(
        complete.code == 0 && complete.stdout_text().trim() == "false",
        "complete Git history unavailable"
    );
    for revision in revisions {
        check.args = vec![
            "--no-replace-objects".into(),
            "-C".into(),
            repository.as_os_str().to_owned(),
            "cat-file".into(),
            "-e".into(),
            format!("{revision}^{{commit}}").into(),
        ];
        let result = controlled(check.clone(), 15)?;
        ensure!(
            result.success(),
            "pull request revision missing from complete checkout"
        );
    }
    let wrapper = std::env::current_exe()?
        .parent()
        .context("native tool directory missing")?
        .join(format!(
            "revayat-gitleaks-git{}",
            std::env::consts::EXE_SUFFIX
        ));
    ensure!(
        wrapper.is_file() && !crate::identity::is_link(&wrapper)?,
        "native Git stream adapter missing"
    );
    fs::copy(
        &wrapper,
        directory.join(if cfg!(windows) { "git.exe" } else { "git" }),
    )?;
    let mut history_args = vec![
        "-C".to_owned(),
        repository
            .to_str()
            .context("repository path must be UTF-8")?
            .to_owned(),
        "log".into(),
        "-p".into(),
        "-U0".into(),
    ];
    history_args.extend(options.split_whitespace().map(str::to_owned));
    let history_sha256 = git_child::arguments_sha256(&history_args);
    let nonce = token()?;
    let binding = git_child::Binding {
        schema: 1,
        nonce: nonce.clone(),
        real_git: git.clone(),
        real_git_sha256: crate::build::file_hash(&git)?,
        history_sha256: history_sha256.clone(),
    };
    let mut binding_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(git_child::BINDING))?;
    binding_file.write_all(&serde_json::to_vec(&binding)?)?;
    binding_file.sync_all()?;
    drop(binding_file);
    let config = directory.join("scanner.toml");
    fs::write(&config, "[extend]\nuseDefault = true\n")?;
    let report = directory.join("findings.json");
    let mut command = CommandSpec::new(binary.as_os_str())
        .args(["git"])
        .args([repository.as_os_str()])
        .args(["--config"])
        .args([config.as_os_str()])
        .args(["--gitleaks-ignore-path"])
        .args([directory.as_os_str()])
        .args([
            "--ignore-gitleaks-allow",
            "--redact=100",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "--exit-code=2",
            "--report-format=json",
            "--report-path",
        ])
        .args([report.as_os_str()])
        .args([format!("--log-opts={options}")]);
    command.cwd = Some(workspace.to_owned());
    let paths = std::iter::once(directory.to_path_buf())
        .chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ))
        .collect::<Vec<_>>();
    command
        .env
        .insert("PATH".into(), std::env::join_paths(paths)?);
    log("DEBUG", &format!("Scan scope: {scope}."))?;
    let output = controlled(command, 930)?;
    verify_gitleaks_history(directory, &nonce, &history_sha256)?;
    let findings = gitleaks_locations(
        output.code,
        &output.stdout,
        &output.stderr,
        &read_bounded(&report, 64 * 1024 * 1024)?,
    )?;
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY").filter(|p| !p.is_empty()) {
        let mut output = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?;
        output.write_all(gitleaks_summary(&findings, scope)?.as_bytes())?;
        output.flush()?;
    }
    if findings.is_empty() {
        log(
            "INFO",
            "The scan completed successfully; no matching secrets were detected.",
        )?;
        Ok(0)
    } else {
        log(
            "WARNING",
            &format!(
                "Detected {} potential secrets. Review the redacted locations in the job summary.",
                findings.len()
            ),
        )?;
        Ok(1)
    }
}
pub(super) fn run() -> Result<i32> {
    ensure!(
        std::env::var("RUNNER_DEBUG").as_deref() != Ok("1"),
        "disable Actions step debug logging before scanning"
    );
    let workspace = private(
        "workspace admission",
        PathBuf::from(std::env::var_os("GITHUB_WORKSPACE").context("GitHub workspace missing")?)
            .canonicalize()
            .map_err(Into::into),
    )?;
    let event = std::env::var("GITHUB_EVENT_NAME").context("GitHub event missing")?;
    let parent = std::env::var_os("RUNNER_TEMP").context("runner temporary directory missing")?;
    let directory = private(
        "private staging",
        tempfile::Builder::new()
            .prefix("revayat-gitleaks-")
            .tempdir_in(parent)
            .map_err(Into::into),
    )?;
    log("INFO", "Starting the repository secret scan.")?;
    let result = private("verified scan", scan(directory.path(), &workspace, &event));
    let cleanup = private(
        "private artifact cleanup",
        directory.close().map_err(Into::into),
    );
    crate::runtime::with_cleanup(result, cleanup)
}

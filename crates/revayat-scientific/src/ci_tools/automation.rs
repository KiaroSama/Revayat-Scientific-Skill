//! Bounded hosted prerequisites; no shell programs or implicit browser fallback.
use super::{CommandSpec, Result, ensure, fs, git, resolve};
use anyhow::Context;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
    time::Duration,
};

const ACTIONLINT_URL: &str = "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz";
const ACTIONLINT_SHA256: &str = "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8";
const DOWNLOAD_LIMIT: u64 = 8 * 1024 * 1024;

pub(super) fn checked_run(
    mut command: CommandSpec,
    seconds: u64,
) -> Result<crate::runtime::CommandOutput> {
    command.timeout = Duration::from_secs(seconds);
    command.max_output = command.max_output.min(DOWNLOAD_LIMIT as usize);
    let mut log = crate::runtime::OperationLog::create("ci-prerequisite", Path::new("logs"), None)?;
    log.info(&format!("phase=start timeout_seconds={seconds}"));
    let result = crate::runtime::run(&command);
    match &result {
        Ok(output) => log.info(&format!("phase=finished exit_code={}", output.code)),
        Err(_) => log.write("ERROR", "phase=failed category=bounded-process"),
    }
    let output = result?;
    ensure!(
        output.success(),
        "hosted prerequisite failed exit={}",
        output.code
    );
    Ok(output)
}

pub(super) fn base_from_environment(root: &Path) -> Result<String> {
    let base = std::env::var("BASE_REF")
        .or_else(|_| std::env::var("IDENTITY_BASE"))
        .context("explicit CI base commit is required")?;
    super::require_sha(&base)?;
    let head = std::env::var("HEAD_REF").context("CI head commit is required")?;
    super::require_sha(&head)?;
    resolve(root, &head)?;
    let base = if base.bytes().all(|b| b == b'0') {
        let branch = std::env::var("DEFAULT_BRANCH").context("default branch is required")?;
        ensure!(
            !branch.is_empty() && !branch.starts_with('-') && !branch.contains(['\r', '\n']),
            "invalid default branch"
        );
        git(root, &["check-ref-format", "--branch", &branch])?;
        git(
            root,
            &["merge-base", "--", &format!("origin/{branch}"), &head],
        )?
        .trim()
        .to_owned()
    } else {
        base
    };
    super::require_sha(&base)?;
    resolve(root, &base)
}

pub(super) fn github_output(base: &str) -> Result<()> {
    super::require_sha(base)?;
    let path = std::env::var_os("GITHUB_OUTPUT").context("GITHUB_OUTPUT is required")?;
    let mut output = fs::OpenOptions::new().append(true).open(path)?;
    writeln!(output, "sha={base}")?;
    output.flush()?;
    Ok(())
}

pub(super) fn verified_download(bytes: &[u8], limit: u64, expected: &str) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= limit,
        "CI tool download exceeds bound"
    );
    ensure!(
        format!("{:x}", Sha256::digest(bytes)) == expected,
        "CI tool checksum mismatch"
    );
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ToolReceipt {
    pub(super) directory: std::path::PathBuf,
    pub(super) identity: crate::identity::ObjectId,
}

fn tool_receipt(parent: &Path) -> std::path::PathBuf {
    parent.join("revayat-actionlint-owned.json")
}

#[derive(Debug)]
struct ToolPublicationError {
    phase: &'static str,
    // Retain the original typed cause for inspection, not raw CLI/log formatting.
    _cause: anyhow::Error,
}
impl std::fmt::Display for ToolPublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "CI tool {} failed", self.phase)
    }
}
impl std::error::Error for ToolPublicationError {}

pub(super) fn publication_failure(
    primary: anyhow::Error,
    cleanup: std::io::Result<()>,
) -> anyhow::Error {
    let primary = ToolPublicationError {
        phase: "receipt or PATH publication",
        _cause: primary,
    };
    let cleanup = cleanup.map_err(|error| {
        anyhow::Error::new(ToolPublicationError {
            phase: "receipt cleanup",
            _cause: error.into(),
        })
    });
    crate::runtime::with_cleanup::<()>(Err(primary.into()), cleanup).unwrap_err()
}

fn read_receipt(reader: impl Read) -> Result<ToolReceipt> {
    let mut bytes = Vec::new();
    reader.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "CI tool receipt exceeds bound");
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid CI tool receipt"))
}

fn cleanup_actionlint() -> Result<()> {
    let parent = std::path::PathBuf::from(
        std::env::var_os("RUNNER_TEMP").context("RUNNER_TEMP is required")?,
    )
    .canonicalize()?;
    cleanup_actionlint_at(&parent)
}

fn cleanup_actionlint_at(parent: &Path) -> Result<()> {
    cleanup_owned_at(parent, "revayat-actionlint-owned.json", "revayat-ci-tools-")
}

pub(super) fn cleanup_owned_at(parent: &Path, receipt_name: &str, prefix: &str) -> Result<()> {
    let receipt = parent.join(receipt_name);
    if !receipt.try_exists()? {
        return Ok(());
    }
    ensure!(
        !crate::identity::is_link(&receipt)? && fs::metadata(&receipt)?.len() <= 4096,
        "invalid CI tool receipt"
    );
    let owned = read_receipt(fs::File::open(&receipt)?)?;
    ensure!(
        owned.directory.parent() == Some(parent)
            && owned
                .directory
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(prefix))
            && !crate::identity::is_link(&owned.directory)?
            && crate::identity::path_object_id(&owned.directory)? == owned.identity,
        "CI tool cleanup ownership changed"
    );
    fs::remove_dir_all(owned.directory)?;
    fs::remove_file(receipt)?;
    println!("owned_tool_cleanup=complete");
    Ok(())
}

fn install_actionlint() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux") && cfg!(target_arch = "x86_64"),
        "actionlint setup requires hosted Linux x86_64"
    );
    let parent = std::path::PathBuf::from(
        std::env::var_os("RUNNER_TEMP").context("RUNNER_TEMP is required")?,
    )
    .canonicalize()?;
    ensure!(
        !tool_receipt(&parent).try_exists()?,
        "CI tool receipt already exists"
    );
    let directory = tempfile::Builder::new()
        .prefix("revayat-ci-tools-")
        .tempdir_in(&parent)?;
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let response = client
        .get(ACTIONLINT_URL)
        .send()
        .map_err(|_| anyhow::anyhow!("actionlint download failed"))?
        .error_for_status()
        .map_err(|_| anyhow::anyhow!("actionlint download refused"))?;
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= DOWNLOAD_LIMIT),
        "actionlint download exceeds bound"
    );
    let mut bytes = Vec::new();
    response
        .take(DOWNLOAD_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("actionlint download read failed"))?;
    verified_download(&bytes, DOWNLOAD_LIMIT, ACTIONLINT_SHA256)?;
    let archive = directory.path().join("actionlint.tar.gz");
    fs::write(&archive, bytes)?;
    checked_run(
        CommandSpec::new("tar").args([
            "--extract".into(),
            "--gzip".into(),
            "--file".into(),
            archive.into_os_string(),
            "--directory".into(),
            directory.path().as_os_str().to_owned(),
            "--no-same-owner".into(),
            "--no-same-permissions".into(),
            "actionlint".into(),
        ]),
        30,
    )?;
    let executable = directory.path().join("actionlint");
    ensure!(
        !crate::identity::is_link(&executable)? && executable.is_file(),
        "actionlint extraction is not a plain binary"
    );
    let version = checked_run(
        CommandSpec::new(executable.as_os_str()).args(["-version"]),
        15,
    )?;
    ensure!(
        version.stdout_text().lines().next() == Some("1.7.12"),
        "actionlint version mismatch"
    );
    fs::remove_file(directory.path().join("actionlint.tar.gz"))?;
    let installed = directory.path().canonicalize()?;
    let text = installed
        .to_str()
        .context("CI tool directory must be UTF-8")?;
    ensure!(!text.contains(['\r', '\n']), "invalid CI tool directory");
    let path = std::env::var_os("GITHUB_PATH").context("GITHUB_PATH is required")?;
    let owned = ToolReceipt {
        identity: crate::identity::path_object_id(&installed)?,
        directory: installed.clone(),
    };
    let receipt = tool_receipt(&parent);
    let mut record = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt)?;
    let publication = (|| -> Result<()> {
        serde_json::to_writer(&mut record, &owned)?;
        record.flush()?;
        let mut output = fs::OpenOptions::new().append(true).open(path)?;
        writeln!(output, "{text}")?;
        output.flush()?;
        Ok(())
    })();
    drop(record);
    if let Err(error) = publication {
        return Err(publication_failure(error, fs::remove_file(receipt)));
    }
    let _installed = directory.keep();
    println!("actionlint=1.7.12 checksum=verified");
    Ok(())
}

fn install_scanners() -> Result<()> {
    let home = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".cargo")))
        .context("Cargo home is required")?;
    for (binary, version) in [("cargo-audit", "0.23.0"), ("zizmor", "1.32.0")] {
        let executable = home.join("bin").join(binary);
        let wanted = format!("{binary} {version}");
        let matches = || -> Result<bool> {
            if !executable.is_file() || crate::identity::is_link(&executable)? {
                return Ok(false);
            }
            let output = checked_run(
                CommandSpec::new(executable.as_os_str()).args(["--version"]),
                15,
            )?;
            Ok(output.stdout_text().trim() == wanted)
        };
        if !matches()? {
            checked_run(
                CommandSpec::new("cargo").args([
                    "install",
                    "--locked",
                    "--force",
                    "--root",
                    home.to_str().context("Cargo home must be UTF-8")?,
                    binary,
                    "--version",
                    version,
                ]),
                900,
            )?;
        }
        ensure!(matches()?, "installed scanner version mismatch");
        println!("{binary}={version}");
    }
    Ok(())
}

fn browser_version(bytes: &[u8]) -> Result<&str> {
    let text = std::str::from_utf8(bytes)
        .context("browser version is not UTF-8")?
        .trim();
    let version = text
        .strip_prefix("Google Chrome ")
        .context("selected browser is not Google Chrome")?;
    ensure!(
        !version.is_empty()
            && version.len() <= 64
            && version.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "invalid browser version"
    );
    Ok(version)
}

fn select_browser() -> Result<()> {
    let executable = crate::render::discover_browser(None)?;
    let parent = std::env::var_os("RUNNER_TEMP").context("RUNNER_TEMP is required")?;
    let scratch = tempfile::Builder::new()
        .prefix("revayat-browser-selection-")
        .tempdir_in(parent)?;
    crate::render::preflight_browser(&executable, &scratch.path().canonicalize()?)?;
    let text = executable.to_str().context("browser path is not UTF-8")?;
    ensure!(!text.contains(['\r', '\n']), "invalid browser path");
    let destination = std::env::var_os("GITHUB_ENV").context("GITHUB_ENV is required")?;
    let mut output = fs::OpenOptions::new().append(true).open(destination)?;
    writeln!(output, "REVAYAT_BROWSER={text}")?;
    output.flush()?;
    Ok(())
}

fn browser_preflight() -> Result<()> {
    let selected = std::env::var("REVAYAT_BROWSER").context("REVAYAT_BROWSER is required")?;
    ensure!(
        !selected.is_empty() && !selected.contains(['\r', '\n']),
        "invalid explicit browser selection"
    );
    let executable = crate::runtime::executable(&selected)?;
    let mut command = CommandSpec::new(executable.as_os_str()).args(["--version"]);
    command.max_output = 4096;
    let output = checked_run(command, 15)?;
    let version = browser_version(&output.stdout)?;
    let parent = std::env::var_os("RUNNER_TEMP").context("RUNNER_TEMP is required")?;
    let scratch = tempfile::Builder::new()
        .prefix("revayat-browser-preflight-")
        .tempdir_in(parent)?;
    crate::render::preflight_browser(&executable, &scratch.path().canonicalize()?)?;
    for key in ["RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion"] {
        let value = std::env::var(key).context("hosted runner identity is required")?;
        ensure!(
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "invalid hosted runner identity"
        );
        println!("{key}={value}");
    }
    println!(
        "browser=google-chrome version={version} explicit=true startup=verified cleanup=complete"
    );
    Ok(())
}

pub(super) fn cli(args: &[String]) -> Result<Option<i32>> {
    let Some(mode) = args.first().map(String::as_str) else {
        return Ok(None);
    };
    if mode == "gitleaks" {
        ensure!(args.len() == 1, "Gitleaks mode accepts no extra arguments");
        return super::gitleaks::run().map(Some);
    }
    ensure!(
        args.len() == 1,
        "CI prerequisite mode accepts no extra arguments"
    );
    match mode {
        "prepare-actionlint" | "cleanup-actionlint" | "prepare-scanners" | "browser-preflight"
        | "prepare-poppler" | "poppler-preflight" | "cleanup-poppler" | "select-browser" => {}
        _ => anyhow::bail!("unknown CI prerequisite mode"),
    }
    let mut log = crate::runtime::OperationLog::create("ci-setup", Path::new("logs"), None)?;
    log.info(&format!("mode={mode} phase=start"));
    let result = match mode {
        "prepare-actionlint" => install_actionlint(),
        "cleanup-actionlint" => cleanup_actionlint(),
        "prepare-scanners" => install_scanners(),
        "browser-preflight" => browser_preflight(),
        "prepare-poppler" => super::poppler::prepare(),
        "poppler-preflight" => super::poppler::preflight(),
        "cleanup-poppler" => super::poppler::cleanup(),
        "select-browser" => select_browser(),
        _ => unreachable!(),
    };
    match &result {
        Ok(()) => log.info("phase=finished exit_code=0"),
        Err(_) => log.write("ERROR", "phase=failed category=prerequisite"),
    }
    result?;
    Ok(Some(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_and_cleanup_failures_remain_inspectable_without_private_display() {
        let primary = std::io::Error::other("PRIVATE_PUBLICATION_CANARY");
        let secondary = std::io::Error::other("PRIVATE_CLEANUP_CANARY");
        let error = publication_failure(primary.into(), Err(secondary));
        let retained = error.downcast_ref::<ToolPublicationError>().unwrap();
        assert_eq!(
            retained
                ._cause
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .to_string(),
            "PRIVATE_PUBLICATION_CANARY"
        );
        let cleanup = error
            .downcast_ref::<crate::runtime::CleanupFailure>()
            .unwrap();
        assert_eq!(
            cleanup
                .0
                .downcast_ref::<ToolPublicationError>()
                .unwrap()
                ._cause
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .to_string(),
            "PRIVATE_CLEANUP_CANARY"
        );
        let display = format!("{error:#}");
        assert!(
            display.contains("receipt or PATH publication") && display.contains("receipt cleanup")
        );
        assert!(!display.contains("PRIVATE_"));
        let primary_only =
            publication_failure(std::io::Error::other("PRIVATE_PRIMARY").into(), Ok(()));
        assert!(
            primary_only
                .downcast_ref::<ToolPublicationError>()
                .is_some()
        );
        assert!(
            primary_only
                .downcast_ref::<crate::runtime::CleanupFailure>()
                .is_none()
        );
        assert!(!format!("{primary_only:#}").contains("PRIVATE_"));
    }

    #[test]
    fn untrusted_browser_version_never_reaches_the_report() {
        assert_eq!(
            browser_version(b"Google Chrome 142.0.1.2\n").unwrap(),
            "142.0.1.2"
        );
        for bytes in [
            b"Google Chrome secret-token".as_slice(),
            b"Chromium 142.0",
            &[255],
            b"Google Chrome 1\nprivate",
        ] {
            let error = browser_version(bytes).unwrap_err().to_string();
            assert!(!error.contains("secret-token") && !error.contains("private"));
        }
    }

    #[test]
    fn corrupt_download_is_rejected_before_extraction() {
        assert!(verified_download(b"corrupt archive", DOWNLOAD_LIMIT, ACTIONLINT_SHA256).is_err());
        let expected = format!("{:x}", Sha256::digest(b"fixture"));
        assert!(verified_download(b"fixture", 7, &expected).is_ok());
        for (bytes, limit, digest) in [
            (b"fixture".as_slice(), 6, expected.as_str()),
            (b"PRIVATE_ARCHIVE_CANARY".as_slice(), 64, ACTIONLINT_SHA256),
        ] {
            let error = verified_download(bytes, limit, digest).unwrap_err();
            assert!(!format!("{error:#}").contains("PRIVATE_"));
        }
    }

    #[test]
    fn receipt_read_checks_actual_growth_and_never_consumes_unbounded_input() {
        use std::cell::Cell;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().canonicalize().unwrap();
        let receipt = ToolReceipt {
            identity: crate::identity::path_object_id(&directory).unwrap(),
            directory,
        };
        let mut bytes = serde_json::to_vec(&receipt).unwrap();
        bytes.resize(4096, b' ');
        assert!(read_receipt(std::io::Cursor::new(&bytes)).is_ok());
        bytes.push(b' ');
        assert!(read_receipt(std::io::Cursor::new(bytes)).is_err());
        struct Growing<'a>(&'a Cell<usize>);
        impl Read for Growing<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                output.fill(b'x');
                self.0.set(self.0.get() + output.len());
                Ok(output.len())
            }
        }
        let read = Cell::new(0);
        assert!(read_receipt(Growing(&read)).is_err());
        assert_eq!(read.get(), 4097);
        let error = read_receipt(std::io::Cursor::new(b"PRIVATE_RECEIPT_CANARY"))
            .err()
            .unwrap();
        assert!(!format!("{error:#}").contains("PRIVATE_"));
    }

    #[test]
    fn cleanup_removes_only_the_recorded_owned_directory() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        let directory = parent.join("revayat-ci-tools-fixture");
        fs::create_dir(&directory).unwrap();
        let foreign = parent.join("foreign");
        fs::create_dir(&foreign).unwrap();
        fs::write(foreign.join("sentinel"), b"foreign").unwrap();
        let receipt = ToolReceipt {
            identity: crate::identity::path_object_id(&directory).unwrap(),
            directory: directory.clone(),
        };
        fs::write(tool_receipt(&parent), serde_json::to_vec(&receipt).unwrap()).unwrap();
        cleanup_actionlint_at(&parent).unwrap();
        assert!(!directory.exists() && !tool_receipt(&parent).exists());
        assert_eq!(fs::read(foreign.join("sentinel")).unwrap(), b"foreign");
        cleanup_actionlint_at(&parent).unwrap();
        fs::create_dir(&directory).unwrap();
        let invalid = ToolReceipt {
            identity: crate::identity::path_object_id(&foreign).unwrap(),
            directory: directory.clone(),
        };
        fs::write(tool_receipt(&parent), serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(cleanup_actionlint_at(&parent).is_err());
        assert!(directory.is_dir() && tool_receipt(&parent).is_file());
    }

    #[test]
    fn prerequisite_modes_reject_extra_or_unknown_arguments() {
        assert!(cli(&["unknown".into()]).is_err());
        assert!(cli(&["browser-preflight".into(), "ignored".into()]).is_err());
        assert_eq!(cli(&[]).unwrap(), None);
    }
}

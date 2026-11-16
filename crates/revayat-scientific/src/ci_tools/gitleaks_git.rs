//! Stream the pinned scanner's real Git child and retain its exact completion.
use super::{read_bounded, token};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub(super) const BINDING: &str = "git-binding.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub schema: u8,
    pub nonce: String,
    pub real_git: PathBuf,
    pub real_git_sha256: String,
    pub history_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    nonce: String,
    arguments_sha256: String,
    completed: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
}

pub(super) fn arguments_sha256(args: &[String]) -> String {
    let mut hash = Sha256::new();
    for argument in args {
        hash.update((argument.len() as u64).to_be_bytes());
        hash.update(argument.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

pub fn gitleaks_git_main() -> Result<i32> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let directory = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("private Git binding missing"))?;
    let binding: Binding = serde_json::from_slice(&read_bounded(&directory.join(BINDING), 16384)?)?;
    ensure!(
        binding.schema == 1 && crate::tex_supervisor::valid_token(&binding.nonce),
        "invalid private Git binding"
    );
    ensure!(
        binding.real_git.is_absolute()
            && binding.real_git != executable
            && binding.real_git.canonicalize()? == binding.real_git,
        "invalid fixed Git executable"
    );
    ensure!(
        crate::build::file_hash(&binding.real_git)? == binding.real_git_sha256,
        "fixed Git executable changed"
    );
    let args = std::env::args_os()
        .skip(1)
        .map(|s| {
            s.into_string()
                .map_err(|_| anyhow::anyhow!("Git argument is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    let history =
        args.get(2).is_some_and(|s| s == "log") && args.first().is_some_and(|s| s == "-C");
    let digest = arguments_sha256(&args);
    let mut record = Receipt {
        schema: 1,
        nonce: binding.nonce,
        arguments_sha256: digest.clone(),
        completed: false,
        exit_code: None,
        signal: None,
    };
    let mut receipt = if history {
        let path = directory.join(format!("git-history-{}.json", token()?));
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        writer.write_all(&serde_json::to_vec(&record)?)?;
        writer.sync_all()?;
        ensure!(
            digest == binding.history_sha256,
            "actual Git history arguments differ"
        );
        Some(writer)
    } else {
        None
    };
    // The enclosing runtime owns this wrapper and this inherited child group.
    // Its 930-second deadline and verified tree cleanup cover the entire stream.
    // Streaming avoids truncating a legitimate history at a diagnostic byte cap.
    let status = Command::new(&binding.real_git)
        .arg("--no-replace-objects")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if let Some(writer) = &mut receipt {
        use std::io::{Seek, SeekFrom};
        record.completed = true;
        record.exit_code = status.code();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            record.signal = status.signal();
        }
        writer.seek(SeekFrom::Start(0))?;
        writer.set_len(0)?;
        writer.write_all(&serde_json::to_vec(&record)?)?;
        writer.sync_all()?;
    }
    Ok(status.code().unwrap_or(1))
}

/// Admit one exact, completed history child; never infer success from scanner exit.
pub fn verify_gitleaks_history(
    directory: &Path,
    nonce: &str,
    arguments_sha256: &str,
) -> Result<()> {
    let mut receipts = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("git-history-"))
        {
            receipts.push(path);
            ensure!(receipts.len() <= 1, "contradictory Git-history receipts");
        }
    }
    ensure!(
        receipts.len() == 1,
        "actual Git-history completion receipt missing"
    );
    let receipt: Receipt = serde_json::from_slice(&read_bounded(&receipts[0], 4096)?)?;
    ensure!(
        receipt.schema == 1
            && receipt.nonce == nonce
            && receipt.arguments_sha256 == arguments_sha256
            && receipt.completed
            && receipt.exit_code == Some(0)
            && receipt.signal.is_none(),
        "actual Git-history child did not confirm successful completion"
    );
    Ok(())
}

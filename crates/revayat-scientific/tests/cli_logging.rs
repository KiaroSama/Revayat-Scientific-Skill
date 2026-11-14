use anyhow::Result;
use std::{fs, process::Command};

#[test]
fn parent_cli_records_one_content_free_operation_for_a_failed_private_input() -> Result<()> {
    let job = tempfile::tempdir()?;
    let logs = job.path().join("operation-logs");
    let private = job.path().join("private-manuscript-راز.tex");
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .arg("source-closure")
        .arg(&private)
        .current_dir(job.path())
        .env("REVAYAT_LOG_DIR", &logs)
        .env("REVAYAT_LOG_LEVEL", "DEBUG")
        .output()?;
    assert!(!output.status.success());
    let paths = fs::read_dir(logs)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(paths.len(), 1, "only the parent owns an operation log");
    let text = fs::read_to_string(paths[0].path())?;
    assert!(text.contains("started runtime=rust"));
    assert!(text.contains("command=source-closure"));
    assert!(text.contains("[ERROR] [revayat-scientific] exit_code=2"));
    assert!(text.contains("finished duration_seconds="));
    assert!(!text.contains("manuscript"));
    assert!(!text.contains("راز"));
    assert!(!text.contains(&job.path().to_string_lossy().to_string()));
    Ok(())
}

#[test]
fn failed_log_directory_falls_back_without_blocking_the_command() -> Result<()> {
    let job = tempfile::tempdir()?;
    let blocked = job.path().join("a-file");
    fs::write(&blocked, b"existing content")?;
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["source-closure", "missing.tex"])
        .current_dir(job.path())
        .env("REVAYAT_LOG_DIR", &blocked)
        .env("REVAYAT_LOG_LEVEL", "INFO")
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("file logging unavailable"));
    assert_eq!(fs::read(&blocked)?, b"existing content");
    Ok(())
}

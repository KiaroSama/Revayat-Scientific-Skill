use anyhow::Result;
use revayat_scientific::runtime::{self, CommandSpec, DeadlineExceeded, OperationLog};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};
const TOOL: &str = env!("CARGO_BIN_EXE_revayat-test-tool");

#[test]
fn test_idle_deadline_is_distinct_from_wall_deadline() -> Result<()> {
    let mut spec = CommandSpec::new(TOOL).args(["silent"]);
    spec.timeout = Duration::from_secs(5);
    spec.idle_timeout = Some(Duration::from_millis(150));
    let start = Instant::now();
    let error = runtime::run(&spec).unwrap_err();
    let deadline = error.downcast_ref::<DeadlineExceeded>().unwrap();
    assert!(deadline.idle);
    assert_eq!(deadline.limit, Duration::from_millis(150));
    assert!(start.elapsed() < Duration::from_secs(3));
    Ok(())
}
#[test]
fn test_environment_and_diagnostic_bytes_preserve_exit_code() -> Result<()> {
    let mut spec = CommandSpec::new(TOOL).args(["diagnostics"]);
    spec.env
        .insert("REVAYAT_TEST_ENV".into(), "caller-path فارسی".into());
    let output = runtime::run(&spec)?;
    assert_eq!(output.code, 7);
    assert!(output.stdout_text().contains("caller-path فارسی"));
    assert!(output.stdout_text().contains('\u{fffd}'));
    assert!(output.stderr_text().contains('\u{fffd}'));
    let cli = std::process::Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["run-check", "--", TOOL, "diagnostics"])
        .current_dir(tempfile::tempdir()?.path())
        .output()?;
    assert_eq!(cli.status.code(), Some(7));
    assert!(std::str::from_utf8(&cli.stdout)?.contains('\u{fffd}'));
    assert!(std::str::from_utf8(&cli.stderr)?.contains('\u{fffd}'));
    Ok(())
}
#[test]
fn test_debug_file_logging_is_explicit_utf8() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path;
    {
        let mut log = OperationLog::create("probe", temp.path(), Some("DEBUG"))?;
        log.write("DEBUG", "phase=prepare فارسی");
        log.write("WARNING", "count=0");
        path = log.path().unwrap().to_owned();
    }
    let text = fs::read_to_string(path)?;
    assert!(regex::Regex::new(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\]")?.is_match(&text));
    assert!(text.contains("[DEBUG] [probe] phase=prepare فارسی"));
    assert!(text.contains("[WARNING] [probe] count=0"));
    assert!(text.contains("UTC"));
    Ok(())
}

#[test]
fn utc_logs_use_calendar_dates_and_unique_bounded_filenames() -> Result<()> {
    assert_eq!(runtime::utc_timestamp(0)?, "1970-01-01 00:00:00 UTC");
    assert_eq!(
        runtime::utc_timestamp(951_782_400)?,
        "2000-02-29 00:00:00 UTC"
    );
    assert_eq!(
        runtime::utc_timestamp(4_107_542_400)?,
        "2100-03-01 00:00:00 UTC"
    );
    assert_eq!(
        runtime::utc_timestamp(2_147_483_647)?,
        "2038-01-19 03:14:07 UTC"
    );
    assert!(runtime::utc_timestamp(u64::MAX).is_err());
    let temp = tempfile::tempdir()?;
    let first = OperationLog::create("probe", temp.path(), Some("INFO"))?;
    let second = OperationLog::create("probe", temp.path(), Some("INFO"))?;
    assert_ne!(first.path(), second.path());
    let names = regex::Regex::new(
        r"^probe_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_UTC(?:_[0-9a-f]{8})?\.log$",
    )?;
    for path in [first.path().unwrap(), second.path().unwrap()] {
        assert!(names.is_match(&path.file_name().unwrap().to_string_lossy()));
    }
    Ok(())
}
fn not_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let text = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        text.is_empty()
            || text
                .rsplit_once(") ")
                .is_some_and(|(_, state)| state.starts_with('Z'))
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&output.stdout);
        state.trim().is_empty() || state.trim().starts_with('Z')
    }
    #[cfg(windows)]
    {
        revayat_scientific::windows_security::native::process_exited(pid).unwrap()
    }
}
#[test]
fn test_timeout_terminates_descendant_after_launcher_exits() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("child.txt");
    let mut spec = CommandSpec::new(TOOL).args(["launch-grandchild".as_ref(), path.as_os_str()]);
    spec.timeout = Duration::from_millis(500);
    let start = Instant::now();
    assert!(runtime::run(&spec).is_err());
    let pid = fs::read_to_string(path)?.parse()?;
    assert!(not_alive(pid), "descendant {pid} survived its owner");
    assert!(start.elapsed() < Duration::from_secs(3));
    Ok(())
}
#[test]
fn global_cli_timeout_reaps_nested_native_runtime_and_grandchildren() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pid = temp.path().join("child.txt");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args([
            "--timeout",
            "1",
            "run-check",
            "--timeout",
            "60",
            "--",
            TOOL,
            "run-nested",
        ])
        .arg(&pid)
        .current_dir(temp.path())
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(124),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pid = fs::read_to_string(pid)?.parse()?;
    assert!(not_alive(pid));
    assert!(!fs::read_dir(temp.path())?.any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-tex-owner-")
    }));
    Ok(())
}
#[test]
fn invalid_deadlines_and_diagnostic_budget_are_rejected_before_spawn() -> Result<()> {
    let mut spec = CommandSpec::new(Path::new("nonexistent"));
    spec.timeout = Duration::ZERO;
    assert!(
        runtime::run(&spec)
            .unwrap_err()
            .to_string()
            .contains("positive")
    );
    spec.timeout = Duration::from_secs(1);
    spec.max_output = 0;
    assert!(runtime::run(&spec).is_err());
    Ok(())
}

#[test]
fn bounded_stdin_preserves_bytes_and_obeys_the_same_deadline() -> Result<()> {
    let spec = CommandSpec::new(TOOL).args(["echo-input"]);
    let input = "دانش علمی\n".repeat(4096).into_bytes();
    let output = runtime::run_with_input(&spec, &input)?;
    assert!(output.success());
    assert_eq!(output.stdout, input);
    let mut blocked = CommandSpec::new(TOOL).args(["silent"]);
    blocked.timeout = Duration::from_millis(100);
    assert!(
        runtime::run_with_input(&blocked, &vec![b'x'; 1024 * 1024])
            .unwrap_err()
            .downcast_ref::<DeadlineExceeded>()
            .is_some()
    );
    Ok(())
}

#[test]
fn diagnostic_overflow_reaps_the_producer_without_returning_partial_success() -> Result<()> {
    let mut spec = CommandSpec::new(TOOL).args(["flood"]);
    spec.max_output = 16 * 1024;
    let started = Instant::now();
    let error = runtime::run(&spec).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("diagnostics exceeded 16384 byte limit")
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    Ok(())
}

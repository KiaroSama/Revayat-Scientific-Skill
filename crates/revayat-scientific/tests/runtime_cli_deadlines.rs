use anyhow::Result;
use std::process::Command;

const CLI: &str = env!("CARGO_BIN_EXE_revayat-scientific");
const TOOL: &str = env!("CARGO_BIN_EXE_revayat-test-tool");
const INVALID_VALUES: &[&str] = &[
    "1e300",
    "18446744073709551616",
    "1.7976931348623157e308",
    "NaN",
    "inf",
    "-inf",
    "-1",
    "0",
    "1e-100",
    "not-a-number",
];

#[test]
fn invalid_run_check_timeouts_fail_before_runtime_setup() {
    for option in ["--timeout", "--idle", "--idle-timeout"] {
        for value in INVALID_VALUES {
            let args =
                [option, value, "--", "revayat-command-that-must-not-execute"].map(str::to_owned);
            let result =
                std::panic::catch_unwind(|| revayat_scientific::runtime::cli_run_check(&args));
            assert!(
                result.is_ok(),
                "{option} {value} panicked instead of refusing input"
            );
            let diagnostic = format!("{:#}", result.unwrap().unwrap_err());
            assert!(
                diagnostic.contains("time") || diagnostic.contains("float"),
                "{option} {value} reached execution instead of input validation: {diagnostic}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn unix_run_check_refuses_unrepresentable_wire_deadlines_before_owner_setup() {
    for (option, value) in [
        ("--timeout", "0.000000001"),
        ("--timeout", "86400.001"),
        ("--timeout", "1000000000000000000"),
        ("--idle", "0.0001"),
        ("--idle-timeout", "0.0001"),
        ("--idle-timeout", "1000000000000000000"),
    ] {
        let args =
            [option, value, "--", "revayat-command-that-must-not-execute"].map(str::to_owned);
        let result = std::panic::catch_unwind(|| revayat_scientific::runtime::cli_run_check(&args));
        assert!(result.is_ok(), "{option} {value} panicked");
        let diagnostic = format!("{:#}", result.unwrap().unwrap_err());
        assert!(
            diagnostic.contains("timeout") && diagnostic.contains("milliseconds"),
            "{option} {value} reached owner setup: {diagnostic}"
        );
    }
}

#[test]
fn invalid_run_check_timeouts_return_input_errors_without_panicking() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for option in ["--timeout", "--idle", "--idle-timeout"] {
        for value in INVALID_VALUES {
            let output = Command::new(CLI)
                .args(["run-check", option, value, "--", TOOL, "--version"])
                .current_dir(directory.path())
                .output()?;
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{option} {value} must produce an ordinary input error: {diagnostic}"
            );
            assert!(
                !diagnostic.contains("panicked") && !diagnostic.contains("stack backtrace"),
                "{option} {value} exposed an internal panic: {diagnostic}"
            );
            assert!(
                diagnostic.contains("time") || diagnostic.contains("float"),
                "{option} {value} did not reach input validation: {diagnostic}"
            );
            assert!(
                output.stdout.is_empty(),
                "{option} {value} must not run the requested tool"
            );
        }
    }
    Ok(())
}

#[test]
fn fractional_run_check_timeouts_preserve_successful_child_execution() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = Command::new(CLI)
        .args([
            "run-check",
            "--timeout",
            "3.5",
            "--idle-timeout",
            "2.25",
            "--",
            TOOL,
            "--version",
        ])
        .current_dir(directory.path())
        .output()?;
    assert!(
        output.status.success(),
        "valid fractional timeouts failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout)?.trim(),
        "Revayat controlled test fixture 1.0"
    );
    Ok(())
}

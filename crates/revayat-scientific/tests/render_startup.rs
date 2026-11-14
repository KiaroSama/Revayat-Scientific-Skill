//! Browser failure diagnostics exercise the real renderer/process boundary.
use anyhow::Result;
use revayat_scientific::render::render_html;
use std::{
    fs,
    time::{Duration, Instant},
};

fn prewarm(executable: impl AsRef<std::ffi::OsStr>) -> Result<()> {
    let output = std::process::Command::new(executable)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()?;
    anyhow::ensure!(output.status.success(), "compiled binary pre-warm failed");
    Ok(())
}

fn failed_browser(mode: &str) -> Result<(tempfile::TempDir, String)> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let executable = root.join(format!("browser-{mode}{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &executable)?;
    let source = root.join("source.html");
    let output = root.join("document.pdf");
    fs::write(&source, "<html><body>preserved source</body></html>")?;
    fs::write(&output, b"previous valid output")?;
    prewarm(&executable)?;
    prewarm(env!("CARGO_BIN_EXE_revayat-process-owner"))?;
    let started = Instant::now();
    let error = render_html(&source, &output, &executable, None).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(fs::read(&output)?, b"previous valid output");
    assert_eq!(
        fs::read_to_string(&source)?,
        "<html><body>preserved source</body></html>"
    );
    assert!(!fs::read_dir(&root)?.any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-")
    }));
    Ok((temp, format!("{error:#}")))
}

#[test]
fn early_exit_preserves_code_and_allowlisted_category_without_child_text() -> Result<()> {
    let (_temp, error) = failed_browser("early")?;
    assert!(error.contains("phase=startup"), "{error}");
    assert!(error.contains("exit_code=42"), "{error}");
    assert!(error.contains("sandbox=true"), "{error}");
    assert!(!error.contains("No usable sandbox!"));
    assert!(!error.contains("PRIVATE_BROWSER_CANARY"));
    assert!(!error.contains("devtools/browser/private-token"));
    Ok(())
}

#[test]
fn invalid_utf8_is_counted_without_lossy_private_output() -> Result<()> {
    let (_temp, error) = failed_browser("invalid")?;
    assert!(error.contains("invalid_utf8=true"), "{error}");
    assert!(!error.contains('\u{fffd}'));
    assert!(!error.contains("PRIVATE_BROWSER_CANARY"));
    Ok(())
}

#[test]
fn stderr_flood_fails_closed_without_unbounded_capture_or_pipe_deadlock() -> Result<()> {
    let (_temp, error) = failed_browser("flood")?;
    assert!(error.contains("overflow=true"), "{error}");
    assert!(error.len() < 2048);
    assert!(!error.contains("PRIVATE_BROWSER_CANARY"));
    Ok(())
}

fn exited(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let text = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        text.is_empty()
            || text
                .rsplit_once(") ")
                .is_some_and(|(_, tail)| tail.starts_with('Z'))
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
fn launcher_exit_reaps_descendant_holding_stderr_before_reader_join() -> Result<()> {
    let (temp, error) = failed_browser("held")?;
    let pid: u32 = fs::read_to_string(temp.path().join("browser-child.pid"))?.parse()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !exited(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(exited(pid), "owned descendant survived renderer failure");
    assert!(error.contains("exit_code=42"), "{error}");
    assert!(error.contains("reader_complete=true"), "{error}");
    Ok(())
}

#[test]
fn unrecognized_stderr_never_becomes_a_diagnostic_message() -> Result<()> {
    let (_temp, error) = failed_browser("private")?;
    assert!(error.contains("unknown=true"), "{error}");
    for private in [
        "PRIVATE_BROWSER_CANARY",
        "secret-profile",
        "private-token",
        "https://",
    ] {
        assert!(
            !error.contains(private),
            "private browser content escaped: {private}"
        );
    }
    Ok(())
}

#[test]
fn diagnostics_continue_after_endpoint_readiness_without_exposing_private_child_text() -> Result<()>
{
    let (_temp, error) = failed_browser("ready-private")?;
    assert!(error.contains("phase=render"), "{error}");
    assert!(error.contains("unknown=true"), "{error}");
    assert!(error.contains("invalid_utf8=true"), "{error}");
    assert!(error.contains("reader_complete=true"), "{error}");
    // The outer protocol error may identify loopback, but never child diagnostics.
    for private in ["PRIVATE_BROWSER_CANARY", "secret-profile"] {
        assert!(!error.contains(private));
    }
    Ok(())
}

#[test]
fn inherited_runtime_group_reaps_pipe_holder_without_reader_join_deadlock() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let executable = root.join(format!("browser-held{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &executable)?;
    let source = root.join("source.html");
    let output = root.join("document.pdf");
    fs::write(&source, "<html>source</html>")?;
    fs::write(&output, b"previous valid output")?;
    // Exclude first-launch image scanning from the owned-process cleanup bound.
    prewarm(env!("CARGO_BIN_EXE_revayat-scientific"))?;
    prewarm(env!("CARGO_BIN_EXE_revayat-process-owner"))?;
    prewarm(&executable)?;
    let started = Instant::now();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .arg("render-html")
        .arg(&source)
        .arg(&output)
        .arg("--browser")
        .arg(&executable)
        .current_dir(&root)
        .output()?;
    assert!(!result.status.success());
    let text = String::from_utf8(result.stderr)?;
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "owned pipe-holder cleanup took {:?}: {text}",
        started.elapsed()
    );
    assert!(text.contains("reader_complete=true"), "{text}");
    assert!(!text.contains("PRIVATE_BROWSER_CANARY"));
    let pid: u32 = fs::read_to_string(root.join("browser-child.pid"))?.parse()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !exited(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        exited(pid),
        "outer runtime did not reap inherited pipe holder"
    );
    assert_eq!(fs::read(output)?, b"previous valid output");
    Ok(())
}

#[test]
fn successful_fake_protocol_render_survives_expected_owned_termination() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let executable = root.join(format!("browser-protocol{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &executable)?;
    let source = root.join("source.html");
    let output = root.join("output.pdf");
    fs::write(&source, "<html>source</html>")?;
    render_html(&source, &output, &executable, None)?;
    revayat_scientific::render::validate_pdf(&output)?;
    assert_eq!(fs::read_to_string(source)?, "<html>source</html>");
    Ok(())
}

#[test]
fn readiness_requires_live_protocol_identity_not_only_endpoint_file() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let extension = std::env::consts::EXE_SUFFIX;
    for mode in ["protocol", "ready-private", "early"] {
        let executable = root.join(format!("browser-{mode}{extension}"));
        fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &executable)?;
        let result = revayat_scientific::render::preflight_browser(&executable, &root);
        assert_eq!(result.is_ok(), mode == "protocol", "{mode}: {result:?}");
        if let Err(error) = result {
            let text = format!("{error:#}");
            assert!(!text.contains("PRIVATE_BROWSER_CANARY"));
            assert!(!text.contains("private-token"));
        }
    }
    Ok(())
}

// The full startup deadline is an equipped test, not a shortened production timeout.
#[test]
#[ignore = "equipped browser lifecycle tier exercises the full 30-second startup deadline"]
fn silent_browser_timeout_preserves_output_and_reaps_owner() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let executable = root.join(format!("browser-silent{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &executable)?;
    let source = root.join("source.html");
    fs::write(&source, "<html>source</html>")?;
    prewarm(&executable)?;
    prewarm(env!("CARGO_BIN_EXE_revayat-process-owner"))?;
    let started = Instant::now();
    let error = render_html(&source, &root.join("output.pdf"), &executable, None).unwrap_err();
    assert!(
        error
            .downcast_ref::<revayat_scientific::runtime::DeadlineExceeded>()
            .is_some()
    );
    assert!(
        error
            .downcast_ref::<revayat_scientific::runtime::CleanupFailure>()
            .is_none()
    );
    assert!(started.elapsed() >= Duration::from_secs(30));
    assert!(started.elapsed() < Duration::from_secs(38));
    assert!(format!("{error:#}").contains("phase=startup"));
    Ok(())
}

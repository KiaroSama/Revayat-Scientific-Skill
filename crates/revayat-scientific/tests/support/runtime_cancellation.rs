use anyhow::{Context, Result, bail, ensure};
use revayat_scientific::{
    runtime::{self, CommandSpec},
    tex_container as tex,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn receipts(root: &Path, result: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() {
            receipts(&path, result)?;
        } else if path.file_name().is_some_and(|n| {
            n.to_string_lossy().starts_with("container-") && n.to_string_lossy().ends_with(".json")
        }) {
            result.push(path);
        }
    }
    Ok(())
}
fn receipt_scope() -> Result<PathBuf> {
    let directory = std::env::var_os(revayat_scientific::tex_supervisor::DIRECTORY_ENV)
        .context("cancellation fixture requires the scoped native test runner")?;
    let token = std::env::var(revayat_scientific::tex_supervisor::TOKEN_ENV)?;
    revayat_scientific::tex_supervisor::validate_scope(Path::new(&directory), &token)
}
pub(super) fn surviving_owner_reaps_container() -> Result<()> {
    #[cfg(unix)]
    abrupt_controller_death()?;
    timed_controller_cancellation()
}
#[cfg(unix)]
fn abrupt_controller_death() -> Result<()> {
    let receipt_root = receipt_scope()?;
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("paper.tex");
    let output = temp.path().join("paper.pdf");
    fs::write(
        &source,
        b"\\documentclass{article}\\begin{document}\\loop\\iftrue\\repeat\\end{document}",
    )?;
    fs::write(&output, b"previous approved delivery")?;
    let config = tex::runtime_config()?;
    let mut spec = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args([
        std::ffi::OsString::from("--timeout"),
        "120".into(),
        "tex-container".into(),
        source.into_os_string(),
        output.clone().into_os_string(),
    ]);
    spec.cwd = Some(temp.path().to_owned());
    spec.timeout = Duration::from_secs(120);
    spec.max_output = 1024 * 1024;
    spec.env.insert(
        "REVAYAT_LOG_DIR".into(),
        temp.path().join("logs").into_os_string(),
    );
    let result = (|| -> Result<()> {
        let mut controller = runtime::owner::Interactive::spawn(&spec)?;
        let observed = (|| -> Result<String> {
            let deadline = Instant::now() + Duration::from_secs(40);
            while Instant::now() < deadline {
                let mut paths = Vec::new();
                receipts(&receipt_root, &mut paths)?;
                for path in paths {
                    let receipt: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
                    let run = receipt["run_id"].as_str().context("missing run identity")?;
                    let mut listing = config.base.clone();
                    listing.extend([
                        "ps".into(),
                        "--no-trunc".into(),
                        "--filter".into(),
                        format!("label={}={run}", tex::RUN_LABEL),
                        "--format".into(),
                        "{{.ID}}".into(),
                    ]);
                    let (code, running) = tex::call(&listing, 5)?;
                    if code == 0 && running.split_whitespace().any(|id| id.len() == 64) {
                        ensure!(
                            controller.try_wait()?.is_none(),
                            "controller exited before abrupt seam"
                        );
                        return Ok(run.to_owned());
                    }
                }
                ensure!(
                    controller.try_wait()?.is_none(),
                    "controller exited before container start"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            bail!("container did not start before abrupt-death deadline")
        })();
        // The anchored guardian, not a guessed PID, SIGKILLs the live controller
        // process group. The Docker daemon's container is outside that group and
        // still requires the surviving receipt owner to reclaim it.
        let finished = controller.finish();
        let run = runtime::with_cleanup(observed, finished)?;
        ensure!(
            controller.termination_signal() == Some(libc::SIGKILL),
            "actual controller did not die by SIGKILL"
        );
        ensure!(
            fs::read(&output)? == b"previous approved delivery",
            "abrupt death replaced delivery"
        );
        let mut listing = config.base.clone();
        listing.extend([
            "ps".into(),
            "-a".into(),
            "--filter".into(),
            format!("label={}={run}", tex::RUN_LABEL),
            "--format".into(),
            "{{.ID}}".into(),
        ]);
        let (code, remaining) = tex::call(&listing, 15)?;
        ensure!(
            code == 0 && remaining.trim().is_empty(),
            "owned daemon container survived controller death"
        );
        let mut paths = Vec::new();
        receipts(&receipt_root, &mut paths)?;
        ensure!(paths.is_empty(), "abrupt death retained owned receipts");
        ensure!(
            !fs::read_dir(temp.path())?.any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".revayat-tex-")),
            "abrupt death retained staging"
        );
        Ok(())
    })();
    if let Err(error) = result {
        let retained = temp.keep();
        return Err(error.context(format!(
            "abrupt-death evidence retained: {}",
            retained.display()
        )));
    }
    Ok(())
}
fn timed_controller_cancellation() -> Result<()> {
    let receipt_root = receipt_scope()?;
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("paper.tex");
    let output = temp.path().join("paper.pdf");
    fs::write(
        &source,
        b"\\documentclass{article}\\begin{document}\\loop\\iftrue\\repeat\\end{document}",
    )?;
    fs::write(&output, b"previous approved delivery")?;
    let config = tex::runtime_config()?;
    let mut spec = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args([
        "--timeout",
        "45",
        "run-check",
        "--timeout",
        "120",
        "--",
        env!("CARGO_BIN_EXE_revayat-scientific"),
        "--timeout",
        "120",
        "tex-container",
    ]);
    spec.args
        .extend([source.into_os_string(), output.clone().into_os_string()]);
    spec.cwd = Some(temp.path().to_owned());
    spec.timeout = Duration::from_secs(150);
    spec.max_output = 1024 * 1024;
    spec.env.insert(
        "REVAYAT_LOG_DIR".into(),
        temp.path().join("logs").into_os_string(),
    );
    let result = (|| -> Result<()> {
        let (observed, outcome) = std::thread::scope(|scope| {
            let process = scope.spawn(|| runtime::run_supervised(&spec));
            let observed = (|| -> Result<String> {
                let deadline = Instant::now() + Duration::from_secs(40);
                while Instant::now() < deadline {
                    let mut paths = vec![];
                    receipts(&receipt_root, &mut paths)?;
                    for path in paths {
                        let receipt: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
                        let identity = receipt["run_id"]
                            .as_str()
                            .context("receipt omitted run identity")?;
                        let mut listing = config.base.clone();
                        listing.extend([
                            "ps".into(),
                            "--no-trunc".into(),
                            "--filter".into(),
                            format!("label={}={identity}", tex::RUN_LABEL),
                            "--format".into(),
                            "{{.ID}}".into(),
                        ]);
                        let (code, ids) = tex::call(&listing, 5)?;
                        if code == 0 && ids.split_whitespace().any(|id| id.len() == 64) {
                            return Ok(identity.to_owned());
                        }
                    }
                    ensure!(
                        !process.is_finished(),
                        "controller exited before the cancellation seam"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                bail!("owned TeX container did not start within40seconds")
            })();
            // Join on every observation outcome. The production owner bounds and
            // drains the process tree; no raw child or unread pipes can escape.
            (observed, process.join())
        });
        let outcome = outcome.map_err(|_| anyhow::anyhow!("cancellation runner panicked"))??;
        ensure!(
            outcome.code == 124,
            "global cancellation failed: {}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        let run = observed?;
        ensure!(
            fs::read(&output)? == b"previous approved delivery",
            "cancellation replaced prior delivery"
        );
        let mut listing = config.base.clone();
        listing.extend([
            "ps".into(),
            "-a".into(),
            "--filter".into(),
            format!("label={}={run}", tex::RUN_LABEL),
            "--format".into(),
            "{{.ID}}".into(),
        ]);
        let (code, remaining) = tex::call(&listing, 15)?;
        ensure!(
            code == 0,
            "cannot inspect owned container after cancellation"
        );
        ensure!(
            remaining.trim().is_empty(),
            "owned container survived cancellation"
        );
        let mut paths = vec![];
        receipts(&receipt_root, &mut paths)?;
        ensure!(paths.is_empty(), "cancellation left owned receipts");
        ensure!(
            !fs::read_dir(temp.path())?.any(|e| {
                e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".revayat-tex-")
            }),
            "cancellation left owned staging"
        );
        Ok(())
    })();
    if let Err(error) = result {
        let retained = temp.keep();
        return Err(error.context(format!(
            "cancellation evidence retained: {}",
            retained.display()
        )));
    }
    Ok(())
}

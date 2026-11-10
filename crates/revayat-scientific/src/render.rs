//! Static HTML printing through native Chromium's intercepted DevTools requests.
use crate::{
    build::{BuildGuard, MAX_FILE_BYTES, file_hash},
    publication::{publish_files, validate_destination},
    resource::ResourcePolicy,
    runtime,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[path = "render_diagnostics.rs"]
mod diagnostics;

#[cfg(unix)]
type BrowserChild = runtime::owner::Interactive;
#[cfg(windows)]
type BrowserChild = std::process::Child;
struct Browser {
    child: BrowserChild,
    profile: tempfile::TempDir,
    diagnostics: Option<diagnostics::Diagnostics>,
    stopped: Option<bool>,
    #[cfg(windows)]
    owner: Option<crate::windows_security::native::WindowsJob>,
}
impl Browser {
    fn launch(executable: &Path, parent: &Path) -> Result<(Self, u16, String)> {
        let profile = tempfile::Builder::new()
            .prefix(".revayat-browser-")
            .tempdir_in(parent)?;
        let mut command = Command::new(executable);
        command
            .args([
                "--headless",
                "--remote-debugging-port=0",
                "--remote-debugging-address=127.0.0.1",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-sync",
                "--disable-extensions",
                "--metrics-recording-only",
            ])
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        let (child, owner) = crate::windows_security::native::spawn_owned(
            &mut command,
            crate::windows_security::JobLimits::browser(),
        )?;
        #[cfg(unix)]
        let child = runtime::owner::Interactive::from_command(&command)
            .context("cannot start sandboxed Chromium owner")?;
        let mut browser = Self {
            child,
            profile,
            diagnostics: None,
            stopped: None,
            #[cfg(windows)]
            owner: Some(owner),
        };
        #[cfg(unix)]
        let stderr = browser.child.take_stderr();
        #[cfg(windows)]
        let stderr = browser.child.stderr.take();
        let initialized = stderr
            .context("browser stderr pipe missing")
            .and_then(|pipe| {
                diagnostics::Diagnostics::start(pipe)
                    .map_err(|_| anyhow::anyhow!("browser diagnostic reader initialization failed"))
            });
        match initialized {
            Ok(diagnostics) => browser.diagnostics = Some(diagnostics),
            Err(error) => return Err(browser.initialization_failure(error)),
        }
        let ready = browser.wait_ready();
        match ready {
            Ok((port, endpoint)) => Ok((browser, port, endpoint)),
            Err(error) => Err(browser
                .finish_operation::<()>(Err(error), "startup")
                .unwrap_err()),
        }
    }

    fn wait_ready(&mut self) -> Result<(u16, String)> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            ensure!(
                self.child.try_wait()?.is_none(),
                "Chromium exited before its sandboxed endpoint became available"
            );
            ensure!(
                !self
                    .diagnostics
                    .as_ref()
                    .is_some_and(diagnostics::Diagnostics::failed),
                "Chromium diagnostic capture failed its bound"
            );
            if let Ok(text) = fs::read_to_string(self.profile.path().join("DevToolsActivePort")) {
                let mut lines = text.lines();
                let port: u16 = lines
                    .next()
                    .context("Chromium endpoint omitted port")?
                    .parse()?;
                let endpoint = lines
                    .next()
                    .context("Chromium endpoint omitted identity")?
                    .to_owned();
                ensure!(
                    endpoint.starts_with("/devtools/browser/")
                        && !endpoint.contains(['\r', '\n', ' ']),
                    "invalid Chromium endpoint"
                );
                return Ok((port, endpoint));
            }
            ensure!(
                Instant::now() < deadline,
                "Chromium startup exceeded its deadline"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn initialization_failure(&mut self, error: anyhow::Error) -> anyhow::Error {
        let clean = self.stop();
        error.context(format!(
            "phase=startup diagnostic_init=false cleanup_complete={clean}"
        ))
    }

    fn stop(&mut self) -> bool {
        if let Some(clean) = self.stopped {
            return clean;
        }
        let mut clean = true;
        #[cfg(unix)]
        {
            clean &= self.child.finish().is_ok();
        }
        #[cfg(windows)]
        if let Some(mut owner) = self.owner.take() {
            clean &= owner.finish().is_ok();
            // KILL_ON_JOB_CLOSE fallback runs before the diagnostic reader joins.
            drop(owner);
        }
        #[cfg(windows)]
        {
            // Windows Job owns descendants independently of process-ID lifetime.
            if !matches!(self.child.try_wait(), Ok(Some(_))) {
                clean &= self.child.kill().is_ok();
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    _ => {
                        clean = false;
                        break;
                    }
                }
            }
        }
        self.stopped = Some(clean);
        clean
    }

    fn finish_operation<T>(&mut self, result: Result<T>, phase: &str) -> Result<T> {
        let observed = self.child.try_wait();
        let status_observed = observed.is_ok();
        let status = observed.ok().flatten();
        let clean = self.stop();
        #[cfg(unix)]
        let status = status.or(self.child.natural_status());
        let diagnostics = self
            .diagnostics
            .as_mut()
            .context("browser diagnostics missing")?;
        let reader_complete = diagnostics.finish();
        let capture_failed = diagnostics.failed();
        // Only a naturally observed failure invalidates a completed print. A live
        // browser deliberately terminated by our owner is not an exit-zero contract.
        let naturally_failed = status.is_some_and(|value| !value.success());
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            status.and_then(|value| value.signal())
        };
        #[cfg(not(unix))]
        let signal = None;
        let report = diagnostics.report(phase, status.and_then(|value| value.code()), signal);
        #[cfg(unix)]
        let scope = "registered-guardian-owned-group";
        #[cfg(windows)]
        let scope = "owned-job";
        let cleanup = format!("cleanup_complete={clean} cleanup_scope={scope}");
        match result {
            Err(error) => Err(error.context(format!("browser {report} {cleanup}"))),
            Ok(value)
                if clean
                    && status_observed
                    && reader_complete
                    && !capture_failed
                    && !naturally_failed =>
            {
                Ok(value)
            }
            Ok(_) => bail!("browser verification failed {report} {cleanup}"),
        }
    }
}
impl Drop for Browser {
    fn drop(&mut self) {
        self.stop();
        if let Some(diagnostics) = self.diagnostics.as_mut() {
            diagnostics.finish();
        }
    }
}

#[path = "render_protocol.rs"]
mod protocol;
use protocol::DevTools;

pub fn validate_pdf(path: &Path) -> Result<()> {
    ensure!(
        !crate::identity::is_link(path)?
            && path.is_file()
            && fs::metadata(path)?.len() <= 256 * 1024 * 1024,
        "renderer did not produce a safe bounded PDF"
    );
    let mut file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    ensure!(size >= 32, "renderer produced truncated PDF");
    let mut prefix = [0; 8];
    file.read_exact(&mut prefix)?;
    ensure!(prefix.starts_with(b"%PDF-"), "renderer did not produce PDF");
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(size.saturating_sub(2048)))?;
    let mut trailer = Vec::new();
    file.read_to_end(&mut trailer)?;
    ensure!(
        trailer.trim_ascii_end().ends_with(b"%%EOF"),
        "renderer produced incomplete PDF"
    );
    crate::pdf::validate_pdf(path)?;
    Ok(())
}

/// Qualify the same sandboxed executable/owned endpoint used for rendering.
/// The caller supplies an already-owned private scratch parent; no document is rendered.
pub fn preflight_browser(executable: &Path, parent: &Path) -> Result<()> {
    let (mut browser, port, endpoint) = Browser::launch(executable, parent)?;
    let result = (|| {
        let diagnostics = browser
            .diagnostics
            .as_ref()
            .context("browser diagnostics missing")?;
        // ResourcePolicy is unused by Browser.getVersion but keeps the existing
        // protocol client, limits and diagnostic path shared with real rendering.
        let probe = browser.profile.path().join("preflight.html");
        fs::write(&probe, b"<html></html>")?;
        let mut policy = ResourcePolicy::new(&probe)?;
        let mut tools = DevTools::connect(port, &endpoint, &mut policy, diagnostics)
            .map_err(|_| anyhow::anyhow!("Chromium preflight protocol connection failed"))?;
        tools.deadline = Instant::now() + Duration::from_secs(5);
        let version = tools
            .call("Browser.getVersion", json!({}))
            .map_err(|_| anyhow::anyhow!("Chromium preflight protocol handshake failed"))?;
        ensure!(
            version["product"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
                && version["protocolVersion"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
            "Chromium preflight returned no protocol identity"
        );
        Ok(())
    })();
    browser.finish_operation(result, "preflight")
}

pub fn render_html(
    source: &Path,
    output: &Path,
    browser: &Path,
    guard: Option<&Path>,
) -> Result<()> {
    render_html_with(source, output, guard, |policy, rendered| {
        let (mut browser, port, endpoint) = Browser::launch(browser, rendered.parent().unwrap())?;
        let result = (|| {
            let diagnostics = browser
                .diagnostics
                .as_ref()
                .context("browser diagnostics missing")?;
            let mut tools = DevTools::connect(port, &endpoint, policy, diagnostics)
                .map_err(|_| anyhow::anyhow!("Chromium render protocol connection failed"))?;
            let bytes = tools
                .print()
                .map_err(|_| anyhow::anyhow!("Chromium render protocol operation failed"))?;
            fs::write(rendered, bytes)?;
            Ok(())
        })();
        browser.finish_operation(result, "render")
    })
}

/// Renderer injection happens at the real I/O boundary, allowing mutation and
/// failure regressions to exercise the same admission/publication path.
pub fn render_html_with(
    source: &Path,
    output: &Path,
    guard: Option<&Path>,
    renderer: impl FnOnce(&mut ResourcePolicy, &Path) -> Result<()>,
) -> Result<()> {
    let source = source.canonicalize()?;
    let output = validate_destination(output, std::slice::from_ref(&source))?;
    if let Some(path) = guard {
        let record = BuildGuard::check(path, None)?;
        ensure!(
            record.outputs[0] == output,
            "HTML guard belongs to another renderer output"
        );
    }
    let mut policy = ResourcePolicy::new(&source)?;
    if let Some(path) = guard {
        BuildGuard::check(path, Some(&policy.resources))?;
    }
    fs::create_dir_all(output.parent().context("output parent missing")?)?;
    let stage = tempfile::Builder::new()
        .prefix(".revayat-render-")
        .tempdir_in(output.parent().unwrap())?;
    let rendered = stage.path().join("document.pdf");
    renderer(&mut policy, &rendered)?;
    ensure!(!policy.denied, "render resource access denied");
    validate_pdf(&rendered)?;
    for (name, digest) in &policy.resources {
        ensure!(
            name.starts_with(source.parent().unwrap()) && file_hash(name)? == *digest,
            "document resource changed before publication"
        );
    }
    let mut protected = vec![source];
    protected.extend(policy.resources.keys().cloned());
    if let Some(path) = guard {
        protected.extend(BuildGuard::check(path, Some(&policy.resources))?.protected(path));
    }
    let digest = file_hash(&rendered)?;
    publish_files(
        &[(rendered, output.clone())],
        &protected,
        Some(MAX_FILE_BYTES),
    )?;
    if let Some(path) = guard {
        BuildGuard::seal(path, &output, &digest)?;
    }
    Ok(())
}

pub fn discover_browser(explicit: Option<&str>) -> Result<PathBuf> {
    if let Some(executable) = explicit {
        return runtime::executable(executable);
    }
    for variable in ["REVAYAT_BROWSER", "REVAYAT_CHROMIUM"] {
        if let Ok(executable) = std::env::var(variable)
            && !executable.is_empty()
        {
            return runtime::executable(&executable);
        }
    }
    for name in [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "chrome",
        "msedge",
    ] {
        if let Ok(path) = runtime::executable(name) {
            return Ok(path);
        }
    }
    #[cfg(target_os = "macos")]
    for name in [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ] {
        if Path::new(name).is_file() {
            return Ok(PathBuf::from(name));
        }
    }
    #[cfg(windows)]
    for directory in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(directory) {
            for relative in [
                "Google/Chrome/Application/chrome.exe",
                "Microsoft/Edge/Application/msedge.exe",
            ] {
                let path = PathBuf::from(&root).join(relative);
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
    }
    bail!("sandboxed Chromium is not installed; set REVAYAT_BROWSER")
}

pub fn cli_render(args: &[String]) -> Result<i32> {
    ensure!(
        args.len() >= 2,
        "render-html SOURCE OUTPUT [--browser EXECUTABLE] [--build-guard PATH]"
    );
    let mut browser = None;
    let mut guard = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--browser" => {
                index += 1;
                browser = Some(args.get(index).context("browser value missing")?.as_str());
            }
            "--build-guard" => {
                index += 1;
                guard = Some(Path::new(args.get(index).context("guard value missing")?));
            }
            "--engine" => {
                index += 1;
                ensure!(
                    args.get(index).map(String::as_str) == Some("chromium"),
                    "native HTML engine must be chromium"
                );
            }
            other => bail!("unknown render argument: {other}"),
        };
        index += 1;
    }
    render_html(
        Path::new(&args[0]),
        Path::new(&args[1]),
        &discover_browser(browser)?,
        guard,
    )?;
    Ok(0)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn launch_fixture() -> (Browser, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        let profile = tempfile::tempdir_in(&parent).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "render::lifecycle_tests::fixture_child",
                "--nocapture",
            ])
            .env(
                "REVAYAT_BROWSER_FIXTURE_EXIT",
                profile.path().join("exit-now"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        let (mut child, owner) = crate::windows_security::native::spawn_owned(
            &mut command,
            crate::windows_security::JobLimits::browser(),
        )
        .unwrap();
        #[cfg(unix)]
        let mut child = runtime::owner::Interactive::from_command(&command).unwrap();
        #[cfg(unix)]
        let stderr = child.take_stderr();
        #[cfg(windows)]
        let stderr = child.stderr.take();
        let diagnostics = diagnostics::Diagnostics::start(stderr.unwrap()).unwrap();
        (
            Browser {
                child,
                profile,
                diagnostics: Some(diagnostics),
                stopped: None,
                #[cfg(windows)]
                owner: Some(owner),
            },
            temp,
        )
    }

    #[test]
    fn fixture_child() {
        let Some(marker) = std::env::var_os("REVAYAT_BROWSER_FIXTURE_EXIT") else {
            return;
        };
        while !Path::new(&marker).exists() {
            thread::sleep(Duration::from_millis(5));
        }
        std::process::exit(42);
    }

    #[test]
    fn completed_nonzero_browser_rejects_successful_operation_before_publication() {
        let (mut browser, _temp) = launch_fixture();
        fs::write(browser.profile.path().join("exit-now"), b"exit").unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while browser.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let result = browser.finish_operation(Ok(b"validated PDF bytes"), "render");
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("exit_code=42"));
        drop(browser);
    }

    #[test]
    fn initialization_failure_keeps_primary_error_and_explicit_cleanup_outcome() {
        let (mut browser, _temp) = launch_fixture();
        let error = browser.initialization_failure(anyhow::anyhow!(
            "injected diagnostic initialization failure"
        ));
        let text = format!("{error:#}");
        assert!(text.contains("injected diagnostic initialization failure"));
        assert!(text.contains("diagnostic_init=false"));
        assert!(text.contains("cleanup_complete=true"));
        assert!(browser.child.try_wait().unwrap().is_some());
        drop(browser);
    }
}

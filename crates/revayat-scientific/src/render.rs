//! Static HTML printing through native Chromium's intercepted DevTools requests.
use crate::{
    build::{BuildGuard, MAX_FILE_BYTES, file_hash},
    publication::{publish_files, validate_destination},
    resource::{ORIGIN, ResourcePolicy},
    runtime,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket, stream::MaybeTlsStream};

struct Browser {
    child: Child,
    profile: tempfile::TempDir,
    #[cfg(unix)]
    owns_group: bool,
    #[cfg(windows)]
    owner: crate::windows_security::native::WindowsJob,
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
            .stderr(Stdio::null());
        #[cfg(unix)]
        let owns_group = std::env::var_os("REVAYAT_RUNTIME_GROUP").as_deref()
            != Some(std::ffi::OsStr::new("inherit"));
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            if owns_group {
                command.process_group(0);
            }
            command.env("REVAYAT_RUNTIME_GROUP", "inherit");
        }
        #[cfg(windows)]
        let (child, owner) = crate::windows_security::native::spawn_owned(
            &mut command,
            crate::windows_security::JobLimits::browser(),
        )?;
        #[cfg(not(windows))]
        let child = command.spawn().context("cannot start sandboxed Chromium")?;
        let mut browser = Self {
            child,
            profile,
            #[cfg(unix)]
            owns_group,
            #[cfg(windows)]
            owner,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            ensure!(
                browser.child.try_wait()?.is_none(),
                "Chromium exited before its sandboxed endpoint became available"
            );
            if let Ok(text) = fs::read_to_string(browser.profile.path().join("DevToolsActivePort"))
            {
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
                return Ok((browser, port, endpoint));
            }
            ensure!(
                Instant::now() < deadline,
                "Chromium startup exceeded its deadline"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Browser {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.owns_group {
            let _ = runtime::kill_owned_group(self.child.id());
        }
        #[cfg(windows)]
        let _ = self.owner.finish();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct DevTools<'a> {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    session: Option<String>,
    policy: &'a mut ResourcePolicy,
    deadline: Instant,
    failed: bool,
    loaded: bool,
}
impl<'a> DevTools<'a> {
    fn connect(port: u16, endpoint: &str, policy: &'a mut ResourcePolicy) -> Result<Self> {
        // Only a loopback endpoint read from the newly owned browser profile is
        // ever connected. No network URL from document data reaches this client.
        let config = tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(384 * 1024 * 1024))
            .max_frame_size(Some(384 * 1024 * 1024));
        let (mut socket, _) = tungstenite::client::connect_with_config(
            format!("ws://127.0.0.1:{port}{endpoint}"),
            Some(config),
            0,
        )?;
        if let MaybeTlsStream::Plain(stream) = socket.get_mut() {
            stream.set_read_timeout(Some(Duration::from_millis(250)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        }
        Ok(Self {
            socket,
            next_id: 0,
            session: None,
            policy,
            deadline: Instant::now() + Duration::from_secs(120),
            failed: false,
            loaded: false,
        })
    }
    fn send(&mut self, method: &str, params: Value) -> Result<u64> {
        self.next_id += 1;
        let id = self.next_id;
        let mut request = json!({"id":id,"method":method,"params":params});
        if let Some(session) = &self.session {
            request["sessionId"] = json!(session);
        }
        self.socket
            .send(Message::Text(request.to_string().into()))?;
        Ok(id)
    }
    fn receive(&mut self) -> Result<Option<Value>> {
        ensure!(
            Instant::now() < self.deadline,
            "Chromium render exceeded its deadline"
        );
        match self.socket.read() {
            Ok(Message::Text(text)) => {
                ensure!(
                    text.len() <= 384 * 1024 * 1024,
                    "Chromium response exceeds output limit"
                );
                Ok(Some(serde_json::from_str(&text)?))
            }
            Ok(Message::Ping(bytes)) => {
                self.socket.send(Message::Pong(bytes))?;
                Ok(None)
            }
            Ok(Message::Close(_)) => bail!("Chromium closed its render channel"),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
    fn event(&mut self, message: &Value) -> Result<()> {
        match message["method"].as_str().unwrap_or("") {
            "Fetch.requestPaused" => {
                let params = &message["params"];
                let id = params["requestId"]
                    .as_str()
                    .context("resource request has no identity")?;
                let request = &params["request"];
                let url = request["url"]
                    .as_str()
                    .context("resource request has no URL")?;
                if request["method"] != "GET" {
                    self.failed = true;
                    self.send(
                        "Fetch.failRequest",
                        json!({"requestId":id,"errorReason":"BlockedByClient"}),
                    )?;
                } else if url == format!("{ORIGIN}/favicon.ico") {
                    self.send(
                        "Fetch.fulfillRequest",
                        json!({"requestId":id,"responseCode":204,"body":""}),
                    )?;
                } else {
                    match self.policy.fetch(url) {
                        Ok((bytes, mime)) => {
                            self.send("Fetch.fulfillRequest",json!({"requestId":id,"responseCode":200,"body":STANDARD.encode(bytes),"responseHeaders":[{"name":"Content-Type","value":mime},{"name":"Content-Security-Policy","value":"script-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"}]}))?;
                        }
                        Err(_) => {
                            self.failed = true;
                            self.send(
                                "Fetch.failRequest",
                                json!({"requestId":id,"errorReason":"BlockedByClient"}),
                            )?;
                        }
                    }
                }
            }
            "Network.loadingFailed" => self.failed = true,
            "Page.loadEventFired" => self.loaded = true,
            _ => (),
        }
        Ok(())
    }
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.send(method, params)?;
        loop {
            if let Some(message) = self.receive()? {
                if message["id"].as_u64() == Some(id) {
                    ensure!(
                        message.get("error").is_none(),
                        "Chromium protocol operation failed: {method}"
                    );
                    return Ok(message["result"].clone());
                }
                self.event(&message)?;
            }
        }
    }
    fn print(&mut self) -> Result<Vec<u8>> {
        let targets = self.call("Target.getTargets", json!({}))?;
        let target = targets["targetInfos"]
            .as_array()
            .context("browser has no targets")?
            .iter()
            .find(|t| t["type"] == "page")
            .and_then(|t| t["targetId"].as_str())
            .context("browser has no page")?;
        let target = target.to_owned();
        let result = self.call(
            "Target.attachToTarget",
            json!({"targetId":target,"flatten":true}),
        )?;
        self.session = Some(
            result["sessionId"]
                .as_str()
                .context("browser omitted session identity")?
                .into(),
        );
        self.call("Page.enable", json!({}))?;
        self.call("Network.enable", json!({}))?;
        self.call(
            "Emulation.setScriptExecutionDisabled",
            json!({"value":true}),
        )?;
        self.call("Network.setBypassServiceWorker", json!({"bypass":true}))?;
        self.call("Page.setDownloadBehavior", json!({"behavior":"deny"}))?;
        self.call(
            "Fetch.enable",
            json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}),
        )?;
        let name = self
            .policy
            .source
            .file_name()
            .context("source has no basename")?
            .to_string_lossy();
        let encoded = name
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>();
        self.loaded = false;
        self.call(
            "Page.navigate",
            json!({"url":format!("{ORIGIN}/{encoded}")}),
        )?;
        while !self.loaded {
            if let Some(message) = self.receive()? {
                self.event(&message)?;
            }
        }
        self.call(
            "Runtime.evaluate",
            json!({"expression":"document.fonts.ready","awaitPromise":true,"returnByValue":true}),
        )?;
        ensure!(
            !self.failed && !self.policy.denied,
            "render resource access was denied or failed"
        );
        let result=self.call("Page.printToPDF",json!({"printBackground":true,"preferCSSPageSize":true,"generateTaggedPDF":true,"transferMode":"ReturnAsBase64"}))?;
        ensure!(
            !self.failed && !self.policy.denied,
            "render resource access was denied or failed"
        );
        let data = result["data"]
            .as_str()
            .context("Chromium omitted PDF bytes")?;
        ensure!(
            data.len() <= 384 * 1024 * 1024,
            "Chromium PDF exceeds output limit"
        );
        Ok(STANDARD.decode(data)?)
    }
}

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

pub fn render_html(
    source: &Path,
    output: &Path,
    browser: &Path,
    guard: Option<&Path>,
) -> Result<()> {
    render_html_with(source, output, guard, |policy, rendered| {
        let (_browser, port, endpoint) = Browser::launch(browser, rendered.parent().unwrap())?;
        let bytes = DevTools::connect(port, &endpoint, policy)?.print()?;
        fs::write(rendered, bytes)?;
        Ok(())
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

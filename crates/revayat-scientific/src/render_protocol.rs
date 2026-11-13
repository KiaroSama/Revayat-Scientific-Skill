//! Owned loopback DevTools protocol, resource interception and bounded I/O.
use super::diagnostics::Diagnostics;
use crate::resource::{ORIGIN, ResourcePolicy};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    net::TcpStream,
    thread,
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket};

pub(super) struct DevTools<'a> {
    socket: WebSocket<TcpStream>,
    next_id: u64,
    session: Option<String>,
    policy: &'a mut ResourcePolicy,
    pub(super) deadline: Instant,
    failed: bool,
    loaded: bool,
    diagnostics: &'a Diagnostics,
}
impl<'a> DevTools<'a> {
    pub(super) fn connect(
        port: u16,
        endpoint: &str,
        policy: &'a mut ResourcePolicy,
        diagnostics: &'a Diagnostics,
    ) -> Result<Self> {
        let config = tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(384 * 1024 * 1024))
            .max_frame_size(Some(384 * 1024 * 1024));
        let stream = TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_secs(5),
        )?;
        stream.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut handshake = tungstenite::client::client_with_config(
            format!("ws://127.0.0.1:{port}{endpoint}"),
            stream,
            Some(config),
        );
        let socket = loop {
            ensure!(
                !diagnostics.failed(),
                "Chromium diagnostic capture failed its bound"
            );
            match handshake {
                Ok((socket, _)) => break socket,
                Err(tungstenite::HandshakeError::Interrupted(next)) => {
                    ensure!(
                        Instant::now() < deadline,
                        "Chromium protocol handshake exceeded its deadline"
                    );
                    thread::sleep(Duration::from_millis(5));
                    handshake = next.handshake();
                }
                Err(tungstenite::HandshakeError::Failure(_)) => {
                    bail!("Chromium protocol handshake failed")
                }
            }
        };
        Ok(Self {
            socket,
            next_id: 0,
            session: None,
            policy,
            deadline: Instant::now() + Duration::from_secs(120),
            failed: false,
            loaded: false,
            diagnostics,
        })
    }
    fn send(&mut self, method: &str, params: Value) -> Result<u64> {
        self.next_id += 1;
        let id = self.next_id;
        let mut request = json!({"id":id,"method":method,"params":params});
        if let Some(session) = &self.session {
            request["sessionId"] = json!(session);
        }
        self.write(Message::Text(request.to_string().into()))?;
        Ok(id)
    }
    fn write(&mut self, message: Message) -> Result<()> {
        // tungstenite0.28 retains the frame on WouldBlock: flush, never enqueue it twice.
        match self.socket.write(message) {
            Ok(()) => (),
            Err(tungstenite::Error::Io(error))
                if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            ensure!(
                !self.diagnostics.failed(),
                "Chromium diagnostic capture failed its bound"
            );
            match self.socket.flush() {
                Ok(()) => return Ok(()),
                Err(tungstenite::Error::Io(error))
                    if error.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    ensure!(
                        Instant::now() < deadline,
                        "Chromium protocol write exceeded its deadline"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    fn receive(&mut self) -> Result<Option<Value>> {
        ensure!(
            !self.diagnostics.failed(),
            "Chromium diagnostic capture failed its bound"
        );
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
            // read queues the pong itself; the next read/flush drives it without duplication.
            Ok(Message::Ping(_)) => Ok(None),
            Ok(Message::Close(_)) => bail!("Chromium closed its render channel"),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(5));
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
                            // Resource admission decodes these files as UTF-8;
                            // the HTTP response must preserve that interpretation
                            // when the immutable source omits a declaration.
                            let content_type = match mime.as_str() {
                                "text/html" | "text/css" => format!("{mime}; charset=utf-8"),
                                _ => mime,
                            };
                            self.send("Fetch.fulfillRequest",json!({"requestId":id,"responseCode":200,"body":STANDARD.encode(bytes),"responseHeaders":[{"name":"Content-Type","value":content_type},{"name":"Content-Security-Policy","value":"script-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"}]}))?;
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
    pub(super) fn call(&mut self, method: &str, params: Value) -> Result<Value> {
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
    pub(super) fn print(&mut self) -> Result<Vec<u8>> {
        let targets = self.call("Target.getTargets", json!({}))?;
        let target = targets["targetInfos"]
            .as_array()
            .context("browser has no targets")?
            .iter()
            .find(|target| target["type"] == "page")
            .and_then(|target| target["targetId"].as_str())
            .context("browser has no page")?
            .to_owned();
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
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
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
        let result = self.call("Page.printToPDF", json!({"printBackground":true,"preferCSSPageSize":true,"generateTaggedPDF":true,"transferMode":"ReturnAsBase64"}))?;
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

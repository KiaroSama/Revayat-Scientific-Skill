//! Cooperative Unix command owners. No machine-wide PID scan or hostile-session guarantee.
use super::{CommandOutput, CommandSpec, DeadlineExceeded};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::{Read, Write},
    os::unix::{
        ffi::OsStringExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const OWNER: &str = "REVAYAT_RUNTIME_OWNER";
const SOCKET: &str = "REVAYAT_RUNTIME_ACCOUNTING";
const TOKEN: &str = "REVAYAT_RUNTIME_ACCOUNTING_TOKEN";
const PARENT: &str = "REVAYAT_RUNTIME_PARENT";
// JSON byte arrays can use four bytes per binary byte; input+output are bounded separately.
const LIMIT: usize = 140 * 1024 * 1024;
#[path = "runtime_owner_client.rs"]
mod client;
pub use client::Interactive;
pub use client::run;
const CLEANUP_LIMIT: Duration = Duration::from_secs(30);
thread_local! { static FINALIZING_CONTAINERS: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) }; }

pub(super) fn cleanup_command(
    spec: &CommandSpec,
    input: Option<&[u8]>,
) -> Option<Result<CommandOutput>> {
    FINALIZING_CONTAINERS.with(|active| {
        active.get().map(|deadline| {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context("container cleanup budget exhausted")?;
            let mut bounded = spec.clone();
            bounded.timeout = bounded.timeout.min(remaining);
            super::unix::run(&bounded, input, || false).result
        })
    })
}

fn finish_containers(
    mut scope: crate::tex_supervisor::ContainerScope,
    deadline: Instant,
) -> Result<()> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FINALIZING_CONTAINERS.with(|active| active.set(None));
        }
    }
    FINALIZING_CONTAINERS.with(|active| active.set(Some(deadline)));
    let _reset = Reset;
    let result = scope.finish_until(deadline);
    drop(scope);
    result
}

#[derive(Default)]
pub struct Accounting {
    nodes: BTreeMap<String, (Option<String>, bool, bool, Option<Instant>)>,
    failed: bool,
}
impl Accounting {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, id: &str, parent: Option<&str>) -> Result<()> {
        ensure!(
            !id.is_empty()
                && id.len() <= 128
                && !self.nodes.contains_key(id)
                && self.nodes.len() < 256,
            "invalid ownership registration"
        );
        if let Some(parent) = parent {
            let mut ancestor = Some(parent);
            while let Some(id) = ancestor {
                let node = self
                    .nodes
                    .get(id)
                    .context("ownership parent is not active")?;
                ensure!(!node.1, "ownership ancestor is already finalizing");
                ancestor = node.0.as_deref();
            }
        } else {
            ensure!(self.nodes.is_empty(), "multiple ownership roots");
        }
        self.nodes
            .insert(id.into(), (parent.map(Into::into), false, false, None));
        Ok(())
    }
    pub fn stopped(&mut self, id: &str) -> Result<()> {
        self.stop_at(id, Instant::now() + CLEANUP_LIMIT)
    }
    pub fn stop_at(&mut self, id: &str, deadline: Instant) -> Result<()> {
        let node = self.nodes.get_mut(id).context("unknown stopped owner")?;
        ensure!(!node.1, "duplicate ownership stop");
        node.1 = true;
        node.3 = Some(deadline);
        Ok(())
    }
    pub fn cleanup_deadline(&self, id: &str) -> Result<Option<Instant>> {
        let mut current = Some(id);
        let mut deadline: Option<Instant> = None;
        while let Some(id) = current {
            let node = self.nodes.get(id).context("unknown cleanup owner")?;
            if let Some(cutoff) = node.3 {
                deadline = Some(deadline.map_or(cutoff, |value| value.min(cutoff)));
            }
            current = node.0.as_deref();
        }
        Ok(deadline)
    }
    pub fn descendants_settled(&self, id: &str) -> bool {
        !self.failed
            && !self
                .nodes
                .values()
                .any(|node| node.0.as_deref() == Some(id))
    }
    pub fn done(&mut self, id: &str) -> Result<()> {
        ensure!(
            self.descendants_settled(id),
            "nested owners have not finalized"
        );
        let node = self.nodes.get_mut(id).context("unknown completed owner")?;
        ensure!(
            node.1 && !node.2,
            "ownership must stop before final cleanup"
        );
        node.2 = true;
        Ok(())
    }
    pub fn failed(&mut self) {
        self.failed = true;
    }
    pub fn retire(&mut self, id: &str) -> Result<()> {
        ensure!(self.settled(id), "cannot retire unsettled owner");
        ensure!(
            !self
                .nodes
                .values()
                .any(|node| node.0.as_deref() == Some(id)),
            "owner still has registered descendants"
        );
        self.nodes.remove(id);
        Ok(())
    }
    pub fn settled(&self, id: &str) -> bool {
        !self.failed
            && self.nodes.get(id).is_some_and(|node| node.2)
            && self
                .nodes
                .iter()
                .filter(|(_, node)| node.0.as_deref() == Some(id))
                .all(|(child, _)| self.settled(child))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    token: String,
    id: String,
    parent: Option<String>,
}
struct Peer {
    stream: UnixStream,
    bytes: Vec<u8>,
    id: Option<String>,
    done: bool,
    stopped: bool,
    may_clean: bool,
    started: Instant,
}
struct RootAccounting {
    _directory: tempfile::TempDir,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<Result<()>>>,
}
impl RootAccounting {
    fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            server
                .join()
                .map_err(|_| anyhow::anyhow!("ownership accounting thread failed"))??;
        }
        Ok(())
    }
}
impl Drop for RootAccounting {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn transfer(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    write: bool,
    deadline: Instant,
) -> Result<()> {
    stream.set_nonblocking(true)?;
    let mut offset = 0;
    while offset < bytes.len() {
        ensure!(
            Instant::now() < deadline,
            "ownership protocol deadline exceeded"
        );
        let count = if write {
            stream.write(&bytes[offset..])
        } else {
            stream.read(&mut bytes[offset..])
        };
        match count {
            Ok(0) => bail!("ownership protocol disconnected"),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error.into()),
        }
    }
    stream.set_nonblocking(false)?;
    Ok(())
}
fn frame<T: Serialize>(stream: &mut UnixStream, value: &T, limit: usize) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= limit, "ownership frame exceeds byte limit");
    let deadline = Instant::now() + Duration::from_secs(5);
    transfer(
        stream,
        &mut (bytes.len() as u32).to_be_bytes(),
        true,
        deadline,
    )?;
    transfer(stream, &mut bytes, true, deadline)
}
fn receive<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    limit: usize,
    timeout: Duration,
) -> Result<T> {
    let deadline = Instant::now() + timeout;
    let mut size = [0; 4];
    transfer(stream, &mut size, false, deadline)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size <= limit, "ownership frame exceeds byte limit");
    let mut bytes = vec![0; size];
    transfer(stream, &mut bytes, false, deadline)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn accounting_server(listener: UnixListener, token: String, stop: Arc<AtomicBool>) -> Result<()> {
    listener.set_nonblocking(true)?;
    let mut accounting = Accounting::new();
    let mut peers: Vec<Peer> = Vec::new();
    while !stop.load(Ordering::Acquire) {
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    ensure!(peers.len() < 256, "ownership connection limit exceeded");
                    stream.set_nonblocking(true)?;
                    peers.push(Peer {
                        stream,
                        bytes: Vec::new(),
                        id: None,
                        done: false,
                        stopped: false,
                        may_clean: false,
                        started: Instant::now(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        for peer in &mut peers {
            if peer.done {
                continue;
            }
            let mut bytes = [0; 512];
            match peer.stream.read(&mut bytes) {
                Ok(0) => {
                    accounting.failed();
                    peer.done = true;
                }
                Ok(count) => {
                    peer.bytes.extend_from_slice(&bytes[..count]);
                    ensure!(peer.bytes.len() <= 4096, "ownership registration too large");
                    if peer.id.is_none() && peer.bytes.len() >= 4 {
                        let size = u32::from_be_bytes(peer.bytes[..4].try_into()?) as usize;
                        ensure!(size <= 4092, "ownership registration too large");
                        if peer.bytes.len() >= size + 4 {
                            let request: Registration =
                                serde_json::from_slice(&peer.bytes[4..size + 4])?;
                            ensure!(
                                request.token == token,
                                "ownership registration token mismatch"
                            );
                            accounting.register(&request.id, request.parent.as_deref())?;
                            peer.id = Some(request.id);
                            peer.bytes.drain(..size + 4);
                            peer.stream.write_all(b"R")?;
                        }
                    }
                    if let Some(id) = &peer.id
                        && !peer.bytes.is_empty()
                    {
                        match peer.bytes.as_slice() {
                            b"S" => {
                                accounting.stopped(id)?;
                                peer.stopped = true;
                            }
                            b"D" if peer.may_clean => {
                                ensure!(
                                    accounting
                                        .cleanup_deadline(id)?
                                        .is_some_and(|deadline| Instant::now() < deadline),
                                    "ancestor cleanup budget exhausted; completion refused"
                                );
                                accounting.done(id)?;
                                peer.done = true;
                            }
                            b"F" => {
                                accounting.failed();
                                peer.done = true;
                            }
                            _ => bail!("invalid ownership completion"),
                        }
                        peer.bytes.clear();
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(_) => {
                    accounting.failed();
                    peer.done = true;
                }
            }
            ensure!(
                peer.id.is_some() || peer.started.elapsed() < Duration::from_secs(2),
                "ownership registration deadline exceeded"
            );
        }
        // Retire leaves first, then their parent in later turns. The bound is
        // simultaneous unsettled work, not all calls during a test binary.
        for peer in &mut peers {
            if let Some(id) = &peer.id {
                if peer.stopped && !peer.may_clean && accounting.descendants_settled(id) {
                    let deadline = accounting
                        .cleanup_deadline(id)?
                        .context("cleanup cutoff missing")?;
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .context("cleanup budget exhausted")?;
                    let mut grant = vec![b'Q'];
                    grant.extend_from_slice(&(remaining.as_millis() as u64).to_be_bytes());
                    peer.stream.write_all(&grant)?;
                    peer.may_clean = true;
                }
                if peer.done
                    && accounting.settled(id)
                    && !accounting
                        .nodes
                        .values()
                        .any(|node| node.0.as_deref() == Some(id))
                {
                    peer.stream.write_all(b"C")?;
                    accounting.retire(id)?;
                    peer.id = None;
                }
            }
        }
        peers.retain(|peer| !(peer.done && peer.id.is_none()));
        thread::sleep(Duration::from_millis(5));
    }
    ensure!(
        !accounting.failed && accounting.nodes.is_empty(),
        "nested ownership cleanup incomplete"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    program: Vec<u8>,
    args: Vec<Vec<u8>>,
    cwd: Option<Vec<u8>>,
    env: Vec<(Vec<u8>, Vec<u8>)>,
    env_remove: Vec<Vec<u8>>,
    timeout_ms: u64,
    idle_ms: Option<u64>,
    max_output: usize,
    input: Option<Vec<u8>>,
    interactive: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    deadline_idle: Option<bool>,
    termination_signal: Option<i32>,
    cleanup_complete: bool,
    error: Option<String>,
}

// Only authored stage labels and OS error numbers cross the privacy boundary.
// Child diagnostics, paths, arguments and environment never become error labels.
fn operation_category(error: &anyhow::Error) -> String {
    let error = error
        .downcast_ref::<super::CleanupFailure>()
        .map_or(error, |cleanup| &cleanup.0);
    let stage = ["status-query", "group-cleanup", "child-reap"]
        .into_iter()
        .find(|stage| {
            error
                .chain()
                .any(|cause| cause.to_string() == format!("owned-{stage}"))
        })
        .unwrap_or("unknown");
    let errno = error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error);
    match errno {
        Some(errno) => format!("operation-{stage}-os-{errno}"),
        None => format!("operation-{stage}"),
    }
}

pub fn companion() -> Result<PathBuf> {
    let candidate = if let Some(path) = std::env::var_os(OWNER) {
        PathBuf::from(path)
    } else {
        let executable = std::env::current_exe()?;
        let directory = crate::executable_paths::binary_directory(&executable)?;
        directory.join("revayat-process-owner")
    };
    ensure!(
        candidate.is_absolute() && !crate::identity::is_link(&candidate)? && candidate.is_file(),
        "required Unix runtime companion revayat-process-owner is missing or invalid"
    );
    let path = candidate.canonicalize()?;
    ensure!(
        path.file_name() == Some(OsStr::new("revayat-process-owner")),
        "unexpected runtime companion name"
    );
    Ok(path)
}

/// Called only by the explicit companion auto-bin, never by an arbitrary test executable.
pub fn cli() -> Result<()> {
    use std::os::fd::FromRawFd;
    // SAFETY: only the companion entry calls this function, once. fd0 is the
    // private socket supplied through Command's Stdio ownership transfer.
    let mut lifeline = unsafe { UnixStream::from_raw_fd(0) };
    // fd0 normally survives exec. The private lifeline must not reach commands.
    // SAFETY: this changes only close-on-exec on our owned valid descriptor.
    ensure!(
        unsafe { libc::fcntl(0, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "cannot protect runtime lifeline descriptor"
    );
    lifeline.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request: Request = receive(&mut lifeline, LIMIT, Duration::from_secs(5))?;
    ensure!(
        request.timeout_ms > 0
            && request.timeout_ms <= 24 * 60 * 60 * 1000
            && request.idle_ms.is_none_or(|value| value > 0)
            && request.max_output > 0
            && request.max_output <= super::MAX_DIAGNOSTICS
            && request
                .input
                .as_ref()
                .is_none_or(|value| value.len() <= super::MAX_DIAGNOSTICS),
        "invalid runtime ownership request"
    );
    let inherited = std::env::var_os(SOCKET);
    let mut root = None;
    let (socket, token, parent) = if let Some(socket) = inherited {
        (
            PathBuf::from(socket),
            std::env::var(TOKEN)?,
            Some(std::env::var(PARENT)?),
        )
    } else {
        let directory = tempfile::Builder::new()
            .prefix("revayat-owner-")
            .tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("accounting.sock");
        let listener = UnixListener::bind(&socket)?;
        let token = crate::tex_supervisor::new_token();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let secret = token.clone();
        let server = thread::spawn(move || accounting_server(listener, secret, stopping));
        root = Some(RootAccounting {
            _directory: directory,
            stop,
            server: Some(server),
        });
        (socket, token, None)
    };
    let id = crate::tex_supervisor::new_token();
    let mut account = UnixStream::connect(&socket)?;
    account.set_read_timeout(Some(Duration::from_secs(5)))?;
    account.set_write_timeout(Some(Duration::from_secs(2)))?;
    frame(
        &mut account,
        &Registration {
            token: token.clone(),
            id: id.clone(),
            parent,
        },
        4092,
    )?;
    let mut acknowledged = [0];
    transfer(
        &mut account,
        &mut acknowledged,
        false,
        Instant::now() + Duration::from_secs(5),
    )?;
    ensure!(
        acknowledged == *b"R",
        "runtime owner registration not acknowledged"
    );
    let mut spec = CommandSpec::new(OsString::from_vec(request.program));
    spec.args = request.args.into_iter().map(OsString::from_vec).collect();
    spec.cwd = request
        .cwd
        .map(|value| PathBuf::from(OsString::from_vec(value)));
    spec.env = request
        .env
        .into_iter()
        .map(|(key, value)| (OsString::from_vec(key), OsString::from_vec(value)))
        .collect();
    spec.env_remove = request
        .env_remove
        .into_iter()
        .map(OsString::from_vec)
        .collect();
    if !spec.env_remove.iter().any(|key| key == OsStr::new(OWNER)) {
        spec.env
            .insert(OWNER.into(), std::env::current_exe()?.into_os_string());
    }
    spec.env.insert(SOCKET.into(), socket.into_os_string());
    spec.env.insert(TOKEN.into(), token.into());
    spec.env.insert(PARENT.into(), id.into());
    spec.timeout = Duration::from_millis(request.timeout_ms);
    spec.idle_timeout = request.idle_ms.map(Duration::from_millis);
    spec.max_output = request.max_output;
    lifeline.set_read_timeout(None)?;
    lifeline.set_nonblocking(true)?;
    let mut events = lifeline.try_clone()?;
    let cancelled = || {
        // try_clone shares descriptor flags with event writes; restore nonblocking
        // before every cancellation observation, not only at initialization.
        if lifeline.set_nonblocking(true).is_err() {
            return true;
        }
        let mut byte = [0];
        match lifeline.read(&mut byte) {
            Ok(0) | Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(_) => true,
        }
    };
    // Generic tools may run in read-only CWDs. Scope::create still nests beneath
    // an inherited TeX owner; only its unparented fallback uses the OS temp root.
    let base = std::env::temp_dir().canonicalize()?;
    let scope = crate::tex_supervisor::ContainerScope::create(&base)?;
    spec.env.extend(
        scope
            .environment()
            .into_iter()
            .filter(|(key, _)| !spec.env_remove.contains(key)),
    );
    let natural_exit = |status: i32| frame(&mut events, &client::Event::NaturalExit(status), 4096);
    let owned = super::unix::run_interactive(
        &spec,
        request.input.as_deref(),
        cancelled,
        request.interactive,
        natural_exit,
    );
    let cleanup_started = Instant::now();
    let descendants =
        (|| -> Result<Instant> {
            account.write_all(b"S")?;
            let mut grant = [0; 9];
            transfer(
                &mut account,
                &mut grant,
                false,
                Instant::now() + CLEANUP_LIMIT,
            )?;
            ensure!(grant[0] == b'Q', "nested container owners did not settle");
            let remaining = u64::from_be_bytes(grant[1..].try_into()?);
            ensure!(
                remaining > 0 && remaining <= CLEANUP_LIMIT.as_millis() as u64,
                "invalid cleanup grant"
            );
            // Clamp to this caller's monotonic stop boundary, so a delayed Q
            // transport never grants a renewed per-owner cleanup interval.
            Ok((Instant::now() + Duration::from_millis(remaining))
                .min(cleanup_started + CLEANUP_LIMIT))
        })();
    let container_cleanup = match descendants {
        Ok(deadline) => finish_containers(scope, deadline),
        Err(error) => {
            // Do not let Drop sweep active descendant scopes after failed settlement.
            std::mem::forget(scope);
            Err(error)
        }
    };
    let own_cleanup_complete = owned.cleanup_complete && container_cleanup.is_ok();
    let termination_signal = owned.termination_signal;
    let result = super::with_cleanup(owned.result, container_cleanup);
    // Cleanup commands run directly inside this guardian, not recursively through
    // a new ContainerScope/owner. Leave that mode active through scope Drop too.
    let done = (|| -> Result<()> {
        account.write_all(if own_cleanup_complete { b"D" } else { b"F" })?;
        transfer(
            &mut account,
            &mut acknowledged,
            false,
            Instant::now() + Duration::from_secs(5),
        )?;
        ensure!(acknowledged == *b"C", "nested owners did not settle");
        Ok(())
    })();
    let root_result = if let Some(root) = &mut root {
        root.finish()
    } else {
        Ok(())
    };
    let cleanup_complete = own_cleanup_complete && done.is_ok() && root_result.is_ok();
    let response = match result {
        Ok(output) => Response {
            code: Some(output.code),
            stdout: output.stdout,
            stderr: output.stderr,
            deadline_idle: None,
            termination_signal,
            cleanup_complete,
            error: None,
        },
        Err(error) => {
            let text = error.to_string();
            let category = if text.starts_with("tool diagnostics exceeded") {
                "output-limit".into()
            } else if text.starts_with("tool did not consume") {
                "input".into()
            } else if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            {
                "not-found".into()
            } else if text.starts_with("cannot start owned") {
                "spawn".into()
            } else if text.starts_with("runtime caller cancelled") {
                "cancelled".into()
            } else {
                operation_category(&error)
            };
            Response {
                code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                deadline_idle: error
                    .downcast_ref::<DeadlineExceeded>()
                    .map(|value| value.idle),
                termination_signal,
                cleanup_complete,
                error: Some(category),
            }
        }
    };
    lifeline.set_nonblocking(false)?;
    lifeline.set_write_timeout(Some(Duration::from_secs(2)))?;
    // Caller death may close the response endpoint; cleanup above still ran.
    let _ = frame(&mut lifeline, &client::Event::Complete(response), LIMIT);
    Ok(())
}

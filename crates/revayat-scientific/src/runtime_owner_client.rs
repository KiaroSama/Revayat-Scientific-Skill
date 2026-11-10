//! Caller-side lifeline and interactive process handle for the shared Unix guardian.
use super::{LIMIT, Request, Response, companion, transfer};
use crate::runtime::{CommandOutput, CommandSpec, DeadlineExceeded};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            ffi::OsStrExt,
            net::UnixStream,
            process::{CommandExt, ExitStatusExt},
        },
    },
    process::{Child, ChildStderr, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Event {
    NaturalExit(i32),
    Complete(Response),
}

pub struct Interactive {
    child: Child,
    socket: Option<UnixStream>,
    pending: Vec<u8>,
    natural: Option<ExitStatus>,
    response: Option<Response>,
    finished: bool,
    terminal_error: Option<&'static str>,
    interactive: bool,
    cancel_requested: bool,
    spec: CommandSpec,
    deadline: Instant,
}
impl Interactive {
    pub fn spawn(spec: &CommandSpec) -> Result<Self> {
        Self::start(spec, None, true)
    }
    pub fn from_command(command: &Command) -> Result<Self> {
        let mut spec = CommandSpec::new(command.get_program());
        spec.args = command.get_args().map(Into::into).collect();
        spec.cwd = command.get_current_dir().map(Into::into);
        for (key, value) in command.get_envs() {
            if let Some(value) = value {
                spec.env.insert(key.into(), value.into());
            } else {
                spec.env_remove.push(key.into());
            }
        }
        spec.timeout = Duration::from_secs(180);
        spec.max_output = 64 * 1024;
        Self::spawn(&spec)
    }
    fn start(spec: &CommandSpec, input: Option<&[u8]>, interactive: bool) -> Result<Self> {
        super::super::validate_spec(spec)?;
        let request = Request {
            program: spec.program.as_bytes().into(),
            args: spec
                .args
                .iter()
                .map(|value| value.as_bytes().into())
                .collect(),
            cwd: spec
                .cwd
                .as_ref()
                .map(|path| path.as_os_str().as_bytes().into()),
            env: spec
                .env
                .iter()
                .map(|(key, value)| (key.as_bytes().into(), value.as_bytes().into()))
                .collect(),
            env_remove: spec
                .env_remove
                .iter()
                .map(|key| key.as_bytes().into())
                .collect(),
            timeout_ms: spec.timeout.as_millis().try_into()?,
            idle_ms: spec
                .idle_timeout
                .map(|value| value.as_millis().try_into())
                .transpose()?,
            max_output: spec.max_output,
            input: input.map(Into::into),
            interactive,
        };
        let mut encoded = serde_json::to_vec(&request)?;
        ensure!(
            encoded.len() <= LIMIT,
            "ownership request exceeds byte limit"
        );
        let owner = companion()?;
        let (mut socket, guard) = UnixStream::pair()?;
        let descriptor: OwnedFd = guard.into();
        let mut command = Command::new(owner);
        command
            .arg("--internal-owner-v1")
            .stdin(Stdio::from(descriptor))
            .stdout(Stdio::null())
            .stderr(if interactive {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .process_group(0);
        let child = command
            .spawn()
            .context("cannot start Unix runtime companion")?;
        drop(command);
        let mut result = Self {
            child,
            socket: None,
            pending: Vec::new(),
            natural: None,
            response: None,
            finished: false,
            terminal_error: None,
            interactive,
            cancel_requested: false,
            spec: spec.clone(),
            deadline: Instant::now() + spec.timeout + super::CLEANUP_LIMIT + Duration::from_secs(5),
        };
        let sent = (|| -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(5);
            transfer(
                &mut socket,
                &mut (encoded.len() as u32).to_be_bytes(),
                true,
                deadline,
            )?;
            transfer(&mut socket, &mut encoded, true, deadline)?;
            socket.set_nonblocking(true)?;
            Ok(())
        })();
        result.socket = Some(socket);
        sent?;
        Ok(result)
    }
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }
    /// Natural command status remains observable when it arrives during finish.
    pub fn natural_status(&self) -> Option<ExitStatus> {
        self.natural
    }
    /// Actual command status, distinct from the guardian process's exit.
    pub fn termination_signal(&self) -> Option<i32> {
        self.response
            .as_ref()
            .and_then(|response| response.termination_signal)
    }
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        self.poll()?;
        if self.natural.is_none() && self.finished {
            return Ok(self.child.try_wait()?);
        }
        Ok(self.natural)
    }
    fn poll(&mut self) -> Result<()> {
        let Some(socket) = &mut self.socket else {
            return Ok(());
        };
        let mut buffer = [0; 8192];
        let mut eof = false;
        for _ in 0..16 {
            match socket.read(&mut buffer) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(count) => {
                    self.pending.extend_from_slice(&buffer[..count]);
                    ensure!(
                        self.pending.len() <= LIMIT + 4,
                        "ownership response exceeds byte limit"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        self.decode_pending(eof)
    }
    fn decode_pending(&mut self, eof: bool) -> Result<()> {
        for event in decode_events(&mut self.pending)? {
            match event {
                Event::NaturalExit(status) => {
                    ensure!(self.natural.is_none(), "duplicate natural process exit");
                    self.natural = Some(ExitStatus::from_raw(status));
                }
                Event::Complete(response) => {
                    ensure!(self.response.is_none(), "duplicate runtime completion");
                    self.response = Some(response);
                }
            }
        }
        ensure!(
            !eof || (self.response.is_some() && self.pending.is_empty()),
            "runtime companion disconnected without complete cleanup frame"
        );
        Ok(())
    }
    pub fn finish(&mut self) -> Result<()> {
        if self.finished {
            return self
                .terminal_error
                .map_or(Ok(()), |error| Err(anyhow::anyhow!(error)));
        }
        self.poll()?;
        if self.response.is_none() {
            self.cancel_requested = true;
            if let Some(socket) = &mut self.socket {
                match socket.write(b"X") {
                    Ok(1) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        self.socket.take();
                    }
                    _ => {
                        self.socket.take();
                    }
                }
            }
        }
        let deadline = Instant::now() + super::CLEANUP_LIMIT + Duration::from_secs(5);
        while self.response.is_none() {
            self.poll()?;
            ensure!(
                Instant::now() < deadline,
                "runtime nested cleanup completion missing"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let cleanup = self
            .response
            .as_ref()
            .is_some_and(|response| response.cleanup_complete);
        self.socket.take();
        loop {
            if let Some(status) = self.child.try_wait()? {
                ensure!(
                    status.success() && cleanup,
                    "runtime companion cleanup incomplete"
                );
                self.finished = true;
                let response = self
                    .response
                    .as_ref()
                    .context("runtime completion missing")?;
                self.terminal_error = interactive_failure(
                    self.interactive,
                    self.cancel_requested,
                    self.natural,
                    response,
                );
                return self
                    .terminal_error
                    .map_or(Ok(()), |error| Err(anyhow::anyhow!(error)));
            }
            ensure!(
                Instant::now() < deadline,
                "runtime guardian exit unverified"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Interactive {
    fn drop(&mut self) {
        if !self.finished {
            // EOF is cancellation, never cleanup proof. Retain the guardian if
            // its bounded cleanup cannot be established instead of killing its owner.
            self.socket.take();
            let deadline = Instant::now() + super::CLEANUP_LIMIT + Duration::from_secs(5);
            while Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        }
    }
}

fn interactive_failure(
    interactive: bool,
    cancelled: bool,
    natural: Option<ExitStatus>,
    response: &Response,
) -> Option<&'static str> {
    if !interactive {
        None
    } else if response.deadline_idle.is_some() {
        Some("interactive process exceeded its deadline")
    } else if natural.is_some_and(|status| !status.success())
        || (response.error.is_none() && response.code.is_some_and(|code| code != 0))
        || (response.error.is_some()
            && !(cancelled && response.error.as_deref() == Some("cancelled")))
    {
        Some("interactive process failed before deliberate termination")
    } else {
        None
    }
}

fn decode_events(pending: &mut Vec<u8>) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    while pending.len() >= 4 {
        let size = u32::from_be_bytes(pending[..4].try_into()?) as usize;
        ensure!(size <= LIMIT, "ownership response exceeds byte limit");
        if pending.len() < size + 4 {
            break;
        }
        events.push(serde_json::from_slice(&pending[4..size + 4])?);
        pending.drain(..size + 4);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn completion() -> Vec<u8> {
        let event = Event::Complete(Response {
            code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            deadline_idle: None,
            termination_signal: None,
            cleanup_complete: true,
            error: None,
        });
        let bytes = serde_json::to_vec(&event).unwrap();
        let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
        framed.extend(bytes);
        framed
    }
    #[test]
    fn late_natural_failure_cannot_be_reclassified_as_deliberate_cancellation() {
        let mut pending = Vec::new();
        assert!(
            decode_events(&mut pending).unwrap().is_empty(),
            "initial snapshot is live"
        );
        let natural = serde_json::to_vec(&Event::NaturalExit(42 << 8)).unwrap();
        pending.extend_from_slice(&(natural.len() as u32).to_be_bytes());
        pending.extend(natural);
        pending.extend(completion());
        let events = decode_events(&mut pending).unwrap();
        let [Event::NaturalExit(status), Event::Complete(response)] = events.as_slice() else {
            panic!("late natural exit and completion must both be decoded")
        };
        let natural = Some(ExitStatus::from_raw(*status));
        assert!(interactive_failure(true, true, natural, response).is_some());
        let mut cancelled = Response {
            code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            deadline_idle: None,
            termination_signal: Some(libc::SIGKILL),
            cleanup_complete: true,
            error: Some("cancelled".into()),
        };
        assert!(interactive_failure(true, true, natural, &cancelled).is_some());
        assert!(interactive_failure(true, true, None, &cancelled).is_none());
        assert!(interactive_failure(true, false, None, &cancelled).is_some());
        cancelled.error = None;
        cancelled.code = Some(0);
        assert!(
            interactive_failure(true, false, Some(ExitStatus::from_raw(0)), &cancelled).is_none()
        );
        cancelled.code = Some(42);
        assert!(interactive_failure(true, true, None, &cancelled).is_some());
        assert!(interactive_failure(false, false, natural, &cancelled).is_none());
    }

    // Exercise the actual incremental decoder, without spawning an unrelated process.
    #[test]
    fn complete_then_eof_and_fragmented_frames_preserve_cleanup_result() {
        fn decode(bytes: &[u8], eof: bool) -> Result<bool> {
            let mut pending = bytes.to_vec();
            let mut complete = false;
            for event in decode_events(&mut pending)? {
                complete |= matches!(event, Event::Complete(_));
            }
            ensure!(
                !eof || (complete && pending.is_empty()),
                "incomplete cleanup frame"
            );
            Ok(complete)
        }
        let bytes = completion();
        assert!(decode(&bytes, true).unwrap());
        assert!(!decode(&bytes[..2], false).unwrap());
        let mut fragmented = bytes[..2].to_vec();
        assert!(decode_events(&mut fragmented).unwrap().is_empty());
        fragmented.extend_from_slice(&bytes[2..]);
        assert!(matches!(
            decode_events(&mut fragmented).unwrap().as_slice(),
            [Event::Complete(_)]
        ));
        assert!(fragmented.is_empty());
        assert!(decode(&bytes[..bytes.len() - 1], true).is_err());
        assert!(decode(&[], true).is_err());
    }
}

pub fn run(spec: &CommandSpec, input: Option<&[u8]>) -> Result<CommandOutput> {
    let mut owner = Interactive::start(spec, input, false)?;
    while owner.response.is_none() {
        owner.poll()?;
        ensure!(
            Instant::now() < owner.deadline,
            "runtime companion response deadline exceeded"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let primary = {
        let response = owner
            .response
            .as_ref()
            .context("runtime completion missing")?;
        if let Some(idle) = response.deadline_idle {
            Err(DeadlineExceeded {
                idle,
                limit: if idle {
                    owner.spec.idle_timeout.unwrap_or(spec.timeout)
                } else {
                    spec.timeout
                },
            }
            .into())
        } else if response.error.as_deref() == Some("not-found") {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "owned external tool is missing",
            )
            .into())
        } else if let Some(category) = &response.error {
            Err(anyhow::anyhow!(match category.as_str() {
                "output-limit" =>
                    format!("tool diagnostics exceeded {} byte limit", spec.max_output),
                "input" => "tool did not consume its bounded input".into(),
                "spawn" => "cannot start owned external tool".into(),
                "cancelled" => "runtime caller cancelled or disconnected".into(),
                _ => "owned runtime operation failed".into(),
            }))
        } else {
            Ok(())
        }
    };
    super::super::with_cleanup(primary, owner.finish())?;
    let response = owner
        .response
        .take()
        .context("runtime completion missing")?;
    Ok(CommandOutput {
        code: response.code.context("runtime child exit missing")?,
        stdout: response.stdout,
        stderr: response.stderr,
    })
}

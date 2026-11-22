//! Caller-side lifeline and interactive process handle for the shared Unix guardian.
use super::{LIMIT, Request, Response, companion, diagnostics::split_category, transfer};
use crate::runtime::{CommandOutput, CommandSpec, DeadlineExceeded};
use anyhow::{Context, Result, ensure};
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

fn wire_deadlines(spec: &CommandSpec) -> Result<(u64, Option<u64>)> {
    let wall = spec.timeout.as_millis();
    ensure!(
        wall > 0 && wall <= u128::from(super::MAX_TIMEOUT_MILLIS),
        "wall timeout must encode as 1..={} milliseconds on Unix",
        super::MAX_TIMEOUT_MILLIS
    );
    let idle = spec
        .idle_timeout
        .map(|duration| -> Result<u64> {
            let milliseconds = u64::try_from(duration.as_millis())
                .context("idle timeout exceeds representable milliseconds on Unix")?;
            ensure!(
                milliseconds > 0,
                "idle timeout must encode as positive milliseconds on Unix"
            );
            Ok(milliseconds)
        })
        .transpose()?;
    Ok((wall as u64, idle))
}

fn wait_response(socket: Option<&UnixStream>, deadline: Instant) -> Result<()> {
    let tick = (Instant::now() + Duration::from_millis(5)).min(deadline);
    if let Some(socket) = socket {
        super::transport::ready(socket, false, tick)?;
    } else {
        thread::sleep(tick.saturating_duration_since(Instant::now()));
    }
    Ok(())
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
        let (timeout_ms, idle_ms) = wire_deadlines(spec)?;
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
            timeout_ms,
            idle_ms,
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
                    validate_response(&response, &self.spec)?;
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
            wait_response(self.socket.as_ref(), deadline)?;
        }
        self.socket.take();
        loop {
            if let Some(status) = self.child.try_wait()? {
                let response = self
                    .response
                    .as_ref()
                    .context("runtime completion missing")?;
                companion_completion(status.success(), response)?;
                self.finished = true;
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

fn companion_completion(success: bool, response: &Response) -> Result<()> {
    // Validation normally occurs at receipt; keep even direct error formatting closed.
    let category = response.error.as_deref().map_or("none", |label| {
        if valid_category(label) {
            label
        } else {
            "invalid"
        }
    });
    let failure = if !success {
        Some("runtime companion exited unsuccessfully")
    } else if !response.cleanup_complete {
        Some("runtime companion cleanup incomplete")
    } else {
        None
    };
    failure.map_or(Ok(()), |message| {
        Err(anyhow::anyhow!(message)).context(format!(
            "runtime completion (cleanup_complete={}; category={category})",
            response.cleanup_complete
        ))
    })
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
            && !(cancelled
                && response
                    .error
                    .as_deref()
                    .and_then(split_category)
                    .is_some_and(|(category, _)| category == "cancelled")))
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

pub fn run(spec: &CommandSpec, input: Option<&[u8]>) -> Result<CommandOutput> {
    let mut owner = Interactive::start(spec, input, false)?;
    while owner.response.is_none() {
        owner.poll()?;
        ensure!(
            Instant::now() < owner.deadline,
            "runtime companion response deadline exceeded"
        );
        wait_response(owner.socket.as_ref(), owner.deadline)?;
    }
    let cleanup = owner.finish();
    let response = owner
        .response
        .take()
        .context("runtime completion missing")?;
    completed_result(response, &owner.spec, cleanup)
}

fn completed_result(
    response: Response,
    spec: &CommandSpec,
    cleanup: Result<()>,
) -> Result<CommandOutput> {
    let complete = response.cleanup_complete;
    let primary = (|| {
        validate_response(&response, spec)?;
        let primary = primary_result(&response, spec);
        match response.code {
            Some(code) => {
                let output = CommandOutput {
                    code,
                    stdout: response.stdout,
                    stderr: response.stderr,
                };
                // With code present, a primary error is exclusively a closed late
                // cleanup category. Preserve completed bytes without reporting success.
                super::super::with_command_cleanup(Ok(output), primary)
            }
            None => {
                primary?;
                anyhow::bail!("runtime child exit missing")
            }
        }
    })();
    let cleanup = cleanup.and_then(|()| {
        ensure!(complete, "runtime companion cleanup incomplete");
        Ok(())
    });
    super::super::with_command_cleanup(primary, cleanup)
}

fn validate_response(response: &Response, spec: &CommandSpec) -> Result<()> {
    ensure!(
        response
            .stdout
            .len()
            .checked_add(response.stderr.len())
            .is_some_and(|length| length <= spec.max_output),
        "ownership response exceeds diagnostic budget"
    );
    if let Some(category) = response.error.as_deref() {
        ensure!(
            valid_category(category),
            "invalid runtime completion category"
        );
        ensure!(
            split_category(category)
                .is_some_and(|(_, diagnostic)| diagnostic.is_none() || !response.cleanup_complete),
            "runtime diagnostic contradicts cleanup result"
        );
    }
    if response.code.is_some() {
        ensure!(
            response.deadline_idle.is_none(),
            "completed runtime response contradicts deadline"
        );
        ensure!(
            match (response.cleanup_complete, response.error.as_deref()) {
                (true, None) => true,
                (false, Some(category)) => valid_operation_label(category),
                _ => false,
            },
            "completed runtime response contradicts cleanup result"
        );
    } else {
        ensure!(
            response.stdout.is_empty() && response.stderr.is_empty() && response.error.is_some(),
            "incomplete runtime response has captures or lacks a cause"
        );
        if response.deadline_idle.is_some() {
            ensure!(
                response.error.as_deref().is_some_and(valid_operation_label),
                "runtime deadline contradicts operation category"
            );
        }
    }
    ensure!(
        response.deadline_idle != Some(true) || spec.idle_timeout.is_some(),
        "runtime idle deadline was not requested"
    );
    Ok(())
}

fn primary_result(response: &Response, spec: &CommandSpec) -> Result<()> {
    let category = response
        .error
        .as_deref()
        .and_then(split_category)
        .map(|(label, _)| label);
    if let Some(idle) = response.deadline_idle {
        let deadline = anyhow::Error::new(DeadlineExceeded {
            idle,
            limit: if idle {
                spec.idle_timeout.unwrap_or(spec.timeout)
            } else {
                spec.timeout
            },
        });
        Err(
            if !response.cleanup_complete
                && let Some(category) = response
                    .error
                    .as_deref()
                    .filter(|label| valid_operation_label(label))
            {
                let category = split_category(category).map_or("invalid", |(label, _)| label);
                deadline.context(format!("owned runtime operation failed ({category})"))
            } else {
                deadline
            },
        )
    } else if category == Some("not-found") {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "owned external tool is missing",
        )
        .into())
    } else if let Some(category) = &response.error {
        let base = split_category(category).map_or("invalid", |(label, _)| label);
        Err(anyhow::anyhow!(match base {
            "output-limit" => format!("tool diagnostics exceeded {} byte limit", spec.max_output),
            "input" => "tool did not consume its bounded input".into(),
            "spawn" => "cannot start owned external tool".into(),
            "cancelled" => "runtime caller cancelled or disconnected".into(),
            label if valid_operation_label(label) =>
                format!("owned runtime operation failed ({label})"),
            _ => "owned runtime operation failed".into(),
        }))
    } else {
        Ok(())
    }
}

fn valid_category(label: &str) -> bool {
    split_category(label).is_some_and(|(base, _)| {
        matches!(
            base,
            "output-limit" | "input" | "not-found" | "spawn" | "cancelled"
        ) || valid_operation_label(base)
    })
}

fn valid_operation_label(label: &str) -> bool {
    let Some((label, _)) = split_category(label) else {
        return false;
    };
    ["status-query", "group-cleanup", "child-reap", "unknown"]
        .iter()
        .any(|stage| {
            let prefix = format!("operation-{stage}");
            label == prefix
                || label
                    .strip_prefix(&format!("{prefix}-os-"))
                    .and_then(|number| {
                        number
                            .parse::<i32>()
                            .ok()
                            .map(|value| value.to_string() == number)
                    })
                    == Some(true)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_diagnostics_remain_failures_and_do_not_expose_untrusted_labels() {
        let spec = CommandSpec::new("controlled-unused-program");
        let mut response = super::super::completed_response(
            Ok(CommandOutput {
                code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
            Ok(()),
            false,
            None,
        );
        let diagnostic = super::super::diagnostics::CleanupDiagnostic::collect(
            true,
            true,
            false,
            &Err(anyhow::anyhow!("PRIVATE_ACK")),
            &Err(anyhow::Error::new(
                super::super::diagnostics::AccountingFailure::PeerEof,
            )),
        );
        diagnostic.attach(&mut response);
        validate_response(&response, &spec).unwrap();
        let error = companion_completion(true, &response).unwrap_err();
        assert!(format!("{error:#}").contains("cleanup=1a;accounting=peer-eof"));
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string() == "runtime companion cleanup incomplete")
        );
        let error = companion_completion(false, &response).unwrap_err();
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string() == "runtime companion exited unsuccessfully")
        );
        assert!(error.to_string().contains("cleanup_complete=false"));
        assert!(
            crate::migration::execution::discovery_failure_summary(&error)
                .contains("runtime=companion-exit")
        );
        response.cleanup_complete = true;
        assert!(validate_response(&response, &spec).is_err());
        response.cleanup_complete = false;
        response.error = Some("operation-unknown;cleanup=10;accounting=PRIVATE_TOKEN".into());
        assert!(validate_response(&response, &spec).is_err());
        assert!(
            !format!("{:#}", companion_completion(true, &response).unwrap_err())
                .contains("PRIVATE")
        );
        response.cleanup_complete = true;
        response.error = None;
        assert!(companion_completion(true, &response).is_ok());
        assert!(companion_completion(false, &response).is_err());

        let owned = crate::runtime::with_cleanup::<CommandOutput>(
            Err(DeadlineExceeded {
                idle: false,
                limit: spec.timeout,
            }
            .into()),
            Err(
                anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ECHILD))
                    .context("owned-child-reap"),
            ),
        );
        let mut response = super::super::completed_response(
            owned,
            Err(anyhow::anyhow!("PRIVATE_RECEIPT_ERROR")),
            false,
            None,
        );
        diagnostic.attach(&mut response);
        let cleanup = companion_completion(true, &response);
        let error = completed_result(response, &spec, cleanup).unwrap_err();
        assert_eq!(
            error.downcast_ref::<DeadlineExceeded>().unwrap().limit,
            spec.timeout
        );
        assert!(
            crate::migration::execution::discovery_failure_summary(&error)
                .contains(&format!("runtime=child-reap os_error={}", libc::ECHILD))
        );
        assert!(!format!("{error:#}").contains("PRIVATE"));
    }

    #[test]
    fn wire_deadline_boundaries_match_the_companion_protocol() -> Result<()> {
        let mut spec = CommandSpec::new("must-not-execute");
        spec.timeout = Duration::from_millis(1);
        spec.idle_timeout = Some(Duration::from_millis(u64::MAX));
        assert_eq!(wire_deadlines(&spec)?, (1, Some(u64::MAX)));
        spec.timeout =
            Duration::from_millis(super::super::MAX_TIMEOUT_MILLIS) + Duration::from_nanos(999_999);
        assert_eq!(wire_deadlines(&spec)?.0, super::super::MAX_TIMEOUT_MILLIS);
        spec.timeout += Duration::from_nanos(1);
        assert!(wire_deadlines(&spec).is_err());
        spec.timeout = Duration::from_nanos(1);
        assert!(wire_deadlines(&spec).is_err());
        spec.timeout = Duration::from_millis(1);
        spec.idle_timeout = Some(Duration::from_nanos(1));
        assert!(wire_deadlines(&spec).is_err());
        spec.idle_timeout = Some(Duration::MAX);
        assert!(wire_deadlines(&spec).is_err());
        Ok(())
    }
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
        assert!(valid_operation_label("operation-status-query-os-10"));
        assert!(valid_operation_label("operation-child-reap"));
        assert!(!valid_operation_label("operation-unknown-os-private-path"));
        assert!(!valid_operation_label("operation-private-command"));
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
        super::retained_checks::check_completed_retention();
        super::transport_checks::check_backpressure().unwrap();
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

#[cfg(test)]
#[path = "runtime_transport_checks.rs"]
mod transport_checks;

#[cfg(test)]
#[path = "runtime_retained_checks.rs"]
mod retained_checks;

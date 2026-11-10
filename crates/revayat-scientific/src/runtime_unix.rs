//! Direct-child PGID ownership inside the dedicated cooperative Unix guardian.
use super::{CommandOutput, CommandSpec, DeadlineExceeded};
use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct OwnedResult {
    pub result: Result<CommandOutput>,
    pub cleanup_complete: bool,
    pub termination_signal: Option<i32>,
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    // SAFETY: the pipe descriptor is borrowed and remains owned by its caller.
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    ensure!(flags >= 0, "cannot read owned pipe flags");
    // SAFETY: preserve every existing flag and change only nonblocking I/O.
    ensure!(
        unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "cannot make owned pipe nonblocking"
    );
    Ok(())
}

fn status_without_reaping(pid: u32) -> Result<Option<i32>> {
    // SAFETY: zero initialization is valid for siginfo_t; waitid writes its fields.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // WNOWAIT retains the direct-child PID/PGID anchor until group cleanup.
    // SAFETY: pid identifies our unreaped direct child, never an enumerated PID.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful waitid initialized the documented child PID field.
    if unsafe { info.si_pid() } == 0 {
        return Ok(None);
    }
    // SAFETY: successful waitid initialized status and si_code. Reconstruct the
    // Unix ExitStatus encoding without consuming the child's identity anchor.
    let status = unsafe { info.si_status() };
    Ok(Some(if info.si_code == libc::CLD_EXITED {
        status << 8
    } else {
        status & 0x7f
    }))
}

pub fn run(
    spec: &CommandSpec,
    input: Option<&[u8]>,
    cancelled: impl FnMut() -> bool,
) -> OwnedResult {
    run_interactive(spec, input, cancelled, false, |_| Ok(()))
}

pub fn run_interactive(
    spec: &CommandSpec,
    input: Option<&[u8]>,
    mut cancelled: impl FnMut() -> bool,
    interactive: bool,
    mut natural_exit: impl FnMut(i32) -> Result<()>,
) -> OwnedResult {
    let result = (|| -> Result<_> {
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .envs(&spec.env)
            .env("REVAYAT_RUNTIME_GROUP", "inherit")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(if interactive {
                Stdio::inherit()
            } else {
                Stdio::piped()
            })
            .process_group(0);
        for key in &spec.env_remove {
            command.env_remove(key);
        }
        command.envs(&spec.env);
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        let child = command
            .spawn()
            .context("cannot start owned external tool")?;
        Ok(child)
    })();
    let mut child = match result {
        Ok(child) => child,
        Err(error) => {
            return OwnedResult {
                result: Err(error),
                cleanup_complete: true,
                termination_signal: None,
            };
        }
    };
    let pid = child.id();
    let mut output = [Vec::new(), Vec::new()];
    let result = (|| -> Result<()> {
        let mut stdout = child.stdout.take().context("owned stdout missing")?;
        let mut stderr = child.stderr.take();
        nonblocking(&stdout)?;
        if let Some(pipe) = &stderr {
            nonblocking(pipe)?;
        }
        let mut stdin = child.stdin.take();
        if let Some(stdin) = &stdin {
            nonblocking(stdin)?;
        }
        let mut written = 0;
        let mut ended = [false, interactive];
        let mut observed = false;
        let started = Instant::now();
        let mut progress = started;
        loop {
            let observed_status = status_without_reaping(pid)?;
            if let Some(status) = observed_status {
                if interactive && !observed {
                    natural_exit(status)?;
                    observed = true;
                }
            }
            ensure!(!cancelled(), "runtime caller cancelled or disconnected");
            if started.elapsed() >= spec.timeout {
                return Err(DeadlineExceeded {
                    idle: false,
                    limit: spec.timeout,
                }
                .into());
            }
            if let Some(limit) = spec.idle_timeout {
                if progress.elapsed() >= limit {
                    return Err(DeadlineExceeded { idle: true, limit }.into());
                }
            }
            if let Some(pipe) = &mut stdin {
                let bytes = input.unwrap_or_default();
                match pipe.write(&bytes[written..]) {
                    Ok(count) => {
                        written += count;
                        if count > 0 {
                            progress = Instant::now();
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(error) => return Err(error.into()),
                }
                if written == bytes.len() {
                    stdin = None;
                }
            }
            for index in 0..2 {
                if ended[index] {
                    continue;
                }
                let pipe: &mut dyn Read = if index == 0 {
                    &mut stdout
                } else {
                    stderr.as_mut().context("owned stderr missing")?
                };
                // Bound each turn so a flood cannot starve cancellation/deadlines.
                for _ in 0..8 {
                    let mut bytes = [0; 8192];
                    match pipe.read(&mut bytes) {
                        Ok(0) => {
                            ended[index] = true;
                            break;
                        }
                        Ok(count) => {
                            ensure!(
                                output[0].len() + output[1].len() + count <= spec.max_output,
                                "tool diagnostics exceeded {} byte limit",
                                spec.max_output
                            );
                            output[index].extend_from_slice(&bytes[..count]);
                            progress = Instant::now();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            if observed_status.is_some() && ended == [true, true] {
                ensure!(stdin.is_none(), "tool did not consume its bounded input");
                return Ok(());
            }
            thread::sleep(Duration::from_millis(5));
        }
    })();
    // Never try_wait before this point: a recycled leader PID could invalidate
    // negative-PGID signaling. The unreaped direct child anchors this exact group.
    let cleanup = (|| -> Result<std::process::ExitStatus> {
        super::kill_owned_group(pid)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while status_without_reaping(pid)?.is_none() {
            ensure!(
                Instant::now() < deadline,
                "owned child did not terminate after group cleanup"
            );
            thread::sleep(Duration::from_millis(5));
        }
        Ok(child.wait()?)
    })();
    let cleanup_complete = cleanup.is_ok();
    use std::os::unix::process::ExitStatusExt;
    let termination_signal = cleanup.as_ref().ok().and_then(|status| status.signal());
    let result = match (result, cleanup) {
        (Ok(()), Ok(status)) => Ok(CommandOutput {
            code: status.code().unwrap_or(128),
            stdout: std::mem::take(&mut output[0]),
            stderr: std::mem::take(&mut output[1]),
        }),
        (Err(primary), Ok(_)) => Err(primary),
        (Err(primary), Err(secondary)) => Err(primary.context(super::CleanupFailure(secondary))),
        (Ok(()), Err(error)) => Err(anyhow::Error::new(super::CleanupFailure(error))),
    };
    OwnedResult {
        result,
        cleanup_complete,
        termination_signal,
    }
}

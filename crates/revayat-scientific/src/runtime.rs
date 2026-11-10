//! Bounded subprocess output, separate wall/idle deadlines and native ownership.
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(not(unix))]
use std::{
    io::Read,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};

#[cfg(unix)]
#[path = "runtime_owner.rs"]
pub mod owner;
#[cfg(unix)]
#[path = "runtime_unix.rs"]
mod unix;

pub const MAX_DIAGNOSTICS: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<OsString, OsString>,
    /// Remove inherited variables in this child only, before explicit overrides.
    pub env_remove: Vec<OsString>,
    pub timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_output: usize,
}
impl CommandSpec {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: vec![],
            cwd: None,
            env: BTreeMap::new(),
            env_remove: Vec::new(),
            timeout: Duration::from_secs(120),
            idle_timeout: None,
            max_output: MAX_DIAGNOSTICS,
        }
    }
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }
}

#[derive(Debug)]
pub struct CommandOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
impl CommandOutput {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
    pub fn success(&self) -> bool {
        self.code == 0
    }
}

#[derive(Debug)]
pub struct DeadlineExceeded {
    pub idle: bool,
    pub limit: Duration,
}
impl std::fmt::Display for DeadlineExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "process {} deadline exceeded ({:.3}s)",
            if self.idle { "idle" } else { "wall" },
            self.limit.as_secs_f64()
        )
    }
}
impl std::error::Error for DeadlineExceeded {}

#[cfg(unix)]
pub fn kill_owned_group(id: u32) -> Result<()> {
    ensure!(
        id > 1 && id <= i32::MAX as u32,
        "invalid owned process group identity"
    );
    // SAFETY: a negative, owned child PGID targets precisely its process group.
    let result = unsafe { libc::kill(-(id as i32), libc::SIGKILL) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        ensure!(
            error.raw_os_error() == Some(libc::ESRCH),
            "owned process group cleanup failed: {error}"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
enum PipeEvent {
    Bytes(usize, Vec<u8>),
    End,
    Failed(std::io::Error),
    OverBudget,
}

#[derive(Debug)]
pub struct CleanupFailure(pub anyhow::Error);
impl std::fmt::Display for CleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "secondary cleanup failure: {:#}", self.0)
    }
}
impl std::error::Error for CleanupFailure {}

pub fn is_missing_executable(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CleanupFailure>().is_none()
        && error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Preserve the typed primary cause and inspectable secondary cleanup error.
pub fn with_cleanup<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (Err(primary), Err(secondary)) => Err(primary.context(CleanupFailure(secondary))),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(anyhow::Error::new(CleanupFailure(cleanup))),
        (Ok(value), Ok(())) => Ok(value),
    }
}

pub fn run(spec: &CommandSpec) -> Result<CommandOutput> {
    #[cfg(unix)]
    {
        validate_spec(spec)?;
        owner::cleanup_command(spec, None).unwrap_or_else(|| owner::run(spec, None))
    }
    #[cfg(not(unix))]
    {
        run_input(spec, None)
    }
}

pub fn run_with_input(spec: &CommandSpec, input: &[u8]) -> Result<CommandOutput> {
    ensure!(
        input.len() <= MAX_DIAGNOSTICS,
        "tool stdin exceeds 32 MiB input limit"
    );
    #[cfg(unix)]
    {
        validate_spec(spec)?;
        owner::cleanup_command(spec, Some(input)).unwrap_or_else(|| owner::run(spec, Some(input)))
    }
    #[cfg(not(unix))]
    {
        run_input(spec, Some(input))
    }
}

fn validate_spec(spec: &CommandSpec) -> Result<()> {
    ensure!(
        !spec.timeout.is_zero() && spec.idle_timeout.is_none_or(|d| !d.is_zero()),
        "process time limits must be positive"
    );
    ensure!(
        spec.max_output > 0 && spec.max_output <= MAX_DIAGNOSTICS,
        "invalid process diagnostic budget"
    );
    Ok(())
}

#[cfg(not(unix))]
fn run_input(spec: &CommandSpec, input: Option<&[u8]>) -> Result<CommandOutput> {
    validate_spec(spec)?;
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(&spec.env);
    for key in &spec.env_remove {
        command.env_remove(key);
    }
    command.envs(&spec.env);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    // A command nested inside the CLI worker stays in its surviving owner's
    // group. Creating another group here would let a killed worker orphan it.
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
    let (mut child, mut owner) = crate::windows_security::native::spawn_owned(
        &mut command,
        crate::windows_security::JobLimits::ownership(),
    )?;
    #[cfg(not(windows))]
    let mut child = command.spawn().context("cannot start external tool")?;
    #[cfg(unix)]
    let child_id = child.id();
    let writer = if let Some(input) = input {
        let bytes = input.to_vec();
        let mut pipe = child.stdin.take().context("missing process stdin")?;
        Some(thread::spawn(move || pipe.write_all(&bytes)))
    } else {
        None
    };
    let stdout = child.stdout.take().context("missing process stdout")?;
    let stderr = child.stderr.take().context("missing process stderr")?;
    let (tx, rx) = mpsc::channel();
    let used = Arc::new(AtomicUsize::new(0));
    let mut readers = vec![];
    for (index, mut pipe) in [Box::new(stdout) as Box<dyn Read + Send>, Box::new(stderr)]
        .into_iter()
        .enumerate()
    {
        let tx = tx.clone();
        let used = used.clone();
        let max = spec.max_output;
        readers.push(thread::spawn(move || {
            let mut buffer = [0; 8192];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if used
                            .fetch_add(count, Ordering::Relaxed)
                            .saturating_add(count)
                            > max
                        {
                            let _ = tx.send(PipeEvent::OverBudget);
                            break;
                        }
                        if tx
                            .send(PipeEvent::Bytes(index, buffer[..count].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(PipeEvent::Failed(e));
                        break;
                    }
                }
            }
            let _ = tx.send(PipeEvent::End);
        }));
    }
    drop(tx);
    let result = (|| {
        let started = Instant::now();
        let mut progress = started;
        let mut buffers = [Vec::new(), Vec::new()];
        let mut ended = 0;
        loop {
            let wall_left =
                spec.timeout
                    .checked_sub(started.elapsed())
                    .ok_or(DeadlineExceeded {
                        idle: false,
                        limit: spec.timeout,
                    })?;
            let idle_left = if let Some(limit) = spec.idle_timeout {
                limit
                    .checked_sub(progress.elapsed())
                    .ok_or(DeadlineExceeded { idle: true, limit })?
            } else {
                wall_left
            };
            let status = child.try_wait()?;
            // A dead launcher may leave descendants holding its diagnostic
            // pipes. Preserve the caller's actual wall/idle deadline and error
            // identity instead of returning a generic early-exit error.
            if ended == 2
                && let Some(status) = status
            {
                return Ok(CommandOutput {
                    code: status.code().unwrap_or(128),
                    stdout: std::mem::take(&mut buffers[0]),
                    stderr: std::mem::take(&mut buffers[1]),
                });
            }
            match rx.recv_timeout(wall_left.min(idle_left).min(Duration::from_millis(20))) {
                Ok(PipeEvent::Bytes(index, bytes)) => {
                    progress = Instant::now();
                    buffers[index].extend(bytes);
                }
                Ok(PipeEvent::End) => ended += 1,
                Ok(PipeEvent::Failed(error)) => return Err(error.into()),
                Ok(PipeEvent::OverBudget) => {
                    bail!("tool diagnostics exceeded {} byte limit", spec.max_output)
                }
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if ended < 2 {
                        bail!("process diagnostic reader disconnected");
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    })();
    // Always close the ownership boundary, including successful launchers which
    // have already exited while a descendant still holds inherited pipes.
    #[cfg(windows)]
    let cleanup = owner.finish();
    #[cfg(windows)]
    drop(owner); // close-on-kill fallback must precede joining diagnostic pipes.
    #[cfg(unix)]
    let cleanup = if owns_group {
        kill_owned_group(child_id)
    } else {
        Ok(())
    };
    let finalization = (|| -> Result<()> {
        #[cfg(windows)]
        cleanup?;
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        child.wait()?;
        for reader in readers {
            reader
                .join()
                .map_err(|_| anyhow::anyhow!("tool diagnostic reader failed"))?;
        }
        if let Some(writer) = writer {
            let wrote = writer
                .join()
                .map_err(|_| anyhow::anyhow!("tool stdin writer failed"))?;
            if result.as_ref().is_ok_and(CommandOutput::success) {
                wrote.context("tool did not consume its bounded input")?;
            }
        }
        Ok(())
    })();
    with_cleanup(result, finalization)
}

pub struct OperationLog {
    name: String,
    file: Option<File>,
    level: usize,
    started: Instant,
    path: Option<PathBuf>,
}
fn utc_components(seconds: u64) -> Result<(i64, u32, u32, u32, u32, u32)> {
    let days = i64::try_from(seconds / 86_400)?;
    let z = days
        .checked_add(719_468)
        .context("UTC date exceeds range")?;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    ensure!(
        (1970..=9999).contains(&year),
        "UTC year exceeds supported log range"
    );
    let clock = seconds % 86_400;
    Ok((
        year,
        month as u32,
        day as u32,
        (clock / 3600) as u32,
        ((clock % 3600) / 60) as u32,
        (clock % 60) as u32,
    ))
}
pub fn utc_timestamp(seconds: u64) -> Result<String> {
    let (y, m, d, h, min, s) = utc_components(seconds)?;
    Ok(format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02} UTC"))
}
impl OperationLog {
    pub fn create(name: &str, directory: &Path, level: Option<&str>) -> Result<Self> {
        ensure!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid operation log name"
        );
        let selected = level
            .map(str::to_owned)
            .or_else(|| std::env::var("REVAYAT_LOG_LEVEL").ok())
            .unwrap_or_else(|| "INFO".into())
            .to_uppercase();
        let level = match selected.as_str() {
            "DEBUG" => 0,
            "INFO" => 1,
            "WARNING" => 2,
            "ERROR" => 3,
            _ => bail!("REVAYAT_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR"),
        };
        let (y, m, d, h, min, s) =
            utc_components(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let stamp = format!("{y:04}-{m:02}-{d:02}_{h:02}-{min:02}-{s:02}_UTC");
        let mut path = directory.join(format!("{name}_{stamp}.log"));
        let file = std::fs::create_dir_all(directory)
            .and_then(|()| {
                for _ in 0..16 {
                    match OpenOptions::new().write(true).create_new(true).open(&path) {
                        Ok(file) => return Ok(file),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            let mut random = [0; 4];
                            getrandom::fill(&mut random)
                                .map_err(|e| std::io::Error::other(e.to_string()))?;
                            let suffix = u32::from_ne_bytes(random);
                            path = directory.join(format!("{name}_{stamp}_{suffix:08x}.log"));
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "operation log collision budget exceeded",
                ))
            })
            .ok();
        if file.is_none() {
            eprintln!("{name}: file logging unavailable; using stderr");
        }
        let path = file.as_ref().map(|_| path);
        let mut log = Self {
            name: name.into(),
            file,
            level,
            started: Instant::now(),
            path,
        };
        log.info("started runtime=rust");
        Ok(log)
    }
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
    pub fn write(&mut self, level: &str, message: &str) {
        let priority = match level {
            "DEBUG" => 0,
            "INFO" => 1,
            "WARNING" => 2,
            _ => 3,
        };
        if priority < self.level {
            return;
        }
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let stamp = utc_timestamp(seconds).unwrap_or_else(|_| "unknown UTC".into());
        let line = format!("[{stamp}] [{level}] [{}] {message}\n", self.name);
        if let Some(file) = &mut self.file {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        } else {
            eprint!("{line}");
        }
    }
    pub fn info(&mut self, message: &str) {
        self.write("INFO", message);
    }
}
impl Drop for OperationLog {
    fn drop(&mut self) {
        self.info(&format!(
            "finished duration_seconds={:.3}",
            self.started.elapsed().as_secs_f64()
        ));
    }
}

pub fn executable(name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    if path.components().count() > 1 && path.is_file() {
        return Ok(path.canonicalize()?);
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        for suffix in if cfg!(windows) {
            vec!["", ".exe", ".cmd"]
        } else {
            vec![""]
        } {
            let candidate = directory.join(format!("{name}{suffix}"));
            if candidate.is_file() {
                return Ok(candidate.canonicalize()?);
            }
        }
    }
    bail!("external tool is not available: {name}")
}

/// The CLI parent remains alive to reclaim containers even when a worker is
/// forcibly terminated. Cleanup uncertainty deliberately retains receipts.
pub fn run_supervised(spec: &CommandSpec) -> Result<CommandOutput> {
    #[cfg(unix)]
    {
        run(spec)
    } // Guardian owns the scope and waits for nested cleanup first.
    #[cfg(not(unix))]
    {
        let base = spec.cwd.clone().unwrap_or(std::env::current_dir()?);
        let mut scope = crate::tex_supervisor::ContainerScope::create(&base)?;
        let mut owned = spec.clone();
        owned.env.extend(scope.environment());
        let result = run(&owned);
        with_cleanup(result, scope.finish())
    }
}

pub fn cli_run_check(args: &[String]) -> Result<i32> {
    let mut timeout = 120.0;
    let mut idle = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--" => {
                index += 1;
                break;
            }
            "--timeout" => {
                index += 1;
                timeout = args.get(index).context("timeout missing")?.parse::<f64>()?;
                index += 1;
            }
            "--idle" | "--idle-timeout" => {
                index += 1;
                idle = Some(
                    args.get(index)
                        .context("idle timeout missing")?
                        .parse::<f64>()?,
                );
                index += 1;
            }
            _ => break,
        }
    }
    ensure!(
        timeout.is_finite() && timeout > 0.0 && idle.is_none_or(|d| d.is_finite() && d > 0.0),
        "timeouts must be positive finite seconds"
    );
    let mut spec = CommandSpec::new(args.get(index).context("run-check requires command")?);
    spec.args = args[index + 1..].iter().map(OsString::from).collect();
    spec.timeout = Duration::from_secs_f64(timeout);
    spec.idle_timeout = idle.map(Duration::from_secs_f64);
    let output = run_supervised(&spec)?;
    std::io::stdout().write_all(output.stdout_text().as_bytes())?;
    std::io::stderr().write_all(output.stderr_text().as_bytes())?;
    Ok(output.code)
}

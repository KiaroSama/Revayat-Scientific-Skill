//! Checked command-line deadlines before native process ownership is acquired.
use super::{CommandSpec, run_supervised};
use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, io::Write, time::Duration};

fn deadline(seconds: f64, name: &str) -> Result<Duration> {
    let duration = Duration::try_from_secs_f64(seconds)
        .with_context(|| format!("{name} must be finite, positive, representable seconds"))?;
    ensure!(
        !duration.is_zero(),
        "{name} must remain positive at nanosecond precision"
    );
    Ok(duration)
}

pub fn run_check(args: &[String]) -> Result<i32> {
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
    let timeout = deadline(timeout, "wall timeout")?;
    let idle = idle
        .map(|seconds| deadline(seconds, "idle timeout"))
        .transpose()?;
    let mut spec = CommandSpec::new(args.get(index).context("run-check requires command")?);
    spec.args = args[index + 1..].iter().map(OsString::from).collect();
    spec.timeout = timeout;
    spec.idle_timeout = idle;
    let output = run_supervised(&spec)?;
    std::io::stdout().write_all(output.stdout_text().as_bytes())?;
    std::io::stderr().write_all(output.stderr_text().as_bytes())?;
    Ok(output.code)
}

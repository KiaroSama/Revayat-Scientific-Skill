//! Observe the production boundary's effective Linux controls, without a shell.
use std::{
    env, fs, io,
    net::{SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};
#[cfg(target_os = "linux")]
#[path = "security_helper/mod.rs"]
mod helper;
struct Probe {
    checks: u32,
}
impl Probe {
    fn require(&mut self, condition: bool, message: &str) -> io::Result<()> {
        if !condition {
            return Err(io::Error::other(message));
        }
        self.checks += 1;
        Ok(())
    }
}
fn number(path: &str) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_| io::Error::other(format!("{path} does not contain a finite enforced limit")))
}
fn options<'a>(mounts: &'a str, target: &str) -> io::Result<Vec<&'a str>> {
    let line = mounts
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(target))
        .ok_or_else(|| io::Error::other("required mount is missing"))?;
    Ok(line
        .split_whitespace()
        .nth(3)
        .unwrap_or("")
        .split(',')
        .collect())
}
fn exact_limit(limits: &str, name: &str, expected: u64) -> io::Result<bool> {
    let line = limits
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .ok_or_else(|| io::Error::other("required process resource limit missing"))?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    Ok(fields
        .first()
        .is_some_and(|s| s.parse::<u64>() == Ok(expected))
        && fields
            .get(1)
            .is_some_and(|s| s.parse::<u64>() == Ok(expected)))
}
fn tmp_size(options: &[&str]) -> io::Result<u64> {
    let value = options
        .iter()
        .find_map(|s| s.strip_prefix("size="))
        .ok_or_else(|| io::Error::other("temporary mount size is not explicit"))?;
    let (digits, multiplier) = match value.as_bytes().last() {
        Some(b'k') => (value.trim_end_matches('k'), 1024),
        Some(b'm') => (value.trim_end_matches('m'), 1024 * 1024),
        Some(b'g') => (value.trim_end_matches('g'), 1024 * 1024 * 1024),
        _ => (value, 1),
    };
    digits
        .parse::<u64>()
        .map_err(io::Error::other)?
        .checked_mul(multiplier)
        .ok_or_else(|| io::Error::other("temporary size overflow"))
}
fn run() -> io::Result<()> {
    let mut probe = Probe { checks: 0 };
    probe.require(
        fs::read("/input/sentinel.txt")? == b"public sandbox fixture",
        "approved input is not readable",
    )?;
    probe.require(
        fs::OpenOptions::new()
            .append(true)
            .open("/input/sentinel.txt")
            .is_err(),
        "input is writable",
    )?;
    let mounts = fs::read_to_string("/proc/mounts")?;
    probe.require(
        options(&mounts, "/input")?.contains(&"ro"),
        "input mount is not read-only",
    )?;
    probe.require(
        options(&mounts, "/")?.contains(&"ro"),
        "root mount is not read-only",
    )?;
    probe.require(
        fs::write("/revayat-probe-write", b"probe").is_err(),
        "root filesystem is writable",
    )?;
    probe.require(
        fs::File::open("/usr/bin/timeout").is_ok(),
        "toolchain is not readable",
    )?;
    probe.require(
        fs::write("/usr/local/bin/revayat-probe-write", b"probe").is_err(),
        "toolchain is writable",
    )?;
    probe.require(
        fs::write("/output/probe.txt", b"allowed output").is_ok(),
        "approved output is not writable",
    )?;
    probe.require(
        fs::write("/tmp/probe.txt", b"allowed temporary").is_ok(),
        "private temporary space is not writable",
    )?;
    probe.require(
        env::var_os("REVAYAT_HOST_ONLY_CANARY").is_none(),
        "host environment leaked",
    )?;
    probe.require(
        env::var_os("HOME").is_some_and(|value| value == "/tmp/tex-home"),
        "HOME is not private scratch",
    )?;
    let status = fs::read_to_string("/proc/self/status")?;
    probe.require(
        status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .is_some_and(|line| line.split_whitespace().skip(1).all(|uid| uid != "0")),
        "container uses root authority",
    )?;
    for name in ["CapEff:", "CapBnd:"] {
        probe.require(
            status
                .lines()
                .find(|line| line.starts_with(name))
                .is_some_and(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b == b'0'))
                }),
            "container retains capabilities",
        )?;
    }
    probe.require(
        status.lines().any(|line| line == "NoNewPrivs:\t1"),
        "no-new-privileges not effective",
    )?;
    probe.require(
        number("/sys/fs/cgroup/memory.max")? == 1024 * 1024 * 1024,
        "memory limit not effective",
    )?;
    probe.require(
        number("/sys/fs/cgroup/memory.swap.max")? == 0,
        "swap limit not effective",
    )?;
    probe.require(
        number("/sys/fs/cgroup/pids.max")? == 64,
        "PID limit not effective",
    )?;
    let cpu = fs::read_to_string("/sys/fs/cgroup/cpu.max")?;
    let fields = cpu.split_whitespace().collect::<Vec<_>>();
    let quota = fields
        .first()
        .ok_or_else(|| io::Error::other("CPU quota missing"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let period = fields
        .get(1)
        .ok_or_else(|| io::Error::other("CPU period missing"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    probe.require(
        period > 0 && period.checked_mul(2) == Some(quota),
        "CPU quota not effective",
    )?;
    let limits = fs::read_to_string("/proc/self/limits")?;
    probe.require(
        exact_limit(&limits, "Max file size", 268_435_456)?,
        "file size limit not effective",
    )?;
    probe.require(
        exact_limit(&limits, "Max open files", 128)?,
        "file descriptor limit not effective",
    )?;
    let temporary = options(&mounts, "/tmp")?;
    probe.require(
        tmp_size(&temporary)? == 268_435_456,
        "temporary disk limit not effective",
    )?;
    for flag in ["noexec", "nosuid", "nodev"] {
        probe.require(
            temporary.contains(&flag),
            "temporary isolation flag missing",
        )?;
    }
    let interfaces = fs::read_dir("/sys/class/net")?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    probe.require(
        !interfaces.is_empty() && interfaces.iter().all(|name| name == "lo"),
        "external network interface is available",
    )?;
    let routes = fs::read_to_string("/proc/net/route")?;
    probe.require(
        routes.lines().skip(1).all(|line| {
            line.split_whitespace()
                .next()
                .is_none_or(|name| name == "lo")
        }),
        "external network route is available",
    )?;
    let address: SocketAddr = "192.0.2.1:9".parse().unwrap();
    probe.require(
        TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
        "network connection is available",
    )?;
    probe.require(
        !Path::new("/input/host-private-sentinel").exists(),
        "unapproved host sentinel is mounted",
    )?;
    if probe.checks != 29 {
        return Err(io::Error::other("sandbox probe check inventory mismatch"));
    }
    fs::write(
        "/output/sandbox-verified.json",
        format!("{{\"verified\":true,\"checks\":{}}}\n", probe.checks),
    )?;
    println!("sandbox_controls_verified");
    Ok(())
}
fn main() {
    let mode = env::args().nth(1);
    let outcome = match mode.as_deref() {
        None => run(),
        Some("--helper-entry") | Some("--helper-probe") => {
            #[cfg(target_os = "linux")]
            {
                if mode.as_deref() == Some("--helper-entry") {
                    helper::entry()
                } else {
                    helper::preflight_then_worker()
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(io::Error::other("Linux helper preflight requires Linux"))
            }
        }
        _ => Err(io::Error::other("unsupported trusted probe mode")),
    };
    if let Err(error) = outcome {
        println!("sandbox enforcement failed: {error}");
        std::process::exit(2);
    }
}

//! Trusted Linux preflight. No reviewed target runs before these observations.
use super::{Probe, exact_limit, number, options, tmp_size};
use std::{
    collections::BTreeSet,
    env, fs,
    io::{self, Write},
    net::{SocketAddr, TcpStream},
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const ENVIRONMENT: [(&str, &str); 7] = [
    ("PATH", "/usr/bin:/bin"),
    ("HOME", "/scratch/home"),
    ("TMPDIR", "/scratch/tmp"),
    ("XDG_CACHE_HOME", "/scratch/cache"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("REVAYAT_SECURITY_TIER", "linux"),
];
unsafe extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
    fn posix_fallocate(fd: i32, offset: i64, length: i64) -> i32;
}

pub fn entry() -> io::Result<()> {
    for name in ["home", "tmp", "cache", "work"] {
        let path = Path::new("/scratch").join(name);
        fs::create_dir(&path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let error = Command::new(env::current_exe()?)
        .arg("--helper-probe")
        .current_dir("/scratch/work")
        .env_clear()
        .envs(ENVIRONMENT)
        .stdin(Stdio::null())
        .exec();
    Err(error)
}

struct SignalRestore(usize);
impl Drop for SignalRestore {
    fn drop(&mut self) {
        // SAFETY: restore the disposition captured for SIGXFSZ in this process.
        unsafe {
            signal(25, self.0);
        }
    }
}
fn sparse_file_limit() -> io::Result<bool> {
    // SAFETY: Linux SIGXFSZ=25 and SIG_IGN=1; this trusted probe is single-threaded.
    let previous = unsafe { signal(25, 1) };
    if previous == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    let _restore = SignalRestore(previous);
    let path = Path::new("/scratch/size-control");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let outcome = file.set_len(67_108_865);
    drop(file);
    let cleanup = fs::remove_file(path);
    cleanup?;
    Ok(outcome.is_err_and(|error| error.raw_os_error() == Some(27)))
}
fn aggregate_limit() -> io::Result<bool> {
    let mut paths = Vec::<PathBuf>::new();
    let outcome = (|| {
        for index in 0..9 {
            let path = Path::new("/scratch").join(format!("aggregate-control-{index}"));
            paths.push(path.clone());
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            // SAFETY: live owned descriptor; nonnegative bounded Linux off_t values.
            let code = unsafe { posix_fallocate(file.as_raw_fd(), 0, 16 * 1024 * 1024) };
            if code != 0 {
                return if code == 28 {
                    Ok(true)
                } else {
                    Err(io::Error::from_raw_os_error(code))
                };
            }
        }
        Ok(false)
    })();
    for path in paths {
        fs::remove_file(path)?;
    }
    outcome
}
fn denied_write(path: &str) -> io::Result<bool> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Err(error) => Ok(matches!(error.raw_os_error(), Some(13 | 30))),
        Ok(file) => {
            drop(file);
            let _ = fs::remove_file(path);
            Ok(false)
        }
    }
}
fn route_denied(address: &str) -> io::Result<bool> {
    let address: SocketAddr = address.parse().map_err(io::Error::other)?;
    Ok(
        TcpStream::connect_timeout(&address, Duration::from_millis(100))
            .is_err_and(|error| matches!(error.raw_os_error(), Some(101 | 113))),
    )
}

pub fn preflight_then_worker() -> io::Result<()> {
    let mut probe = Probe { checks: 0 };
    let actual = env::vars_os()
        .map(|(name, _)| name)
        .collect::<BTreeSet<_>>();
    let allowed = ENVIRONMENT
        .iter()
        .map(|(name, _)| std::ffi::OsString::from(*name))
        .collect::<BTreeSet<_>>();
    probe.require(
        actual == allowed,
        "helper environment contains unapproved names",
    )?;
    for (name, value) in ENVIRONMENT {
        probe.require(
            env::var_os(name).is_some_and(|actual| actual == value),
            "helper environment value is not fixed private configuration",
        )?;
    }
    let status = fs::read_to_string("/proc/self/status")?;
    probe.require(
        status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .is_some_and(|line| line.split_whitespace().skip(1).all(|uid| uid != "0")),
        "helper uses root authority",
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
            "helper retains capabilities",
        )?;
    }
    probe.require(
        status.lines().any(|line| line == "NoNewPrivs:\t1"),
        "helper no-new-privileges is not effective",
    )?;
    for target in [
        "/target/.security-write",
        "/usr/.security-write",
        "/.security-write",
        "/dev/.security-write",
        "/dev/shm/.security-write",
        "/dev/mqueue/.security-write",
    ] {
        probe.require(
            denied_write(target)?,
            "helper protected write was not refused with access/readonly denial",
        )?;
    }
    let coverage = fs::read("/target/coverage.json")?;
    probe.require(
        coverage.len() <= 4 * 1024 * 1024 && coverage.starts_with(b"{"),
        "public target metadata is not readable",
    )?;
    let mounts = fs::read_to_string("/proc/self/mounts")?;
    for target in ["/", "/target", "/dev/shm", "/dev/mqueue"] {
        probe.require(
            options(&mounts, target)?.contains(&"ro"),
            "helper protected mount is not read-only",
        )?;
    }
    let positive = Path::new("/scratch/positive");
    fs::write(positive, b"allowed scratch")?;
    probe.require(
        fs::read(positive)? == b"allowed scratch",
        "helper private scratch is not usable",
    )?;
    fs::remove_file(positive)?;
    probe.require(
        !Path::new("/host-only-canary").exists(),
        "unapproved host path is mounted",
    )?;
    let interfaces = fs::read_dir("/sys/class/net")?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    probe.require(
        !interfaces.is_empty() && interfaces.iter().all(|name| name == "lo"),
        "helper has an external interface",
    )?;
    probe.require(
        route_denied("192.0.2.1:9")?,
        "helper IPv4 did not refuse an external route",
    )?;
    probe.require(
        route_denied("[2001:db8::1]:9")?,
        "helper IPv6 did not refuse an external route",
    )?;
    probe.require(
        number("/sys/fs/cgroup/memory.max")? == 1_073_741_824,
        "helper memory limit not effective",
    )?;
    probe.require(
        number("/sys/fs/cgroup/pids.max")? == 64,
        "helper PID limit not effective",
    )?;
    let cpu = fs::read_to_string("/sys/fs/cgroup/cpu.max")?;
    let fields = cpu.split_whitespace().collect::<Vec<_>>();
    let quota = fields
        .first()
        .ok_or_else(|| io::Error::other("helper CPU quota missing"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let period = fields
        .get(1)
        .ok_or_else(|| io::Error::other("helper CPU period missing"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    probe.require(
        period > 0 && period.checked_mul(2) == Some(quota),
        "helper CPU quota not effective",
    )?;
    let limits = fs::read_to_string("/proc/self/limits")?;
    probe.require(
        exact_limit(&limits, "Max file size", 67_108_864)?,
        "helper file limit not effective",
    )?;
    probe.require(
        exact_limit(&limits, "Max open files", 128)?,
        "helper descriptor limit not effective",
    )?;
    let scratch = options(&mounts, "/scratch")?;
    probe.require(
        tmp_size(&scratch)? == 134_217_728,
        "helper aggregate scratch size differs",
    )?;
    for flag in ["noexec", "nosuid", "nodev"] {
        probe.require(
            scratch.contains(&flag),
            "helper scratch isolation flag missing",
        )?;
    }
    probe.require(
        sparse_file_limit()?,
        "helper sparse file growth did not enforce EFBIG",
    )?;
    probe.require(
        aggregate_limit()?,
        "helper aggregate allocation did not enforce ENOSPC",
    )?;
    if probe.checks != 39 {
        return Err(io::Error::other("helper control inventory mismatch"));
    }
    println!(
        "{{\"phase\":\"helper-preflight\",\"status\":\"passed\",\"checks\":{},\"environment_names\":7,\"scratch_bytes\":134217728,\"file_bytes\":67108864}}",
        probe.checks
    );
    io::stdout().flush()?;
    let error = Command::new("/target/security-worker")
        .current_dir("/scratch/work")
        .stdin(Stdio::null())
        .exec();
    Err(error)
}

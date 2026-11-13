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
            return Err(io::Error::other(format!(
                "probe-control-{:02}: {message}",
                self.checks + 1
            )));
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

#[cfg(target_os = "linux")]
fn output_allocation_limits() -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
        fn posix_fallocate(fd: i32, offset: i64, length: i64) -> i32;
    }
    const LIMIT: u64 = 268_435_456;
    // SIGXFSZ must be ignored temporarily so the probe observes EFBIG rather
    // than terminating. No reviewed target runs concurrently with this probe.
    let previous = unsafe { signal(25, 1) };
    if previous == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    let sparse = Path::new("/output/per-file-control");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(sparse)?;
    let at_limit = file.set_len(LIMIT).is_ok();
    let per_file = file.set_len(LIMIT + 1);
    drop(file);
    let restored = unsafe { signal(25, previous) };
    fs::remove_file(sparse)?;
    if restored == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    if !at_limit || !per_file.is_err_and(|error| error.raw_os_error() == Some(27)) {
        return Ok(false);
    }
    let mut paths = Vec::new();
    let mut admitted = 0;
    let outcome = (|| {
        for index in 0..17 {
            let path = Path::new("/output").join(format!("aggregate-control-{index}"));
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            paths.push(path);
            // Every allocation is 16 MiB, well below RLIMIT_FSIZE. Reservation
            // consumes real pages; sparse lengths cannot prove aggregate quota.
            let code = unsafe { posix_fallocate(file.as_raw_fd(), 0, 16 * 1024 * 1024) };
            if code != 0 {
                return if code == 28 {
                    // probe.txt already occupies one page, so exactly fifteen
                    // complete 16MiB reservations fit; the sixteenth must fail.
                    Ok(admitted == 15)
                } else {
                    Err(io::Error::from_raw_os_error(code))
                };
            }
            admitted += 1;
        }
        Ok(false)
    })();
    for path in paths {
        fs::remove_file(path)?;
    }
    outcome
}

#[cfg(not(target_os = "linux"))]
fn output_allocation_limits() -> io::Result<bool> {
    Err(io::Error::other(
        "production output enforcement requires Linux",
    ))
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
    let output = options(&mounts, "/output")?;
    let output_type = mounts
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some("/output"))
        .and_then(|line| line.split_whitespace().nth(2));
    probe.require(
        fs::write("/output/probe.txt", b"allowed output\n").is_ok()
            && output_type == Some("tmpfs")
            && tmp_size(&output)? == 268_435_456
            && ["rw", "noexec", "nosuid", "nodev"]
                .iter()
                .all(|flag| output.contains(flag)),
        "approved output is not a private quota-backed tmpfs",
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
    if !output_allocation_limits()? {
        return Err(io::Error::other(
            "production output EFBIG/aggregate ENOSPC enforcement failed",
        ));
    }
    let status = std::process::Command::new("/usr/local/bin/revayat-tex-entry")
        .arg("/input/.revayat-main.tex")
        .stdin(std::process::Stdio::null())
        .status()?;
    if !status.success()
        || fs::read_to_string("/output/public-one.txt")?.trim() != "public harmless first"
        || fs::read_to_string("/output/public-two.txt")?.trim() != "public harmless second"
        || fs::metadata("/output/document.pdf")?.len() == 0
    {
        return Err(io::Error::other(
            "production harmless XeLaTeX output controls failed",
        ));
    }
    fs::write(
        "/output/sandbox-verified.json",
        format!(
            "{{\"verified\":true,\"checks\":{},\"output_mount\":\"tmpfs\",\"output_bytes\":268435456,\"per_file_bytes\":268435456,\"per_file_efbig\":true,\"aggregate_enospc\":true,\"tex_openout_files\":2,\"ordinary_pdf\":true}}\n",
            probe.checks
        ),
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

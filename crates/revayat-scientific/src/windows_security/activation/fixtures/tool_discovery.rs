//! Real installed Rust1.100/MSVC/SDK preparation. Discovery text and paths are withheld.
use super::{
    build::{self, RustTools},
    io,
    prepared::PreparedSet,
};
use crate::{
    runtime::{self, CommandSpec},
    windows_security::activation::Failures,
};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
#[path = "tool_lease.rs"]
mod lease;
#[path = "tool_windows.rs"]
mod windows;
use lease::Pins;
#[path = "python_base.rs"]
pub mod python_base;
pub struct DiscoveredRustTools {
    tools: RustTools,
    pins: Pins,
}
impl DiscoveredRustTools {
    pub fn tools(&self) -> &RustTools {
        &self.tools
    }
    pub fn verify(&mut self) -> Result<()> {
        self.pins
            .verify()
            .context("fixed Rust/MSVC tool identities changed; private_cause_retained=True")
    }
    pub fn close(mut self) -> Result<()> {
        self.pins.close()
    }
    /// All compiler and target-library pins remain held until compilation and
    /// post-verification finish. Every close is attempted before results escape.
    pub fn prepare(mut self, python: &Path, state: &Path, sources: &Path) -> Result<PreparedSet> {
        let result = (|| {
            self.verify()?;
            let result = build::prepare(&self.tools, python, state, sources);
            runtime::with_cleanup(result, self.verify())
        })();
        runtime::with_cleanup(result, self.pins.close())
    }
}
impl RustTools {
    pub fn discover(state: &Path) -> Result<DiscoveredRustTools> {
        let mut pins = Pins::new();
        let result = discover(&mut pins, state)
            .context("fixed Rust/MSVC discovery failed; private_cause_retained=True");
        match result {
            Ok(tools) => Ok(DiscoveredRustTools { tools, pins }),
            Err(error) => runtime::with_cleanup(Err(error), pins.close()),
        }
    }
}
fn command(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    system: &Path,
    search: &[&Path],
) -> Result<String> {
    let mut spec = CommandSpec::new(program.as_os_str());
    spec.args = args.into();
    spec.cwd = Some(cwd.into());
    spec.timeout = Duration::from_secs(30);
    spec.idle_timeout = Some(Duration::from_secs(15));
    spec.max_output = 65536;
    spec.env_remove = std::env::vars_os().map(|(name, _)| name).collect();
    let paths = std::iter::once(program.parent().unwrap())
        .chain(search.iter().copied())
        .chain(std::iter::once(system.join("System32").as_path()))
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    let path = std::env::join_paths(paths)?;
    for (name, value) in [
        ("SystemRoot", system.as_os_str()),
        ("WINDIR", system.as_os_str()),
        ("TEMP", cwd.as_os_str()),
        ("TMP", cwd.as_os_str()),
        ("PATH", path.as_os_str()),
    ] {
        spec.env.insert(name.into(), value.into());
    }
    let mut output =
        runtime::run(&spec).context("fixed discovery process failed; raw_output_withheld=True")?;
    let result = (|| {
        ensure!(
            output.code == 0 && output.stderr.is_empty(),
            "fixed discovery process refused exit={} raw_output_withheld=True",
            output.code
        );
        Ok(std::str::from_utf8(&output.stdout)?.to_owned())
    })();
    output.stdout.fill(0);
    output.stderr.fill(0);
    result
}
fn one_path(text: &str) -> Result<PathBuf> {
    let lines = text
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        lines.len() == 1 && lines[0].len() <= 32768 && !lines[0].contains('\0'),
        "fixed discovery path output is missing/ambiguous"
    );
    let path = PathBuf::from(lines[0]);
    ensure!(
        path.is_absolute(),
        "fixed discovery returned a relative path"
    );
    Ok(path)
}
fn version(text: &str) -> Result<[u32; 4]> {
    let parts = text.split('.').collect::<Vec<_>>();
    ensure!(
        (2..=4).contains(&parts.len()) && text.len() <= 128,
        "fixed tool version shape differs"
    );
    let mut result = [0; 4];
    for (index, part) in parts.iter().enumerate() {
        ensure!(
            !part.is_empty() && part.bytes().all(|v| v.is_ascii_digit()),
            "fixed tool version is not decimal"
        );
        result[index] = part.parse()?;
    }
    Ok(result)
}
fn entries(path: &Path, maximum: usize) -> Result<Vec<PathBuf>> {
    let mut selected = Vec::new();
    for entry in fs::read_dir(path)? {
        ensure!(
            selected.len() < maximum,
            "fixed discovery directory exceeds entry bound"
        );
        let entry = entry?;
        io::plain(&entry.path(), false)?;
        selected.push(entry.path());
    }
    Ok(selected)
}
fn dlls(pins: &mut Pins, path: &Path, require_driver: bool) -> Result<()> {
    let mut drivers = 0;
    let mut count = 0;
    for path in entries(path, 256)? {
        if path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("dll"))
        {
            count += 1;
            ensure!(count <= 64, "fixed tool DLL set exceeds bound");
            if path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("rustc_driver-"))
            {
                drivers += 1;
            }
            pins.file(&path)?;
        }
    }
    ensure!(
        !require_driver || drivers == 1,
        "real Rust toolchain driver is missing/ambiguous"
    );
    Ok(())
}
fn discover(pins: &mut Pins, state: &Path) -> Result<RustTools> {
    crate::windows_security::activation::native::require_host()?;
    let state = pins.path(state)?;
    ensure!(state.is_dir(), "fixed tool state is not a directory");
    let system_root = pins.path(&windows::system_root()?)?;
    let vswhere = pins.file(
        &windows::program_files_x86()?
            .join("Microsoft Visual Studio")
            .join("Installer")
            .join("vswhere.exe"),
    )?;
    let text = command(
        &vswhere,
        &[
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
            "-utf8",
        ]
        .map(OsString::from),
        &state,
        &system_root,
        &[],
    )?;
    let install = pins.path(&one_path(&text)?)?;
    let metadata = install
        .join("VC")
        .join("Auxiliary")
        .join("Build")
        .join("Microsoft.VCToolsVersion.default.txt");
    let mut bytes = pins.read(&metadata, 128)?;
    let parsed = (|| {
        let text = std::str::from_utf8(&bytes)?.trim();
        version(text)?;
        Ok::<_, anyhow::Error>(text.to_owned())
    })();
    bytes.fill(0);
    let vc_version = parsed?;
    let vc = pins.path(
        &install
            .join("VC")
            .join("Tools")
            .join("MSVC")
            .join(vc_version)
            .join("bin")
            .join("Hostx64")
            .join("x64"),
    )?;
    let linker = pins.file(&vc.join("link.exe"))?;
    dlls(pins, &vc, false)?;
    let sdk = pins.path(&windows::sdk_root()?)?;
    let libraries = pins.path(&sdk.join("Lib"))?;
    let mut candidates = Vec::new();
    for path in entries(&libraries, 32)? {
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Ok(parsed) = version(name) else { continue };
        let library = path.join("um").join("x64").join("kernel32.lib");
        io::plain(&library, true)?;
        if library.try_exists()? {
            candidates.push((parsed, library));
        }
    }
    candidates.sort_by_key(|value| std::cmp::Reverse(value.0));
    let Some((_, library)) = candidates.first() else {
        anyhow::bail!("installed x64 Kernel32 import library is unavailable")
    };
    if candidates.len() > 1 {
        ensure!(
            candidates[0].0 != candidates[1].0,
            "installed SDK version selection is ambiguous"
        );
    }
    let kernel32 = pins.file(library)?;
    let rustup = match std::env::var_os("RUSTUP_HOME") {
        Some(path) => PathBuf::from(path),
        None => windows::profile()?.join(".rustup"),
    };
    let sysroot = pins.path(
        &rustup
            .join("toolchains")
            .join("1.100.0-x86_64-pc-windows-msvc"),
    )?;
    let bin = pins.path(&sysroot.join("bin"))?;
    let rustc = pins.file(&bin.join("rustc.exe"))?;
    dlls(pins, &bin, true)?;
    let text = command(
        &rustc,
        &["--version".into(), "--verbose".into()],
        &state,
        &system_root,
        &[&vc],
    )?;
    ensure!(
        text.lines().any(|line| line == "release: 1.100.0")
            && text
                .lines()
                .any(|line| line == "host: x86_64-pc-windows-msvc"),
        "real compiler version or target differs"
    );
    let expected = pins.path(
        &sysroot
            .join("lib")
            .join("rustlib")
            .join("x86_64-pc-windows-msvc")
            .join("lib"),
    )?;
    let text = command(
        &rustc,
        &[
            "--print".into(),
            "target-libdir".into(),
            "--target=x86_64-pc-windows-msvc".into(),
        ],
        &state,
        &system_root,
        &[&vc],
    )?;
    let actual = pins.path(&one_path(&text)?)?;
    ensure!(
        actual == expected,
        "compiler target library root differs from pinned toolchain"
    );
    for prefix in ["libcore-", "libcompiler_builtins-"] {
        let selected = entries(&expected, 256)?
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|v| v.to_str())
                    .is_some_and(|v| v.starts_with(prefix) && v.ends_with(".rlib"))
            })
            .collect::<Vec<_>>();
        ensure!(
            selected.len() == 1,
            "required no-CRT target library is missing/ambiguous"
        );
        pins.file(&selected[0])?;
    }
    pins.verify()?;
    Ok(RustTools {
        rustc,
        linker,
        kernel32,
        system_root,
    })
}

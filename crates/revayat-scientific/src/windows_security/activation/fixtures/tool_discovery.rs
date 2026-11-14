//! Real installed Rust1.100/MSVC/SDK preparation. Discovery text and paths are withheld.
use super::{
    build::{self, RustTools},
    io,
    prepared::PreparedSet,
};
use crate::{
    runtime::{self, CommandSpec},
    windows_security::activation::{
        Failures,
        diagnostics::{self, Numbers, Stage},
    },
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
fn step<T>(stage: Stage, body: impl FnOnce() -> Result<T>) -> Result<T> {
    body().map_err(|error| diagnostics::operation(error, stage))
}
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
        step(Stage::FixturePinsVerify, || self.pins.verify())
            .context("fixed Rust/MSVC tool identities changed; private_cause_retained=True")
    }
    pub fn close(mut self) -> Result<()> {
        step(Stage::FixturePinsClose, || self.pins.close())
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
// The Python discovery sibling retains its existing private command interface.
fn command(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    system: &Path,
    search: &[&Path],
) -> Result<String> {
    command_at(Stage::FixtureDiscover, program, args, cwd, system, search)
}
fn command_at(
    stage: Stage,
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
    let numbers = Numbers {
        result: Some(output.code as u32),
        stdout_bytes: u32::try_from(output.stdout.len()).ok(),
        stderr_bytes: u32::try_from(output.stderr.len()).ok(),
        ..Default::default()
    };
    let result = (|| {
        ensure!(
            output.code == 0 && output.stderr.is_empty(),
            "fixed discovery process refused exit={} raw_output_withheld=True",
            output.code
        );
        Ok(std::str::from_utf8(&output.stdout)?.to_owned())
    })()
    .map_err(|error| diagnostics::annotate(error, stage, numbers));
    output.stdout.fill(0);
    output.stderr.fill(0);
    result
}
fn one_path(text: &str) -> Result<PathBuf> {
    let lines = text
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let result = (|| {
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
    })();
    result.map_err(|error| {
        diagnostics::annotate(
            error,
            Stage::FixturePathShape,
            Numbers {
                count: u32::try_from(lines.len()).ok(),
                bytes: u32::try_from(text.len()).ok(),
                // Closed flags only: BOM, absolute first line, NUL. No path/output text.
                properties: Some(
                    u32::from(text.starts_with('\u{feff}'))
                        | (u32::from(
                            lines
                                .first()
                                .is_some_and(|line| Path::new(line).is_absolute()),
                        ) << 1)
                        | (u32::from(text.contains('\0')) << 2),
                ),
                ..Default::default()
            },
        )
    })
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
    let result = (|| {
        ensure!(
            !require_driver || drivers == 1,
            "real Rust toolchain driver is missing/ambiguous"
        );
        Ok(())
    })();
    result.map_err(|error| {
        diagnostics::annotate(
            error,
            if require_driver {
                Stage::FixtureRustDlls
            } else {
                Stage::FixtureVcDlls
            },
            Numbers {
                count: Some(drivers),
                properties: Some(count),
                ..Default::default()
            },
        )
    })
}
fn discover(pins: &mut Pins, state: &Path) -> Result<RustTools> {
    step(
        Stage::FixtureHost,
        crate::windows_security::activation::native::require_host,
    )?;
    let state = step(Stage::FixtureState, || {
        let state = pins.path(state)?;
        ensure!(state.is_dir(), "fixed tool state is not a directory");
        Ok(state)
    })?;
    let system_root = step(Stage::FixtureWindowsRoot, || {
        pins.path(&windows::system_root()?)
    })?;
    let program_files = step(Stage::FixtureProgramFiles, windows::program_files_x86)?;
    let vswhere = step(Stage::FixtureVswhere, || {
        pins.file(
            &program_files
                .join("Microsoft Visual Studio")
                .join("Installer")
                .join("vswhere.exe"),
        )
    })?;
    let text = step(Stage::FixtureVswhereRun, || {
        command_at(
            Stage::FixtureVswhereRun,
            &vswhere,
            &[
                "-nologo",
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
        )
    })?;
    let install = step(Stage::FixtureVsInstall, || pins.path(&one_path(&text)?))?;
    let metadata = install
        .join("VC")
        .join("Auxiliary")
        .join("Build")
        .join("Microsoft.VCToolsVersion.default.txt");
    let mut bytes = step(Stage::FixtureVcMetadata, || pins.read(&metadata, 128))?;
    let parsed = step(Stage::FixtureVcVersion, || {
        let text = std::str::from_utf8(&bytes)?.trim();
        version(text)?;
        Ok(text.to_owned())
    });
    bytes.fill(0);
    let vc_version = parsed?;
    let vc = step(Stage::FixtureVcBin, || {
        pins.path(
            &install
                .join("VC")
                .join("Tools")
                .join("MSVC")
                .join(vc_version)
                .join("bin")
                .join("Hostx64")
                .join("x64"),
        )
    })?;
    let linker = step(Stage::FixtureLinker, || pins.file(&vc.join("link.exe")))?;
    step(Stage::FixtureVcDlls, || dlls(pins, &vc, false))?;
    let sdk = step(Stage::FixtureSdkRoot, || pins.path(&windows::sdk_root()?))?;
    let libraries = step(Stage::FixtureSdkLibraries, || pins.path(&sdk.join("Lib")))?;
    let library = step(Stage::FixtureSdkSelect, || {
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
        let selected = (|| {
            let Some((_, library)) = candidates.first() else {
                anyhow::bail!("installed x64 Kernel32 import library is unavailable")
            };
            if candidates.len() > 1 {
                ensure!(
                    candidates[0].0 != candidates[1].0,
                    "installed SDK version selection is ambiguous"
                );
            }
            Ok(library.clone())
        })();
        selected.map_err(|error| {
            diagnostics::annotate(
                error,
                Stage::FixtureSdkSelect,
                Numbers {
                    count: u32::try_from(candidates.len()).ok(),
                    ..Default::default()
                },
            )
        })
    })?;
    let kernel32 = step(Stage::FixtureKernel32, || pins.file(&library))?;
    let rustup = step(Stage::FixtureRustupRoot, || {
        Ok(match std::env::var_os("RUSTUP_HOME") {
            Some(path) => PathBuf::from(path),
            None => windows::profile()?.join(".rustup"),
        })
    })?;
    let sysroot = step(Stage::FixtureRustSysroot, || {
        pins.path(
            &rustup
                .join("toolchains")
                .join("1.100.0-x86_64-pc-windows-msvc"),
        )
    })?;
    let bin = step(Stage::FixtureRustBin, || pins.path(&sysroot.join("bin")))?;
    let rustc = step(Stage::FixtureRustc, || pins.file(&bin.join("rustc.exe")))?;
    step(Stage::FixtureRustDlls, || dlls(pins, &bin, true))?;
    step(Stage::FixtureRustVersion, || {
        let text = command_at(
            Stage::FixtureRustVersion,
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
        Ok(())
    })?;
    let expected = step(Stage::FixtureTargetLibdir, || {
        pins.path(
            &sysroot
                .join("lib")
                .join("rustlib")
                .join("x86_64-pc-windows-msvc")
                .join("lib"),
        )
    })?;
    step(Stage::FixtureTargetIdentity, || {
        let text = command_at(
            Stage::FixtureTargetIdentity,
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
        Ok(())
    })?;
    for (prefix, stage) in [
        ("libcore-", Stage::FixtureCore),
        ("libcompiler_builtins-", Stage::FixtureBuiltins),
    ] {
        step(stage, || {
            let selected = entries(&expected, 256)?
                .into_iter()
                .filter(|path| {
                    path.file_name()
                        .and_then(|v| v.to_str())
                        .is_some_and(|v| v.starts_with(prefix) && v.ends_with(".rlib"))
                })
                .collect::<Vec<_>>();
            let result = (|| {
                ensure!(
                    selected.len() == 1,
                    "required no-CRT target library is missing/ambiguous"
                );
                pins.file(&selected[0])?;
                Ok(())
            })();
            result.map_err(|error| {
                diagnostics::annotate(
                    error,
                    stage,
                    Numbers {
                        count: u32::try_from(selected.len()).ok(),
                        ..Default::default()
                    },
                )
            })
        })?;
    }
    step(Stage::FixturePinsVerify, || pins.verify())?;
    Ok(RustTools {
        rustc,
        linker,
        kernel32,
        system_root,
    })
}

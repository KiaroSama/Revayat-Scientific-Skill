//! Actual independent no-CRT producers. Compiled roles are not native-execution evidence.
use super::{
    io::{self, HeldFile},
    lease::{self, CloseOrder, Lease},
    prepared::Snapshot,
    registry_loader::{self, HeldRegistryLoader, RegistryLoader},
    tool_discovery::{DiscoveredRustTools, python_base::PreparedPythonBase},
};
use crate::{
    runtime::{self, CommandSpec},
    windows_security::{
        activation::Failures,
        diagnostic_validation::FixedNativeImage,
        image::{self, PeImage},
    },
};
use anyhow::{Result, ensure};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};
#[path = "native_producer_io.rs"]
mod owned;
use owned::{Bytes, Inputs};
#[path = "native_control_plan.rs"]
mod control_plan;
#[path = "native_python_sdk.rs"]
mod python_sdk;
#[path = "native_producer_sources.rs"]
mod sources;
pub use control_plan::check_order_validation;
#[path = "independent_id2.rs"]
pub mod independent_id2;
pub use independent_id2::CompiledIndependentId2;
#[path = "python_authority_producer.rs"]
pub mod python_authority;
pub use python_authority::{CompiledPythonAuthority, HeldPythonAuthority};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeControlRole {
    Startup,
    DebugControl,
}
impl NativeControlRole {
    fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup-native.exe",
            Self::DebugControl => "debug-control-native.exe",
        }
    }
}
pub struct CompiledNativeControl {
    role: NativeControlRole,
    python: PathBuf,
    image: PathBuf,
    inputs: Vec<Snapshot>,
    site: Option<u32>,
}
pub struct NativeControls {
    startup: CompiledNativeControl,
    debug: CompiledNativeControl,
}
impl NativeControls {
    pub fn get(&self, role: NativeControlRole) -> &CompiledNativeControl {
        match role {
            NativeControlRole::Startup => &self.startup,
            NativeControlRole::DebugControl => &self.debug,
        }
    }
    /// Original NativeFixture.Build then BuildDebugControlFixed, never reversed.
    pub fn build(
        tools: &mut DiscoveredRustTools,
        base: &PreparedPythonBase,
        run: &str,
        state: &Path,
    ) -> Result<Self> {
        check_order_validation()?;
        require_runtime(base, run, state)?;
        tools.verify()?;
        let root = state.join("independent-native-build");
        owned::directory(&root)?;
        let mut inputs = Inputs::new();
        let result = (|| {
            let [startup, debug] =
                control_plan::execute(|role| build_control(tools, base, &root, &mut inputs, role))?;
            inputs.verify()?;
            tools.verify()?;
            Ok(Self { startup, debug })
        })();
        inputs.finish(result)
    }
}
impl CompiledNativeControl {
    pub fn role(&self) -> NativeControlRole {
        self.role
    }
    pub fn image(&self) -> &Path {
        &self.image
    }
    pub fn debug_site(&self) -> Option<u32> {
        self.site
    }
    pub fn hold(&self, python: &Path) -> Result<Lease<HeldFile>> {
        ensure!(
            python == self.python,
            "native control prepared for another runtime"
        );
        io::no_overrides(&self.image)?;
        let opens = self
            .inputs
            .iter()
            .map(|snapshot| {
                Box::new(move || HeldFile::open(&snapshot.path, snapshot.maximum))
                    as Box<dyn FnOnce() -> Result<HeldFile>>
            })
            .collect();
        lease::acquire(opens, CloseOrder::Reverse, |held| {
            for (file, snapshot) in held.iter_mut().zip(&self.inputs) {
                let bytes = Bytes(file.bytes()?);
                io::require_identity(&bytes.0, snapshot.length, &snapshot.digest)?;
                if file.path() == self.image {
                    let image = FixedNativeImage::parse(&bytes.0)?;
                    if let Some(expected) = self.site {
                        ensure!(
                            image.debug_control_site()? == expected,
                            "debug-control site changed"
                        );
                    }
                }
            }
            Ok(())
        })
    }
}
/// Opaque actual-compiler producer result, unlike capture_prebuilt. Admission
/// borrows this owner and the genuine runtime+three-loader-dependency lease.
pub struct CompiledRegistryLoader {
    loader: RegistryLoader,
    python: PathBuf,
    image: PathBuf,
}
impl CompiledRegistryLoader {
    pub fn image(&self) -> &Path {
        &self.image
    }
    pub fn hold(&self, python: &Path) -> Result<HeldRegistryLoader> {
        ensure!(
            python == self.python,
            "compiled registry loader runtime differs"
        );
        self.loader.hold(python)
    }
    pub fn build(
        tools: &mut DiscoveredRustTools,
        base: &PreparedPythonBase,
        run: &str,
        state: &Path,
    ) -> Result<Self> {
        require_runtime(base, run, state)?;
        tools.verify()?;
        let root = state.join("registry-loader-rust-build");
        owned::directory(&root)?;
        let mut inputs = Inputs::new();
        let result = (|| {
            let library = python_sdk::qualify(base, &mut inputs)?;
            sources::copy(&mut inputs, &root, "python_abi.rs", "python_abi.rs")?;
            sources::copy(&mut inputs, &root, "registry_loader.rs", "main.rs")?;
            let config = registry_loader::header(
                base.python()
                    .parent()
                    .unwrap()
                    .join("DLLs")
                    .join("_ctypes.pyd")
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("fixed loader path is not Unicode"))?,
            )?;
            inputs.create(&root.join("config.rs"), config.as_bytes(), 16384)?;
            let image = base
                .python()
                .parent()
                .unwrap()
                .join("DLLs")
                .join("_registry_loader.pyd");
            compile(
                tools,
                &mut inputs,
                &root,
                &image,
                LinkRole::RegistryLoader(&library),
            )?;
            let bytes = Bytes(inputs.bytes(&image)?);
            image::qualify_registry_loader(&bytes.0)?;
            inputs.verify()?;
            tools.verify()?;
            let mut loader = RegistryLoader::default();
            loader.capture_prebuilt(base.runtime().identity())?;
            Ok(Self {
                loader,
                python: base.python().into(),
                image,
            })
        })();
        inputs.finish(result)
    }
}
fn require_runtime(base: &PreparedPythonBase, run: &str, state: &Path) -> Result<()> {
    let runtime = crate::windows_security::activation::native_pass::runtime_path(run, state)?;
    ensure!(
        base.python() == runtime.join("python.exe"),
        "independent native producer is outside owned runtime"
    );
    base.runtime().identity().hold(base.python())?.close()
}
fn build_control(
    tools: &mut DiscoveredRustTools,
    base: &PreparedPythonBase,
    root: &Path,
    inputs: &mut Inputs,
    role: NativeControlRole,
) -> Result<CompiledNativeControl> {
    let folder = root.join(match role {
        NativeControlRole::Startup => "startup",
        NativeControlRole::DebugControl => "debug-control",
    });
    owned::directory(&folder)?;
    sources::copy(
        inputs,
        &folder,
        match role {
            NativeControlRole::Startup => "startup_native.rs",
            NativeControlRole::DebugControl => "debug_control.rs",
        },
        "main.rs",
    )?;
    let image = base.python().parent().unwrap().join(role.name());
    compile(tools, inputs, &folder, &image, LinkRole::Control(role))?;
    let bytes = Bytes(inputs.bytes(&image)?);
    let parsed = FixedNativeImage::parse(&bytes.0)?;
    let site = if role == NativeControlRole::DebugControl {
        Some(parsed.debug_control_site()?)
    } else {
        None
    };
    Ok(CompiledNativeControl {
        role,
        python: base.python().into(),
        image,
        inputs: inputs.snapshots(),
        site,
    })
}
enum LinkRole<'a> {
    Control(NativeControlRole),
    RegistryLoader(&'a Path),
    PythonAuthority(&'a Path),
    IndependentId2(&'a Path),
}
fn compile(
    tools: &DiscoveredRustTools,
    inputs: &mut Inputs,
    folder: &Path,
    output: &Path,
    role: LinkRole<'_>,
) -> Result<()> {
    io::missing(output)?;
    io::no_overrides(output)?;
    let raw = tools.tools();
    for path in [&raw.rustc, &raw.linker, &raw.kernel32] {
        inputs.open(path, 67108864)?;
    }
    let mut command = CommandSpec::new(raw.rustc.as_os_str());
    command.cwd = Some(folder.into());
    command.timeout = Duration::from_secs(60);
    command.idle_timeout = Some(Duration::from_secs(20));
    command.max_output = 1048576;
    command.env_remove = std::env::vars_os().map(|(name, _)| name).collect();
    let path = std::env::join_paths([
        raw.rustc.parent().unwrap().to_path_buf(),
        raw.linker.parent().unwrap().to_path_buf(),
        raw.system_root.join("System32"),
    ])?;
    for (name, value) in [
        ("SystemRoot", raw.system_root.as_os_str()),
        ("WINDIR", raw.system_root.as_os_str()),
        ("TEMP", folder.as_os_str()),
        ("TMP", folder.as_os_str()),
        ("PATH", path.as_os_str()),
    ] {
        command.env.insert(name.into(), value.into());
    }
    command.args = [
        "--edition=2024",
        "--crate-type=bin",
        "--target=x86_64-pc-windows-msvc",
        "--crate-name=revayat_native_fixture",
        "-Dwarnings",
        "-Cpanic=abort",
        "-Cdebuginfo=0",
        "-Ccodegen-units=1",
    ]
    .map(OsString::from)
    .into();
    command
        .args
        .push(format!("-Clinker={}", raw.linker.display()).into());
    let mut link = vec![
        "/NOLOGO".to_owned(),
        "/NODEFAULTLIB".into(),
        "/MANIFEST:NO".into(),
        "/SUBSYSTEM:CONSOLE".into(),
        "/MACHINE:X64".into(),
        "/INCREMENTAL:NO".into(),
    ];
    let maximum = if matches!(
        &role,
        LinkRole::RegistryLoader(_) | LinkRole::PythonAuthority(_)
    ) {
        16 * 1024 * 1024
    } else {
        1048576
    };
    let artifacts = match role {
        LinkRole::Control(NativeControlRole::Startup) => {
            command.args.push("-Copt-level=0".into());
            link.push("/ENTRY:StartupEntry".into());
            None
        }
        LinkRole::Control(NativeControlRole::DebugControl) => {
            command.args.push("-Copt-level=2".into());
            link.extend([
                "/ENTRY:StartupEntry".into(),
                "/EXPORT:DebugControlSite".into(),
            ]);
            Some(folder.join("debug-control-native.lib"))
        }
        LinkRole::RegistryLoader(library) => {
            command.args.push("-Copt-level=2".into());
            link.extend([
                "/DLL".into(),
                "/NOENTRY".into(),
                "/EXPORT:PyInit__registry_loader".into(),
            ]);
            command
                .args
                .push(format!("-Lnative={}", library.parent().unwrap().display()).into());
            command
                .args
                .push(format!("-Clink-arg={}", library.display()).into());
            Some(folder.join("registry-loader.lib"))
        }
        LinkRole::PythonAuthority(library) => {
            command.args.push("-Copt-level=2".into());
            link.extend([
                "/DLL".into(),
                "/NOENTRY".into(),
                "/EXPORT:PyInit__registry_authority".into(),
            ]);
            command
                .args
                .push(format!("-Lnative={}", library.parent().unwrap().display()).into());
            command
                .args
                .push(format!("-Clink-arg={}", library.display()).into());
            Some(folder.join("python-authority.lib"))
        }
        LinkRole::IndependentId2(resource) => {
            command.args.push("-Copt-level=0".into());
            link.extend(["/ENTRY:StartupEntry".into(), "/ALLOWISOLATION:NO".into()]);
            command
                .args
                .push(format!("-Clink-arg={}", resource.display()).into());
            None
        }
    };
    if let Some(library) = &artifacts {
        io::missing(library)?;
        io::missing(&library.with_extension("exp"))?;
        link.push(format!("/IMPLIB:{}", library.display()));
    }
    command.args.extend(
        link.into_iter()
            .map(|value| format!("-Clink-arg={value}").into()),
    );
    command
        .args
        .push(format!("-Lnative={}", raw.kernel32.parent().unwrap().display()).into());
    command
        .args
        .push(format!("-Clink-arg={}", raw.kernel32.display()).into());
    command.args.extend([
        "-o".into(),
        output.as_os_str().into(),
        folder.join("main.rs").into_os_string(),
    ]);
    let mut result = runtime::run(&command)?;
    let passed = result.code == 0 && result.stdout.is_empty() && result.stderr.is_empty();
    let code = result.code;
    result.stdout.fill(0);
    result.stderr.fill(0);
    ensure!(
        passed,
        "fixed independent Rust compiler failed exit={code} raw_output_withheld=True"
    );
    inputs.verify()?;
    inputs.open(output, maximum)?;
    if let Some(library) = artifacts {
        inputs.open(&library, 131072)?;
        inputs.open(&library.with_extension("exp"), 131072)?;
    }
    Ok(())
}
